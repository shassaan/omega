from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

import argparse
import json
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from hooks.lib import config as config_mod
from hooks.lib import event as event_mod
from hooks.lib import io as io_mod
from hooks.lib import git_signing, paths, shell, state

SCRIPT = "hooks/prod_guard.py"
MAX_LENGTH = 20000
FOOTER = ("Guard limits: scripts on disk, make/npm run targets and program internals are not inspected; "
          "credentials are the real boundary.")

ALTERNATIVES = {
    "git": "Commit and push only as the trusted identity with signing on (commit.gpgsign=true and the trusted "
           "user.signingkey in the repository's git config, which only the human sets); never override identity "
           "or signing with -c, --author, --no-gpg-sign or GIT_* variables",
    "gh": "Ask the human to do it; gh pr is allowed, plus read-only gh (issue view/list, repo view, run "
          "list/view, auth status, api GET)",
    "terraform": "Run terraform plan, show the plan to the human and let them apply it",
    "kubectl": "Use read-only kubectl/helm (get, describe, logs, list, status, template) and ask the "
               "human to make the change",
    "docker": "Use docker ps/logs/inspect/build; local docker run/exec/compose is allowed only without "
              "--host/--context/DOCKER_HOST",
    "db": "Write a migration with the Edit tool and let the human apply it; read-only SELECT/WITH/SHOW/"
          "EXPLAIN against the local database is allowed",
    "migrations": "Write the migration file with the Edit tool and ask the human to apply or roll it back",
    "rm": "Delete individual files without -r, or rm -rf only a build directory listed in "
          "guards.prod.rm_rf_allowlist inside the workspace",
    "pipe": "Download to a file under .scratch/, show it to the human and let them run it; requests "
            "with a body are allowed only against a local host (guards.prod.local_hosts)",
    "sys": "Ask the human to run it",
    "cloud": "Ask the human to run it; read-only describe/list/get commands are allowed",
    "net": "Ask the human to run it; the agent has no remote shell or file transfer access",
    "env": "Reference variables by name without printing them, and do not override PATH, GIT_*, "
           "loader or interpreter variables",
    "harness": "Ask the human",
    "dynamic": "Spell the command out as a literal",
    "custom": "Ask the human; this command matches guards.prod.extra_deny_regex",
}

DYNAMIC_RULES = (
    ("ansi_quoting", "dynamic.ansi_quoting", "uses $'...' or $\"...\" quoting, which cannot be resolved statically"),
    ("command_word", "dynamic.command_word", "computes the command name at run time"),
    ("eval", "dynamic.eval", "runs text through eval"),
    ("source", "dynamic.eval", "sources a script the guard cannot judge"),
    ("opaque_shell", "dynamic.opaque_shell", "hands commands to a shell the guard cannot read"),
    ("parse_failure", "dynamic.parse_failure", "cannot be parsed (unbalanced quotes)"),
    ("nesting", "dynamic.nesting", "nests shells or substitutions deeper than 6 levels"),
    ("too_long", "dynamic.too_long", "is longer than 20000 characters"),
)

DANGEROUS_ASSIGNMENT = re.compile(
    r"^(PATH|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|DYLD_\w+|GIT_\w+|PAGER|EDITOR|VISUAL|SHELL|BASH_ENV|ENV|IFS|"
    r"PYTHONPATH|PYTHONSTARTUP|PYTHONHOME|NODE_OPTIONS|NODE_PATH|PERL5OPT|PERL5LIB|RUBYOPT|RUBYLIB|"
    r"DOCKER_HOST|DOCKER_CONTEXT|KUBECONFIG|PROMPT_COMMAND|PS4|ZDOTDIR)\+?=")
SECRET_NAME = re.compile(r"(?i)(key|token|secret|password|passwd|credential)")
VAR_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")

INTERP_BAD = re.compile(
    r"os\.(system|popen|exec\w*|spawn\w*|fork|kill)|subprocess|pty\.spawn|commands\.getoutput|child_process|"
    r"execSync|spawnSync|Runtime\.getRuntime|\bsystem\s*\(|\bexec\s*\(|\bpopen\s*\(|\beval\s*\(|__import__|"
    r"shutil\.rmtree|os\.(remove|unlink|rmdir|removedirs)|\brmtree\b|requests\.(post|put|delete|patch)|"
    r"urllib|socket|http\.client|httpx|ctypes|`|\b(system|exec|spawn|fork)\s*\(|(?<![\"'\w])(system|exec|spawn)\s+[\"'$@\[%]|"
    r"\bqx\s*[\(\{\[</|!]|%x[\(\{\[<|]|"
    r"IO\.popen|Open3|Kernel\.|do\s+shell\s+script|\bpcntl_|\bpassthru\b|\bshell_exec\b|\bproc_open\b", re.I)
ENV_DUMP_CODE = re.compile(
    r"os\.environ\s*[)\]},;]|os\.environ\s*$|os\.environ\.(items|values|keys|copy)\s*\(|dict\(\s*os\.environ|"
    r"process\.env\s*[)\]},;]|process\.env\s*$|JSON\.stringify\(\s*process\.env|Object\.(keys|entries|values)"
    r"\(\s*process\.env|ENV\.(to_h|to_a|each|inspect)|%ENV|os\.getenv\(\s*\)", re.M)

SQL_BAD = re.compile(
    r"\b(drop\s+(database|schema|table|view|index|user|role|owned|materialized|function|extension|trigger|type|sequence)"
    r"|truncate|alter\s+(table|database|system|user|role|schema)|grant|revoke|flushall|flushdb|vacuum\s+full"
    r"|copy\s+.*\bprogram\b|pg_terminate_backend|pg_cancel_backend|insert\s+into|update\s+[\w\".]+(?:\.[\w\"]+)*\s+set"
    r"|create\s+(or\s+replace\s+)?(table|database|user|role|function|schema|extension|trigger)|dropdatabase"
    r"|\.drop\s*\(|deletemany\s*\(|\.remove\s*\(|config\s+set|shutdown)\b|\\!", re.I | re.S)
SQL_READONLY = re.compile(r"^\s*(select|with|show|explain|values|table|describe|desc|\\d\w*|\\l|\\dt|pragma)\b", re.I)
SQL_WRITE_WORD = re.compile(r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|merge|call|"
                            r"do|set|vacuum|reindex|cluster|lock|into)\b", re.I)

REMOTE_SHELL = re.compile(
    r"\b(curl|wget|fetch|aria2c|iwr|Invoke-WebRequest)\b[^\n]*\|\s*(sudo\s+)?(env\s+\S+\s+)*(ba|z|da|k|c|tc|fi)?sh\b"
    r"|\b(ba|z|da|k)?sh\s+(-\w+\s+)*<\(\s*(curl|wget)|\b(source|\.)\s+<\(\s*(curl|wget)")
REMOTE_INTERP = re.compile(
    r"\b(curl|wget|fetch)\b[^\n]*\|\s*(sudo\s+)?(python[\d.]*|perl|ruby|node|php|bun|deno|osascript)\s*(-\s*)?($|[|;&)])"
    r"|\b(python[\d.]*|perl|ruby|node|php|bun|deno)\s+(-\w+\s+)*<\(\s*(curl|wget)")
DECODED_SHELL = re.compile(
    r"(base64|b64decode|xxd\s+-r|openssl\s+(enc|base64)|uudecode)[^|;&\n]*\|\s*(sudo\s+)?"
    r"((ba|z|da|k)?sh|python[\d.]*|perl|ruby|node|php)\b")

GIT_READ = {"status", "diff", "log", "show", "blame", "ls-files", "rev-parse", "fetch", "describe", "grep",
            "shortlog", "ls-tree", "cat-file", "show-ref", "rev-list", "for-each-ref", "name-rev", "help",
            "version", "add", "diff-tree", "diff-index", "diff-files", "merge-base", "count-objects", "fsck",
            "check-ignore", "check-attr", "ls-remote", "range-diff", "whatchanged", "var", "show-branch",
            "cherry", "annotate", "verify-commit", "verify-tag", "get-tar-commit-id", "hash-object",
            "check-ref-format", "column", "interpret-trailers", "mailinfo", "stripspace"}
GIT_WRITE = {"push", "commit", "merge", "tag", "rebase", "cherry-pick", "revert", "am", "pull", "rm", "mv",
             "apply", "init", "clone", "bisect", "gc", "prune", "update-ref", "symbolic-ref", "maintenance",
             "restore", "notes", "replace", "repack", "pack-refs", "update-index", "read-tree", "write-tree",
             "commit-tree", "mktag", "mktree", "fast-import", "format-patch", "request-pull", "sparse-checkout",
             "lfs", "subtree", "switch", "checkout", "stash", "reset", "branch", "clean", "worktree", "submodule",
             "remote", "reflog"}
GIT_DENY = {"credential": "git credential reads or stores credentials",
            "daemon": "git daemon serves the repository over the network",
            "instaweb": "git instaweb starts a web server",
            "send-email": "git send-email sends mail",
            "svn": "git svn talks to a remote Subversion server",
            "p4": "git p4 talks to a remote Perforce server",
            "filter-branch": "git filter-branch runs shell filters the guard cannot read and strips signatures",
            "filter-repo": "git filter-repo rewrites history with code the guard cannot read and strips signatures"}
GIT_CONFIG_INJECTION = re.compile(r"^(alias\.|core\.(sshcommand|pager|editor|hookspath|fsmonitor|askpass|gitproxy|"
                                  r"alternaterefscommand|worktree)|credential\.|include\.|includeif\.|sequence\.editor"
                                  r"|diff\.external|diff\.[^.=]+\.(textconv|command)|difftool\.|mergetool\.|pager\."
                                  r"|filter\.|merge\.[^.=]+\.driver|gpg\.|uploadpack\.|receivepack\.|protocol\."
                                  r"|remote\.[^=]+\.(uploadpack|receivepack|vcs)|init\.templatedir|ssh\.variant|"
                                  r"http\.[^=]*proxy|interactive\.difffilter|web\.browser|browser\.)", re.I)
GIT_EXEC_OPTIONS = ("--upload-pack", "--receive-pack", "--exec", "--open-files-in-pager", "--exec-path", "--ext-diff")
AWK = {"awk", "gawk", "mawk", "nawk", "busybox-awk"}
AWK_BAD = re.compile(r"\bsystem\s*\(|\|\s*getline|\bprint[f]?\b[^;}]*\|\s*[\"$]|\|&")
SED_EXEC = re.compile(r"(^|[;\n{}])\s*([0-9]+|\$|/[^/\n]*/)?(,([0-9]+|\$|/[^/\n]*/))?\s*e(\s|;|$)"
                      r"|^\s*s(.)(?:\\.|(?!\6).)*\6(?:\\.|(?!\6).)*\6[gpIiMmw0-9]*e")
EDITORS = {"vi", "vim", "nvim", "ex", "view", "vimdiff", "gvim", "mvim", "emacs", "nano"}
EXTRA_WRAPPERS = {"pkexec", "runuser", "flock", "chronic", "ifne", "unshare", "nsenter", "firejail", "systemd-run", "sg",
                  "taskset", "numactl", "chrt", "cgexec", "torsocks", "proxychains", "proxychains4", "catchsegv",
                  "valgrind", "strace", "ltrace", "faketime", "dotenv", "envchain", "op", "doppler", "aws-vault",
                  "sops", "with-contenv", "parallel", "sem", "retry", "entr", "watchexec", "nodemon", "concurrently",
                  "script", "tmux", "screen", "expect", "xvfb-run", "dbus-launch", "setpriv", "capsh", "prlimit",
                  "dtruss", "sandbox-exec", "arch", "lldb", "gdb", "npm-run-all", "run-p", "run-s", "direnv",
                  "mise", "asdf", "rtx", "pipx", "tox", "nox", "invoke", "honcho", "foreman", "overmind"}
GIT_BRANCH_LIST = {"--list", "-l", "-a", "-r", "--all", "--remotes", "--show-current", "--contains",
                   "--no-contains", "--merged", "--no-merged", "--points-at", "-v", "-vv", "--verbose",
                   "--format", "--sort", "--column", "--no-column", "--color", "--no-color", "-i",
                   "--ignore-case"}
GIT_BRANCH_MUTATE = {"-d", "-D", "-m", "-M", "-c", "-C", "--delete", "--force", "-f", "--move", "--copy",
                     "--set-upstream-to", "-u", "--unset-upstream", "--edit-description", "--track", "-t",
                     "--no-track", "--create-reflog", "--recurse-submodules"}
GIT_BRANCH_VALUED = {"--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--format",
                     "--sort", "--column"}
GIT_CONFIG_READ = {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l", "--get-color",
                   "--get-colorbool", "--show-origin", "--show-scope", "--name-only"}
GIT_CONFIG_WRITE = {"--unset", "--unset-all", "--add", "--replace-all", "--edit", "-e", "--remove-section",
                    "--rename-section", "--set"}

DB_CLIENTS = {"psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "redis-cli", "clickhouse-client",
              "clickhouse", "bq", "snowsql", "sqlcmd", "cockroach", "duckdb", "pgcli", "mycli", "litecli",
              "usql", "cqlsh", "valkey-cli", "influx"}
DB_TOOLS_BLOCK = {"dropdb", "dropuser", "pg_restore", "mongorestore", "mysqladmin"}

SYS_BLOCK = {"dd", "mkfs", "fdisk", "sfdisk", "parted", "gdisk", "diskutil", "shutdown", "reboot", "halt",
             "poweroff", "launchctl", "systemctl", "service", "crontab", "at", "mount", "umount", "iptables",
             "ip6tables", "nft", "ufw", "pfctl", "passwd", "chpasswd", "visudo", "sudoedit", "killall", "pkill",
             "useradd", "userdel", "usermod", "groupadd", "groupdel", "dscl", "csrutil", "nvram", "su", "wipefs",
             "swapoff", "sysctl", "kextload", "spctl", "tmutil"}
NET_BLOCK = {"ssh", "scp", "sftp", "nc", "ncat", "netcat", "telnet", "ftp", "socat", "mosh", "rsh", "rlogin",
             "sshpass", "lftp", "smbclient"}
CLOUD_CLIS = {"aws", "gcloud", "az", "gsutil", "doctl", "linode-cli", "oci", "ibmcloud", "aliyun", "s3cmd",
              "rclone", "bq"}
CLOUD_VERB = re.compile(
    r"^(delete|rm|remove|terminate|destroy|purge|drop|deregister|detach|put|create|update|modify|run-instances|"
    r"start|stop|reboot|deploy|set|add|import|reset|restart|resize|scale|apply|patch|attach|enable|disable|cp|"
    r"mv|rsync|sync|mb|rb|upload|publish|invoke|send|execute|restore|revoke|grant|tag|untag|copy|write|"
    r"release|associate|disassociate|replace|promote|failover|rotate|cancel|submit|ssh|scp|login|logout|"
    r"move|rename|purge|batch-write|batch-delete|admin-|init|setiamp|acl|rewrite)(-|$|iampolicy)", re.I)
PLATFORM_CLIS = {"pulumi", "cdk", "cdktf", "serverless", "sls", "vercel", "netlify", "fly", "flyctl", "heroku",
                 "railway", "wrangler", "supabase", "firebase", "render", "amplify", "eb", "copilot",
                 "sam", "zappa", "dokku", "convex", "planetscale", "pscale", "neonctl", "turso"}
PLATFORM_VERBS = {"up", "destroy", "deploy", "delete", "remove", "rm", "publish", "prod", "secrets", "secret",
                  "db", "apps", "scale", "restart", "run", "push", "migrate", "release", "rollback", "promote",
                  "env", "config", "domains", "certs", "redeploy", "kill", "stop", "start", "reset", "link",
                  "login", "logout", "import", "refresh", "cancel", "alias", "dns", "volumes", "postgres",
                  "pg", "redis", "ssh", "sync", "upload", "branch", "functions"}
PACKAGE_PUBLISHERS = {"npm", "pnpm", "yarn", "bun"}
PACKAGE_PUBLISH_VERBS = {"publish", "unpublish", "deprecate", "login", "adduser", "token", "access", "owner",
                         "dist-tag", "logout", "team", "org", "hook", "profile", "star", "unstar"}
BUILD_PUBLISHERS = {"pip", "pip3", "cargo", "gem", "twine", "mvn", "gradle", "gradlew", "poetry", "uv",
                    "hatch", "flit", "pdm", "dotnet", "nuget", "go", "rye"}
BUILD_PUBLISH_VERBS = {"upload", "publish", "push", "deploy", "yank", "owner", "login", "release"}
NESTED_AGENTS = {"claude", "claude-code", "codex", "gemini", "gemini-cli", "aider", "opencode", "cursor-agent"}
NESTED_PACKAGES = re.compile(r"^@?(anthropic-ai/claude-code|openai/codex|google/gemini-cli|claude-code|"
                             r"codex|gemini-cli)(@.*)?$")
PACKAGE_RUNNERS = {"npx", "pnpx", "bunx"}
WRITEISH = {"rm", "unlink", "rmdir", "shred", "srm", "trash", "mv", "cp", "install", "ln", "tee", "truncate",
            "touch", "chmod", "chown", "chgrp", "chflags", "xattr", "dd", "rsync", "patch", "mkdir", "ditto",
            "setfacl", "chattr"}
RM_COMMANDS = {"rm", "unlink", "rmdir", "shred", "srm", "trash", "trash-put", "gio"}
SYSTEM_DIRS = re.compile(r"^/(usr|etc|var|bin|sbin|lib|lib64|opt|boot|dev|home|Users|System|Library|Applications|"
                         r"private|Volumes|root|srv|proc|sys|cores|nix)(/\*?)?/?$")


@dataclass
class Verdict:
    blocked: bool
    rule: str
    reason: str
    alternative: str


@dataclass
class GuardContext:
    workspace: str
    harness_root: Path
    cfg: object
    env: dict = field(default_factory=dict)
    cwd: Optional[str] = None
    transcript_path: Optional[str] = None


ALLOWED = Verdict(False, "allow", "", "")


def guard_context(workspace: Optional[str] = None, cwd: Optional[str] = None, cfg=None,
                  transcript_path: Optional[str] = None, env: Optional[dict] = None) -> GuardContext:
    ws = os.path.realpath(workspace or paths.workspace_of({}))
    root = paths.harness_root()
    return GuardContext(workspace=ws, harness_root=root, cfg=cfg if cfg is not None else config_mod.load(root, ws),
                        env=dict(env if env is not None else os.environ), cwd=cwd or ws,
                        transcript_path=transcript_path)


def family_of(rule: str) -> str:
    return rule.split(".", 1)[0]


def block(rule: str, what: str, alternative: Optional[str] = None) -> Verdict:
    alt = alternative or ALTERNATIVES.get(family_of(rule), "Ask the human")
    what = what.rstrip(".")
    reason = "[prod-guard] blocked (%s): %s. %s. %s" % (rule, what, alt.rstrip("."), FOOTER)
    return Verdict(True, rule, reason, alt)


def _cwd(ctx: GuardContext) -> str:
    return os.path.realpath(ctx.cwd or ctx.workspace)


def _resolve(path: str, base: str) -> str:
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        expanded = os.path.join(base, expanded)
    return os.path.normpath(expanded)


def _cfg(ctx: GuardContext, dotted: str, default=None):
    getter = getattr(ctx.cfg, "get", None)
    if getter is None:
        return default
    value = getter(dotted, default)
    return default if value is None else value


def mask_quotes(text: str) -> str:
    return re.sub(r"'[^']*'|\"(?:\\.|[^\"\\])*\"", "''", text or "")


def _head_words(head: str) -> list:
    try:
        return shell.tokens(head.replace("$(", " ").replace("(", " ").replace(")", " "))
    except ValueError:
        return []


def heredoc_consumer(head: str) -> Optional[str]:
    words = _head_words(head)
    if not words and head.strip():
        return "shell"
    for word in words:
        inner = shell.unwrap([word]) or [word]
        name = shell.basename(inner[0])
        if name in shell.SHELLS or name in shell.EVAL_WORDS:
            return "shell"
    for word in words:
        if shell.is_interpreter(word):
            return shell.basename(word)
    return None


def shell_c_payload(argv: list) -> Optional[str]:
    for index, token in enumerate(argv[1:], 1):
        if re.match(r"^-[A-Za-z]*c[A-Za-z]*$", token):
            return argv[index + 1] if index + 1 < len(argv) else ""
        if token.startswith("-") or token.startswith("+"):
            continue
        return None
    return None


def segment_argv(segment: str) -> Optional[list]:
    try:
        shell.tokens(segment)
        return shell.strip_control(shell.argv_of(segment))
    except ValueError:
        return None


def _exec_blocks(argv: list) -> list:
    blocks: list = []
    for index, token in enumerate(argv):
        if token in ("-exec", "-execdir", "-ok", "-okdir"):
            end = index + 1
            while end < len(argv) and argv[end] not in (";", "+", "\\;"):
                end += 1
            blocks.append(argv[index + 1:end])
    return blocks


def _nested_texts(argv: list) -> list:
    inner = shell.unwrap(argv)
    if not inner:
        return []
    name = shell.basename(inner[0])
    if name == "eval":
        return [" ".join(inner[1:])]
    if shell.is_shell(name):
        payload = shell_c_payload(inner)
        return [payload] if payload else []
    if name == "find":
        found: list = []
        for block_argv in _exec_blocks(inner):
            found.extend(_nested_texts(block_argv))
        return found
    return []


def shell_texts(command: str, depth: int = 0) -> list:
    out: list = []
    _collect_texts(command or "", depth, out)
    return out


def _collect_texts(text: str, depth: int, out: list) -> None:
    if depth > shell.MAX_DEPTH or len(out) > 400:
        return
    out.append(text)
    stripped = shell.strip_heredocs(text)
    for head, body in shell.heredocs(text):
        if heredoc_consumer(head) == "shell":
            _collect_texts(body, depth + 1, out)
    for inner in shell.substitutions(stripped):
        _collect_texts(inner, depth + 1, out)
    for segment in shell.split_commands(stripped):
        argv = segment_argv(segment)
        if not argv:
            continue
        for nested in _nested_texts(argv):
            _collect_texts(nested, depth + 1, out)


def _segments_of(text: str) -> list:
    found: list = []
    for segment in shell.split_commands(shell.strip_heredocs(text)):
        argv = segment_argv(segment)
        if argv:
            found.append(argv)
    return found


def _positional(args: list) -> list:
    return [a for a in args if not a.startswith("-")]


DOCKER_VALUE_OPTIONS = {"-H", "--host", "--context", "-c", "--config", "-l", "--log-level", "--tlscacert",
                        "--tlscert", "--tlskey", "-f", "--file", "-p", "--project-name", "--profile", "--env-file",
                        "--project-directory", "--ansi", "--progress", "--parallel"}
KUBECTL_VALUE_OPTIONS = {"-n", "--namespace", "--context", "--cluster", "--user", "-l", "--selector", "-o",
                         "--output", "-f", "--filename", "-c", "--container", "--kubeconfig", "-s", "--server",
                         "--token", "--as", "--as-group", "-L", "--label-columns", "--field-selector", "--sort-by",
                         "--template", "-p", "--request-timeout", "--kube-context", "--repo", "--version",
                         "--values", "--set", "--set-string", "--set-file", "--timeout", "--revision"}


def _words(args: list, valued: set) -> list:
    words: list = []
    skip = False
    for token in args:
        if skip:
            skip = False
            continue
        if token in valued:
            skip = True
            continue
        if token.startswith("-"):
            continue
        words.append(token)
    return words


def _normalise_runner(argv: list) -> list:
    if not argv:
        return argv
    name = shell.basename(argv[0])
    rest = list(argv[1:])
    if name in PACKAGE_RUNNERS or (name in ("pnpm", "npm", "yarn", "bun") and rest[:1] and rest[0] in ("exec", "dlx", "x")):
        if name not in PACKAGE_RUNNERS:
            rest = rest[1:]
        while rest and rest[0].startswith("-"):
            flag = rest.pop(0)
            if flag in ("-p", "--package", "-c", "--call") and rest:
                rest.pop(0)
        if rest:
            return [shell.basename(rest[0]) if "/" in rest[0] and not rest[0].startswith("@") else rest[0]] + rest[1:]
        return argv
    if re.match(r"^python(\d+(\.\d+)*)?$", name):
        index = 0
        while index < len(rest) and rest[index].startswith("-"):
            if rest[index] == "-m" and index + 1 < len(rest):
                return [rest[index + 1]] + rest[index + 2:]
            if rest[index] in ("-c", "-"):
                return argv
            index += 1
        if index < len(rest):
            return [shell.basename(rest[index])] + rest[index + 1:]
        return argv
    if name == "yarn" and rest and not rest[0].startswith("-") and rest[0] not in PACKAGE_PUBLISH_VERBS:
        return [rest[0]] + rest[1:]
    return argv


def _git_location(argv: list, rest: list, ctx: GuardContext) -> list:
    return git_signing.location_of(argv, len(rest), _cwd(ctx))


def _git_signing(sub: str, argv: list, rest: list, ctx: GuardContext) -> Optional[Verdict]:
    creates_tag = sub == "tag" and git_signing.tag_creates(rest)
    if sub not in git_signing.COMMIT_MAKERS and sub != "push" and not creates_tag:
        return None
    pol = git_signing.policy(ctx.cfg, ctx.workspace, ctx.env)
    if not pol.require_signed:
        return None
    flags = git_signing.flag_problems(sub, rest, pol)
    if flags:
        rule = "git.identity_override" if "--author" in flags[0] else "git.signing_override"
        return block(rule, flags[0])
    location = _git_location(argv, rest, ctx)
    problems = git_signing.config_problems(location, pol, ctx.env)
    if problems:
        return block("git.signing_required", "git %s needs signed commits as the trusted identity: %s" %
                     (sub, "; ".join(problems)))
    if creates_tag and not git_signing.tag_signed(rest, location, ctx.env):
        return block("git.unsigned_tag", "git tag creates an unsigned tag; use git tag -s or set tag.gpgsign")
    if sub == "push":
        outgoing = git_signing.outgoing_problems(location, git_signing.push_refs(rest), pol, ctx.env)
        if outgoing:
            shown = "; ".join(outgoing[:5]) + ("; and %d more" % (len(outgoing) - 5) if len(outgoing) > 5 else "")
            return block("git.unsigned_push", "git push would publish commits that are not signed by the trusted "
                         "identity: %s" % shown, "Ask the human to re-sign or drop those commits, then push again")
    return None


def _git(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    sub, rest, configs = shell.git_subcommand(argv)
    for value in configs:
        if GIT_CONFIG_INJECTION.match(value or ""):
            return block("git.config_injection", "git -c %s injects a command through git configuration" % value)
        if git_signing.SIGNING_CONFIG.match(value or ""):
            return block("git.signing_override", "git -c %s overrides the commit identity or signing settings" % value)
    raw_args = argv[1:]
    for token in raw_args:
        if token.split("=", 1)[0] in GIT_EXEC_OPTIONS or (sub in ("ls-remote", "clone") and token == "-u") or \
                (sub == "grep" and (token == "-O" or token.startswith("-O"))) or (sub == "rebase" and token == "-x"):
            return block("git.config_injection", "git %s runs an external program through %s" % (sub or "", token.split("=", 1)[0]))
        if token == "--output" or token.startswith("--output="):
            return block("git.output_file", "git %s --output writes a file outside the edit tools" % sub)
        if sub in ("init", "clone") and (token == "--template" or token.startswith("--template=")):
            return block("git.config_injection", "git %s --template installs hooks from a template directory" % sub)
    if sub == "clone":
        for index, token in enumerate(rest):
            value = None
            if token in ("-c", "--config") and index + 1 < len(rest):
                value = rest[index + 1]
            elif token.startswith("--config="):
                value = token.split("=", 1)[1]
            if value is not None and (GIT_CONFIG_INJECTION.match(value) or git_signing.SIGNING_CONFIG.match(value)):
                return block("git.config_injection", "git clone --config %s sets risky configuration" % value)
    if not sub or sub in ("version", "help"):
        return None
    if sub in GIT_DENY:
        return block("git.%s" % sub, GIT_DENY[sub])
    if sub == "submodule" and "foreach" in _positional(rest):
        return block("git.submodule_foreach", "git submodule foreach runs a shell command in every submodule")
    if sub == "bisect" and _positional(rest)[:1] == ["run"]:
        return block("git.bisect_run", "git bisect run runs a command the guard cannot judge")
    if sub == "config":
        if any(a in GIT_CONFIG_WRITE or a.split("=", 1)[0] in GIT_CONFIG_WRITE for a in rest):
            return block("git.config", "git config %s writes configuration" % " ".join(rest[:2]))
        if any(a in GIT_CONFIG_READ for a in rest):
            return None
        values = [a for a in rest if not a.startswith("-")]
        if len(values) >= 2:
            return block("git.config", "git config %s %s writes configuration" % (values[0], values[1]))
        return None
    if sub == "archive":
        if any(a in ("-o", "--output") or a.startswith("--output=") or (a.startswith("-o") and len(a) > 2)
               for a in rest):
            return block("git.archive", "git archive -o writes an archive file")
        return None
    if sub in GIT_WRITE:
        return _git_signing(sub, argv, rest, ctx)
    if sub in GIT_READ:
        return None
    return block("git.unknown_subcommand", "git %s is not a known git command" % sub)


def _gh(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    args = argv[1:]
    words = _positional(args)
    if not words:
        return None
    group = words[0]
    action = words[1] if len(words) > 1 else ""
    allowed = {
        "pr": None,
        "issue": {"view", "list", "status"},
        "repo": {"view", "list"},
        "run": {"list", "view", "watch"},
        "workflow": {"list", "view"},
        "auth": {"status"},
        "variable": {"list", "get"},
        "release": set(),
        "secret": set(),
        "label": {"list"},
        "search": None,
        "status": None,
        "browse": None,
        "help": None,
        "version": None,
        "completion": None,
    }
    if group == "api":
        method = None
        for index, token in enumerate(args):
            if token in ("-X", "--method") and index + 1 < len(args):
                method = args[index + 1]
            elif token.startswith("--method="):
                method = token.split("=", 1)[1]
            elif token.startswith("-X") and len(token) > 2:
                method = token[2:]
        if method and method.upper() not in ("GET", "HEAD"):
            return block("gh.api", "gh api -X %s changes GitHub state" % method.upper())
        if any(t in ("-f", "-F", "--field", "--raw-field", "--input") or t.startswith("--field=")
               or t.startswith("--raw-field=") or t.startswith("--input=")
               or (len(t) > 2 and t[:2] in ("-f", "-F") and "=" in t) for t in args):
            return block("gh.api", "gh api with a request body implies a POST")
        return None
    if group not in allowed:
        return block("gh.unknown", "gh %s is not a known read-only gh command" % group)
    permitted = allowed[group]
    if permitted is None or not action or action in permitted:
        return None
    return block("gh.%s" % group, "gh %s %s changes GitHub state" % (group, action))


def _terraform(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    name = argv[0]
    words = _positional(argv[1:])
    if not words:
        return None
    verb = words[0]
    if name == "terragrunt" and verb in ("run-all", "run"):
        if len(words) > 1 and words[1] in ("plan", "validate", "init", "output", "show", "fmt", "graph"):
            if verb == "run-all":
                return block("terraform.run_all", "terragrunt run-all fans out across every module")
            return None
        return block("terraform.run_all", "terragrunt %s runs commands across modules" % verb)
    if verb in ("apply", "destroy", "import", "taint", "untaint", "force-unlock", "refresh"):
        return block("terraform.%s" % verb.replace("-", "_"), "%s %s changes real infrastructure or state" % (name, verb))
    if verb == "state":
        action = words[1] if len(words) > 1 else ""
        if action in ("list", "show", "pull", ""):
            return None
        return block("terraform.state", "%s state %s rewrites remote state" % (name, action))
    if verb == "workspace":
        action = words[1] if len(words) > 1 else ""
        if action in ("list", "show", ""):
            return None
        return block("terraform.workspace", "%s workspace %s switches or changes workspaces" % (name, action))
    if verb in ("init", "validate", "fmt", "plan", "show", "output", "providers", "version", "graph", "console",
                "get", "test", "metadata", "modules", "help", "hclfmt", "render-json", "graph-dependencies",
                "terragrunt-info", "validate-inputs", "output-module-groups", "-version", "login"):
        if verb == "login":
            return block("terraform.login", "%s login stores registry credentials" % name)
        return None
    return block("terraform.unknown_subcommand", "%s %s is not a known read-only command" % (name, verb))


def _kubectl(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    name = argv[0]
    words = _words(argv[1:], KUBECTL_VALUE_OPTIONS)
    if name == "helm":
        if not words:
            return None
        if words[0] in ("list", "ls", "status", "template", "lint", "version", "show", "inspect", "search",
                        "history", "get", "env", "help", "verify", "completion", "dependency", "dep"):
            if words[0] in ("dependency", "dep") and len(words) > 1 and words[1] in ("update", "build"):
                return None
            return None
        if words[0] == "repo" and (len(words) < 2 or words[1] in ("list", "ls")):
            return None
        return block("kubectl.helm_%s" % words[0].replace("-", "_"), "helm %s changes cluster state" % words[0])
    if not words:
        return None
    verb = words[0]
    if verb in ("get", "describe", "logs", "top", "version", "explain", "api-resources", "api-versions",
                "cluster-info", "diff", "wait", "events", "help", "completion", "kustomize"):
        return None
    if verb == "config":
        action = words[1] if len(words) > 1 else "view"
        if action in ("view", "current-context", "get-contexts", "get-clusters", "get-users"):
            return None
        return block("kubectl.config", "%s config %s changes the kubeconfig" % (name, action))
    return block("kubectl.%s" % verb.replace("-", "_"), "%s %s changes cluster state" % (name, verb))


def _docker_remote(argv: list, assignments: list, ctx: GuardContext) -> Optional[str]:
    for token in argv:
        if token in ("--context", "-H", "--host", "-c") or token.startswith("--context=") or token.startswith("--host=") \
                or (token.startswith("-H") and len(token) > 2):
            return "it targets another docker host (%s)" % token
    for assignment in assignments:
        if assignment.split("=", 1)[0] in ("DOCKER_HOST", "DOCKER_CONTEXT"):
            return "it sets %s" % assignment.split("=", 1)[0]
    host = (ctx.env or {}).get("DOCKER_HOST", "")
    if host and not host.startswith("unix://") and not any(h in host for h in _local_hosts(ctx)):
        return "DOCKER_HOST points at %s" % host
    return None


def _docker(argv: list, assignments: list, ctx: GuardContext) -> Optional[Verdict]:
    name = argv[0]
    words = _words(argv[1:], DOCKER_VALUE_OPTIONS)
    if name == "docker-compose":
        words = ["compose"] + words
    if not words:
        return None
    if "prune" in words:
        return block("docker.prune", "%s %s prune deletes resources" % (name, " ".join(words[:1])))
    local_ok = bool(_cfg(ctx, "guards.prod.allow_local_docker", True))
    remote = _docker_remote(argv, assignments, ctx)
    verb = words[0]
    reads = {"ps", "images", "logs", "inspect", "version", "info", "build", "pull", "stats", "top", "history",
             "port", "diff", "events", "search", "help", "buildx", "manifest", "scout", "init"}
    local = {"run", "exec", "start", "restart", "create", "cp", "pause", "unpause", "attach", "wait", "export",
             "save", "load", "commit", "rename", "update", "tag"}
    blocked = {"rm", "rmi", "kill", "stop", "push", "login", "logout", "swarm", "service", "stack", "secret",
               "config", "node", "plugin", "trust"}
    groups = {"container", "image", "volume", "network", "context", "builder", "system", "compose"}
    if verb in groups:
        action = words[1] if len(words) > 1 else "ls"
        if verb == "compose":
            if action == "push":
                return block("docker.push", "docker compose push uploads images")
            if action in ("up", "down", "rm", "run", "exec", "start", "stop", "restart", "kill", "pause",
                          "unpause", "create", "cp", "watch"):
                return _docker_local(name, "compose %s" % action, local_ok, remote)
            return None
        if action in ("ls", "list", "inspect", "df", "show", "history", "logs", "top", "stats", "port", "diff",
                      "build", "bake", "version", "info", "events", "du"):
            return None
        if action in ("rm", "remove", "prune", "kill", "stop", "use", "create", "update", "import", "export",
                      "disconnect", "connect", "push"):
            if verb in ("container", "image") and action in ("create",):
                return _docker_local(name, "%s %s" % (verb, action), local_ok, remote)
            return block("docker.%s_%s" % (verb, action), "%s %s %s changes docker resources" % (name, verb, action))
        if verb in ("container", "image") and action in local:
            return _docker_local(name, "%s %s" % (verb, action), local_ok, remote)
        return block("docker.%s_%s" % (verb, action), "%s %s %s is not a known read-only docker command" % (name, verb, action))
    if verb in blocked:
        return block("docker.%s" % verb, "%s %s changes docker resources or registries" % (name, verb))
    if verb in reads:
        if remote:
            return block("docker.remote", "%s %s %s" % (name, verb, remote))
        return None
    if verb in local:
        return _docker_local(name, verb, local_ok, remote)
    return block("docker.unknown", "%s %s is not a known docker command" % (name, verb))


def _docker_local(name: str, verb: str, local_ok: bool, remote: Optional[str]) -> Optional[Verdict]:
    if not local_ok:
        return block("docker.%s" % verb.replace(" ", "_"), "%s %s runs containers (guards.prod.allow_local_docker is false)" % (name, verb))
    if remote:
        return block("docker.remote", "%s %s runs against a non-local docker: %s" % (name, verb, remote))
    return None


def sql_problem(text: str) -> Optional[tuple]:
    cleaned = re.sub(r"--[^\n]*|/\*.*?\*/", " ", text or "", flags=re.S)
    match = SQL_BAD.search(cleaned)
    if match:
        return "db.destructive_sql", "the SQL contains %r" % " ".join(match.group(0).split())[:40]
    for statement in cleaned.split(";"):
        if re.search(r"\bdelete\s+from\b", statement, re.I) and not re.search(r"\bwhere\b", statement, re.I):
            return "db.delete_without_where", "the SQL deletes every row (DELETE without WHERE)"
        if re.match(r"\s*['\"]?\s*update\b", statement, re.I) and not re.search(r"\bwhere\b", statement, re.I):
            return "db.update_without_where", "the SQL updates every row (UPDATE without WHERE)"
    if re.search(r"\bdelete\s+from\b", cleaned, re.I):
        return "db.delete", "the SQL deletes rows (DELETE needs human review)"
    return None


def _sql_files(argv: list, ctx: GuardContext) -> str:
    texts: list = []
    for index, token in enumerate(argv):
        value = None
        if token in ("-f", "--file", "-i", "--init", "--source") and index + 1 < len(argv):
            value = argv[index + 1]
        elif token.startswith("--file="):
            value = token.split("=", 1)[1]
        if not value:
            continue
        target = _resolve(value, _cwd(ctx))
        try:
            with open(target, "r", encoding="utf-8", errors="replace") as handle:
                texts.append(handle.read(200000))
        except OSError:
            texts.append("<unreadable %s>" % value)
    return "\n".join(texts)


def _readonly_proven(argv: list, sql_text: str) -> bool:
    inline: list = []
    for index, token in enumerate(argv[1:], 1):
        if token in ("-c", "--command", "-e", "--execute", "--eval", "-q", "--query") and index + 1 < len(argv):
            inline.append(argv[index + 1])
    if not inline and shell.basename(argv[0]) in ("sqlite3", "duckdb"):
        positional = _positional(argv[1:])
        if len(positional) >= 2:
            inline.append(positional[-1])
    if not inline or sql_text.strip():
        return False
    for chunk in inline:
        for statement in [s for s in chunk.split(";") if s.strip()]:
            if not SQL_READONLY.match(statement) or SQL_WRITE_WORD.search(statement):
                return False
    return True


def _db(argv: list, ctx: GuardContext, command_text: str) -> Optional[Verdict]:
    name = argv[0]
    if name in DB_TOOLS_BLOCK:
        return block("db.%s" % name, "%s drops or overwrites a database" % name)
    file_text = _sql_files(argv, ctx)
    problem = sql_problem(command_text + "\n" + file_text)
    if problem:
        return block(problem[0], "%s: %s" % (name, problem[1]))
    if bool(_cfg(ctx, "guards.prod.strict_db", False)) and not _readonly_proven(argv, file_text):
        return block("db.unproven_readonly", "%s runs SQL that cannot be proven read-only (guards.prod.strict_db)" % name)
    return None


def _migrations(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    name = shell.basename(argv[0])
    words = _positional(argv[1:])
    if name == "prisma":
        if words[:1] == ["migrate"] and any(w in words for w in ("reset", "deploy", "dev", "resolve")):
            return block("migrations.prisma", "prisma %s changes the database schema" % " ".join(words[:2]))
        if words[:1] == ["db"] and any(w in words for w in ("push", "execute", "seed")):
            return block("migrations.prisma", "prisma %s writes to the database" % " ".join(words[:2]))
        return None
    if name == "alembic":
        if words[:1] and words[0] in ("downgrade", "stamp"):
            return block("migrations.alembic_%s" % words[0], "alembic %s rewrites the database schema history" % words[0])
        if words[:1] == ["upgrade"] and not bool(_cfg(ctx, "guards.prod.allow_alembic_upgrade", True)):
            return block("migrations.alembic_upgrade", "alembic upgrade changes the database (guards.prod.allow_alembic_upgrade is false)")
        return None
    if name == "flask" and words[:1] == ["db"] and len(words) > 1 and words[1] in ("downgrade", "stamp", "drop"):
        return block("migrations.flask_db", "flask db %s rewrites the database" % words[1])
    if name in ("rails", "rake"):
        for word in words:
            if re.match(r"^db:(drop|reset|schema:load|migrate:reset|rollback|setup|purge|truncate_all|seed:replant)", word):
                return block("migrations.rails", "%s %s destroys or rewrites the database" % (name, word))
        return None
    if name in ("manage.py", "django-admin"):
        verb = words[0] if words else ""
        if verb in ("flush", "sqlflush", "reset_db", "dbshell", "reset_schema"):
            return block("migrations.django", "%s %s wipes or opens the database" % (name, verb))
        if verb == "migrate" and len(words) >= 3:
            return block("migrations.django", "%s migrate %s %s can roll migrations back" % (name, words[1], words[2]))
        return None
    if name in ("knex", "sequelize", "sequelize-cli", "typeorm", "drizzle-kit", "flyway", "liquibase", "dbmate",
                "goose", "migrate", "atlas", "sqitch", "mikro-orm", "kysely-migration-cli"):
        for word in words:
            if re.search(r"(rollback|drop|clean|destroy|push|undo|revert|reset|down|repair|wipe)", word):
                return block("migrations.%s" % re.sub(r"[^a-z0-9]", "_", name), "%s %s rolls back or drops schema" % (name, word))
        return None
    return None


def _catastrophic(path: str) -> bool:
    literal = {"/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/", "${HOME}/", "$HOME/*", "${HOME}/*",
               "*", ".", "..", "./", "./*", "../", "../*", ".*", "/.", "/..", "~/.*"}
    if path in literal:
        return True
    if SYSTEM_DIRS.match(path):
        return True
    home = os.path.expanduser("~")
    if path.startswith("~"):
        normalised = os.path.normpath(home + path[1:])
    elif path.startswith("/"):
        normalised = os.path.normpath(path)
    else:
        return False
    return normalised in ("/", home) or normalised == os.path.dirname(home)


def _rm_allowed(path: str, ctx: GuardContext) -> bool:
    if "$" in path or "`" in path or not path:
        return False
    base = _cwd(ctx)
    target = _resolve(path, base)
    glob_at = next((i for i, ch in enumerate(path) if ch in "*?[{"), None)
    workspace = os.path.realpath(ctx.workspace)
    temp_roots = paths.temp_roots()
    if target not in temp_roots and paths.is_scratch(target, ctx) and \
            paths.rel(target, workspace).startswith("/") and paths.rel(target, str(ctx.harness_root)).startswith("/"):
        return True
    relative = paths.rel(target, workspace)
    if relative.startswith("/") or relative in (".", ""):
        return False
    allow = set(str(x).strip("/") for x in _cfg(ctx, "guards.prod.rm_rf_allowlist", []) or [])
    parts = relative.split("/")
    if glob_at is not None:
        prefix = path[:glob_at]
        prefix_target = _resolve(prefix.rsplit("/", 1)[0] if "/" in prefix else ".", base)
        prefix_rel = paths.rel(prefix_target, workspace)
        if prefix_rel.startswith("/") or prefix_rel == ".":
            return False
        return any(p in allow for p in prefix_rel.split("/"))
    return any(p in allow for p in parts) or relative in allow


def _rm(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    name = argv[0]
    if name == "gio" and (len(argv) < 2 or argv[1] not in ("trash", "remove")):
        return None
    args = argv[2:] if name == "gio" else argv[1:]
    if "--" in args:
        cut = args.index("--")
        options, operands = args[:cut], args[cut + 1:]
    else:
        options = [a for a in args if a.startswith("-") and a != "-"]
        operands = [a for a in args if not (a.startswith("-") and a != "-")]
    short = "".join(a[1:] for a in options if not a.startswith("--"))
    long_options = [a for a in options if a.startswith("--")]
    if "--no-preserve-root" in long_options:
        return block("rm.no_preserve_root", "%s --no-preserve-root disables the root safety net" % name)
    for operand in operands:
        if _catastrophic(operand):
            return block("rm.catastrophic", "%s %s deletes a home, root or system directory" % (name, operand))
    recursive = "r" in short.lower() or "--recursive" in long_options
    if recursive and name in ("rm", "srm", "trash", "trash-put", "gio"):
        for operand in operands:
            if not _rm_allowed(operand, ctx):
                return block("rm.recursive", "%s -%s %s recursively deletes a path that is not an allowlisted "
                             "build directory inside the workspace" % (name, short or "r", operand))
    return None


def _find(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    if "-delete" in argv:
        return block("rm.find_delete", "find -delete deletes every match")
    return None


def _local_hosts(ctx: GuardContext) -> list:
    return [str(h) for h in (_cfg(ctx, "guards.prod.local_hosts", []) or [])]


def _url_is_local(url: str, ctx: GuardContext) -> bool:
    if not url or shell.is_opaque(url.replace("?", "").replace("[", "").replace("{", "").replace("*", "")):
        return False
    text = url if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url) else "http://" + url
    try:
        host = urlsplit(text).hostname or ""
    except ValueError:
        return False
    if not host:
        return False
    if host in _local_hosts(ctx):
        return True
    return "." not in host and ":" not in host


CURL_VALUE_OPTIONS = {"-H", "--header", "-u", "--user", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie",
                      "-c", "--cookie-jar", "-w", "--write-out", "-m", "--max-time", "--connect-timeout",
                      "--retry", "-K", "--config", "--cacert", "--cert", "--key", "--resolve", "-x", "--proxy",
                      "-r", "--range", "--limit-rate", "-y", "-Y", "--max-filesize", "--proto", "--interface",
                      "--retry-delay", "--retry-max-time", "-E", "--oauth2-bearer", "--aws-sigv4", "--url-query"}
CURL_BODY_OPTIONS = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "-F",
                     "--form", "--form-string", "-T", "--upload-file", "--json"}


def _curl(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    args = argv[1:]
    method = None
    body = False
    outputs: list = []
    remote_name = False
    urls: list = []
    index = 0
    while index < len(args):
        token = args[index]
        nxt = args[index + 1] if index + 1 < len(args) else ""
        if token in ("-X", "--request"):
            method = nxt
            index += 2
            continue
        if token.startswith("--request="):
            method = token.split("=", 1)[1]
        elif token in CURL_BODY_OPTIONS:
            body = True
            index += 2
            continue
        elif any(token.startswith(o + "=") for o in CURL_BODY_OPTIONS if o.startswith("--")):
            body = True
        elif token in ("-o", "--output", "--output-dir"):
            outputs.append(nxt)
            index += 2
            continue
        elif token.startswith("--output=") or token.startswith("--output-dir="):
            outputs.append(token.split("=", 1)[1])
        elif token in ("-O", "--remote-name", "--remote-name-all", "-J", "--remote-header-name"):
            remote_name = remote_name or token in ("-O", "--remote-name", "--remote-name-all")
        elif token == "--url":
            urls.append(nxt)
            index += 2
            continue
        elif token in CURL_VALUE_OPTIONS:
            index += 2
            continue
        elif token.startswith("--"):
            pass
        elif token.startswith("-") and len(token) > 1:
            flags = token[1:]
            if flags[0] == "X":
                method = flags[1:] or nxt
                index += 1 if flags[1:] else 2
                continue
            if flags[0] in "dFT" and len(flags) > 1 and not flags.isalpha():
                body = True
            if "O" in flags:
                remote_name = True
            last = flags[-1]
            if last == "o":
                outputs.append(nxt)
                index += 2
                continue
            if last in "dFT":
                body = True
                index += 2
                continue
            if last == "X":
                method = nxt
                index += 2
                continue
            if last in "HuAebcwmKrxyYE":
                index += 2
                continue
        else:
            urls.append(token)
        index += 1
    mutating = body or (method is not None and method.upper() not in ("GET", "HEAD", "OPTIONS"))
    if mutating:
        remote = [u for u in urls if not _url_is_local(u, ctx)] or ([] if urls else ["<no literal URL>"])
        if remote:
            return block("pipe.remote_write", "%s sends data (%s) to %s, which is not a local host" %
                         (argv[0], (method or "POST").upper(), remote[0]),
                         "Run it against the local service only (host in guards.prod.local_hosts)")
    return _download_targets(argv[0], outputs, remote_name, ctx)


def _download_targets(name: str, outputs: list, remote_name: bool, ctx: GuardContext) -> Optional[Verdict]:
    for target in outputs:
        if target in ("-", "/dev/null", "/dev/stdout"):
            continue
        if not target or shell.is_opaque(target):
            return block("pipe.download_write", "%s writes its download to a path computed at run time" % name)
        resolved = _resolve(target, _cwd(ctx))
        if not paths.is_scratch(resolved, ctx):
            return block("pipe.download_write", "%s writes its download to %s, outside scratch" % (name, target),
                         "Download to /tmp or .scratch/ instead, then inspect the file")
    if remote_name and not paths.is_scratch(_cwd(ctx) + "/x", ctx):
        return block("pipe.download_write", "%s -O writes the download into %s, outside scratch" % (name, _cwd(ctx)),
                     "Download to /tmp or .scratch/ instead, then inspect the file")
    return None


def _wget(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    args = argv[1:]
    body = False
    method = None
    outputs: list = []
    prefix = None
    spider = False
    urls: list = []
    index = 0
    while index < len(args):
        token = args[index]
        nxt = args[index + 1] if index + 1 < len(args) else ""
        if token in ("--post-data", "--post-file", "--body-data", "--body-file"):
            body = True
            index += 2
            continue
        if any(token.startswith(o + "=") for o in ("--post-data", "--post-file", "--body-data", "--body-file")):
            body = True
        elif token == "--method":
            method = nxt
            index += 2
            continue
        elif token.startswith("--method="):
            method = token.split("=", 1)[1]
        elif token in ("-O", "--output-document"):
            outputs.append(nxt)
            index += 2
            continue
        elif token.startswith("--output-document="):
            outputs.append(token.split("=", 1)[1])
        elif token.startswith("-O") and len(token) > 2:
            outputs.append(token[2:])
        elif token in ("-P", "--directory-prefix"):
            prefix = nxt
            index += 2
            continue
        elif token.startswith("--directory-prefix="):
            prefix = token.split("=", 1)[1]
        elif token == "--spider":
            spider = True
        elif token in ("-o", "-a", "--output-file", "--append-output", "-U", "--user-agent", "--header", "-t",
                       "--tries", "-T", "--timeout", "-e", "--execute", "--user", "--password"):
            index += 2
            continue
        elif not token.startswith("-"):
            urls.append(token)
        index += 1
    if body or (method and method.upper() not in ("GET", "HEAD")):
        remote = [u for u in urls if not _url_is_local(u, ctx)] or ([] if urls else ["<no literal URL>"])
        if remote:
            return block("pipe.remote_write", "wget sends data to %s, which is not a local host" % remote[0],
                         "Run it against the local service only (host in guards.prod.local_hosts)")
    if spider:
        return None
    if not outputs:
        target_dir = _resolve(prefix, _cwd(ctx)) if prefix else _cwd(ctx)
        if not paths.is_scratch(target_dir + "/x", ctx):
            return block("pipe.download_write", "wget saves the download into %s, outside scratch" % target_dir,
                         "Use wget -O /tmp/<file> or -O - instead, then inspect the output")
        return None
    return _download_targets("wget", outputs, False, ctx)


def _sys(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    name = argv[0]
    if name in SYS_BLOCK or name.startswith("mkfs") or name.startswith("newfs"):
        if name == "at" and len(argv) > 1 and argv[1] in ("-l",):
            return None
        return block("sys.%s" % re.sub(r"[^a-z0-9]", "_", name), "%s changes the machine, its services or its users" % name)
    if name in ("chmod", "chown", "chgrp"):
        if any(a in ("-R", "-r", "--recursive") or (a.startswith("-") and not a.startswith("--") and "R" in a)
               for a in argv[1:]):
            return block("sys.recursive_%s" % name, "%s -R changes permissions on a whole tree" % name)
        return None
    if name == "kill":
        args = argv[1:]
        if any(a in ("-l", "-L", "--list") for a in args):
            return None
        targets: list = []
        skip = False
        for a in args:
            if skip:
                skip = False
                continue
            if a == "-1":
                return block("sys.kill", "kill -1 signals every process the user owns")
            if a in ("-s", "-n", "--signal"):
                skip = True
                continue
            if a.startswith("-") and len(a) > 1 and a != "--":
                continue
            if a == "--":
                continue
            targets.append(a)
        for target in targets:
            if not re.match(r"^\d+$", target) or target in ("0", "1"):
                return block("sys.kill", "kill %s targets a process group, a job or a computed pid" % target,
                             "Kill one numeric pid you started")
        return None
    return None


def _cloud(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    name = argv[0]
    args = argv[1:]
    words = _positional(args)
    if name in CLOUD_CLIS:
        for word in words:
            if CLOUD_VERB.match(word):
                return block("cloud.%s" % re.sub(r"[^a-z0-9]", "_", name), "%s %s changes cloud resources" % (name, word))
        if name in ("rclone",) and words:
            return block("cloud.rclone", "rclone %s moves data between remotes" % words[0])
        return None
    if name in PLATFORM_CLIS:
        if not words:
            if name in ("vercel", "netlify", "firebase", "fly", "flyctl", "railway", "serverless", "sls", "amplify"):
                return block("cloud.%s" % name, "%s with no subcommand deploys" % name)
            return None
        parts = re.split(r"[:]", words[0])
        if any(p in PLATFORM_VERBS for p in parts) or any(re.match(r"(destroy|delete|reset|deploy|remove)", p) for p in parts):
            return block("cloud.%s" % re.sub(r"[^a-z0-9]", "_", name), "%s %s deploys or changes hosted resources" % (name, words[0]))
        if "--prod" in args or "--production" in args:
            return block("cloud.%s" % re.sub(r"[^a-z0-9]", "_", name), "%s %s --prod targets production" % (name, words[0]))
        return None
    if name in PACKAGE_PUBLISHERS:
        if words[:1] and words[0] in PACKAGE_PUBLISH_VERBS:
            return block("cloud.%s_%s" % (name, words[0].replace("-", "_")), "%s %s changes a package registry" % (name, words[0]))
        return None
    if name in BUILD_PUBLISHERS:
        if words[:1] and words[0] in BUILD_PUBLISH_VERBS:
            return block("cloud.%s_%s" % (name, words[0]), "%s %s publishes to a registry" % (name, words[0]))
        if name == "dotnet" and words[:2] == ["nuget", "push"]:
            return block("cloud.dotnet_nuget_push", "dotnet nuget push publishes a package")
        return None
    return None


def _net(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    name = argv[0]
    if name in NET_BLOCK:
        return block("net.%s" % name, "%s opens a remote shell, port or file transfer" % name)
    if name == "rsync":
        for operand in _positional(argv[1:]):
            if operand.startswith("rsync://") or re.match(r"^[^/.~][^/]*:", operand):
                return block("net.rsync", "rsync %s copies to or from a remote host" % operand)
    return None


def _env(argv: list, assignments: list, ctx: GuardContext) -> Optional[Verdict]:
    for assignment in assignments:
        if DANGEROUS_ASSIGNMENT.match(assignment):
            return block("env.dangerous_assignment", "%s overrides a variable that changes which program runs "
                         "or what it loads" % assignment.split("=", 1)[0])
    name = argv[0]
    args = argv[1:]
    if name in ("env", "printenv"):
        return block("env.dump", "%s prints the whole environment, including secrets" % name)
    if name in ("export", "declare", "typeset", "readonly", "local"):
        if not args or any(a in ("-p", "-x", "-px", "-xp") for a in args) and not any("=" in a for a in args):
            return block("env.dump", "%s %s prints exported variables, including secrets" % (name, " ".join(args)))
        for a in args:
            if "=" in a and DANGEROUS_ASSIGNMENT.match(a):
                return block("env.dangerous_assignment", "%s %s overrides a variable that changes which program "
                             "runs or what it loads" % (name, a.split("=", 1)[0]))
        return None
    if name == "set" and not args:
        return block("env.dump", "set with no arguments prints every variable, including secrets")
    if name == "compgen" and any(a in ("-v", "-e") for a in args):
        return block("env.dump", "compgen -v lists every variable")
    if any(re.search(r"/proc/[^/\s]*/environ", a) for a in args) or name.endswith("environ"):
        return block("env.dump", "%s reads a process environment, including secrets" % name)
    if name in ("echo", "printf", "print"):
        for a in args:
            for ref in VAR_REF.findall(a):
                if SECRET_NAME.search(ref):
                    return block("env.secret_echo", "%s prints $%s, which looks like a secret" % (name, ref))
    return None


def _harness(argv: list, raw: list, ctx: GuardContext) -> Optional[Verdict]:
    name = argv[0]
    normalised = _normalise_runner(argv)
    candidate = shell.basename(normalised[0]) if normalised else name
    if name in NESTED_AGENTS or candidate in NESTED_AGENTS or NESTED_PACKAGES.match(normalised[0] if normalised else ""):
        return block("omega.nested_agent", "%s starts another coding agent outside this session's hooks" % candidate,
                     "Do the work in this session; nested agents bypass the harness")
    return None


def _protected_operands(argv: list, ctx: GuardContext) -> Optional[Verdict]:
    name = argv[0]
    if name not in WRITEISH and not (name in ("sed", "perl") and any(re.match(r"^-[a-zA-Z]*i", a) for a in argv[1:])):
        return None
    base = _cwd(ctx)
    operands = [a for a in argv[1:] if a and not a.startswith("-")]
    if name in ("cp", "install", "ditto", "rsync"):
        targets = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a in ("-t", "--target-directory")]
        operands = targets or operands[-1:]
    for operand in operands:
        candidate = operand.split("=", 1)[1] if name == "dd" and "=" in operand else operand
        if shell.is_opaque(candidate):
            continue
        target = _resolve(candidate, base)
        if paths.is_protected(target, ctx):
            return block("omega.protected_path", "%s touches %s, a protected path (hook configuration, git "
                         "internals or harness state)" % (name, operand), "Ask the human to change it")
    return None


def _is_harness_launcher(operand: str, ctx: GuardContext) -> bool:
    if not operand:
        return False
    target = os.path.realpath(_resolve(operand, _cwd(ctx)))
    return target == os.path.realpath(str(Path(ctx.harness_root) / "bin" / "launch.sh"))


def _dynamic_verdict(reason: str, ctx: GuardContext) -> Optional[Verdict]:
    kind, _, detail = reason.partition(":")
    detail = detail.strip()
    if kind == "opaque_shell":
        match = re.match(r"^\S+ runs a script (.+)$", detail)
        if match and _is_harness_launcher(match.group(1), ctx):
            return None
    for prefix, rule, text in DYNAMIC_RULES:
        if kind == prefix:
            what = "the command %s" % text
            if detail:
                what += " (%s)" % detail
            return block(rule, what)
    return block("dynamic.unknown", "the command cannot be resolved statically (%s)" % reason)


def _sed_scripts(args: list) -> list:
    scripts: list = []
    explicit = False
    positional: list = []
    skip = None
    for token in args:
        if skip:
            if skip == "e":
                scripts.append(token)
            skip = None
            continue
        if token in ("-e", "--expression"):
            explicit = True
            skip = "e"
            continue
        if token in ("-f", "--file"):
            explicit = True
            skip = "f"
            continue
        if token.startswith("--expression="):
            explicit = True
            scripts.append(token.split("=", 1)[1])
            continue
        if token.startswith("-"):
            continue
        positional.append(token)
    if not explicit and positional:
        scripts.append(positional[0])
    return scripts


def _code_runners(argv: list, ctx: GuardContext, depth: int) -> Optional[Verdict]:
    name = argv[0]
    args = argv[1:]
    if name in AWK:
        program = next((a for a in args if not a.startswith("-")), "")
        if AWK_BAD.search(program) or any(a == "-f" or a.startswith("--file") for a in args):
            return block("dynamic.interpreter_code", "%s runs shell commands from its program (system, getline or a pipe)" % name)
        return None
    if name in ("sed", "gsed"):
        for script in _sed_scripts(args):
            if SED_EXEC.search(script):
                return block("dynamic.interpreter_code", "sed's e command runs shell commands")
        return None
    if name in EDITORS:
        for index, token in enumerate(args):
            value = args[index + 1] if token in ("-c", "--cmd", "--eval", "-S") and index + 1 < len(args) else \
                (token[1:] if token.startswith("+") else None)
            if value is not None and re.search(r"!|system\s*\(|shell-command|call-process|start-process|:r\s*!|\bterm", value):
                return block("dynamic.interpreter_code", "%s runs a shell command from %s" % (name, token))
            if token in ("-S", "-s", "--batch", "-batch", "--script", "-l", "--load") and name in ("vi", "vim", "nvim", "ex", "emacs"):
                return block("dynamic.interpreter_code", "%s runs a script the guard cannot read (%s)" % (name, token))
        return None
    if name == "alias" and any("=" in a for a in args):
        return block("dynamic.alias", "alias defines a command name the guard cannot follow")
    if name == "hash" and any(a.startswith("-p") for a in args):
        return block("dynamic.alias", "hash -p maps a command name to another program")
    if name in ("shopt",) and "expand_aliases" in args:
        return block("dynamic.alias", "shopt expand_aliases lets aliases replace command names")
    if name == "trap":
        action = next((a for a in args if not a.startswith("-")), "")
        if action and action not in ("-", ""):
            return _nested(action, ctx, depth)
        return None
    if name in EXTRA_WRAPPERS:
        for index in range(1, len(argv)):
            verdict = _nested(shlex.join(argv[index:]), ctx, depth)
            if verdict:
                return verdict
            if " " in argv[index] or ";" in argv[index]:
                verdict = _nested(argv[index], ctx, depth)
                if verdict:
                    return verdict
        return None
    return None


def _nested(text: str, ctx: GuardContext, depth: int) -> Optional[Verdict]:
    if depth >= shell.MAX_DEPTH:
        return block("dynamic.nesting", "the command nests deeper than %d levels" % shell.MAX_DEPTH)
    verdict = _judge(text, ctx, depth + 1)
    return verdict if verdict.blocked else None


def judge_command(argv: list, assignments: list, raw: list, ctx: GuardContext, command_text: str = "",
                  depth: int = 0) -> Optional[Verdict]:
    if not argv:
        return None
    argv = [shell.basename(argv[0])] + list(argv[1:])
    checks = (
        lambda: _env(argv, assignments, ctx),
        lambda: _harness(argv, raw, ctx),
        lambda: _protected_operands(argv, ctx),
    )
    for check in checks:
        verdict = check()
        if verdict:
            return verdict
    verdict = _code_runners(argv, ctx, depth)
    if verdict:
        return verdict
    normalised = _normalise_runner(argv)
    name = shell.basename(normalised[0]) if normalised else argv[0]
    targets = [argv] if normalised == argv else [argv, [name] + normalised[1:]]
    for candidate in targets:
        head = candidate[0]
        if head == "git":
            verdict = _git(candidate, ctx)
        elif head == "gh":
            verdict = _gh(candidate, ctx)
        elif head in ("terraform", "tofu", "terragrunt"):
            verdict = _terraform(candidate, ctx)
        elif head in ("kubectl", "oc", "k", "helm", "kubectx", "kubens"):
            verdict = _kubectl(candidate, ctx) if head not in ("kubectx", "kubens") else \
                (block("kubectl.context", "%s switches the cluster context" % head) if len(candidate) > 1 else None)
        elif head in ("docker", "podman", "nerdctl", "docker-compose", "podman-compose"):
            verdict = _docker([("docker-compose" if head.endswith("compose") else head)] + candidate[1:], assignments, ctx)
        elif head in DB_CLIENTS or head in DB_TOOLS_BLOCK:
            verdict = _db(candidate, ctx, command_text)
        elif head in RM_COMMANDS:
            verdict = _rm(candidate, ctx)
        elif head == "find":
            verdict = _find(candidate, ctx)
        elif head == "curl":
            verdict = _curl(candidate, ctx)
        elif head == "wget":
            verdict = _wget(candidate, ctx)
        else:
            verdict = None
        if verdict is None:
            verdict = _migrations(candidate, ctx)
        if verdict is None:
            verdict = _sys(candidate, ctx)
        if verdict is None:
            verdict = _cloud(candidate, ctx)
        if verdict is None:
            verdict = _net(candidate, ctx)
        if verdict:
            return verdict
    return None


def _bare_assignment_verdict(text: str) -> Optional[Verdict]:
    for argv in _segments_of(text):
        lead, _ = shell.leading_assignments(argv)
        for assignment in lead:
            if DANGEROUS_ASSIGNMENT.match(assignment):
                return block("env.dangerous_assignment", "%s overrides a variable that changes which program runs "
                             "or what it loads" % assignment.split("=", 1)[0])
    return None


def _pipe_verdict(text: str) -> Optional[Verdict]:
    masked = mask_quotes(shell.strip_heredocs(text))
    if REMOTE_SHELL.search(masked):
        return block("pipe.remote_shell", "a downloaded script is piped straight into a shell")
    if REMOTE_INTERP.search(masked):
        return block("pipe.remote_interpreter", "a download is piped straight into an interpreter")
    if DECODED_SHELL.search(masked):
        return block("pipe.decoded_shell", "a decoded or transformed payload is piped into a shell or interpreter")
    return None


def _code_verdict(interpreter: str, code: str) -> Optional[Verdict]:
    if ENV_DUMP_CODE.search(code or ""):
        return block("env.dump", "%s code prints the environment, including secrets" % interpreter)
    match = INTERP_BAD.search(code or "")
    if match:
        return block("dynamic.interpreter_code", "%s code uses %s (spawns processes, deletes files or opens the "
                     "network)" % (interpreter, match.group(0)))
    return None


def _extra_deny(command: str, ctx: GuardContext) -> Optional[Verdict]:
    for pattern in _cfg(ctx, "guards.prod.extra_deny_regex", []) or []:
        try:
            if re.search(str(pattern), command):
                return block("custom.extra_deny", "the command matches the configured pattern %r" % pattern)
        except re.error:
            return block("custom.extra_deny", "guards.prod.extra_deny_regex holds an invalid pattern %r" % pattern)
    return None


def _protected_writes(command: str, ctx: GuardContext) -> Optional[Verdict]:
    from hooks import bash_write_guard
    targets, _ = bash_write_guard.destinations(command, _cwd(ctx), ctx)
    for target in targets:
        if paths.is_protected(target, ctx):
            return block("omega.protected_path", "the command writes %s, a protected path (hook configuration, "
                         "git internals or harness state)" % target, "Ask the human to change it")
    return None


def _patch_verdict(command: str, ctx: GuardContext) -> Optional[Verdict]:
    if event_mod.PATCH_MARKER not in command:
        return None
    if not event_mod.parse_apply_patch(command, _cwd(ctx)):
        return block("omega.unparsed_mutation", "the command carries a patch whose file paths cannot be parsed",
                     "Use apply_patch with explicit *** Add/Update/Delete File headers")
    return None


def judge(command: str, ctx: GuardContext) -> Verdict:
    try:
        return _judge(command, ctx)
    except Exception as exc:
        return block("dynamic.internal_error", "the guard could not analyse the command (%s: %s)" %
                     (exc.__class__.__name__, str(exc)[:120]))


def case_arms(text: str) -> list:
    found: list = []
    for argv in _segments_of(text):
        rest = list(argv)
        if rest and rest[0] == "case":
            cut = next((i for i, t in enumerate(rest) if t.endswith(")") and i > 0), None)
            rest = rest[cut + 1:] if cut is not None else []
        elif rest and (rest[0].endswith(")") or rest[0].startswith("(")) and len(rest) > 1:
            cut = next((i for i, t in enumerate(rest) if t.endswith(")")), None)
            rest = rest[cut + 1:] if cut is not None else rest
        else:
            continue
        rest = [t for t in rest if t not in (";;", ";&", ";;&")]
        if rest and rest[0] != "esac":
            found.append(rest)
    return found


def _judge(command: str, ctx: GuardContext, depth: int = 0) -> Verdict:
    if not isinstance(command, str) or not command.strip():
        return block("dynamic.parse_failure", "the Bash payload has no command text")
    if len(command) > MAX_LENGTH:
        return block("dynamic.too_long", "the command is %d characters long (limit %d)" % (len(command), MAX_LENGTH))
    if "$'" in command or '$"' in command:
        return block("dynamic.ansi_quoting", "the command uses $'...' or $\"...\" quoting, which cannot be resolved "
                     "statically")
    for verdict in (_extra_deny(command, ctx), _patch_verdict(command, ctx)):
        if verdict:
            return verdict
    texts = shell_texts(command)
    for text in texts:
        verdict = _pipe_verdict(text)
        if verdict:
            return verdict
    walked = shell.walk(command)
    for entry in walked.commands:
        verdict = judge_command(list(entry.get("argv") or []), list(entry.get("assignments") or []),
                                list(entry.get("raw") or []), ctx, command, depth)
        if verdict:
            return verdict
    for text in texts:
        for arm in case_arms(text):
            verdict = _nested(shlex.join(arm), ctx, depth)
            if verdict:
                return verdict
    for text in texts:
        verdict = _bare_assignment_verdict(text)
        if verdict:
            return verdict
    for interpreter, code in walked.code:
        verdict = _code_verdict(interpreter, code)
        if verdict:
            return verdict
    for reason in walked.dynamic:
        verdict = _dynamic_verdict(reason, ctx)
        if verdict:
            return verdict
    verdict = _protected_writes(command, ctx)
    if verdict:
        return verdict
    return ALLOWED


def judge_argv(argv: list, ctx: GuardContext, depth: int = 0) -> Optional[Verdict]:
    if depth > shell.MAX_DEPTH:
        return block("dynamic.nesting", "the command nests deeper than %d levels" % shell.MAX_DEPTH)
    verdict = judge(shlex.join([str(a) for a in argv or []]), ctx)
    return verdict if verdict.blocked else None


def verdict_dict(verdict: Verdict) -> dict:
    return {"blocked": verdict.blocked, "rule": verdict.rule, "reason": verdict.reason,
            "alternative": verdict.alternative}


def _hook(provider: Optional[str]) -> int:
    name = provider or os.environ.get("OMEGA_PROVIDER") or "claude"
    try:
        payload = io_mod.read_payload()
        event = event_mod.normalize(payload, provider)
        name = event.provider
        ctx = state.configure(event)
        if event.tool_name != "Bash":
            return io_mod.emit(name, "PreToolUse", io_mod.Decision("allow"))
        guard = GuardContext(ctx.workspace, ctx.harness_root, ctx.cfg, dict(os.environ), event.cwd, ctx.transcript_path)
        verdict = judge(event.command or "", guard)
        decision = io_mod.Decision("deny", reason=verdict.reason) if verdict.blocked else io_mod.Decision("allow")
        return io_mod.emit(name, "PreToolUse", decision)
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        return io_mod.fail_closed(name, "PreToolUse", exc, SCRIPT)


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="prod_guard.py", description="Judge a shell command against the harness deny tables.")
    parser.add_argument("--provider", choices=("claude", "codex"))
    parser.add_argument("--command", dest="command_text")
    parser.add_argument("--workspace")
    parser.add_argument("--cwd")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv[1:])
    if args.command_text is None:
        return _hook(args.provider)
    ctx = guard_context(args.workspace, args.cwd)
    verdict = judge(args.command_text, ctx)
    if args.json:
        print(json.dumps(verdict_dict(verdict)))
    else:
        print(verdict.reason if verdict.blocked else "[prod-guard] allowed")
    return 1 if verdict.blocked else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

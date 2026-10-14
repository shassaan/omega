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
from dataclasses import dataclass, field
from typing import Optional

from hooks.lib import event as event_mod
from hooks.lib import io as io_mod
from hooks.lib import paths, shell, state
from hooks.prod_guard import (GuardContext, Verdict, case_arms, guard_context, heredoc_consumer, segment_argv,
                              shell_c_payload)

SCRIPT = "hooks/bash_write_guard.py"
ALLOW = "write.allow"
REFUSE = "write.refuse"
UNPROVEN = "write.unproven"
PROTECTED = "omega.protected_path"

_DEST_ONLY = {"cp", "install", "ln", "rsync", "ditto"}
_ALL_ARGS = {"mv", "rm", "tee", "truncate", "touch", "patch", "unlink", "shred", "rmdir", "srm", "ed", "ex"}
_WRITERS = _DEST_ONLY | _ALL_ARGS | {"sed", "perl", "dd", "curl", "wget", "tar", "unzip", "sort", "find"}
_TARGET_DIR_COMMANDS = {"cp", "mv", "install", "ln"}
_VALUE_OPTIONS = {
    "cp": {"-S", "--suffix", "--reflink", "--sparse", "--preserve", "--no-preserve", "--backup"},
    "mv": {"-S", "--suffix", "--backup"},
    "install": {"-m", "--mode", "-o", "--owner", "-g", "--group", "-S", "--suffix", "--strip-program"},
    "ln": {"-S", "--suffix", "--backup"},
    "rsync": {"--exclude", "--include", "-e", "--rsh", "--filter", "-f", "--files-from", "--chmod", "--chown",
              "--backup-dir", "--partial-dir", "--temp-dir", "-T", "--exclude-from", "--include-from",
              "--compare-dest", "--link-dest", "--copy-dest", "--password-file", "--port", "--bwlimit",
              "--timeout", "--max-size", "--min-size", "--usermap", "--groupmap", "-M", "--remote-option",
              "--suffix", "--rsync-path"},
    "ditto": {"--arch", "--hfsCompression"},
    "truncate": {"-s", "--size", "-r", "--reference"},
    "touch": {"-d", "--date", "-t", "-r", "--reference"},
    "patch": {"-p", "--strip", "-i", "--input", "-d", "--directory", "-r", "--reject-file", "-F", "--fuzz",
              "-D", "--ifdef", "-B", "--prefix", "-V", "--version-control", "-z", "--suffix", "-Y",
              "--basename-prefix", "-o", "--output"},
    "shred": {"-n", "--iterations", "-s", "--size"},
    "tee": set(),
    "rm": set(),
    "unlink": set(),
    "rmdir": set(),
    "srm": set(),
    "ed": {"-p", "--prompt"},
    "ex": {"-c", "-S", "-u", "-i", "-T", "-w", "-W"},
}
_WRITE_API = re.compile(
    r"\.write_text\s*\(|\.write_bytes\s*\(|\bopen\s*\([^)]*[\"'](?:[rwab+tx]*[wax][rwab+tx]*)[\"']"
    r"|\bopen\s*\([^)]*mode\s*=\s*[\"'][rb+t]*[wax]|shutil\.(copy\w*|move|rmtree|copytree)\s*\("
    r"|os\.(remove|unlink|rename|renames|replace|truncate|rmdir|removedirs|symlink|link|chmod|utime)\s*\("
    r"|\.unlink\s*\(|\.touch\s*\(|\.rename\s*\(|\.rmdir\s*\(|\.symlink_to\s*\(|\.hardlink_to\s*\("
    r"|writeFileSync|writeFile\s*\(|appendFile(Sync)?\s*\(|createWriteStream|fs\.(rm|rmSync|unlink|unlinkSync|"
    r"rename|renameSync|copyFile|copyFileSync|truncate|mkdir|rmdir|cp|cpSync|symlink)\b|Deno\.write|Bun\.write"
    r"|File\.(write|open|delete|rename|unlink)|FileUtils\.|IO\.write|open\s*\(\s*[A-Z_]*\s*,?\s*[\"']?\s*[>+]"
    r"|\bopen\s*\(\s*my\s+\$\w+\s*,\s*[\"'][>+]|\bunlink\s*\(|\brename\s*\(|\bmove_uploaded_file|file_put_contents",
    re.I)
_STRING_LITERAL = re.compile(r"'([^'\\\n]*)'|\"([^\"\\\n]*)\"")
_MODE_WORDS = {"r", "w", "a", "x", "rb", "wb", "ab", "r+", "w+", "a+", "rb+", "wb+", "ab+", "xb", "rt", "wt", "at",
               "utf-8", "utf8", "ascii", "latin-1", "ignore", "replace", "strict"}
SENSITIVE_HOME = (".ssh", ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv",
                  ".zlogin", ".aws", ".gitconfig", ".config/git", ".npmrc", ".pypirc", ".netrc", ".docker", ".kube",
                  ".gnupg", ".config/gh", ".cargo/credentials", ".terraformrc", ".pgpass", ".my.cnf",
                  "Library/LaunchAgents", ".config/fish", ".inputrc", ".vimrc", ".tmux.conf")
SENSITIVE_SYSTEM = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/opt", "/System", "/Library", "/boot",
                    "/private/etc", "/var/root", "/Applications")


@dataclass
class _Scan:
    targets: list = field(default_factory=list)
    reasons: list = field(default_factory=list)


@dataclass
class _Cwd:
    path: str
    opaque: bool = False


def _home() -> str:
    return os.path.expanduser("~")


def _is_launcher(path: str, ctx) -> bool:
    root = getattr(ctx, "harness_root", None) or paths.harness_root()
    return os.path.realpath(path) == os.path.realpath(str(Path(root) / "bin" / "launch.sh"))


def _glob_index(token: str) -> Optional[int]:
    return next((i for i, ch in enumerate(token) if ch in "*?[{"), None)


def _add(scan: _Scan, raw: str, cwd: _Cwd, what: str) -> None:
    token = raw if raw is not None else ""
    if token == "" or "$" in token or "`" in token:
        scan.reasons.append("%s goes to %s, computed at run time" % (what, token or "an empty word"))
        return
    if token in ("-",):
        return
    glob_at = _glob_index(token)
    if glob_at is not None:
        prefix = token[:glob_at]
        token = prefix.rsplit("/", 1)[0] if "/" in prefix else "."
        if prefix.startswith("/") and token == "":
            token = "/"
    expanded = os.path.expanduser(token)
    if not os.path.isabs(expanded):
        if cwd.opaque:
            scan.reasons.append("%s goes to the relative path %s after a cd the guard cannot follow" % (what, raw))
            return
        expanded = os.path.join(cwd.path, expanded)
    target = os.path.normpath(expanded)
    if target not in scan.targets:
        scan.targets.append(target)


def _operands(name: str, args: list) -> tuple:
    values = _VALUE_OPTIONS.get(name, set())
    operands: list = []
    target_dir: Optional[str] = None
    extra: list = []
    index = 0
    options_done = False
    while index < len(args):
        token = args[index]
        if options_done or not token.startswith("-") or token == "-":
            operands.append(token)
            index += 1
            continue
        if token == "--":
            options_done = True
            index += 1
            continue
        if name in _TARGET_DIR_COMMANDS and token in ("-t", "--target-directory"):
            target_dir = args[index + 1] if index + 1 < len(args) else ""
            index += 2
            continue
        if name in _TARGET_DIR_COMMANDS and token.startswith("--target-directory="):
            target_dir = token.split("=", 1)[1]
            index += 1
            continue
        if name == "patch" and token in ("-o", "--output"):
            extra.append(args[index + 1] if index + 1 < len(args) else "")
            index += 2
            continue
        if name == "patch" and token.startswith("--output="):
            extra.append(token.split("=", 1)[1])
            index += 1
            continue
        if name == "rsync" and (token == "--log-file" or token.startswith("--log-file=")):
            if "=" in token:
                extra.append(token.split("=", 1)[1])
                index += 1
            else:
                extra.append(args[index + 1] if index + 1 < len(args) else "")
                index += 2
            continue
        if token in values:
            index += 2
            continue
        if "=" in token and token.split("=", 1)[0] in values:
            index += 1
            continue
        index += 1
    return operands, target_dir, extra


def _sed_files(args: list) -> list:
    files: list = []
    script_given = False
    skip = False
    positional: list = []
    for index, token in enumerate(args):
        if skip:
            skip = False
            continue
        if token in ("-e", "--expression", "-f", "--file"):
            script_given = True
            skip = True
            continue
        if token.startswith("--expression=") or token.startswith("--file="):
            script_given = True
            continue
        if token in ("-i", "--in-place") and index + 1 < len(args) and args[index + 1] == "":
            skip = True
            continue
        if token.startswith("-") and token != "-":
            if re.match(r"^-[A-Za-z]*[ef]$", token) and not token.startswith("--"):
                script_given = True
                skip = True
            continue
        if token == "":
            continue
        positional.append(token)
    files = positional if script_given else positional[1:]
    return files


def _perl_files(args: list) -> list:
    files: list = []
    skip = False
    code_given = False
    for token in args:
        if skip:
            skip = False
            continue
        if token.startswith("-") and token != "-":
            if re.match(r"^-[A-Za-z0-9.]*[eE]$", token):
                skip = True
                code_given = True
            elif token in ("-M", "-I", "-m"):
                skip = True
            continue
        files.append(token)
    return files if code_given else files[1:]


def _in_place(name: str, args: list) -> bool:
    if name == "sed":
        return any(a in ("-i", "--in-place") or a.startswith("--in-place=") or re.match(r"^-[a-zA-Z]*i", a)
                   for a in args)
    return any(re.match(r"^-[a-zA-Z0-9]*i", a) for a in args if not a.startswith("--"))


def _code_writes(interpreter: str, code: str, cwd: _Cwd, scan: _Scan) -> None:
    if not _WRITE_API.search(code or ""):
        return
    literals = []
    for match in _STRING_LITERAL.finditer(code or ""):
        value = match.group(1) if match.group(1) is not None else match.group(2)
        if not value or value.lower() in _MODE_WORDS or " " in value.strip():
            continue
        if "/" in value or value.startswith(".") or value.startswith("~") or re.match(r"^[\w.-]+\.[A-Za-z0-9]{1,8}$", value):
            literals.append(value)
    if not literals:
        scan.reasons.append("%s code writes a file but names no literal path" % interpreter)
        return
    for value in literals:
        _add(scan, value, cwd, "%s code" % interpreter)


def _interp_code(argv: list) -> Optional[str]:
    for index, token in enumerate(argv[1:], 1):
        if token in shell.INTERP_CODE_FLAGS:
            return argv[index + 1] if index + 1 < len(argv) else ""
        if re.match(r"^-[A-Za-z]*[ce]$", token) and shell.basename(argv[0]) in ("perl", "ruby", "node"):
            return argv[index + 1] if index + 1 < len(argv) else ""
        if token == "-" or not token.startswith("-"):
            return None
    return None


def _follow_script(path: str, cwd: _Cwd, scan: _Scan, depth: int, script_depth: int, ctx) -> None:
    if not path or "$" in path or "`" in path:
        scan.reasons.append("a script whose name is computed at run time is run")
        return
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        if cwd.opaque:
            scan.reasons.append("script %s is run after a cd the guard cannot follow" % path)
            return
        expanded = os.path.join(cwd.path, expanded)
    if _is_launcher(expanded, ctx):
        return
    if script_depth >= 1:
        scan.reasons.append("script %s runs another script (only one level is followed)" % path)
        return
    try:
        with open(expanded, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(200000)
    except OSError:
        scan.reasons.append("script %s cannot be read, so what it writes is unknown" % path)
        return
    _scan_text(text, _Cwd(cwd.path, cwd.opaque), scan, depth + 1, script_depth + 1, ctx)


def _xargs_feeds(argv: list, inner: list) -> bool:
    head = argv[:len(argv) - len(inner)] if inner else argv
    return any(shell.basename(t) == "xargs" for t in head)


def _find_writes(args: list, cwd: _Cwd, scan: _Scan, depth: int, script_depth: int, ctx) -> None:
    starts: list = []
    for token in args:
        if token.startswith("-") or token in ("(", ")", "!"):
            break
        starts.append(token)
    for index, token in enumerate(args):
        if token in ("-fprint", "-fprint0", "-fprintf", "-fls") and index + 1 < len(args):
            _add(scan, args[index + 1], cwd, "find %s" % token)
    if "-delete" in args:
        for start in starts or ["."]:
            _add(scan, start, cwd, "find -delete")
    for index, token in enumerate(args):
        if token in ("-exec", "-execdir", "-ok", "-okdir"):
            end = index + 1
            while end < len(args) and args[end] not in (";", "+", "\\;"):
                end += 1
            block = args[index + 1:end]
            if block:
                _scan_argv(block, cwd, scan, depth + 1, script_depth, ctx, from_find=True)


def _tar_writes(args: list, cwd: _Cwd, scan: _Scan) -> None:
    if not args:
        return
    first = args[0]
    mode = ""
    cluster = first.lstrip("-") if not first.startswith("--") else ""
    for token in args:
        if token in ("--extract", "--get", "-x") or (token.startswith("-") and not token.startswith("--") and "x" in token):
            mode = "x"
        if token in ("--create", "-c", "--append", "-r", "--update", "-u") or \
                (token.startswith("-") and not token.startswith("--") and any(c in token for c in "cru")):
            mode = mode or "c"
    if not mode and cluster and not first.startswith("-"):
        if "x" in cluster:
            mode = "x"
        elif any(c in cluster for c in "cru"):
            mode = "c"
    directory = None
    archive = None
    for index, token in enumerate(args):
        if token in ("-C", "--directory") and index + 1 < len(args):
            directory = args[index + 1]
        elif token.startswith("--directory="):
            directory = token.split("=", 1)[1]
        elif token in ("-f", "--file") and index + 1 < len(args):
            archive = args[index + 1]
        elif token.startswith("--file="):
            archive = token.split("=", 1)[1]
    if archive is None:
        letters = (first.lstrip("-") if not first.startswith("--") else "")
        if "f" in letters and len(args) > 1:
            archive = args[1]
    if mode == "x":
        _add(scan, directory if directory is not None else ".", cwd, "tar extraction")
    elif mode == "c" and archive and archive != "-":
        _add(scan, archive, cwd, "tar archive")


def _unzip_writes(args: list, cwd: _Cwd, scan: _Scan) -> None:
    if any(a in ("-l", "-t", "-v", "-Z", "-p", "-c", "-z") for a in args):
        return
    directory = None
    for index, token in enumerate(args):
        if token == "-d" and index + 1 < len(args):
            directory = args[index + 1]
    _add(scan, directory if directory is not None else ".", cwd, "unzip")


def _curl_writes(name: str, args: list, cwd: _Cwd, scan: _Scan) -> None:
    for index, token in enumerate(args):
        nxt = args[index + 1] if index + 1 < len(args) else ""
        if name == "curl":
            if token in ("-o", "--output", "--output-dir"):
                if nxt not in ("-", "/dev/null"):
                    _add(scan, nxt, cwd, "curl output")
            elif token.startswith("--output=") or token.startswith("--output-dir="):
                _add(scan, token.split("=", 1)[1], cwd, "curl output")
            elif token in ("-O", "--remote-name", "--remote-name-all") or \
                    (token.startswith("-") and not token.startswith("--") and "O" in token):
                _add(scan, ".", cwd, "curl -O download")
            elif token.startswith("-") and not token.startswith("--") and len(token) > 2 and token.endswith("o"):
                if nxt not in ("-", "/dev/null"):
                    _add(scan, nxt, cwd, "curl output")
        else:
            if token in ("-O", "--output-document"):
                if nxt not in ("-", "/dev/null"):
                    _add(scan, nxt, cwd, "wget output")
            elif token.startswith("--output-document="):
                value = token.split("=", 1)[1]
                if value not in ("-", "/dev/null"):
                    _add(scan, value, cwd, "wget output")
            elif token.startswith("-O") and len(token) > 2:
                if token[2:] not in ("-", "/dev/null"):
                    _add(scan, token[2:], cwd, "wget output")
    if name == "wget" and not any(t in ("-O", "--output-document", "--spider") or t.startswith("--output-document=")
                                  or (t.startswith("-O") and len(t) > 2) for t in args):
        prefix = None
        for index, token in enumerate(args):
            if token in ("-P", "--directory-prefix") and index + 1 < len(args):
                prefix = args[index + 1]
            elif token.startswith("--directory-prefix="):
                prefix = token.split("=", 1)[1]
        _add(scan, prefix if prefix is not None else ".", cwd, "wget download")


def _cd(inner: list, cwd: _Cwd) -> None:
    args = [a for a in inner[1:] if a not in ("-P", "-L", "-e", "-@", "--")]
    if not args:
        cwd.path = _home()
        return
    target = args[0]
    if target == "-" or shell.is_opaque(target):
        cwd.opaque = True
        return
    expanded = os.path.expanduser(target)
    if not os.path.isabs(expanded):
        if cwd.opaque:
            return
        expanded = os.path.join(cwd.path, expanded)
    cwd.path = os.path.normpath(expanded)
    cwd.opaque = False


def _scan_argv(argv: list, cwd: _Cwd, scan: _Scan, depth: int, script_depth: int, ctx, from_find: bool = False) -> None:
    inner, _ = shell.unwrap_with_assignments(argv)
    if not inner:
        return
    head = inner[0]
    if shell.is_opaque(head) and not head.startswith("-") and not (from_find and head == "{}"):
        scan.reasons.append("the command name %s is computed at run time" % head)
        return
    name = shell.basename(head)
    args = list(inner[1:])
    if _xargs_feeds(argv, inner) and name in _WRITERS:
        scan.reasons.append("xargs hands %s paths the guard cannot see" % name)
        return
    if name in ("cd", "pushd"):
        _cd(inner, cwd)
        return
    if name == "popd":
        cwd.opaque = True
        return
    if name == "eval":
        scan.reasons.append("eval runs text the guard cannot read")
        return
    if name in ("source", "."):
        _follow_script(args[0] if args else "", cwd, scan, depth, script_depth, ctx)
        return
    if shell.is_shell(name):
        payload = shell_c_payload(inner)
        if payload is not None:
            _scan_text(payload, _Cwd(cwd.path, cwd.opaque), scan, depth + 1, script_depth, ctx)
            return
        operands = [a for a in args if not a.startswith("-") and not a.startswith("+")]
        if not operands:
            scan.reasons.append("%s reads commands from stdin" % name)
            return
        _follow_script(operands[0], cwd, scan, depth, script_depth, ctx)
        return
    if name == "perl" and _in_place(name, args):
        files = _perl_files(args)
        if not files:
            scan.reasons.append("perl -i edits files the guard cannot read")
        for value in files:
            _add(scan, value, cwd, "perl -i")
        return
    if shell.is_interpreter(name):
        code = _interp_code(inner)
        if code is not None:
            _code_writes(name, code, cwd, scan)
        return
    if name == "find":
        _find_writes(args, cwd, scan, depth, script_depth, ctx)
        return
    if name in _DEST_ONLY:
        operands, target_dir, extra = _operands(name, args)
        for value in extra:
            _add(scan, value, cwd, "%s log" % name)
        if target_dir is not None:
            _add(scan, target_dir, cwd, name)
        elif operands:
            last = operands[-1]
            if name == "rsync" and (last.startswith("rsync://") or re.match(r"^[^/.~][^/]*:", last)):
                return
            _add(scan, last, cwd, name)
        else:
            scan.reasons.append("%s has no destination the guard can read" % name)
        return
    if name in _ALL_ARGS:
        operands, target_dir, extra = _operands(name, args)
        destinations = operands + ([target_dir] if target_dir is not None else []) + extra
        if name == "patch" and not operands and not extra:
            scan.reasons.append("patch writes the files named inside the diff")
            return
        if not destinations and name not in ("tee",):
            scan.reasons.append("%s has no operand the guard can read" % name)
            return
        for value in destinations:
            _add(scan, value, cwd, name)
        return
    if name in ("sed", "perl"):
        if not _in_place(name, args):
            return
        files = _sed_files(args) if name == "sed" else _perl_files(args)
        if not files:
            scan.reasons.append("%s -i edits files the guard cannot read" % name)
        for value in files:
            _add(scan, value, cwd, "%s -i" % name)
        return
    if name == "dd":
        for token in args:
            if token.startswith("of="):
                _add(scan, token[3:], cwd, "dd of=")
        return
    if name in ("curl", "wget"):
        _curl_writes(name, args, cwd, scan)
        return
    if name in ("tar", "bsdtar", "gtar"):
        _tar_writes(args, cwd, scan)
        return
    if name == "unzip":
        _unzip_writes(args, cwd, scan)
        return
    if name == "sort":
        for index, token in enumerate(args):
            if token in ("-o", "--output") and index + 1 < len(args):
                _add(scan, args[index + 1], cwd, "sort -o")
            elif token.startswith("--output="):
                _add(scan, token.split("=", 1)[1], cwd, "sort -o")


def _scan_text(text: str, cwd: _Cwd, scan: _Scan, depth: int, script_depth: int, ctx) -> None:
    if depth > shell.MAX_DEPTH:
        scan.reasons.append("commands nest deeper than %d levels" % shell.MAX_DEPTH)
        return
    stripped = shell.strip_heredocs(text or "")
    for head, body in shell.heredocs(text or ""):
        consumer = heredoc_consumer(head)
        if consumer == "shell":
            _scan_text(body, _Cwd(cwd.path, cwd.opaque), scan, depth + 1, script_depth, ctx)
        elif consumer:
            _code_writes(consumer, body, cwd, scan)
    for inner in shell.substitutions(stripped):
        _scan_text(inner, _Cwd(cwd.path, cwd.opaque), scan, depth + 1, script_depth, ctx)
    for segment in shell.split_commands(stripped):
        targets, opaque = shell.redirect_targets(segment)
        for target in targets:
            _add(scan, target, cwd, "a redirect")
        if opaque:
            scan.reasons.append("a redirect target is computed at run time (%s)" % " ".join(segment.split())[:80])
        argv = segment_argv(segment)
        if argv is None:
            scan.reasons.append("the command cannot be parsed (unbalanced quotes)")
            continue
        if argv:
            _scan_argv(argv, cwd, scan, depth, script_depth, ctx)
    for arm in case_arms(stripped):
        _scan_argv(arm, cwd, scan, depth, script_depth, ctx)


def analyse(command: str, cwd: str, ctx=None) -> _Scan:
    scan = _Scan()
    _scan_text(command or "", _Cwd(os.path.normpath(cwd or os.getcwd())), scan, 0, 0, ctx)
    return scan


def destinations(command: str, cwd: str, ctx=None) -> tuple:
    scan = analyse(command, cwd, ctx)
    return list(scan.targets), bool(scan.reasons)


def _sensitive(target: str) -> bool:
    home = _home()
    for rel_path in SENSITIVE_HOME:
        root = os.path.join(home, rel_path)
        if target == root or target.startswith(root.rstrip("/") + "/"):
            return True
    for root in SENSITIVE_SYSTEM:
        if target == root or target.startswith(root + "/"):
            return True
    return False


def _display(target: str, ctx) -> str:
    workspace = getattr(ctx, "workspace", None)
    if workspace:
        relative = paths.rel(target, workspace)
        if not relative.startswith("/"):
            return relative
    return target


def judge(command: str, ctx) -> Verdict:
    try:
        return _judge(command, ctx)
    except Exception as exc:
        reason = ("[bash-write-guard] this command writes somewhere the guard cannot work out: the guard failed "
                  "(%s: %s). Spell the destination out as a literal path, or show what the script writes."
                  % (exc.__class__.__name__, str(exc)[:120]))
        return Verdict(True, UNPROVEN, reason, "Spell the destination out as a literal path")


def _judge(command: str, ctx) -> Verdict:
    if not isinstance(command, str) or not command.strip():
        return Verdict(False, ALLOW, "", "")
    cwd = getattr(ctx, "cwd", None) or getattr(ctx, "workspace", None) or os.getcwd()
    scan = analyse(command, os.path.realpath(cwd), ctx)
    protected = [t for t in scan.targets if paths.is_protected(t, ctx)]
    if protected:
        shown = ", ".join(_display(t, ctx) for t in protected)
        reason = ("[bash-write-guard] refused (%s): this command writes %s, a protected path (hook "
                  "configuration, git internals or harness state). Ask the human to change it." % (PROTECTED, shown))
        return Verdict(True, PROTECTED, reason, "Ask the human to change it")
    governed = [t for t in scan.targets if not paths.is_scratch(t, ctx) and paths.is_governed(t, ctx)]
    if governed:
        shown = [_display(t, ctx) for t in governed]
        reason = ("[bash-write-guard] this command writes into a path the harness governs: %s. Use the Edit or "
                  "Write tool on %s instead; a shell write skips the change ledger, the TDD gate and the contract "
                  "gate." % (", ".join(shown), shown[0]))
        return Verdict(True, REFUSE, reason, "Use the Edit or Write tool on %s" % shown[0])
    sensitive = [t for t in scan.targets if not paths.is_scratch(t, ctx) and _sensitive(t)]
    if sensitive:
        reason = ("[bash-write-guard] this command writes into a system or user configuration path: %s. Ask the "
                  "human to change it." % ", ".join(sensitive))
        return Verdict(True, REFUSE, reason, "Ask the human to change it")
    if scan.reasons:
        reason = ("[bash-write-guard] this command writes somewhere the guard cannot work out: %s. Spell the "
                  "destination out as a literal path, or show what the script writes." % "; ".join(scan.reasons[:3]))
        return Verdict(True, UNPROVEN, reason, "Spell the destination out as a literal path")
    return Verdict(False, ALLOW, "", "")


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
    parser = argparse.ArgumentParser(prog="bash_write_guard.py", description="Judge where a shell command writes.")
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
        targets, opaque = destinations(args.command_text, ctx.cwd or ctx.workspace, ctx)
        print(json.dumps({"blocked": verdict.blocked, "rule": verdict.rule, "reason": verdict.reason,
                          "targets": targets, "opaque": opaque}))
    else:
        print(verdict.reason if verdict.blocked else "[bash-write-guard] allowed")
    return 1 if verdict.blocked else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

"""Fail-closed shell command guard. Stdlib only."""
import re, shlex, base64, os

MAX_DEPTH = 6
WRAPPERS = {"sudo","doas","env","nohup","time","command","builtin","exec","nice","ionice","stdbuf",
            "timeout","xargs","watch","setsid","chroot","unbuffer","caffeinate","busybox"}
SHELLS = {"sh","bash","zsh","dash","ksh","fish","ash"}
INTERPS = {"python","python2","python3","perl","ruby","node","php","lua"}
SEPS = re.compile(r"(?:\|\||&&|;;?|\||&|\n)")  # applied only OUTSIDE quotes via splitter

class Deny(Exception):
    pass

def split_commands(s):
    """Split on unquoted ; & | newline, honouring quotes, backslash and $(...) / backticks as opaque-but-recursed."""
    out, buf, i, q = [], [], 0, None
    s = s.replace("\\\n", "")  # line continuations
    while i < len(s):
        c = s[i]
        if q:
            buf.append(c)
            if c == "\\" and q == '"' and i+1 < len(s): buf.append(s[i+1]); i += 1
            elif c == q: q = None
        elif c in "'\"": q = c; buf.append(c)
        elif c == "\\" and i+1 < len(s): buf.append(c+s[i+1]); i += 1
        elif c in ";&|\n" or c in "()" and False:
            out.append("".join(buf)); buf = []
        else: buf.append(c)
        i += 1
    out.append("".join(buf))
    return [x.strip() for x in out if x.strip()]

SUBST = re.compile(r"\$\(([^()]*(?:\([^()]*\)[^()]*)*)\)|`([^`]*)`|[<>]\(([^()]*)\)")

def tokens(seg):
    lex = shlex.shlex(seg, posix=True, punctuation_chars=False)
    lex.whitespace_split = True; lex.commenters = ""
    return list(lex)

def basename(t): return os.path.basename(t)

DENY_RULES = []  # (name, predicate on argv list)
def _a(name):
    def deco(f): DENY_RULES.append((name, f)); return f
    return deco

def git_sub(argv):
    """Return (subcommand, rest) skipping git global options incl -C/-c/--git-dir."""
    i = 1; cfg = []
    while i < len(argv):
        a = argv[i]
        if a in ("-C","--git-dir","--work-tree","--namespace","--exec-path") : i += 2; continue
        if a == "-c": cfg.append(argv[i+1] if i+1 < len(argv) else ""); i += 2; continue
        if a.startswith("--") and "=" in a or a in ("--no-pager","--bare","-p","--paginate","--no-replace-objects","--literal-pathspecs"): i += 1; continue
        break
    return (argv[i] if i < len(argv) else ""), argv[i+1:], cfg

GIT_BLOCK = {"push","commit","merge","tag","rebase","cherry-pick","revert","am","pull"}
@_a("git")
def _git(argv):
    if basename(argv[0]) != "git": return
    sub, rest, cfg = git_sub(argv)
    if any(re.match(r"(alias\.|core\.(sshcommand|pager|editor|hookspath|fsmonitor)|credential\.|include)", c, re.I) for c in cfg):
        return "git -c alias/exec config injection"
    if sub in GIT_BLOCK: return f"git {sub}"
    if sub == "stash" and (rest[:1] or ["push"])[0] not in ("list","show"): return "git stash mutate"
    if sub == "reset" and ("--hard" in rest or "--merge" in rest): return "git reset --hard"
    if sub == "branch" and any(x in ("-d","-D","-m","-M","--delete","--force","-f","--move") for x in rest): return "git branch mutate"
    if sub == "branch" and [x for x in rest if not x.startswith("-")] and not any(x in ("--list","-l","-a","-r","--show-current","--contains","--merged","--no-merged") for x in rest): return "git branch create"
    if sub in ("clean",) and any("f" in x for x in rest if x.startswith("-")): return "git clean -f"
    if sub in ("checkout","switch") and any(x in ("-B","-b","-c","-C","--force","-f","--orphan") for x in rest): return "git branch via checkout"
    if sub == "checkout" and "--" in rest[:1]: return "git checkout -- discard"
    if sub == "restore": return "git restore"
    if sub == "worktree" and rest[:1] == ["remove"]: return "git worktree remove"
    if sub in ("update-ref","symbolic-ref","filter-branch","filter-repo","gc","prune","reflog") and sub != "reflog": return f"git {sub}"
    if sub not in ("status","diff","log","show","blame","ls-files","rev-parse","remote","fetch","branch","config","describe","grep","shortlog","ls-tree","cat-file","show-ref","rev-list","for-each-ref","name-rev","stash","help","version","add","checkout","switch","worktree","reflog","submodule","apply","mv","rm","bisect","diff-tree","merge-base","blame","archive","bundle","count-objects","fsck","check-ignore","ls-remote","range-diff","whatchanged","var","maintenance"): return f"git unknown subcommand {sub!r}"

@_a("gh")
def _gh(argv):
    if basename(argv[0]) != "gh": return
    w = [a for a in argv[1:] if not a.startswith("-")]
    if w[:2] in (["pr","merge"],["pr","close"],["pr","ready"],["pr","review"],["repo","delete"],["release","create"],["release","delete"],["issue","delete"],["workflow","run"],["run","rerun"]) : return "gh " + " ".join(w[:2])
    if w[:1] == ["api"] and any(x in ("-X","--method") and argv[i+1:i+2] and argv[i+1].upper() not in ("GET","HEAD") for i,x in enumerate(argv)): return "gh api mutating"
    if w[:1] == ["api"] and any(x in ("-f","-F","--field","--raw-field","--input") for x in argv): return "gh api with body (implies POST)"

@_a("terraform")
def _tf(argv):
    if basename(argv[0]) not in ("terraform","tofu","terragrunt"): return
    w = [a for a in argv[1:] if not a.startswith("-")]
    if w[:1] and w[0] in ("apply","destroy","import","taint","untaint","force-unlock","refresh"): return f"terraform {w[0]}"
    if w[:1] == ["state"] and w[1:2] and w[1] in ("rm","mv","push","replace-provider"): return "terraform state mutate"
    if w[:1] == ["workspace"] and w[1:2] in (["delete"],["new"]): return "terraform workspace mutate"
    if w[:1] and w[0] in ("run-all",): return "terragrunt run-all"

@_a("kubectl")
def _k(argv):
    if basename(argv[0]) not in ("kubectl","oc","helm","k"): return
    w = [a for a in argv[1:] if not a.startswith("-")]
    if basename(argv[0]) == "helm":
        if w[:1] and w[0] in ("install","upgrade","uninstall","delete","rollback"): return f"helm {w[0]}"
        return
    if w[:1] and w[0] in ("delete","apply","replace","patch","edit","drain","cordon","scale","rollout","exec","cp","create","annotate","label","taint","set","run","debug","auth"): return f"kubectl {w[0]}"

@_a("docker")
def _d(argv):
    if basename(argv[0]) not in ("docker","podman","docker-compose","nerdctl"): return
    w = [a for a in argv[1:] if not a.startswith("-")]
    if "prune" in w: return "docker prune"
    if w[:1] and w[0] in ("rm","rmi","kill","stop","volume","network","system","push","login","run","exec","down","compose") and w[:2] != ["volume","ls"] and w[:2] != ["network","ls"]: return f"docker {w[0]}"

@_a("db")
def _db(argv):
    if basename(argv[0]) not in ("psql","mysql","mariadb","sqlite3","mongosh","mongo","redis-cli","pg_restore","dropdb","createdb","dropuser","clickhouse-client","bq","snowsql","sqlcmd","cockroach"): return
    b = basename(argv[0])
    if b in ("dropdb","dropuser","pg_restore","redis-cli") and b != "redis-cli": return b
    return _sql(" ".join(argv[1:])) or ("db client: cannot prove read-only" if STRICT_DB else None)
STRICT_DB = False

SQL_BAD = re.compile(r"\b(drop\s+(database|schema|table|view|index|user|role)|truncate|alter\s+(table|database|system)|grant|revoke|flushall|flushdb|"
                     r"drop\s+owned|vacuum\s+full|copy\s+.*\bprogram\b|\\!|\bpg_terminate_backend|\binsert\s+into|\bupdate\s+\w+(?:\.\w+)*\s+set\b|\bcreate\s+(or\s+replace\s+)?(table|database|user|role|function))\b", re.I|re.S)
def _sql(text):
    t = re.sub(r"--[^\n]*|/\*.*?\*/", " ", text, flags=re.S)
    m = SQL_BAD.search(t)
    if m: return "SQL: " + m.group(0)[:30]
    for stmt in re.split(r";", t):
        if re.match(r"\s*delete\s+from\b", stmt, re.I) and not re.search(r"\bwhere\b", stmt, re.I): return "SQL: DELETE without WHERE"
        if re.match(r"\s*update\b", stmt, re.I) and not re.search(r"\bwhere\b", stmt, re.I): return "SQL: UPDATE without WHERE"
    if re.search(r"\bdelete\s+from\b", t, re.I): return "SQL: DELETE (needs human review)"

@_a("migrations")
def _mig(argv):
    b = basename(argv[0]); w = [a for a in argv[1:] if not a.startswith("-")]
    if b in ("prisma","npx","pnpx","bunx") and "prisma" in argv[:2] or b == "prisma":
        if "migrate" in w and any(x in w for x in ("reset","deploy","dev","resolve")): return "prisma migrate " + ",".join(w)
        if "db" in w and any(x in w for x in ("push","execute","seed")): return "prisma db " + ",".join(w)
    if b == "alembic" and w[:1] and w[0] in ("downgrade","upgrade","stamp"): return f"alembic {w[0]}"
    if b in ("rails","rake") and any(re.match(r"db:(drop|reset|schema:load|migrate:reset|rollback|setup)",x) for x in w): return "rails db destructive"
    if b in ("flask","django-admin","manage.py") and any(x in w for x in ("flush","sqlflush","reset_db","migrate")): return "django db"
    if b.startswith("python") and len(argv) > 2 and argv[1].endswith("manage.py") and any(x in argv for x in ("flush","reset_db","migrate","sqlflush")): return "manage.py db"
    if b in ("knex","sequelize","typeorm","drizzle-kit","flyway","liquibase") and any(x in w for x in ("rollback","migrate:rollback","drop","clean","destroy","push","migrate","undo","revert")): return b + " destructive"

@_a("rm")
def _rm(argv):
    b = basename(argv[0])
    if b not in ("rm","unlink","rmdir","shred","srm","trash") and not (b in ("find",) and ("-delete" in argv)): return
    flags = "".join(a.lstrip("-") for a in argv[1:] if a.startswith("-") and not a.startswith("--"))
    long_ = [a for a in argv[1:] if a.startswith("--")]
    rec = "r" in flags.lower() or "--recursive" in long_ or b == "find"
    paths = [a for a in argv[1:] if not a.startswith("-")]
    home = os.path.expanduser("~")
    for p in paths:
        pn = os.path.normpath(os.path.expandvars(p)) if p not in ("~","~/") else home
        if p.startswith("~"): pn = os.path.normpath(home + p[1:])
        if pn in ("/","/*", home, home+"/*") or p in ("/","/*","~","~/","~/*","$HOME","${HOME}","$HOME/","$HOME/*","*",".",".."," ./","./*","../*") or re.fullmatch(r"/(usr|etc|var|bin|sbin|lib|opt|boot|dev|home|Users|System|Library|Applications)/?\*?", p):
            return f"rm of protected path {p}"
    if rec and "f" in flags.lower(): return "rm -rf (needs explicit allowlist)"
    if "--no-preserve-root" in long_: return "rm --no-preserve-root"

@_a("curl-sh")
def _dl(argv): return None  # pipelines handled in analyse()

@_a("misc")
def _misc(argv):
    b = basename(argv[0])
    if b in ("dd","mkfs","fdisk","parted","shutdown","reboot","halt","poweroff","launchctl","systemctl","crontab","chmod","chown","chgrp","kill","killall","pkill","mount","umount","iptables","ufw","passwd","visudo","sudoedit") : 
        if b in ("chmod","chown","chgrp") and not any(x in ("-R","-r","--recursive") for x in argv): return
        return f"dangerous binary {b}"
    if b in ("aws","gcloud","az","gsutil","pulumi","cdk","serverless","sls","vercel","netlify","fly","flyctl","heroku","railway","wrangler","supabase","firebase","npm","pnpm","yarn","pip","pip3","cargo","gem","twine","mvn","gradle","ssh","scp","rsync","sftp","nc","ncat","netcat","telnet","ftp"):
        w = [a for a in argv[1:] if not a.startswith("-")]
        if b in ("npm","pnpm","yarn") and w[:1] and w[0] in ("publish","unpublish","deprecate","login","adduser","token","access","owner","dist-tag"): return f"{b} {w[0]}"
        if b in ("pip","pip3","cargo","gem","twine","mvn","gradle") and w[:1] and w[0] in ("upload","publish","push","deploy","yank"): return f"{b} {w[0]}"
        if b in ("aws","gcloud","az","gsutil") and any(re.match(r"(delete|rm|remove|terminate|destroy|purge|drop|deregister|detach|put-|create-|update-|modify-|run-instances|start-|stop-|reboot|deploy)",x) for x in w): return f"{b} mutating verb"
        if b in ("pulumi","cdk","serverless","sls","vercel","netlify","fly","flyctl","heroku","railway","wrangler","supabase","firebase") and w[:1] and w[0] in ("up","destroy","deploy","delete","remove","rm","publish","prod","secrets","db","apps","scale","restart","run","push","migrate","release"): return f"{b} {w[0]}"
        if b in ("ssh","scp","rsync","sftp","nc","ncat","netcat","telnet","ftp"): return f"network binary {b}"

def eval_argv(argv, depth):
    if not argv: return None
    # leading VAR=val assignments and redirections
    while argv and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]):
        v = argv[0]
        if re.match(r"^(PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_\w+|GIT_\w+|PAGER|EDITOR|SHELL|BASH_ENV|ENV|IFS|PYTHONPATH|PYTHONSTARTUP|NODE_OPTIONS)=", v): return f"dangerous env assignment {v.split('=')[0]}"
        argv = argv[1:]
    if not argv: return None
    b = basename(argv[0])
    if re.search(r"[\$`*?\[{]", argv[0]) and not argv[0].startswith("-"): return "command word is dynamic ($var/glob/brace): cannot resolve"
    if b in ("eval","source",".","exec") and b != "exec": return f"{b}: dynamic code"
    if b in WRAPPERS:
        rest = argv[1:]
        # skip wrapper options (and their simple args); fail closed if nothing left
        j = 0
        while j < len(rest) and (rest[j].startswith("-") or re.match(r"^[A-Za-z_]\w*=", rest[j]) or (b in ("timeout","nice","ionice","stdbuf") and re.match(r"^[\d.]+[smhd]?$", rest[j]))):
            if rest[j] in ("-u","-g","-C","-h","-p","-n","-i","-o","-e","-a","-L","-I","-P","-s") and b in ("sudo","env","xargs","doas"): j += 1
            j += 1
        inner = rest[j:]
        if b == "xargs" and not inner: return None
        if b in ("command","builtin") and inner[:1] and inner[0] in ("-v","-V"): return None
        return eval_argv(inner, depth) if inner else None
    if b == "find":
        for k, a in enumerate(argv):
            if a in ("-exec","-execdir","-ok","-okdir"):
                end = k+1
                while end < len(argv) and argv[end] not in (";","+","\;"): end += 1
                r = eval_argv(argv[k+1:end], depth)
                if r: return "find -exec: " + r
        if "-delete" in argv: return "find -delete"
    if b in SHELLS or b in INTERPS or re.match(r"python\d(\.\d+)?$", b):
        for k, a in enumerate(argv[1:], 1):
            if b in SHELLS and re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", a) and k+1 < len(argv):
                return analyse(argv[k+1], depth+1)
            if b in INTERPS or b.startswith("python"):
                if a in ("-c","-e","-E","-r") and k+1 < len(argv): return analyse_interp_code(argv[k+1], depth)
        if b in SHELLS and len(argv) == 1: return "bare interactive shell"
        if b in SHELLS and not any(a == "-c" for a in argv): return "shell executing script/stdin: cannot inspect"
    for name, pred in DENY_RULES:
        r = pred(argv)
        if r: return r

INTERP_BAD = re.compile(r"os\.(system|popen|exec\w*|spawn\w*)|subprocess|pty\.spawn|commands\.getoutput|child_process|execSync|spawnSync|Runtime\.getRuntime|\bsystem\s*\(|\bexec\s*\(|\bpopen\s*\(|\beval\s*\(|__import__|shutil\.rmtree|os\.(remove|unlink|rmdir|removedirs)|\brmtree\b|requests\.(post|put|delete|patch)|urllib|socket", re.I)
def analyse_interp_code(code, depth):
    if INTERP_BAD.search(code): return "interpreter -c/-e code spawns processes or does destructive/network ops"

B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
def analyse(cmd, depth=0):
    """Return None if allowed else a reason string. Fail closed."""
    if depth > MAX_DEPTH: return "nesting too deep"
    if len(cmd) > 20000: return "command too long"
    if re.search(r"\$'|\$\"", cmd): return "ANSI-C/locale quoting: cannot statically resolve"
    if re.search(r"<<-?\s*\\?['\"]?\w+", cmd) :
        # heredoc: body may be fed to a shell. Inspect body as commands if consumer is a shell.
        m = re.search(r"(\b(?:sh|bash|zsh|dash|ksh|python3?|perl|ruby|node)\b[^\n<]*)<<-?\s*\\?['\"]?(\w+)['\"]?\s*\n(.*?)\n\s*\2\b", cmd, re.S)
        if m: 
            body = m.group(3)
            r = analyse(body, depth+1) if re.match(r"(ba|z|da|k)?sh", m.group(1).strip()) else analyse_interp_code(body, depth)
            if r: return "heredoc: " + r
    # command substitution anywhere (even inside double quotes) is recursed
    for m in SUBST.finditer(cmd):
        inner = next(g for g in m.groups() if g is not None)
        r = analyse(inner, depth+1)
        if r: return "substitution: " + r
    # base64/xxd/openssl decode piped into a shell
    if re.search(r"(base64|b64decode|xxd\s+-r|openssl\s+(enc|base64))[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", cmd): return "decoded payload piped to shell"
    if re.search(r"\b(curl|wget|fetch|http|iwr|Invoke-WebRequest)\b[^\n]*\|\s*(sudo\s+)?(env\s+\S+\s+)?(ba|z|da|k)?sh\b|\b(ba|z|da|k)?sh\s+<\(\s*(curl|wget)|\bsource\s+<\(\s*(curl|wget)", cmd): return "remote script piped to shell"
    if re.search(r"\b(curl|wget)\b[^\n]*\|\s*(python3?|perl|ruby|node|php)\b", cmd): return "remote script piped to interpreter"
    if re.search(r"\b(curl|wget)\b.*\s(-X\s*(POST|PUT|DELETE|PATCH)|--request\s+(POST|PUT|DELETE|PATCH)|-d\b|--data\S*|-F\b|--form\b|-T\b|--upload-file|-o\s*/|-O\b)", cmd): return "curl/wget mutating or writing"
    try:
        segs = split_commands(cmd)
    except Exception: return "parse failure"
    for seg in segs:
        seg = re.sub(r"^\s*[!({]+\s*|\s*[)}]+\s*$", "", seg)
        # strip redirections that would otherwise appear as args
        try: argv = tokens(seg)
        except ValueError: return "shlex parse failure (unbalanced quotes)"
        argv = [a for a in argv if not re.fullmatch(r"\d*[<>]+&?\d*-?|\d*>>?", a)]
        # redirect to a file path is a write; flag writes to sensitive paths
        if re.search(r">>?\s*(/etc/|/usr/|/bin/|/sbin/|~/\.(ssh|bashrc|zshrc|profile|aws|gitconfig)|\$HOME/\.|\.git/(hooks|config)|\.claude/|\.codex/)", seg): return "redirect into sensitive path"
        if len(argv) >= 2 and argv[0] in ("if","then","else","elif","while","until","do","for","case","time","!") : argv = argv[1:]
        r = eval_argv(argv, depth)
        if r: return r
    return None

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Optional

MAX_DEPTH = 6
MAX_LENGTH = 20000
WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "command", "builtin", "exec", "nice", "ionice",
            "stdbuf", "timeout", "xargs", "watch", "setsid", "chroot", "unbuffer", "caffeinate",
            "busybox"}
RUN_WRAPPERS = {"uv": ("run",), "poetry": ("run",), "pipenv": ("run",), "pdm": ("run",),
                "hatch": ("run",), "rye": ("run",)}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "mksh", "tcsh", "csh"}
INTERPS = {"python", "python2", "python3", "perl", "ruby", "node", "php", "lua", "deno", "bun",
           "osascript", "pwsh", "tclsh", "Rscript"}
EVAL_WORDS = {"eval", "source", "."}
CONTROL_WORDS = {"if", "then", "else", "elif", "while", "until", "do", "!", "time", "{", "(", "coproc"}
CLOSING_WORDS = {"fi", "done", "esac", "}", ")", "then", "else", "do"}
HEADER_WORDS = {"for", "select", "case", "function", "in"}
INTERP_CODE_FLAGS = {"-c", "-e", "-E", "-r", "--eval", "-p", "--print", "-x", "-n"}
_PYTHON = re.compile(r"^python(?:\d+(?:\.\d+)*)?$")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
_HEREDOC = re.compile(r"<<(-?)[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\?([A-Za-z0-9_.\-]+))")
_OPAQUE_CHARS = ("$", "`", "*", "?", "[", "{")
_WRITE_REDIRECTS = (">", ">>", ">|", "&>", "&>>", "<>", ">&")
_FD_DUP = re.compile(r"^(?:\d+|-)$")

_WRAPPER_VALUE_OPTIONS = {
    "sudo": {"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D", "-R", "-T", "--user", "--group",
             "--host", "--prompt", "--role", "--type", "--other-user", "--chdir", "--chroot",
             "--close-from", "--command-timeout"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-P", "-S", "--unset", "--chdir", "--split-string", "-a", "--argv0"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "xargs": {"-I", "-L", "-n", "-P", "-s", "-E", "-d", "-a", "-i", "--replace", "--max-lines",
              "--max-args", "--max-procs", "--max-chars", "--eof", "--delimiter", "--arg-file"},
    "watch": {"-n", "--interval", "-d", "--differences", "-c"},
    "exec": {"-a"},
    "chroot": {"--userspec", "--groups"},
    "setsid": set(),
    "unbuffer": set(),
    "caffeinate": {"-t", "-w"},
    "time": {"-f", "--format", "-o", "--output"},
    "busybox": set(),
    "nohup": set(),
    "command": set(),
    "builtin": set(),
}
_WRAPPER_POSITIONAL = {"timeout": 1, "chroot": 1}


def basename(tok: str) -> str:
    return os.path.basename(str(tok).rstrip("/")) if tok else ""


def is_opaque(tok: str) -> bool:
    if tok is None or tok == "":
        return True
    return any(ch in tok for ch in _OPAQUE_CHARS)


def _balanced_paren(text: str, start: int) -> int:
    depth = 0
    i = start
    n = len(text)
    quote: Optional[str] = None
    while i < n:
        c = text[i]
        if quote == "'":
            if c == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == '"':
                quote = None
                i += 1
                continue
            if text.startswith("$(", i):
                i = _balanced_paren(text, i + 1)
                continue
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c in "'\"":
            quote = c
            i += 1
            continue
        if c == "`":
            close = _backtick_end(text, i)
            i = close
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _backtick_end(text: str, start: int) -> int:
    i = start + 1
    n = len(text)
    while i < n:
        if text[i] == "\\" and i + 1 < n:
            i += 2
            continue
        if text[i] == "`":
            return i + 1
        i += 1
    return n


def _word_start(text: str, i: int) -> bool:
    return i == 0 or text[i - 1] in " \t\n;&|()"


def split_commands(cmd: str) -> list:
    text = cmd or ""
    out: list = []
    buf: list = []
    quote: Optional[str] = None
    i = 0
    n = len(text)

    def flush():
        piece = "".join(buf).strip()
        if piece:
            out.append(piece)
        del buf[:]

    while i < n:
        c = text[i]
        if quote == "'":
            buf.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if c == "\\" and i + 1 < n:
                if text[i + 1] == "\n":
                    i += 2
                    continue
                buf.append(text[i:i + 2])
                i += 2
                continue
            if text.startswith("$(", i):
                end = _balanced_paren(text, i + 1)
                buf.append(text[i:end])
                i = end
                continue
            if c == "`":
                end = _backtick_end(text, i)
                buf.append(text[i:end])
                i = end
                continue
            buf.append(c)
            if c == '"':
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            if text[i + 1] == "\n":
                i += 2
                continue
            buf.append(text[i:i + 2])
            i += 2
            continue
        if c in "'\"":
            quote = c
            buf.append(c)
            i += 1
            continue
        if text.startswith("$(", i) or text.startswith("<(", i) or text.startswith(">(", i):
            end = _balanced_paren(text, i + 1)
            buf.append(text[i:end])
            i = end
            continue
        if c == "`":
            end = _backtick_end(text, i)
            buf.append(text[i:end])
            i = end
            continue
        if c == "#" and _word_start(text, i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c in ";\n":
            flush()
            i += 1
            continue
        if c == "|":
            prev = text[i - 1] if i > 0 else ""
            if prev == ">":
                buf.append(c)
                i += 1
                continue
            flush()
            i += 2 if text.startswith("||", i) or text.startswith("|&", i) else 1
            continue
        if c == "&":
            prev = text[i - 1] if i > 0 else ""
            nxt = text[i + 1] if i + 1 < n else ""
            if prev in "<>" or nxt == ">":
                buf.append(c)
                i += 1
                continue
            flush()
            i += 2 if nxt == "&" else 1
            continue
        buf.append(c)
        i += 1
    flush()
    return out


def tokens(segment: str) -> list:
    lexer = shlex.shlex(segment, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def substitutions(cmd: str) -> list:
    text = cmd or ""
    found: list = []
    quote: Optional[str] = None
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if quote == "'":
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if quote is None and c == "'":
            quote = "'"
            i += 1
            continue
        if c == '"':
            quote = None if quote == '"' else '"'
            i += 1
            continue
        if text.startswith("$((", i):
            end = _balanced_paren(text, i + 1)
            inner = text[i + 3:max(i + 3, end - 2)]
            found.extend(substitutions(inner))
            i = end
            continue
        if text.startswith("$(", i) or (quote is None and (text.startswith("<(", i) or text.startswith(">(", i))):
            end = _balanced_paren(text, i + 1)
            inner = text[i + 2:end - 1] if end <= n and text[end - 1:end] == ")" else text[i + 2:end]
            found.append(inner)
            i = end
            continue
        if c == "`":
            end = _backtick_end(text, i)
            inner = text[i + 1:end - 1] if text[end - 1:end] == "`" else text[i + 1:end]
            found.append(inner.replace("\\`", "`"))
            i = end
            continue
        i += 1
    return found


def _heredoc_scan(cmd: str) -> tuple:
    text = cmd or ""
    out: list = []
    bodies: list = []
    pending: list = []
    quote: Optional[str] = None
    line_start = 0
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if quote == "'":
            out.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if c == "\\" and i + 1 < n:
                out.append(text[i:i + 2])
                i += 2
                continue
            out.append(c)
            if c == '"':
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
            continue
        if c in "'\"":
            quote = c
            out.append(c)
            i += 1
            continue
        if c == "#" and _word_start(text, i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("<<<", i):
            out.append("<<<")
            i += 3
            continue
        if text.startswith("<<", i):
            m = _HEREDOC.match(text, i)
            if m:
                delim = next(g for g in (m.group(2), m.group(3), m.group(4)) if g is not None)
                pending.append((delim, m.group(1) == "-"))
                out.append(" ")
                i = m.end()
                continue
        if c == "\n":
            if pending:
                head = "".join(out[line_start:])
                i += 1
                for delim, strip_tabs in pending:
                    body: list = []
                    while i < n:
                        end = text.find("\n", i)
                        line = text[i:] if end == -1 else text[i:end]
                        i = n if end == -1 else end + 1
                        candidate = line.lstrip("\t") if strip_tabs else line
                        if candidate == delim or candidate.rstrip() == delim:
                            break
                        body.append(candidate)
                    bodies.append((head.strip(), "\n".join(body)))
                pending = []
                out.append("\n")
                line_start = len(out)
                continue
            out.append(c)
            i += 1
            line_start = len(out)
            continue
        out.append(c)
        i += 1
    if pending:
        head = "".join(out[line_start:])
        for _ in pending:
            bodies.append((head.strip(), ""))
    return "".join(out), bodies


def heredocs(cmd: str) -> list:
    return _heredoc_scan(cmd)[1]


def strip_heredocs(cmd: str) -> str:
    return _heredoc_scan(cmd)[0]


def mask_expansions(cmd: str) -> str:
    text = cmd or ""
    out: list = []
    i = 0
    n = len(text)
    quote: Optional[str] = None
    while i < n:
        c = text[i]
        if quote == "'":
            out.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
            continue
        if quote is None and c == "'":
            quote = "'"
            out.append(c)
            i += 1
            continue
        if c == '"':
            quote = None if quote == '"' else '"'
            out.append(c)
            i += 1
            continue
        if text.startswith("$(", i):
            i = _balanced_paren(text, i + 1)
            out.append("$SUBST")
            continue
        if c == "`":
            i = _backtick_end(text, i)
            out.append("$SUBST")
            continue
        if quote is None and text.startswith("[[", i) and _word_start(text, i):
            close = text.find("]]", i + 2)
            i = n if close == -1 else close + 2
            out.append(" _test_ ")
            continue
        if quote is None and text.startswith("((", i) and _word_start(text, i):
            close = text.find("))", i + 2)
            i = n if close == -1 else close + 2
            out.append(" _arith_ ")
            continue
        out.append(c)
        i += 1
    return "".join(out)


@dataclass
class Token:
    value: str
    raw: str
    op: bool = False
    opaque: bool = False


def lex(segment: str) -> list:
    text = segment or ""
    out: list = []
    value: list = []
    raw: list = []
    state = {"opaque": False, "started": False}
    quote: Optional[str] = None
    i = 0
    n = len(text)

    def flush():
        if state["started"]:
            out.append(Token("".join(value), "".join(raw), False, state["opaque"]))
        del value[:]
        del raw[:]
        state["opaque"] = False
        state["started"] = False

    def operator(op_text: str):
        out.append(Token(op_text, op_text, True, False))

    while i < n:
        c = text[i]
        if quote == "'":
            raw.append(c)
            if c == "'":
                quote = None
            else:
                value.append(c)
            i += 1
            continue
        if quote == '"':
            raw.append(c)
            if c == "\\" and i + 1 < n and text[i + 1] in '"\\$`\n':
                raw.append(text[i + 1])
                if text[i + 1] != "\n":
                    value.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                quote = None
                i += 1
                continue
            if c in "$`":
                state["opaque"] = True
            value.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            state["started"] = True
            raw.append(text[i:i + 2])
            if text[i + 1] != "\n":
                value.append(text[i + 1])
            i += 2
            continue
        if c in "'\"":
            state["started"] = True
            quote = c
            raw.append(c)
            i += 1
            continue
        if c in " \t\n":
            flush()
            i += 1
            continue
        if c in "<>" or (c == "&" and text[i + 1:i + 2] == ">"):
            digits = "".join(value)
            if state["started"] and not (digits.isdigit() and "".join(raw) == digits):
                flush()
                digits = ""
            else:
                del value[:]
                del raw[:]
                state["started"] = False
                state["opaque"] = False
            for candidate in ("&>>", "&>", ">>", ">|", ">&", "<<<", "<<", "<>", "<&", ">", "<"):
                if text.startswith(candidate, i):
                    operator(digits + candidate)
                    i += len(candidate)
                    break
            continue
        if c in "|;&":
            flush()
            for candidate in ("||", "&&", "|&", ";;", "|", ";", "&"):
                if text.startswith(candidate, i):
                    operator(candidate)
                    i += len(candidate)
                    break
            continue
        state["started"] = True
        if c in _OPAQUE_CHARS:
            state["opaque"] = True
        value.append(c)
        raw.append(c)
        i += 1
    if quote is not None:
        raise ValueError("unbalanced quotes")
    flush()
    return out


def _redirect_kind(op: str) -> str:
    bare = op.lstrip("0123456789")
    if bare in ("<<", "<<<"):
        return "heredoc"
    if bare in ("<", "<&"):
        return "read"
    if bare == ">&":
        return "dup"
    if bare in ("|", "||", "&&", "|&", ";", ";;", "&"):
        return "separator"
    return "write"


def redirect_targets(segment: str) -> tuple:
    targets: list = []
    opaque = False
    try:
        lexed = lex(mask_expansions(strip_heredocs(segment)))
    except ValueError:
        return [], True
    index = 0
    while index < len(lexed):
        token = lexed[index]
        index += 1
        if not token.op:
            continue
        kind = _redirect_kind(token.value)
        if kind in ("separator", "heredoc", "read"):
            if kind != "separator" and index < len(lexed) and not lexed[index].op:
                index += 1
            continue
        target = lexed[index] if index < len(lexed) and not lexed[index].op else None
        if target is not None:
            index += 1
        if kind == "dup":
            if target is not None and _FD_DUP.match(target.value):
                continue
        if target is None or target.value == "":
            opaque = True
            continue
        if target.opaque:
            opaque = True
            continue
        targets.append(target.value)
    return targets, opaque


def argv_of(segment: str) -> list:
    lexed = lex(segment)
    argv: list = []
    index = 0
    while index < len(lexed):
        token = lexed[index]
        index += 1
        if token.op:
            kind = _redirect_kind(token.value)
            if kind != "separator" and index < len(lexed) and not lexed[index].op:
                index += 1
            continue
        argv.append(token.value)
    return argv


_REDIRECT_OP = re.compile(r"^\d*(?:&>>|&>|>>|>\||>&|<<<|<<|<>|<&|>|<)$")
_REDIRECT_ATTACHED = re.compile(r"^\d*(?:&>>|&>|>>|>\||>&|<<<|<>|<&|>|<)\S+$")


def strip_redirect_tokens(argv: list) -> list:
    out: list = []
    skip = False
    for token in argv or []:
        if skip:
            skip = False
            continue
        if _REDIRECT_OP.match(token):
            skip = True
            continue
        if _REDIRECT_ATTACHED.match(token):
            continue
        out.append(token)
    return out


def leading_assignments(argv: list) -> tuple:
    assignments: list = []
    index = 0
    items = list(argv or [])
    while index < len(items) and _ASSIGNMENT.match(items[index]):
        assignments.append(items[index])
        index += 1
    return assignments, items[index:]


def _peel_options(name: str, rest: list) -> tuple:
    values = _WRAPPER_VALUE_OPTIONS.get(name, set())
    assignments: list = []
    index = 0
    split_extra: list = []
    while index < len(rest):
        token = rest[index]
        if token == "--":
            index += 1
            break
        if name in ("env", "sudo", "doas") and _ASSIGNMENT.match(token):
            assignments.append(token)
            index += 1
            continue
        if name == "env" and token == "-":
            index += 1
            continue
        if token.startswith("-") and len(token) > 1:
            if name == "env" and (token in ("-S", "--split-string") or token.startswith("--split-string=")
                                  or (token.startswith("-S") and len(token) > 2)):
                if token in ("-S", "--split-string"):
                    payload = rest[index + 1] if index + 1 < len(rest) else ""
                    index += 2
                elif token.startswith("--split-string="):
                    payload = token.split("=", 1)[1]
                    index += 1
                else:
                    payload = token[2:]
                    index += 1
                try:
                    split_extra = tokens(payload)
                except ValueError:
                    split_extra = [payload]
                return assignments, split_extra + rest[index:]
            if token in values:
                index += 2
                continue
            if "=" in token and token.split("=", 1)[0] in values:
                index += 1
                continue
            if name in ("timeout", "nice", "watch") and re.match(r"^-\d", token):
                index += 1
                continue
            index += 1
            continue
        break
    remaining = rest[index:]
    positional = _WRAPPER_POSITIONAL.get(name, 0)
    if name == "timeout" and remaining and re.match(r"^[\d.]+[smhd]?$", remaining[0]):
        remaining = remaining[1:]
    elif positional and name != "timeout":
        remaining = remaining[positional:]
    return assignments, remaining


def unwrap_with_assignments(argv: list) -> tuple:
    current = list(argv or [])
    collected: list = []
    for _ in range(32):
        lead, current = leading_assignments(current)
        collected.extend(lead)
        if not current:
            return [], collected
        name = basename(current[0])
        if name in RUN_WRAPPERS and len(current) > 1 and current[1] in RUN_WRAPPERS[name]:
            rest = current[2:]
            while rest and rest[0].startswith("-"):
                rest = rest[1:]
            current = rest
            continue
        if name not in WRAPPERS:
            return current, collected
        rest = current[1:]
        if name in ("command", "builtin") and rest and rest[0] in ("-v", "-V"):
            return [], collected
        if name == "command":
            while rest and rest[0] in ("-p", "--"):
                rest = rest[1:]
        if name == "busybox":
            current = rest
            continue
        lead, rest = _peel_options(name, rest)
        collected.extend(lead)
        current = rest
    return current, collected


def unwrap(argv: list) -> list:
    return unwrap_with_assignments(argv)[0]


_GIT_VALUE_OPTIONS = {"-C", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix",
                      "--config-env", "--list-cmds", "--attr-source"}
_GIT_FLAG_OPTIONS = {"--no-pager", "-P", "-p", "--paginate", "--bare", "--no-replace-objects",
                     "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs",
                     "--icase-pathspecs", "--no-optional-locks", "--no-lazy-fetch", "--no-advice"}
_GIT_ALIASES = {"--version": "version", "-v": "version", "--help": "help", "-h": "help"}


def git_subcommand(argv: list) -> tuple:
    items = list(argv or [])
    configs: list = []
    index = 1
    while index < len(items):
        token = items[index]
        if token in _GIT_ALIASES:
            return _GIT_ALIASES[token], items[index + 1:], configs
        if token == "-c":
            configs.append(items[index + 1] if index + 1 < len(items) else "")
            index += 2
            continue
        if token.startswith("-c") and len(token) > 2 and not token.startswith("--"):
            configs.append(token[2:])
            index += 1
            continue
        if token == "--config-env" or token.startswith("--config-env="):
            value = token.split("=", 1)[1] if "=" in token else (items[index + 1] if index + 1 < len(items) else "")
            configs.append(value)
            index += 1 if "=" in token else 2
            continue
        if token in _GIT_VALUE_OPTIONS:
            index += 2
            continue
        if token.startswith("-C") and len(token) > 2:
            index += 1
            continue
        if token.startswith("--") and "=" in token:
            index += 1
            continue
        if token in _GIT_FLAG_OPTIONS or token.startswith("-"):
            index += 1
            continue
        return token, items[index + 1:], configs
    return "", [], configs


def strip_control(argv: list) -> list:
    items = list(argv or [])
    while items and items[0] in CONTROL_WORDS:
        items = items[1:]
    while items and items[0].startswith("(") and items[0] != "(":
        items[0] = items[0][1:]
        if not items[0]:
            items = items[1:]
    if items and items[0].endswith("()"):
        items = items[1:]
        while items and items[0] in ("{", "("):
            items = items[1:]
    while items and items[-1] in (")", "}", ";;"):
        items = items[:-1]
    if items and items[-1].endswith(")") and not items[-1].startswith("$(") and "(" not in items[-1]:
        items[-1] = items[-1].rstrip(")")
        if not items[-1]:
            items = items[:-1]
    if items and items[0] in CLOSING_WORDS and len(items) == 1:
        return []
    return items


def is_shell(name: str) -> bool:
    return basename(name) in SHELLS


def is_interpreter(name: str) -> bool:
    base = basename(name)
    return base in INTERPS or bool(_PYTHON.match(base))


@dataclass
class Walk:
    commands: list = field(default_factory=list)
    dynamic: list = field(default_factory=list)
    code: list = field(default_factory=list)
    depth: int = 0

    def merge(self, other: "Walk") -> None:
        self.commands.extend(other.commands)
        self.dynamic.extend(other.dynamic)
        self.code.extend(other.code)
        self.depth = max(self.depth, other.depth)


def _shell_c_payload(argv: list) -> Optional[str]:
    for index, token in enumerate(argv[1:], 1):
        if re.match(r"^-[A-Za-z]*c[A-Za-z]*$", token) and not token.startswith("--"):
            return argv[index + 1] if index + 1 < len(argv) else ""
        if token.startswith("-") or token.startswith("+"):
            continue
        return None
    return None


def _interp_code(argv: list) -> Optional[str]:
    for index, token in enumerate(argv[1:], 1):
        if token in INTERP_CODE_FLAGS:
            return argv[index + 1] if index + 1 < len(argv) else ""
        if re.match(r"^-[A-Za-z]*[ce]$", token) and basename(argv[0]) in ("perl", "ruby", "node"):
            return argv[index + 1] if index + 1 < len(argv) else ""
        if token == "-" or not token.startswith("-"):
            return None
    return None


def _walk_argv(argv: list, depth: int, result: Walk) -> None:
    inner, assignments = unwrap_with_assignments(argv)
    if not inner:
        if argv and basename(argv[0]) in WRAPPERS:
            result.commands.append({"argv": [basename(argv[0])], "assignments": assignments, "depth": depth,
                                    "raw": list(argv)})
        return
    head = inner[0]
    if is_opaque(head) and not head.startswith("-"):
        result.dynamic.append("command_word: %s" % head)
        return
    name = basename(head)
    entry = {"argv": [name] + inner[1:], "assignments": assignments, "depth": depth, "raw": list(argv)}
    result.commands.append(entry)
    if name in EVAL_WORDS:
        if name == "eval":
            result.dynamic.append("eval")
            result.merge(walk(" ".join(inner[1:]), depth + 1))
        else:
            result.dynamic.append("source: %s" % (" ".join(inner[1:]) or "<stdin>"))
        return
    if name == "find":
        for index, token in enumerate(inner):
            if token in ("-exec", "-execdir", "-ok", "-okdir"):
                end = index + 1
                while end < len(inner) and inner[end] not in (";", "+", "\\;"):
                    end += 1
                _walk_argv(inner[index + 1:end], depth + 1, result)
        return
    if is_shell(name):
        payload = _shell_c_payload(inner)
        if payload is not None:
            result.merge(walk(payload, depth + 1))
            return
        operands = [t for t in inner[1:] if not t.startswith("-") and not t.startswith("+")]
        if not operands:
            result.dynamic.append("opaque_shell: %s reads commands from stdin" % name)
        else:
            result.dynamic.append("opaque_shell: %s runs a script %s" % (name, operands[0]))
        return
    if is_interpreter(name):
        code = _interp_code(inner)
        if code is not None:
            result.code.append((name, code))


def _head_consumer(head: str) -> Optional[str]:
    try:
        words = tokens(head.replace("$(", " ").replace("(", " ").replace(")", " "))
    except ValueError:
        return "shell"
    for word in words:
        inner = unwrap([word]) or [word]
        name = basename(inner[0])
        if name in SHELLS or name in EVAL_WORDS:
            return "shell"
    for word in words:
        if is_interpreter(word):
            return basename(word)
    return None


def walk(cmd: str, depth: int = 0) -> Walk:
    result = Walk(depth=depth)
    text = cmd or ""
    if depth > MAX_DEPTH:
        result.dynamic.append("nesting: deeper than %d levels" % MAX_DEPTH)
        return result
    if len(text) > MAX_LENGTH:
        result.dynamic.append("too_long: %d characters" % len(text))
        return result
    if "$'" in text or '$"' in text:
        result.dynamic.append("ansi_quoting")
    stripped, bodies = _heredoc_scan(text)
    for head, body in bodies:
        consumer = _head_consumer(head)
        if consumer == "shell":
            result.merge(walk(body, depth + 1))
        elif consumer:
            result.code.append((consumer, body))
    for inner in substitutions(stripped):
        result.merge(walk(inner, depth + 1))
    for segment in split_commands(stripped):
        try:
            tokens(segment)
            argv = argv_of(segment)
        except ValueError:
            result.dynamic.append("parse_failure: unbalanced quotes")
            continue
        argv = strip_control(argv)
        if not argv or argv[0] in HEADER_WORDS:
            continue
        _walk_argv(argv, depth, result)
    return result

from __future__ import annotations

import functools
import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Optional

from . import config as config_mod

DEV_FILES = ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty")
SYSTEM_TEMP_ROOTS = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
AGENT_HOME_ROOTS = (("~", ".claude"), ("~", ".codex"), ("~", ".gemini"), ("~", ".gitconfig"), ("~", ".config", "git"),
                    ("~", ".gnupg"), ("~", ".ssh"))


def harness_root() -> Path:
    import hooks.lib as lib
    return Path(lib.__file__).resolve().parents[2]


def state_root() -> Path:
    raw = os.environ.get("OMEGA_STATE_DIR")
    root = Path(os.path.abspath(os.path.expanduser(raw))) if raw else harness_root() / ".omega" / "state"
    if not root.is_dir():
        os.makedirs(str(root), mode=0o700, exist_ok=True)
        try:
            os.chmod(str(root), 0o700)
        except OSError:
            pass
    return root


def workspace_of(payload: Optional[dict]) -> str:
    payload = payload if isinstance(payload, dict) else {}
    for candidate in (os.environ.get("OMEGA_WORKSPACE"), payload.get("cwd"),
                      os.environ.get("CLAUDE_PROJECT_DIR")):
        if isinstance(candidate, str) and candidate.strip():
            return os.path.realpath(os.path.expanduser(candidate.strip()))
    return os.path.realpath(os.getcwd())


def workspace_hash(workspace: str) -> str:
    return hashlib.sha256(os.path.realpath(workspace).encode("utf-8")).hexdigest()[:16]


def _forms(path: str) -> list:
    absolute = os.path.abspath(os.path.expanduser(str(path)))
    real = os.path.realpath(absolute)
    return [absolute] if real == absolute else [absolute, real]


def _root_forms(root) -> list:
    return _forms(str(root))


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _rel_under(path: str, root) -> Optional[str]:
    for form in _forms(path):
        for base in _root_forms(root):
            if _under(form, base):
                if form == base:
                    return "."
                return Path(os.path.relpath(form, base)).as_posix()
    return None


def _rel_forms(path: str, root) -> list:
    found: list = []
    for form in _forms(path):
        for base in _root_forms(root):
            if _under(form, base):
                value = "." if form == base else Path(os.path.relpath(form, base)).as_posix()
                if value not in found:
                    found.append(value)
    return found


def rel(path: str, root: str) -> str:
    found = _rel_under(path, root)
    if found is not None:
        return found
    return Path(os.path.abspath(os.path.expanduser(str(path)))).as_posix()


@functools.lru_cache(maxsize=512)
def _glob_regex(pattern: str):
    out = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
                i += 1
            else:
                body = pattern[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def match_glob(path_rel: str, pattern: str) -> bool:
    while path_rel.startswith("./"):
        path_rel = path_rel[2:]
    if not pattern:
        return False
    if pattern.endswith("/") and not pattern.endswith("**/"):
        pattern = pattern + "**"
    regex = _glob_regex(pattern)
    if regex.match(path_rel):
        return True
    if pattern.endswith("/**") and path_rel == pattern[:-3]:
        return True
    if "/" not in pattern:
        return bool(regex.match(path_rel.rsplit("/", 1)[-1]))
    return False


def match_globs(path_rel: str, globs) -> bool:
    if not path_rel:
        return False
    return any(match_glob(path_rel, g) for g in (globs or []) if isinstance(g, str))


def _cfg(ctx):
    cfg = getattr(ctx, "cfg", None)
    if cfg is None:
        cfg = config_mod.load(workspace=getattr(ctx, "workspace", None))
    return cfg


def _workspace(ctx) -> str:
    return os.path.realpath(str(getattr(ctx, "workspace", None) or workspace_of({})))


def _harness(ctx) -> str:
    root = getattr(ctx, "harness_root", None)
    return str(root) if root else str(harness_root())


def is_dev() -> bool:
    return os.environ.get("OMEGA_DEV", "") == "1"


def _ignored(rel_path: str, ignored) -> bool:
    parts = rel_path.split("/")
    for entry in ignored or []:
        wanted = [p for p in str(entry).strip("/").split("/") if p]
        if not wanted:
            continue
        width = len(wanted)
        for start in range(0, len(parts) - width + 1):
            if parts[start:start + width] == wanted:
                return True
    return False


def is_governed(path: str, ctx) -> bool:
    ignored = _cfg(ctx).get("workspace.ignored_dirs", [])
    for root in (_workspace(ctx), _harness(ctx)):
        found = _rel_under(path, root)
        if found is not None:
            return found == "." or not _ignored(found, ignored)
    return False


def _outside_protected(path: str, ctx) -> bool:
    forms = _forms(path)
    transcript = getattr(ctx, "transcript_path", None)
    if transcript:
        targets = set(_forms(transcript))
        if any(f in targets for f in forms):
            return True
    human_log = os.environ.get("OMEGA_HUMAN_LOG")
    if human_log:
        targets = set(_forms(human_log))
        if any(f in targets for f in forms):
            return True
    for parts in AGENT_HOME_ROOTS:
        root = os.path.join(os.path.expanduser(parts[0]), *parts[1:])
        if any(_under(f, base) for f in forms for base in _root_forms(root)):
            return True
    return False


def is_protected(path: str, ctx) -> bool:
    cfg = _cfg(ctx)
    globs = cfg.get("guards.protected_globs", {}) or {}
    for found in _rel_forms(path, _workspace(ctx)):
        if found != "." and match_globs(found, globs.get("workspace", [])):
            return True
    if not is_dev():
        for found in _rel_forms(path, _harness(ctx)):
            if found != "." and match_globs(found, globs.get("harness", [])):
                return True
    if _rel_forms(path, str(state_root())):
        return True
    return _outside_protected(path, ctx)


def is_exempt(path: str, ctx) -> bool:
    found = _rel_under(path, _workspace(ctx))
    if found is None:
        found = Path(path).as_posix()
    return match_globs(found, _cfg(ctx).get("tdd.exempt_globs", []))


def temp_roots() -> list:
    roots = [tempfile.gettempdir()] + list(SYSTEM_TEMP_ROOTS)
    env_tmp = os.environ.get("TMPDIR")
    if env_tmp:
        roots.append(env_tmp)
    seen: list = []
    for root in roots:
        for form in _root_forms(root):
            if form not in seen and form != "/":
                seen.append(form)
    return seen


def is_scratch(path: str, ctx) -> bool:
    forms = _forms(path)
    if any(f in DEV_FILES for f in forms):
        return True
    scratch_globs = _cfg(ctx).get("workspace.scratch_globs", [])
    for root in (_workspace(ctx), _harness(ctx)):
        found = _rel_under(path, root)
        if found is not None:
            return found != "." and match_globs(found, scratch_globs)
    return any(_under(f, root) for f in forms for root in temp_roots())

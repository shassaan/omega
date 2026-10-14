from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import config as config_mod
from . import io as io_mod
from . import paths

PROVIDERS = ("claude", "codex")
TOKEN_PATTERN = re.compile(r"^hs-[0-9a-f]{6}$")
_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]")
CONTEXT_FILE = "context.json"
OVERRIDE_TOKEN_FILE = "override_token"


class AmbiguousSession(RuntimeError):
    def __init__(self, candidates: list, message: Optional[str] = None):
        self.candidates = list(candidates)
        if message is None:
            if not self.candidates:
                message = "no session with a change ledger was found; pass --session"
            else:
                message = "more than one session could be meant; pass --session one of: " + \
                    ", ".join(self.candidates)
        super().__init__(message)


@dataclass
class SessionContext:
    provider: str
    workspace: str
    session_id: str
    transcript_path: Optional[str]
    run_id: Optional[str]
    dir: Path
    harness_root: Path
    cfg: "config_mod.Config"
    model: Optional[str] = None


def iso(ts_ns: Optional[int] = None) -> str:
    seconds = (ts_ns if ts_ns is not None else time.time_ns()) / 1e9
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def stamp() -> tuple:
    ts_ns = time.time_ns()
    return iso(ts_ns), ts_ns


def safe_id(value: Optional[str]) -> str:
    text = _SAFE_ID.sub("_", str(value or "")).strip()
    if not text or set(text) <= {"."}:
        return "no-session"
    return text[:200]


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def workspace_dir(workspace: str) -> Path:
    return paths.state_root() / paths.workspace_hash(workspace)


def session_path(workspace: str, provider: str, session_id: str) -> Path:
    return workspace_dir(workspace) / provider / safe_id(session_id)


def session_dir(ctx: SessionContext) -> Path:
    return _ensure_dir(Path(ctx.dir))


def read_json(path: Path, default=None):
    try:
        with open(str(path), "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def write_json_atomic(path: Path, obj) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(".%s.tmp-%d-%d" % (target.name, os.getpid(), time.time_ns()))
    data = json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=False)
    try:
        with open(str(tmp), "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(tmp), str(target))
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def append_jsonl(path: Path, row: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(str(target), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        written = 0
        while written < len(line):
            written += os.write(fd, line[written:])
    finally:
        os.close(fd)


def read_jsonl(path: Path) -> list:
    rows: list = []
    try:
        with open(str(path), "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict):
                    rows.append(row)
    except OSError:
        return []
    return rows


def _observe(provider: str, event_name: str) -> None:
    if not event_name:
        return
    target = paths.state_root() / "observed" / ("%s.json" % provider)
    try:
        seen = read_json(target, {}) or {}
        if not isinstance(seen, dict):
            seen = {}
        seen[event_name] = iso()
        write_json_atomic(target, seen)
    except OSError:
        pass


def _write_context(ctx: SessionContext) -> None:
    target = ctx.dir / CONTEXT_FILE
    existing = read_json(target, None)
    if isinstance(existing, dict):
        changed = False
        for key, value in (("transcript_path", ctx.transcript_path), ("model", ctx.model),
                           ("run_id", ctx.run_id)):
            if value and not existing.get(key):
                existing[key] = value
                changed = True
        if changed:
            write_json_atomic(target, existing)
        return
    write_json_atomic(target, {
        "provider": ctx.provider,
        "workspace": ctx.workspace,
        "session_id": ctx.session_id,
        "transcript_path": ctx.transcript_path,
        "run_id": ctx.run_id,
        "created_ts": iso(),
        "model": ctx.model,
    })


def configure(event) -> SessionContext:
    workspace = os.path.realpath(event.workspace)
    root = paths.harness_root()
    cfg = config_mod.load(root, workspace)
    directory = _ensure_dir(session_path(workspace, event.provider, event.session_id))
    ctx = SessionContext(
        provider=event.provider,
        workspace=workspace,
        session_id=event.session_id or "no-session",
        transcript_path=event.transcript_path,
        run_id=event.run_id,
        dir=directory,
        harness_root=root,
        cfg=cfg,
        model=event.model,
    )
    io_mod.bind_session_dir(directory)
    _observe(event.provider, event.name)
    _write_context(ctx)
    stored = read_json(directory / CONTEXT_FILE, {}) or {}
    if not ctx.transcript_path and stored.get("transcript_path"):
        ctx.transcript_path = stored.get("transcript_path")
    if not ctx.model and stored.get("model"):
        ctx.model = stored.get("model")
    return ctx


def _candidates(workspace: str, provider: Optional[str]) -> list:
    base = workspace_dir(workspace)
    found: list = []
    for prov in ([provider] if provider else list(PROVIDERS)):
        root = base / prov
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir()):
            if child.is_dir() and (child / "changed.jsonl").is_file():
                found.append((prov, child.name))
    return found


def latest_session(workspace: str, provider: Optional[str] = None) -> str:
    found = _candidates(os.path.realpath(workspace), provider)
    ids = sorted({sid for _, sid in found})
    if len(ids) != 1:
        raise AmbiguousSession(["%s/%s" % pair for pair in found])
    return ids[0]


def _providers_with(workspace: str, session_id: str) -> list:
    base = workspace_dir(workspace)
    return [prov for prov in PROVIDERS if (base / prov / safe_id(session_id)).is_dir()]


def load_context(session_id: Optional[str], workspace: Optional[str] = None,
                 provider: Optional[str] = None) -> SessionContext:
    ws = os.path.realpath(workspace) if workspace else paths.workspace_of({})
    sid = session_id or os.environ.get("OMEGA_SESSION_ID") or None
    if not sid:
        sid = latest_session(ws, provider)
    prov = provider
    if prov is None:
        present = _providers_with(ws, sid)
        if len(present) == 1:
            prov = present[0]
        elif len(present) > 1:
            env_provider = os.environ.get("OMEGA_PROVIDER")
            if env_provider in present:
                prov = env_provider
            else:
                raise AmbiguousSession(["%s/%s" % (p, sid) for p in present])
        else:
            env_provider = os.environ.get("OMEGA_PROVIDER")
            prov = env_provider if env_provider in PROVIDERS else "claude"
    directory = _ensure_dir(session_path(ws, prov, sid))
    stored = read_json(directory / CONTEXT_FILE, {}) or {}
    root = paths.harness_root()
    ctx = SessionContext(
        provider=prov,
        workspace=ws,
        session_id=sid,
        transcript_path=stored.get("transcript_path"),
        run_id=stored.get("run_id") or os.environ.get("OMEGA_RUN_ID") or None,
        dir=directory,
        harness_root=root,
        cfg=config_mod.load(root, ws),
        model=stored.get("model"),
    )
    io_mod.bind_session_dir(directory)
    return ctx


def _counter_path(ctx: SessionContext, name: str) -> Path:
    return session_dir(ctx) / safe_id(name)


def _parse_int(text: str) -> int:
    try:
        return max(0, int(text.strip() or "0"))
    except ValueError:
        return 0


def counter_get(ctx: SessionContext, name: str) -> int:
    try:
        return _parse_int(_counter_path(ctx, name).read_text(encoding="utf-8"))
    except OSError:
        return 0


def counter_incr(ctx: SessionContext, name: str) -> int:
    target = _counter_path(ctx, name)
    fd = os.open(str(target), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.lseek(fd, 0, os.SEEK_SET)
        current = _parse_int(os.read(fd, 64).decode("utf-8", errors="replace"))
        value = current + 1
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.write(fd, str(value).encode("ascii"))
        os.fsync(fd)
        return value
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def counter_reset(ctx: SessionContext, name: str) -> None:
    target = _counter_path(ctx, name)
    fd = os.open(str(target), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, b"0")
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def read_override_token(ctx: SessionContext) -> Optional[str]:
    try:
        token = (session_dir(ctx) / OVERRIDE_TOKEN_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token if TOKEN_PATTERN.match(token) else None


def ensure_override_token(ctx: SessionContext) -> str:
    existing = read_override_token(ctx)
    if existing:
        return existing
    target = session_dir(ctx) / OVERRIDE_TOKEN_FILE
    token = "hs-" + secrets.token_hex(3)
    try:
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
        existing = read_override_token(ctx)
        if existing:
            return existing
        fd = os.open(str(target), os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, token.encode("ascii"))
    finally:
        os.close(fd)
    return token

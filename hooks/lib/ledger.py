from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from . import hashing, state
from . import paths as paths_mod

CHANGED = "changed.jsonl"
RECONCILED = "reconciled.jsonl"
UNPARSED = "unparsed_mutation.txt"
CONTRACTS_TOUCHED = "contracts_touched.txt"
CHANGED_KINDS = ("added", "modified", "deleted", "renamed_from", "renamed_to", "unknown")
RECONCILED_KINDS = ("reconciled", "deleted")


def _row(ctx, path: str, kind: str, tool: Optional[str], tool_use_id: Optional[str]) -> dict:
    ts, ts_ns = state.stamp()
    absolute = os.path.abspath(os.path.expanduser(str(path)))
    return {
        "ts": ts,
        "ts_ns": ts_ns,
        "path": absolute,
        "rel": paths_mod.rel(absolute, ctx.workspace),
        "kind": kind,
        "tool": tool,
        "tool_use_id": tool_use_id,
        "provider": ctx.provider,
        "session_id": ctx.session_id,
        "sha256_after": hashing.sha256_file(absolute),
    }


def append(ctx, path: str, kind: str, tool: Optional[str], tool_use_id: Optional[str]) -> None:
    if kind not in CHANGED_KINDS:
        kind = "unknown"
    state.append_jsonl(state.session_dir(ctx) / CHANGED, _row(ctx, path, kind, tool, tool_use_id))


def append_reconciled(ctx, path: str, kind: str) -> None:
    if kind not in RECONCILED_KINDS:
        kind = "reconciled"
    state.append_jsonl(state.session_dir(ctx) / RECONCILED, _row(ctx, path, kind, None, None))


def rows(ctx) -> list:
    directory = state.session_dir(ctx)
    merged = state.read_jsonl(directory / CHANGED) + state.read_jsonl(directory / RECONCILED)
    valid = [r for r in merged if isinstance(r.get("path"), str) and r.get("path")]
    return sorted(valid, key=lambda r: int(r.get("ts_ns") or 0))


def paths(ctx) -> list:
    seen: list = []
    marks: set = set()
    for row in rows(ctx):
        path = row["path"]
        if path not in marks:
            marks.add(path)
            seen.append(path)
    return seen


def existing(ctx) -> list:
    return [p for p in paths(ctx) if os.path.isfile(p)]


def rel_paths(ctx) -> list:
    return [paths_rel(ctx, p) for p in paths(ctx)]


def paths_rel(ctx, path: str) -> str:
    return paths_mod.rel(path, ctx.workspace)


def source_paths(ctx, cfg=None) -> list:
    from . import testmap
    cfg = cfg if cfg is not None else ctx.cfg
    found: list = []
    for path in existing(ctx):
        relative = paths_rel(ctx, path)
        if relative.startswith("/"):
            continue
        if testmap.is_source(relative, cfg) and relative not in found:
            found.append(relative)
    return found


def note_unparsed(ctx, reason: str) -> None:
    line = " ".join(str(reason or "unparsed mutation").split())
    target = state.session_dir(ctx) / UNPARSED
    with open(str(target), "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def unparsed(ctx) -> list:
    target = state.session_dir(ctx) / UNPARSED
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []
    except OSError:
        return ["unparsed mutation marker is unreadable"]
    return [line for line in text.splitlines() if line.strip()]


def note_contract_touched(ctx, path: str) -> None:
    absolute = os.path.abspath(os.path.expanduser(str(path)))
    if absolute in contracts_touched(ctx):
        return
    target = state.session_dir(ctx) / CONTRACTS_TOUCHED
    with open(str(target), "a", encoding="utf-8") as handle:
        handle.write(absolute + "\n")


def contracts_touched(ctx) -> list:
    target = state.session_dir(ctx) / CONTRACTS_TOUCHED
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    found: list = []
    for line in text.splitlines():
        line = line.strip()
        if line and line not in found:
            found.append(line)
    return found


def touched_since(state_root: Path, workspace_hash: str, ts_ns: int) -> set:
    base = Path(state_root) / workspace_hash
    found: set = set()
    if not base.is_dir():
        return found
    for provider_dir in base.iterdir():
        if not provider_dir.is_dir():
            continue
        for session in provider_dir.iterdir():
            for name in (CHANGED, RECONCILED):
                for row in state.read_jsonl(session / name):
                    if int(row.get("ts_ns") or 0) >= int(ts_ns or 0) and row.get("path"):
                        found.add(str(row["path"]))
    return found

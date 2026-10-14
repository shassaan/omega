from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import hashing, ledger, paths, state

BASELINE = "baseline.json"
CLEAN = "<clean>"
MAX_ENTRIES = 50000
GIT_TIMEOUT_S = 30


@dataclass
class Reconciliation:
    found: list = field(default_factory=list)
    unreadable: list = field(default_factory=list)
    note: Optional[str] = None


def _git(root: str, args: list) -> Optional[str]:
    env = dict(os.environ)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        proc = subprocess.run(["git", "-C", root] + args, capture_output=True, timeout=GIT_TIMEOUT_S,
                              env=env, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", errors="surrogateescape")


def _ignored_parts(rel: str, ignored: list) -> bool:
    parts = rel.split("/")
    for entry in ignored:
        wanted = [p for p in str(entry).strip("/").split("/") if p]
        width = len(wanted)
        if not width:
            continue
        for start in range(0, len(parts) - width + 1):
            if parts[start:start + width] == wanted:
                return True
    return False


def dirty_state(root: str, ignored: Optional[list] = None) -> Optional[dict]:
    real_root = os.path.realpath(root)
    top = _git(real_root, ["rev-parse", "--show-toplevel"])
    if top is None or os.path.realpath(top.strip()) != real_root:
        return None
    out = _git(real_root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if out is None:
        return None
    skip = list(ignored or []) + [".omega"]
    entries = out.split("\0")
    found: dict = {}
    index = 0
    while index < len(entries) and len(found) < MAX_ENTRIES:
        entry = entries[index]
        index += 1
        if len(entry) < 4:
            continue
        code, rel = entry[:2], entry[3:]
        names = [rel]
        if code[0] in "RC" and index < len(entries):
            names.append(entries[index])
            index += 1
        for name in names:
            posix = Path(name).as_posix().rstrip("/")
            if _ignored_parts(posix, skip):
                continue
            absolute = os.path.join(real_root, posix)
            found[absolute] = hashing.sha256_file(absolute)
    return found


def snapshot(roots: list, ignored: Optional[list] = None) -> dict:
    return {os.path.realpath(str(root)): dirty_state(str(root), ignored) for root in roots}


def deltas(before: dict, after: dict) -> list:
    changed: set = set()
    for root, now in (after or {}).items():
        then = (before or {}).get(root)
        if now is None or then is None:
            continue
        for path in set(then) | set(now):
            if then.get(path, CLEAN) != now.get(path, CLEAN):
                changed.add(path)
    return sorted(changed)


def _roots(ctx) -> list:
    return [ctx.workspace]


def _ignored(ctx) -> list:
    return list(ctx.cfg.get("workspace.ignored_dirs", []) or [])


def ensure_baseline(ctx) -> None:
    target = state.session_dir(ctx) / BASELINE
    if target.exists():
        return
    ts, ts_ns = state.stamp()
    state.write_json_atomic(target, {"ts": ts, "ts_ns": ts_ns,
                                     "state": snapshot(_roots(ctx), _ignored(ctx))})


def reconcile(ctx) -> Reconciliation:
    target = state.session_dir(ctx) / BASELINE
    if not target.exists():
        ensure_baseline(ctx)
        return Reconciliation([], [], "no session-start baseline was recorded, so writes made outside "
                                      "the edit hooks before now cannot be detected")
    baseline = state.read_json(target, None)
    if not isinstance(baseline, dict) or not isinstance(baseline.get("state"), dict):
        return Reconciliation([], [], "the session-start baseline is unreadable")
    before = baseline["state"]
    current = snapshot(list(before.keys()), _ignored(ctx))
    unreadable = sorted(root for root, now in current.items() if now is None or before.get(root) is None)
    recorded = {os.path.realpath(p) for p in ledger.paths(ctx)}
    since = int(baseline.get("ts_ns") or 0)
    explained = {os.path.realpath(p) for p in
                 ledger.touched_since(paths.state_root(), paths.workspace_hash(ctx.workspace), since)}
    found = [p for p in deltas(before, current) if p not in recorded and p not in explained]
    for path in found:
        ledger.append_reconciled(ctx, path, "reconciled" if os.path.exists(path) else "deleted")
    note = None
    if unreadable:
        note = "not a git checkout (cannot reconcile): " + ", ".join(unreadable)
    return Reconciliation(found, unreadable, note)

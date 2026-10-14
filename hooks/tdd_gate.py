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
import time
from dataclasses import asdict, dataclass, field
from types import SimpleNamespace
from typing import Optional

from hooks.lib import adapters, hashing, jobstore, ledger, paths, state, testmap
from hooks.lib import config as config_mod
from hooks.lib.io import Decision

SCRIPT = "hooks/tdd_gate.py"
PASS, FAIL, UNVERIFIED, NOT_APPLICABLE = "PASS", "FAIL", "UNVERIFIED", "NOT_APPLICABLE"
EDIT_KINDS = ("added", "modified")
FREE_KINDS = ("deleted", "renamed_from", "renamed_to")
RED = "red.jsonl"
GREEN = "green.jsonl"


@dataclass
class GateResult:
    gate: str
    status: str
    required: bool
    detail: str
    items: list = field(default_factory=list)
    duration_ms: int = 0
    data: dict = field(default_factory=dict)


def as_dict(result: GateResult) -> dict:
    return asdict(result)


def mode_of(cfg) -> str:
    mode = str(cfg.get("tdd.mode", "strict") or "strict").strip().lower()
    return mode if mode in ("strict", "red-or-green", "off") else "strict"


def _required(cfg, gate: str) -> bool:
    return bool(cfg.get("stop.gates.%s.required" % gate, True))


def _command(ctx) -> str:
    return adapters.harness_command(SCRIPT, getattr(ctx, "harness_root", None))


def _under_workspace(path: str, ctx) -> Optional[str]:
    relative = paths.rel(path, ctx.workspace)
    if relative.startswith("/") or relative in (".", ""):
        return None
    return relative


def _rows(ctx, name: str) -> list:
    return state.read_jsonl(state.session_dir(ctx) / name)


def red_for(ctx, test_rel: str, test_sha: str) -> Optional[dict]:
    found = None
    for row in _rows(ctx, RED):
        files = row.get("test_files") or {}
        if isinstance(files, dict) and files.get(test_rel) == test_sha and row.get("status", "fail") == "fail":
            if found is None or int(row.get("ts_ns") or 0) >= int(found.get("ts_ns") or 0):
                found = row
    return found


def green_after(ctx, test_rel: str, test_sha: str, red_ts_ns: int) -> Optional[dict]:
    found = None
    for row in _rows(ctx, GREEN):
        files = row.get("test_files") or {}
        if not isinstance(files, dict) or files.get(test_rel) != test_sha:
            continue
        if int(row.get("ts_ns") or 0) <= int(red_ts_ns or 0):
            continue
        if found is None or int(row.get("ts_ns") or 0) >= int(found.get("ts_ns") or 0):
            found = row
    return found


def green_for(ctx, test_rel: str, test_sha: str) -> Optional[dict]:
    return green_after(ctx, test_rel, test_sha, 0)


def _sha(ctx, test_rel: str) -> str:
    return hashing.sha256_file(os.path.join(ctx.workspace, test_rel))


def _existing(ctx, mapped) -> list:
    return [c for c in mapped.candidates if os.path.isfile(os.path.join(ctx.workspace, c))]


def _last_line(text: str) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1][:160] if lines else ""


def job_state(ctx, test_rel: str, test_sha: str) -> str:
    view = jobstore.newest(ctx, testmap.scope_key(test_rel))
    if view is None:
        return "none (run: %s run --session %s --test %s)" % (_command(ctx), ctx.session_id, test_rel)
    if not view.get("done"):
        return "running (wait a moment, then retry)"
    result = view.get("result") or {}
    status = result.get("status") or view.get("state") or "error"
    launched = (view.get("test_files") or {}).get(test_rel)
    if launched and launched != test_sha and status in ("pass", "fail"):
        return ("stale (the newest job ran an earlier version of the test; it re-runs after your next test edit, "
                "or run: %s run --session %s --test %s)" % (_command(ctx), ctx.session_id, test_rel))
    if status == "pass":
        return "pass (the test passed without the change — make it fail first)"
    if status == "skipped_env":
        return "skipped_env (%s)" % (_last_line(result.get("output", "")) or "environment problem")
    if status == "not_installed":
        argv = view.get("argv") or ["?"]
        return "not_installed (%s)" % argv[0]
    if status == "skipped_no_tests":
        return "skipped_no_tests (the test file collected no tests)"
    if status == "fail":
        return "fail"
    return "%s (%s)" % (status, _last_line(result.get("output", "")) or "no output")


def _deny(rule: str, text: str) -> Decision:
    return Decision("deny", reason="%s [%s]" % (text, rule))


def _newest_completed(ctx, test_rel: str) -> Optional[dict]:
    view = jobstore.newest(ctx, testmap.scope_key(test_rel))
    if view is None:
        return None
    if view.get("done"):
        return view
    done = [v for v in jobstore.results(ctx) if v.get("scope_key") == testmap.scope_key(test_rel)]
    return done[-1] if done else None


def _red_or_green_ok(ctx, test_rel: str, test_sha: str) -> bool:
    if red_for(ctx, test_rel, test_sha):
        return True
    view = _newest_completed(ctx, test_rel)
    if view is None:
        return False
    result = view.get("result") or {}
    launched = (view.get("test_files") or {}).get(test_rel)
    return result.get("status") in ("fail", "pass") and launched == test_sha


def judge(mutations: list, ctx, cfg) -> Decision:
    mode = mode_of(cfg)
    if mode == "off":
        return Decision("allow")
    contracts_cache: list = []
    for mutation in mutations or []:
        kind = getattr(mutation, "kind", "unknown")
        path = getattr(mutation, "path", "")
        if kind in FREE_KINDS:
            continue
        relative = _under_workspace(path, ctx)
        if kind not in EDIT_KINDS:
            if relative is None:
                continue
            return _deny("tdd.unknown_mutation", "[tdd-gate] refused: the harness cannot tell how %s changes "
                         "(mutation kind %r), so it cannot check the TDD rule." % (relative, kind))
        if relative is None:
            continue
        if paths.is_exempt(path, ctx) or testmap.is_test(relative, cfg) or not testmap.is_source(relative, cfg):
            continue
        if not contracts_cache:
            from hooks.lib import contracts as contracts_mod
            try:
                contracts_cache.append(contracts_mod.load_all(ctx.workspace, cfg))
            except OSError:
                contracts_cache.append([])
        mapped = testmap.map_test(relative, ctx, cfg, contracts_cache[0])
        existing = _existing(ctx, mapped)
        if not existing:
            expected = ", ".join(mapped.candidates) or "(no mapping matches; add tdd.overrides or a contract)"
            return _deny("tdd.no_test_file", "[tdd-gate] refused: %s has no test file yet. Expected one of: %s. "
                         "Write the failing test first (the Edit/Write tool on the test file is always allowed), "
                         "let the background runner observe it red, then edit the source." % (relative, expected))
        if any(red_for(ctx, test, _sha(ctx, test)) for test in existing):
            continue
        if mode == "red-or-green" and any(_red_or_green_ok(ctx, test, _sha(ctx, test)) for test in existing):
            continue
        test = existing[0]
        sha = _sha(ctx, test)
        return _deny("tdd.not_red", "[tdd-gate] refused: %s may change only after %s has been observed failing "
                     "(red) at its current content (%s@%s). Newest test job: %s. Make the test fail for the "
                     "missing behaviour first; the background runner records the red." %
                     (relative, test, test, sha[:7], job_state(ctx, test, sha)))
    return Decision("allow")


def _stamp_of(row: Optional[dict]) -> Optional[dict]:
    if not row:
        return None
    return {"ts": row.get("ts"), "ts_ns": row.get("ts_ns"), "job_id": row.get("job_id"), "rc": row.get("rc")}


def _pair(ctx, cfg, source: str, mode: str, contracts: list) -> dict:
    mapped = testmap.map_test(source, ctx, cfg, contracts)
    existing = _existing(ctx, mapped)
    entry = {"source": source, "test": existing[0] if existing else (mapped.candidates[0] if mapped.candidates else None),
             "candidates": list(mapped.candidates), "test_sha256": None, "red": None, "green": None,
             "status": FAIL, "detail": ""}
    if not existing:
        entry["status"] = FAIL if mode == "strict" else UNVERIFIED
        entry["detail"] = "no test file (expected one of: %s)" % (", ".join(mapped.candidates) or "no mapping")
        return entry
    best = None
    for test in existing:
        sha = _sha(ctx, test)
        red = red_for(ctx, test, sha)
        green = green_after(ctx, test, sha, int(red.get("ts_ns") or 0)) if red else None
        view = jobstore.newest(ctx, testmap.scope_key(test))
        running = view is not None and not view.get("done")
        candidate = {"test": test, "sha": sha, "red": red, "green": green, "running": running,
                     "green_any": green_for(ctx, test, sha)}
        rank = (2 if red and green else 1 if red else 0, 1 if not running else 0)
        if best is None or rank > best[0]:
            best = (rank, candidate)
    chosen = best[1]
    entry["test"] = chosen["test"]
    entry["test_sha256"] = chosen["sha"]
    entry["red"] = _stamp_of(chosen["red"])
    entry["green"] = _stamp_of(chosen["green"] or (chosen["green_any"] if mode == "red-or-green" else None))
    if chosen["running"]:
        entry["status"] = UNVERIFIED
        entry["detail"] = "red observed, green job still running" if chosen["red"] else "test job still running"
    elif mode == "red-or-green" and chosen["green_any"]:
        entry["status"] = PASS
        entry["detail"] = "green for the current test" + ("" if chosen["red"] else " (red-or-green: no red required)")
    elif not chosen["red"]:
        entry["status"] = FAIL
        entry["detail"] = "no red observed for the current test"
    elif not chosen["green"]:
        entry["status"] = FAIL
        entry["detail"] = "red observed, no green since"
    else:
        entry["status"] = PASS
        entry["detail"] = "red then green observed for the current test"
    return entry


def _line(entry: dict) -> str:
    sha = (entry.get("test_sha256") or "")[:7]
    test = entry.get("test") or "?"
    return "%s ← %s%s: %s" % (entry["source"], test, ("@" + sha) if sha else "", entry.get("detail", ""))


def _contracts(ctx, cfg) -> list:
    from hooks.lib import contracts as contracts_mod
    try:
        return contracts_mod.load_all(ctx.workspace, cfg)
    except OSError:
        return []


def green_check(ctx, cfg) -> GateResult:
    started = time.monotonic()
    required = _required(cfg, "tdd")
    mode = mode_of(cfg)
    sources = ledger.source_paths(ctx, cfg)
    if mode == "off":
        return GateResult("tdd", NOT_APPLICABLE, required, "tdd.mode is off", [], _ms(started), {"mode": mode})
    if not sources:
        return GateResult("tdd", NOT_APPLICABLE, required, "no source files changed in this session", [],
                          _ms(started), {"mode": mode})
    contracts = _contracts(ctx, cfg)
    items = [_pair(ctx, cfg, source, mode, contracts) for source in sources]
    statuses = [item["status"] for item in items]
    if FAIL in statuses:
        status = FAIL
    elif UNVERIFIED in statuses:
        status = UNVERIFIED
    else:
        status = PASS
    worst = [item for item in items if item["status"] == status]
    if status == PASS:
        detail = "%d source file(s) red then green" % len(items)
    else:
        detail = _line(worst[0]) + ("" if len(worst) == 1 else " (+%d more)" % (len(worst) - 1))
    return GateResult("tdd", status, required, detail, items, _ms(started), {"mode": mode})


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def status(ctx, cfg) -> dict:
    mode = mode_of(cfg)
    contracts = _contracts(ctx, cfg)
    entries: list = []
    for source in ledger.source_paths(ctx, cfg):
        entry = _pair(ctx, cfg, source, mode, contracts)
        test = entry.get("test")
        view = jobstore.newest(ctx, testmap.scope_key(test)) if test else None
        entry["job"] = None if view is None else {"id": view.get("id"), "state": view.get("state"),
                                                  "done": view.get("done"), "ts": view.get("ts")}
        entries.append(entry)
    overall = NOT_APPLICABLE
    if entries:
        statuses = [e["status"] for e in entries]
        overall = FAIL if FAIL in statuses else UNVERIFIED if UNVERIFIED in statuses else PASS
    return {"session_id": ctx.session_id, "workspace": ctx.workspace, "mode": mode, "status": overall,
            "sources": entries, "reds": len(_rows(ctx, RED)), "greens": len(_rows(ctx, GREEN))}


def launch_test(ctx, cfg, test_rel: str, source_files: Optional[list] = None) -> Optional[dict]:
    argv = testmap.runner_for(test_rel, ctx, cfg)
    if not argv:
        return None
    runner = "pytest" if testmap.lang_of(test_rel) == "python" else (testmap.js_runner(ctx.workspace) or "tests")
    return jobstore.launch(ctx, testmap.scope_key(test_rel), "test", "%s %s" % (runner, test_rel), argv,
                           ctx.workspace, [test_rel], list(source_files or []),
                           int(cfg.get("tdd.job_timeout_s", 240) or 240))


def run(ctx, cfg, test_rel: str) -> dict:
    relative = paths.rel(test_rel, ctx.workspace) if os.path.isabs(test_rel) else test_rel
    if not os.path.isfile(os.path.join(ctx.workspace, relative)):
        return {"state": "error", "detail": "test file %s does not exist" % relative, "test": relative}
    spec = launch_test(ctx, cfg, relative)
    if spec is None:
        return {"state": "error", "detail": "no test runner can be chosen for %s" % relative, "test": relative}
    timeout = float(cfg.get("tdd.job_timeout_s", 240) or 240) + float(cfg.get("tdd.debounce_s", 0.8) or 0) + 15.0
    deadline = time.monotonic() + timeout
    view = None
    while time.monotonic() < deadline:
        view = jobstore.newest(ctx, testmap.scope_key(relative))
        if view and view.get("id") == spec["id"] and view.get("done"):
            break
        if view and view.get("id") != spec["id"]:
            break
        time.sleep(0.1)
    view = view or {}
    result = view.get("result") or {}
    sha = (spec.get("test_files") or {}).get(relative)
    return {"state": result.get("status") or view.get("state") or "pending", "test": relative, "job_id": spec["id"],
            "rc": result.get("rc"), "test_sha256": sha, "duration_ms": result.get("duration_ms"),
            "output": result.get("output", ""), "red": bool(sha and red_for(ctx, relative, sha))}


def _context(args):
    return state.load_context(args.session, args.workspace, args.provider)


def _map_context(args) -> SimpleNamespace:
    workspace = os.path.realpath(args.workspace or paths.workspace_of({}))
    root = paths.harness_root()
    return SimpleNamespace(workspace=workspace, harness_root=root, cfg=config_mod.load(root, workspace),
                           session_id=args.session or "none")


def _print_status(report: dict) -> None:
    sys.stdout.write("[tdd-gate] mode %s · session %s · %s\n" % (report["mode"], report["session_id"], report["status"]))
    for entry in report["sources"]:
        sys.stdout.write("  %-10s %s\n" % (entry["status"], _line(entry)))
    if not report["sources"]:
        sys.stdout.write("  no source files changed in this session\n")


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="tdd_gate.py", description="Observed-red TDD gate.")
    parser.add_argument("--session")
    parser.add_argument("--workspace")
    parser.add_argument("--provider", choices=("claude", "codex"))
    sub = parser.add_subparsers(dest="cmd")
    p_status = sub.add_parser("status")
    p_status.add_argument("--json", action="store_true")
    p_status.add_argument("--session", dest="sub_session")
    p_status.add_argument("--workspace", dest="sub_workspace")
    p_run = sub.add_parser("run")
    p_run.add_argument("--test", required=True)
    p_run.add_argument("--json", action="store_true")
    p_run.add_argument("--session", dest="sub_session")
    p_run.add_argument("--workspace", dest="sub_workspace")
    p_map = sub.add_parser("map")
    p_map.add_argument("rel")
    p_map.add_argument("--json", action="store_true")
    p_map.add_argument("--session", dest="sub_session")
    p_map.add_argument("--workspace", dest="sub_workspace")
    args = parser.parse_args(argv[1:])
    args.session = getattr(args, "sub_session", None) or args.session
    args.workspace = getattr(args, "sub_workspace", None) or args.workspace
    command = args.cmd or "status"
    try:
        if command == "map":
            ctx = _map_context(args)
            relative = paths.rel(args.rel, ctx.workspace) if os.path.isabs(args.rel) else args.rel
            mapped = testmap.map_test(relative, ctx, ctx.cfg)
            payload = {"source": relative, "candidates": mapped.candidates, "existing": mapped.existing,
                       "lang": mapped.lang, "from_contract": mapped.from_contract,
                       "is_source": testmap.is_source(relative, ctx.cfg), "is_test": testmap.is_test(relative, ctx.cfg)}
            if getattr(args, "json", False):
                sys.stdout.write(json.dumps(payload) + "\n")
            else:
                for candidate in mapped.candidates:
                    marker = "*" if candidate == mapped.existing else " "
                    sys.stdout.write("%s %s\n" % (marker, candidate))
            return 0
        ctx = _context(args)
        cfg = ctx.cfg
        if command == "run":
            result = run(ctx, cfg, args.test)
            if args.json:
                sys.stdout.write(json.dumps(result) + "\n")
            else:
                sys.stdout.write("[tdd-gate] %s %s (job %s)\n" % (result.get("state"), result.get("test"), result.get("job_id")))
                if result.get("output"):
                    sys.stdout.write(result["output"].rstrip() + "\n")
            state_name = result.get("state")
            return 0 if state_name == "pass" else 1 if state_name == "fail" else 2
        report = status(ctx, cfg)
        if getattr(args, "json", False):
            sys.stdout.write(json.dumps(report) + "\n")
        else:
            _print_status(report)
        return 0
    except state.AmbiguousSession as exc:
        sys.stderr.write("[tdd-gate] %s\n" % exc)
        return 2
    except Exception as exc:
        sys.stderr.write("[tdd-gate] error: %s: %s\n" % (exc.__class__.__name__, exc))
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

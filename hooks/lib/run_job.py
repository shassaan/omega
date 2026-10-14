from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import os
import subprocess
import time

from hooks.lib import config as config_mod
from hooks.lib import jobstore, redaction, state

DEFAULT_TIMEOUT_S = 240


def _superseded(job_path: Path, spec: dict) -> bool:
    for other in job_path.parent.glob("*.job.json"):
        if other == job_path:
            continue
        candidate = state.read_json(other, None)
        if not isinstance(candidate, dict):
            continue
        if candidate.get("scope_key") == spec.get("scope_key") and \
                int(candidate.get("ts_ns") or 0) > int(spec.get("ts_ns") or 0):
            return True
    return False


def _decode(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def execute(spec: dict, cfg) -> tuple:
    argv = [str(a) for a in spec.get("argv") or []]
    cwd = str(spec.get("cwd") or "")
    timeout_s = int(spec.get("timeout_s") or DEFAULT_TIMEOUT_S)
    if not argv:
        return 1, "error", "job has no argv"
    if not cwd or not Path(cwd).is_dir():
        return 1, "error", "working directory does not exist: %s" % cwd
    env = dict(os.environ)
    env.update({str(k): str(v) for k, v in (spec.get("env_add") or {}).items()})
    try:
        proc = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout_s)
        rc = proc.returncode
        output = _decode(proc.stdout)
    except FileNotFoundError:
        return 127, "not_installed", "%s not installed" % argv[0]
    except subprocess.TimeoutExpired as exc:
        return 124, "timeout", "timed out after %ss\n%s" % (timeout_s, _decode(exc.output))
    except OSError as exc:
        return 1, "error", "failed to run: %s" % exc
    return rc, jobstore.classify(rc, output, argv, cfg, cwd), output


def _ledger_row(spec: dict, result: dict, output: str) -> dict:
    ts, ts_ns = state.stamp()
    return {
        "ts": ts,
        "ts_ns": ts_ns,
        "job_id": spec["id"],
        "scope_key": spec.get("scope_key"),
        "test_files": spec.get("test_files", {}),
        "source_files": spec.get("source_files", []),
        "argv": spec.get("argv", []),
        "cwd": spec.get("cwd"),
        "rc": result["rc"],
        "status": result["status"],
        "output_tail": jobstore.tail(output, lines=jobstore.TAIL_LINES),
    }


def run(job_path: Path) -> int:
    spec = state.read_json(job_path, None)
    if not isinstance(spec, dict) or not spec.get("id"):
        return 0
    directory = job_path.parent
    cfg = config_mod.load(workspace=spec.get("workspace") or spec.get("cwd"))
    try:
        debounce = float(spec.get("debounce_s", cfg.get("tdd.debounce_s", 0.8)))
    except (TypeError, ValueError):
        debounce = 0.8
    time.sleep(max(0.0, debounce))
    if _superseded(job_path, spec):
        jobstore.write_result(directory, jobstore._synthetic(
            spec, None, "cancelled", "cancelled: superseded by a newer job", "superseded by a newer job"))
        return 0
    if (directory / ("%s.result.json" % spec["id"])).exists():
        return 0
    started = time.time_ns()
    try:
        rc, status, output = execute(spec, cfg)
    except Exception as exc:
        rc, status, output = 1, "error", "runner crashed: %s: %s" % (exc.__class__.__name__, exc)
    finished = time.time_ns()
    result = {
        "id": spec["id"],
        "rc": rc,
        "status": status,
        "output": jobstore.tail(output),
        "started_ns": started,
        "finished_ns": finished,
        "duration_ms": int((finished - started) / 1e6),
        "test_files": spec.get("test_files", {}),
        "cancelled_by": None,
    }
    final = directory / ("%s.result.json" % spec["id"])
    if final.exists():
        return 0
    if spec.get("kind") == "test" and status in ("fail", "pass"):
        session_dir = Path(spec.get("session_dir") or directory.parent)
        target = session_dir / ("red.jsonl" if status == "fail" else "green.jsonl")
        state.append_jsonl(target, _ledger_row(spec, result, output))
    jobstore.write_result(directory, result)
    return 0


def main(argv: list) -> int:
    if len(argv) < 2:
        return 0
    try:
        return run(Path(argv[1]))
    except Exception as exc:
        try:
            spec = state.read_json(Path(argv[1]), None) or {}
            if spec.get("id"):
                jobstore.write_result(Path(argv[1]).parent, jobstore._synthetic(
                    spec, 1, "error", redaction.redact("runner failed: %s: %s" % (exc.__class__.__name__, exc))[0]))
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

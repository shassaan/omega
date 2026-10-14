from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import config as config_mod
from . import hashing, redaction, state

STATUSES = ("pass", "fail", "skipped_env", "skipped_no_tests", "not_installed", "timeout",
            "cancelled", "error")
SKIPPED = ("skipped_env", "skipped_no_tests", "not_installed")
FAILURES = ("fail", "timeout", "error")
RESULT_LINES = 200
RESULT_CHARS = 16384
TAIL_LINES = 40
ENV_ADD = {"PYTHONDONTWRITEBYTECODE": "1", "CI": "1"}
RUN_JOB = Path(__file__).resolve().parent / "run_job.py"
NO_TESTS = ("no tests ran", "no tests collected", "collected 0 items", "No test files found",
            "No tests found")
ENV_SIGNATURES = ("ECONNREFUSED", "Temporary failure in name resolution", "Max retries exceeded",
                  "Could not find a version that satisfies")
ENV_SIGNATURES_CI = ("connection refused", "could not connect to server")
_MODULE = re.compile(r"No module named ['\"]?([A-Za-z0-9_.]+)['\"]?")
_SAFE = re.compile(r"[^A-Za-z0-9_-]")
_LAUNCHED: list = []


@dataclass
class Harvest:
    failures: list = field(default_factory=list)
    passes: list = field(default_factory=list)
    skipped: list = field(default_factory=list)


def jobs_dir(ctx) -> Path:
    directory = state.session_dir(ctx) / "jobs"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def job_id_for(scope_key: str, ts_ns: int) -> str:
    return _SAFE.sub("_", scope_key) + "-" + str(ts_ns)


def tail(text: str, lines: int = RESULT_LINES, chars: int = RESULT_CHARS) -> str:
    kept = "\n".join((text or "").splitlines()[-lines:])
    if len(kept) > chars:
        kept = kept[-chars:]
    return redaction.redact(kept)[0]


def is_no_tests(output: str) -> bool:
    text = output or ""
    return any(marker in text for marker in NO_TESTS)


def is_environment_failure(output: str, cfg=None, cwd: Optional[str] = None) -> bool:
    text = output or ""
    cfg = cfg if cfg is not None else config_mod.load()
    third_party = set(cfg.get("proof.third_party_modules", []) or [])
    for match in _MODULE.finditer(text):
        top = match.group(1).split(".")[0]
        if top in third_party:
            return True
    if "Cannot find module" in text and cwd and not os.path.isdir(os.path.join(cwd, "node_modules")):
        return True
    if any(signature in text for signature in ENV_SIGNATURES):
        return True
    lowered = text.lower()
    return any(signature in lowered for signature in ENV_SIGNATURES_CI)


def _is_pytest(argv: list) -> bool:
    return any("pytest" in os.path.basename(str(token)) for token in argv or [])


def classify(rc: Optional[int], output: str, argv: list, cfg=None, cwd: Optional[str] = None) -> str:
    text = output or ""
    if rc is None:
        return "error"
    if rc == 0:
        return "pass"
    if rc == 127:
        return "not_installed"
    if rc == 124:
        return "timeout"
    if is_no_tests(text) or (rc == 5 and _is_pytest(argv)):
        return "skipped_no_tests"
    if is_environment_failure(text, cfg, cwd):
        return "skipped_env"
    if rc == 4 and ("error: unrecognized arguments" in text or text.lstrip().startswith("usage:")):
        return "error"
    return "fail"


def _read(path: Path) -> Optional[dict]:
    data = state.read_json(path, None)
    return data if isinstance(data, dict) else None


def _view(directory: Path, spec: dict) -> dict:
    job_id = spec.get("id", "")
    result = _read(directory / ("%s.result.json" % job_id))
    view = dict(spec)
    view["done"] = result is not None
    view["result"] = result
    view["delivered"] = (directory / ("%s.delivered" % job_id)).exists()
    view["state"] = result.get("status", "error") if result else "pending"
    return view


def _load(ctx) -> list:
    directory = jobs_dir(ctx)
    views: list = []
    for path in directory.glob("*.job.json"):
        spec = _read(path)
        if not spec or not spec.get("id"):
            continue
        views.append(_view(directory, spec))
    return sorted(views, key=lambda v: int(v.get("ts_ns") or 0))


def _by_scope(views: list) -> dict:
    grouped: dict = {}
    for view in views:
        grouped.setdefault(view.get("scope_key", ""), []).append(view)
    return grouped


def write_result(directory: Path, result: dict) -> bool:
    final = directory / ("%s.result.json" % result["id"])
    if final.exists():
        return False
    tmp = directory / (".%s.result.tmp-%d-%d" % (result["id"], os.getpid(), time.time_ns()))
    try:
        with open(str(tmp), "w", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(str(tmp), str(final))
        except FileExistsError:
            return False
        return True
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def _synthetic(spec: dict, rc: Optional[int], status: str, output: str, cancelled_by=None) -> dict:
    now = time.time_ns()
    return {
        "id": spec["id"],
        "rc": rc,
        "status": status,
        "output": tail(output),
        "started_ns": now,
        "finished_ns": now,
        "duration_ms": 0,
        "test_files": spec.get("test_files", {}),
        "cancelled_by": cancelled_by,
    }


def _alive_group(pid: int) -> bool:
    try:
        return os.getpgid(pid) == pid
    except OSError:
        return False


def cancel(ctx, job_id: str, reason: str = "superseded by a newer job") -> None:
    directory = jobs_dir(ctx)
    spec = _read(directory / ("%s.job.json" % job_id)) or {"id": job_id}
    if not (directory / ("%s.result.json" % job_id)).exists():
        try:
            pid = int((directory / ("%s.pid" % job_id)).read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            pid = 0
        if pid > 0 and _alive_group(pid):
            try:
                os.killpg(pid, signal.SIGTERM)
            except OSError:
                pass
        write_result(directory, _synthetic(spec, None, "cancelled", "cancelled: %s" % reason, reason))


def _reap() -> None:
    for proc in list(_LAUNCHED):
        if proc.poll() is not None:
            _LAUNCHED.remove(proc)


def launch(ctx, scope_key: str, kind: str, label: str, argv: list, cwd: str, test_files: list,
           source_files: list, timeout_s: int) -> dict:
    _reap()
    directory = jobs_dir(ctx)
    for view in _load(ctx):
        if view.get("scope_key") == scope_key and not view["done"]:
            cancel(ctx, view["id"])
    ts, ts_ns = state.stamp()
    hashes: dict = {}
    for rel in test_files or []:
        absolute = rel if os.path.isabs(rel) else os.path.join(ctx.workspace, rel)
        hashes[rel] = hashing.sha256_file(absolute)
    spec = {
        "id": job_id_for(scope_key, ts_ns),
        "scope_key": scope_key,
        "kind": kind,
        "label": label,
        "argv": [str(a) for a in argv],
        "cwd": cwd,
        "env_add": dict(ENV_ADD),
        "ts": ts,
        "ts_ns": ts_ns,
        "session_id": ctx.session_id,
        "timeout_s": int(timeout_s),
        "test_files": hashes,
        "source_files": list(source_files or []),
        "session_dir": str(state.session_dir(ctx)),
        "workspace": ctx.workspace,
        "debounce_s": float(ctx.cfg.get("tdd.debounce_s", 0.8)),
    }
    job_path = directory / ("%s.job.json" % spec["id"])
    state.write_json_atomic(job_path, spec)
    env = dict(os.environ)
    env.update(ENV_ADD)
    try:
        proc = subprocess.Popen(
            [sys.executable, "-I", "-B", str(RUN_JOB), str(job_path)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True, env=env, cwd=str(directory),
        )
        _LAUNCHED.append(proc)
        (directory / ("%s.pid" % spec["id"])).write_text(str(proc.pid), encoding="utf-8")
    except OSError as exc:
        write_result(directory, _synthetic(spec, 1, "error",
                                           "could not launch background job: %s" % exc.__class__.__name__))
    return spec


def newest(ctx, scope_key: str) -> Optional[dict]:
    group = [v for v in _load(ctx) if v.get("scope_key") == scope_key]
    return group[-1] if group else None


def results(ctx) -> list:
    return [v for v in _load(ctx) if v["done"]]


def running(ctx) -> list:
    return [v for v in _load(ctx) if not v["done"]]


def harvest(ctx) -> Harvest:
    directory = jobs_dir(ctx)
    out = Harvest()
    for scope, group in _by_scope(_load(ctx)).items():
        latest = group[-1]
        if not latest["done"] or latest["delivered"] or latest["state"] == "cancelled":
            continue
        if latest["state"] == "pass":
            out.passes.append(latest)
        elif latest["state"] in SKIPPED:
            out.skipped.append(latest)
        else:
            out.failures.append(latest)
        for view in group:
            if view["done"]:
                try:
                    (directory / ("%s.delivered" % view["id"])).touch()
                except OSError:
                    pass
    return out


def settle(ctx, timeout_s: float) -> list:
    deadline = time.monotonic() + max(0.0, float(timeout_s))
    while True:
        grouped = _by_scope(_load(ctx))
        pending = [g[-1] for g in grouped.values() if not g[-1]["done"]]
        if not pending or time.monotonic() >= deadline:
            break
        time.sleep(0.2)
    outcomes: list = []
    for scope, group in _by_scope(_load(ctx)).items():
        for older in group[:-1]:
            if not older["done"]:
                cancel(ctx, older["id"])
        outcomes.append(group[-1])
    return sorted(outcomes, key=lambda v: int(v.get("ts_ns") or 0))

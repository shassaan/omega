from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import dataclasses
import glob
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

from hooks.lib import jobstore, ledger, paths, redaction, state, testmap

PASS, FAIL, UNVERIFIED, NOT_APPLICABLE = "PASS", "FAIL", "UNVERIFIED", "NOT_APPLICABLE"
STATUSES = (PASS, FAIL, UNVERIFIED, NOT_APPLICABLE)
TAIL_LINES = 40
TAIL_CHARS = 4096
DEFAULT_TIMEOUT_S = 200
CHILD_ENV_DROP = ("OMEGA_SECRET", "OMEGA_UI_TOKEN", "OMEGA_GIT_TOKEN")
CHILD_ENV_ADD = {"PYTHONDONTWRITEBYTECODE": "1", "CI": "1"}
PY_EXTS = (".py",)
JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
JOB_STATUS_MAP = {"pass": PASS, "fail": FAIL, "timeout": FAIL, "error": FAIL,
                  "skipped_env": UNVERIFIED, "skipped_no_tests": UNVERIFIED, "not_installed": UNVERIFIED}
TOOL_NAMES = ("pytest", "vitest", "jest", "ruff", "eslint", "tsc", "gitleaks")


@dataclass
class GateResult:
    gate: str
    status: str
    required: bool
    detail: str
    items: list = field(default_factory=list)
    duration_ms: int = 0
    data: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"gate": self.gate, "status": self.status, "required": self.required,
                "detail": self.detail, "items": list(self.items), "duration_ms": int(self.duration_ms)}


@dataclass
class CheckResult:
    gate: str
    check: str
    status: str
    required: bool
    detail: str
    rc: Optional[int]
    duration_ms: int
    argv: list
    cwd: str
    output_tail: str

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


def one_line(text: str, limit: int = 300) -> str:
    flat = " ".join(str(text or "").split())
    return redaction.redact_text(flat[:limit])


def output_tail(text: str, lines: int = TAIL_LINES, chars: int = TAIL_CHARS) -> str:
    kept = "\n".join((text or "").splitlines()[-lines:])
    cleaned = redaction.redact_text(kept)
    return cleaned[-chars:] if len(cleaned) > chars else cleaned


def last_line(text: str) -> str:
    for line in reversed((text or "").splitlines()):
        stripped = line.strip().strip("=").strip()
        if stripped:
            return stripped
    return ""


def child_env(extra: Optional[dict] = None) -> dict:
    env = dict(os.environ)
    for name in CHILD_ENV_DROP:
        env.pop(name, None)
    env.update(CHILD_ENV_ADD)
    env.update(extra or {})
    return env


def detected(suite: dict, workspace: str) -> bool:
    patterns = suite.get("detect") or []
    if not patterns:
        return True
    for entry in patterns:
        text = str(entry)
        if any(ch in text for ch in "*?["):
            if glob.glob(os.path.join(workspace, text), recursive=True):
                return True
        elif text.endswith("/"):
            if os.path.isdir(os.path.join(workspace, text.rstrip("/"))):
                return True
        elif os.path.exists(os.path.join(workspace, text)):
            return True
    return False


def _changed(workspace: str, scope: list, exts: tuple) -> list:
    found: list = []
    for item in scope or []:
        absolute = item if os.path.isabs(item) else os.path.join(workspace, item)
        if not os.path.isfile(absolute) or not absolute.endswith(exts):
            continue
        relative = os.path.relpath(absolute, workspace)
        if relative.startswith(".."):
            continue
        posix = Path(relative).as_posix()
        if posix not in found:
            found.append(posix)
    return found


def expand_argv(suite: dict, workspace: str, scope: list) -> tuple:
    values = {"{python}": testmap.workspace_python(workspace), "{workspace}": workspace}
    lists = {"{changed_py}": _changed(workspace, scope, PY_EXTS),
             "{changed_js}": _changed(workspace, scope, JS_EXTS)}
    argv: list = []
    for token in suite.get("argv") or []:
        text = str(token)
        if text in lists:
            if not lists[text]:
                return [], "no changed files of this kind"
            argv.extend(lists[text])
            continue
        for key, value in values.items():
            text = text.replace(key, value)
        argv.append(text)
    return argv, ""


def _result(suite_id: str, status: str, required: bool, detail: str, rc, started: float,
            argv: list, cwd: str, output: str = "") -> CheckResult:
    return CheckResult(gate="proof", check=suite_id, status=status, required=required,
                       detail=one_line(detail), rc=rc,
                       duration_ms=max(0, int((time.monotonic() - started) * 1000)),
                       argv=[str(a) for a in argv], cwd=cwd, output_tail=output_tail(output))


def run_capability(suite: dict, ctx, cfg, scope: list) -> CheckResult:
    started = time.monotonic()
    suite_id = str(suite.get("id") or "check")
    required = bool(suite.get("required", True))
    workspace = str(getattr(ctx, "workspace", "") or "")
    try:
        if not workspace or not os.path.isdir(workspace):
            return _result(suite_id, FAIL, required, "cannot run: directory does not exist", None,
                           started, list(suite.get("argv") or []), workspace)
        argv, na_reason = expand_argv(suite, workspace, scope)
        if na_reason:
            return _result(suite_id, NOT_APPLICABLE, required, na_reason, None, started, [], workspace)
        if not argv:
            return _result(suite_id, NOT_APPLICABLE, required, "suite has no command", None, started, [],
                           workspace)
        timeout_s = float(suite.get("timeout_s") or DEFAULT_TIMEOUT_S)
        try:
            proc = subprocess.run(argv, cwd=workspace, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=timeout_s, env=child_env())
        except FileNotFoundError:
            return _result(suite_id, UNVERIFIED, required, "%s not installed" % argv[0], None, started,
                           argv, workspace)
        except subprocess.TimeoutExpired as exc:
            partial = exc.output.decode("utf-8", "replace") if isinstance(exc.output, bytes) else (exc.output or "")
            return _result(suite_id, FAIL, required, "timed out after %ds" % int(timeout_s), None, started,
                           argv, workspace, partial)
        except OSError as exc:
            return _result(suite_id, FAIL, required, "cannot run: %s: %s" % (exc.__class__.__name__, exc),
                           None, started, argv, workspace)
        output = proc.stdout.decode("utf-8", "replace") if isinstance(proc.stdout, bytes) else (proc.stdout or "")
        if proc.returncode == 0:
            return _result(suite_id, PASS, required, last_line(output) or "exit 0", 0, started, argv,
                           workspace, output)
        kind = jobstore.classify(proc.returncode, output, argv, cfg, workspace)
        if kind == "skipped_no_tests":
            return _result(suite_id, UNVERIFIED, required, "no tests collected (exit %d)" % proc.returncode,
                           proc.returncode, started, argv, workspace, output)
        if kind == "skipped_env":
            return _result(suite_id, UNVERIFIED, required,
                           "environment not ready (exit %d): %s" % (proc.returncode, last_line(output)),
                           proc.returncode, started, argv, workspace, output)
        if kind == "not_installed":
            return _result(suite_id, UNVERIFIED, required, "%s not installed (exit %d)" % (argv[0], proc.returncode),
                           proc.returncode, started, argv, workspace, output)
        return _result(suite_id, FAIL, required, "exit %d — %s" % (proc.returncode, last_line(output)),
                       proc.returncode, started, argv, workspace, output)
    except Exception as exc:
        return _result(suite_id, FAIL, required, "cannot run: %s: %s" % (exc.__class__.__name__, exc), None,
                       started, list(suite.get("argv") or []), workspace)


def tool_of(argv: list) -> str:
    for token in argv or []:
        base = os.path.basename(str(token))
        for name in TOOL_NAMES:
            if base == name or base.startswith(name):
                return name
    return os.path.basename(str(argv[0])) if argv else ""


def _job_result(view: dict, status: str, detail: str, rc, output: str, duration_ms: int) -> CheckResult:
    return CheckResult(gate="proof", check="job:%s" % (view.get("label") or view.get("scope_key") or view.get("id")),
                       status=status, required=view.get("kind") == "test", detail=one_line(detail), rc=rc,
                       duration_ms=max(0, int(duration_ms or 0)), argv=[str(a) for a in view.get("argv") or []],
                       cwd=str(view.get("cwd") or ""), output_tail=output_tail(output))


def _rerun(view: dict, cfg) -> CheckResult:
    argv = [str(a) for a in view.get("argv") or []]
    cwd = str(view.get("cwd") or "")
    started = time.monotonic()
    if not cwd or not os.path.isdir(cwd):
        return _job_result(view, FAIL, "cannot run: directory does not exist", None, "", 0)
    try:
        proc = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=float(view.get("timeout_s") or DEFAULT_TIMEOUT_S),
                              env=child_env(view.get("env_add") or {}))
    except FileNotFoundError:
        return _job_result(view, UNVERIFIED, "%s not installed" % (argv[0] if argv else "command"), None, "", 0)
    except subprocess.TimeoutExpired:
        return _job_result(view, FAIL, "timed out on rerun", None, "", int((time.monotonic() - started) * 1000))
    except OSError as exc:
        return _job_result(view, FAIL, "cannot run: %s" % exc.__class__.__name__, None, "", 0)
    output = proc.stdout.decode("utf-8", "replace") if isinstance(proc.stdout, bytes) else (proc.stdout or "")
    kind = jobstore.classify(proc.returncode, output, argv, cfg, cwd)
    status = JOB_STATUS_MAP.get(kind, FAIL)
    detail = "rerun at Stop: %s (exit %s)" % (kind, proc.returncode)
    return _job_result(view, status, detail, proc.returncode, output, int((time.monotonic() - started) * 1000))


def background_outcomes(ctx, covered: Optional[set] = None, cfg=None) -> list:
    cfg = cfg if cfg is not None else ctx.cfg
    covered = set(covered or ())
    outcomes: list = []
    for view in jobstore.settle(ctx, 0):
        if view.get("state") == "cancelled":
            continue
        if tool_of(view.get("argv") or []) in covered:
            continue
        if not view.get("done"):
            outcomes.append(_rerun(view, cfg))
            continue
        result = view.get("result") or {}
        kind = str(result.get("status") or "error")
        status = JOB_STATUS_MAP.get(kind, FAIL)
        detail = "background %s (exit %s)" % (kind, result.get("rc"))
        outcomes.append(_job_result(view, status, detail, result.get("rc"), str(result.get("output") or ""),
                                    int(result.get("duration_ms") or 0)))
    return outcomes


def _scope_has_code(workspace: str, scope: list, cfg) -> bool:
    exts = tuple(cfg.get("tdd.source_exts", []) or []) or PY_EXTS + JS_EXTS
    for item in scope or []:
        if str(paths.rel(item, workspace)).endswith(exts):
            return True
    return False


def aggregate(results: list) -> str:
    required = [r for r in results if r.required]
    if any(r.status == FAIL for r in required):
        return FAIL
    if any(r.status == UNVERIFIED for r in required):
        return UNVERIFIED
    if results and all(r.status == NOT_APPLICABLE for r in results):
        return NOT_APPLICABLE
    return PASS


def _detail(results: list, status: str) -> str:
    counts: dict = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    if status in (FAIL, UNVERIFIED):
        culprits = [r for r in results if r.required and r.status == status]
        if culprits:
            first = culprits[0]
            more = " (+%d more)" % (len(culprits) - 1) if len(culprits) > 1 else ""
            return one_line("%s: %s%s" % (first.check, first.detail, more))
    ran = [r.check for r in results if r.status == PASS]
    warn = [r.check for r in results if not r.required and r.status in (FAIL, UNVERIFIED)]
    text = "%d check(s) passed" % len(ran) if ran else "nothing to run"
    if ran:
        text += ": " + ", ".join(ran[:6])
    if warn:
        text += "; non-blocking: " + ", ".join(warn[:6])
    return one_line(text)


def prove(ctx, cfg, scope: list) -> GateResult:
    started = time.monotonic()
    cfg = cfg if cfg is not None else ctx.cfg
    workspace = str(ctx.workspace)
    suites = [s for s in (cfg.get("proof.suites", []) or []) if isinstance(s, dict) and detected(s, workspace)]
    results: list = []
    if suites:
        with ThreadPoolExecutor(max_workers=min(4, len(suites))) as pool:
            results = list(pool.map(lambda s: run_capability(s, ctx, cfg, scope), suites))
    covered = {r.check for r in results if r.status in (PASS, FAIL)}
    covered |= {tool_of(r.argv) for r in results if r.status in (PASS, FAIL)}
    results.extend(background_outcomes(ctx, covered, cfg))
    if not results or all(r.status in (UNVERIFIED, NOT_APPLICABLE) for r in results):
        has_code = _scope_has_code(workspace, scope, cfg)
        results.append(CheckResult(gate="proof", check="proof", status=UNVERIFIED, required=has_code,
                                   detail="UNPROVEN — nothing ran" + ("" if has_code else " (no code in scope)"),
                                   rc=None, duration_ms=0, argv=[], cwd=workspace, output_tail=""))
    status = aggregate(results)
    return GateResult(gate="proof", status=status, required=bool(cfg.get("stop.gates.proof.required", True)),
                      detail=_detail(results, status), items=[r.as_dict() for r in results],
                      duration_ms=int((time.monotonic() - started) * 1000),
                      data={"results": [r.as_dict() for r in results]})


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="stop_proof.py", description="Run the proof suites for a session.")
    parser.add_argument("--session")
    parser.add_argument("--workspace")
    parser.add_argument("--provider")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        ctx = state.load_context(args.session, args.workspace, args.provider)
    except state.AmbiguousSession as exc:
        sys.stderr.write("[proof] %s\n" % exc)
        return 2
    scope = ledger.paths(ctx)
    result = prove(ctx, ctx.cfg, scope)
    if args.json:
        sys.stdout.write(json.dumps(result.as_dict(), ensure_ascii=False) + "\n")
    else:
        out = sys.stdout if result.status in (PASS, NOT_APPLICABLE) else sys.stderr
        out.write("[proof] %s %s\n" % (result.status, result.detail))
        for item in result.items:
            out.write("  %-10s %-14s %s\n" % (item["check"], item["status"], item["detail"]))
    return 0 if result.status in (PASS, NOT_APPLICABLE) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

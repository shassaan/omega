from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Optional

OMEGA_ROOT = Path(__file__).resolve().parents[1]
if str(OMEGA_ROOT) not in sys.path:
    sys.path.insert(0, str(OMEGA_ROOT))

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from hooks.lib import OMEGA_VERSION, adapters, contracts, costledger, hashing, ledger, paths, redaction, state, transcript
from hooks.lib import config as config_mod
from ui.provider_manager import BudgetExceeded, Choice, KeyRejected, NoProvider, PROVIDERS, ProviderManager

USER_ID = "local"
STATIC_DIR = Path(__file__).resolve().parent / "static"
ROLES = ("research", "architect", "implementer", "utility")
PERMISSION_MODES = ("acceptEdits", "default", "plan", "dontAsk")
ACTIVE = ("queued", "running")
TERMINAL_STICKY = ("cancelled", "budget_exceeded")
RUN_ID_PATTERN = re.compile(r"^run-\d{14}-[0-9a-f]{4}$")
PROJECT_ID_PATTERN = re.compile(r"^prj-[0-9a-f]{8}$")
CLEARANCES = ("proof", "contract", "review")
MAX_PROMPT = 100_000
MAX_TEXT = 4_000
SUMMARY_LIMIT = 2_000
TEXT_FLUSH_S = 0.1
QUEUE_SIZE = 1000
CANCEL_GRACE_S = 10.0
TIMEOUT_GRACE_S = 5.0
CLI_TIMEOUT_S = 600
PROBE_PROMPT = "Reply with OK"
PROBE_BUDGET_USD = 0.05

log = logging.getLogger("omega.ui")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class Unavailable(RuntimeError):
    pass


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": redaction.redact_text(str(message))}}, status_code=status)


def _now_iso() -> str:
    return state.iso()


def _truncate(text: Any, limit: int = SUMMARY_LIMIT) -> str:
    value = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False, default=str)
    return value if len(value) <= limit else value[:limit] + "…"


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redaction.redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    return value


def sign_row(key: bytes, row: dict) -> str:
    body = {k: v for k, v in row.items() if k != "sig"}
    return hmac.new(key, hashing.canonical_json(body).encode("utf-8"), hashlib.sha256).hexdigest()


def verify_rows(key: bytes, rows: list) -> tuple:
    good: list = []
    bad = 0
    for row in rows:
        sig = row.get("sig")
        if isinstance(sig, str) and hmac.compare_digest(sig, sign_row(key, row)):
            good.append(row)
        else:
            bad += 1
    return good, bad


def claude_argv(prompt: str, model: str, budget_usd: float, settings_path: str, permission_mode: str,
                resume: Optional[str]) -> list:
    argv = ["claude", "-p", prompt, "--model", model, "--output-format", "stream-json", "--verbose",
            "--include-partial-messages", "--permission-mode", permission_mode, "--bare", "--settings",
            settings_path, "--max-budget-usd", str(budget_usd)]
    if resume:
        argv += ["--resume", resume]
    return argv


def codex_argv(prompt: str, model: Optional[str], sandbox: str, last_message_path: str) -> list:
    argv = ["codex", "exec", "--json", "--sandbox", sandbox, "-o", last_message_path]
    if model:
        argv += ["-m", model]
    return argv + [prompt]


def _ev(kind: str, **data) -> dict:
    return {"kind": kind, "data": data}


def _summary(value: Any) -> str:
    return _truncate(redaction.redact_text(value if isinstance(value, str) else
                                           json.dumps(value, ensure_ascii=False, default=str)))


def _tool_result_text(content: Any) -> str:
    if isinstance(content, list):
        parts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
        return "\n".join(p for p in parts if p) or json.dumps(content, ensure_ascii=False, default=str)
    if isinstance(content, str):
        return content
    return json.dumps(content, ensure_ascii=False, default=str)


def _raw(line: Any) -> list:
    kind = line.get("type") if isinstance(line, dict) else None
    return [_ev("raw", type=str(kind), truncated=_summary(line))]


def normalize_claude(line: dict) -> list:
    if not isinstance(line, dict):
        return _raw(line)
    kind = line.get("type")
    if kind == "stream_event":
        event = line.get("event") or {}
        delta = event.get("delta") or {}
        if event.get("type") == "content_block_delta" and delta.get("type") == "text_delta":
            return [_ev("text", delta=str(delta.get("text", "")))] if delta.get("text") else []
        return []
    if kind == "system":
        subtype = str(line.get("subtype") or "")
        if subtype == "init":
            return [_ev("status", status="running", session_id=line.get("session_id"), model=line.get("model"))]
        if "hook" in subtype:
            decision = str(line.get("decision") or line.get("outcome") or "")
            if line.get("exit_code") == 2:
                decision = "block"
            elif decision not in ("allow", "deny", "block"):
                decision = "allow"
            return [_ev("hook", event=str(line.get("hook_event") or line.get("hook_event_name") or subtype),
                        decision=decision, reason=_summary(line.get("stderr") or line.get("output") or line.get("reason") or ""))]
        return _raw(line)
    if kind == "attachment":
        payload = line.get("attachment") or {}
        return [_ev("hook", event=str(payload.get("hookEvent") or payload.get("type") or "hook"),
                    decision="block" if payload.get("blocking") else "allow",
                    reason=_summary(payload.get("content") or payload.get("stderr") or ""))]
    if kind == "assistant":
        out: list = []
        for block in (line.get("message") or {}).get("content") or []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                out.append(_ev("tool_call", id=str(block.get("id") or ""), name=str(block.get("name") or ""),
                               input_summary=_summary(block.get("input") or {})))
        return out
    if kind == "user":
        out = []
        content = (line.get("message") or {}).get("content")
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                out.append(_ev("tool_result", id=str(block.get("tool_use_id") or ""), ok=not block.get("is_error"),
                               summary=_summary(_tool_result_text(block.get("content")))))
        return out
    if kind == "result":
        usage = line.get("usage") or {}
        cost = line.get("total_cost_usd")
        cost = float(cost) if isinstance(cost, (int, float)) and not isinstance(cost, bool) else None
        return [
            _ev("usage", **{"in": int(usage.get("input_tokens") or 0), "out": int(usage.get("output_tokens") or 0),
                            "cache_read": int(usage.get("cache_read_input_tokens") or 0),
                            "cache_write": int(usage.get("cache_creation_input_tokens") or 0),
                            "usd": cost, "source": "cli_result"}),
            _ev("done", exit_code=None, is_error=bool(line.get("is_error")), cost_usd=cost,
                session_id=line.get("session_id")),
        ]
    return _raw(line)


def normalize_codex(line: dict) -> list:
    if not isinstance(line, dict):
        return _raw(line)
    kind = line.get("type")
    if kind == "thread.started":
        return [_ev("status", status="running", session_id=line.get("thread_id"))]
    if kind in ("turn.started",):
        return []
    if kind == "turn.completed":
        usage = line.get("usage") or {}
        return [_ev("usage", **{"in": int(usage.get("input_tokens") or 0),
                                "out": int(usage.get("output_tokens") or 0) + int(usage.get("reasoning_output_tokens") or 0),
                                "cache_read": int(usage.get("cached_input_tokens") or 0), "cache_write": 0,
                                "usd": None, "source": "cli_result"})]
    if kind == "turn.failed":
        error = line.get("error") or {}
        message = error.get("message") if isinstance(error, dict) else error
        return [_ev("error", message=_summary(message or "turn failed"))]
    if kind == "error":
        return [_ev("error", message=_summary(line.get("message") or "codex error"))]
    if kind in ("item.started", "item.completed", "item.updated"):
        item = line.get("item") or {}
        item_type = item.get("type")
        item_id = str(item.get("id") or "")
        if item_type == "agent_message":
            if kind != "item.completed":
                return []
            return [_ev("text", delta=str(item.get("text") or ""))] if item.get("text") else []
        if item_type == "command_execution":
            if kind == "item.started":
                return [_ev("tool_call", id=item_id, name="shell", input_summary=_summary(item.get("command") or ""))]
            if kind == "item.completed":
                exit_code = item.get("exit_code")
                ok = item.get("status") in ("completed", None) and exit_code in (0, None)
                return [_ev("tool_result", id=item_id, ok=bool(ok),
                            summary=_summary(item.get("aggregated_output") or item.get("command") or ""))]
            return []
        if item_type in ("file_change", "mcp_tool_call", "web_search"):
            if kind == "item.started":
                return [_ev("tool_call", id=item_id, name=str(item_type), input_summary=_summary(
                    item.get("changes") or item.get("query") or item.get("tool") or {}))]
            if kind == "item.completed":
                return [_ev("tool_result", id=item_id, ok=item.get("status") in ("completed", None),
                            summary=_summary(item.get("changes") or item.get("result") or item.get("status") or ""))]
            return []
        return _raw(line)
    return _raw(line)


class Hub:
    def __init__(self, store: "RunStore", on_event: Optional[Callable] = None, enrich: Optional[Callable] = None):
        self.store = store
        self.on_event = on_event
        self.enrich = enrich
        self.subs: dict = {}
        self.procs: dict = {}
        self._seq: dict = {}
        self._lock = threading.Lock()

    def sub(self, run_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        self.subs.setdefault(run_id, set()).add(queue)
        return queue

    def unsub(self, run_id: str, queue: asyncio.Queue) -> None:
        self.subs.get(run_id, set()).discard(queue)

    def attach(self, run_id: str, proc) -> None:
        self.procs[run_id] = proc

    def detach(self, run_id: str) -> None:
        self.procs.pop(run_id, None)

    def _next_seq(self, run_id: str) -> int:
        if run_id not in self._seq:
            self._seq[run_id] = self.store.last_seq(run_id)
        self._seq[run_id] += 1
        return self._seq[run_id]

    def pub(self, run_id: str, ev: dict) -> dict:
        run = self.store.get(run_id) or {}
        with self._lock:
            ts, ts_ns = state.stamp()
            row = {
                "run_id": run_id,
                "seq": self._next_seq(run_id),
                "ts": ts,
                "ts_ns": ts_ns,
                "role": run.get("role"),
                "runtime": run.get("runtime"),
                "kind": str(ev.get("kind") or "raw"),
                "data": redact_value(ev.get("data") or {}),
            }
            if self.enrich is not None:
                try:
                    row = self.enrich(run_id, run, row)
                except Exception as exc:
                    log.warning("event enrichment failed for %s: %s", run_id, exc.__class__.__name__)
            self.store.append_event(run_id, row)
        if self.on_event is not None:
            try:
                self.on_event(run_id, row)
            except Exception as exc:
                log.warning("event side effect failed for %s: %s", run_id, exc.__class__.__name__)
        for queue in list(self.subs.get(run_id, ())):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(row)
        return row


class RunStore:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def dir(self, run_id: str) -> Path:
        if not RUN_ID_PATTERN.match(run_id or ""):
            raise ApiError(404, "not_found", "unknown run")
        return self.root / run_id

    def new_id(self) -> str:
        while True:
            run_id = "run-%s-%s" % (time.strftime("%Y%m%d%H%M%S", time.gmtime()), secrets.token_hex(2))
            if not (self.root / run_id).exists():
                return run_id

    def create(self, run: dict) -> dict:
        directory = self.root / run["run_id"]
        directory.mkdir(parents=True, exist_ok=False)
        os.chmod(str(directory), 0o700)
        state.write_json_atomic(directory / "run.json", run)
        return run

    def get(self, run_id: str) -> Optional[dict]:
        try:
            directory = self.dir(run_id)
        except ApiError:
            return None
        data = state.read_json(directory / "run.json", None)
        return data if isinstance(data, dict) else None

    def update(self, run_id: str, **fields) -> dict:
        with self._lock:
            run = self.get(run_id) or {}
            run.update(fields)
            state.write_json_atomic(self.dir(run_id) / "run.json", run)
            return run

    def list(self) -> list:
        runs = []
        for child in self.root.iterdir() if self.root.is_dir() else []:
            data = state.read_json(child / "run.json", None)
            if isinstance(data, dict):
                runs.append(data)
        runs.sort(key=lambda r: str(r.get("started_at") or ""), reverse=True)
        return runs

    def events_path(self, run_id: str) -> Path:
        return self.dir(run_id) / "events.jsonl"

    def human_log(self, run_id: str) -> Path:
        return self.dir(run_id) / "human_turns.jsonl"

    def append_event(self, run_id: str, row: dict) -> None:
        state.append_jsonl(self.events_path(run_id), row)

    def last_seq(self, run_id: str) -> int:
        last = 0
        for row in state.read_jsonl(self.events_path(run_id)):
            if isinstance(row.get("seq"), int):
                last = max(last, row["seq"])
        return last

    def events(self, run_id: str, after: int = 0, limit: Optional[int] = None) -> list:
        rows = [r for r in state.read_jsonl(self.events_path(run_id))
                if isinstance(r.get("seq"), int) and r["seq"] > after]
        rows.sort(key=lambda r: r["seq"])
        return rows[:limit] if limit else rows


class ProjectStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def _load(self) -> dict:
        data = state.read_json(self.path, {})
        return data if isinstance(data, dict) else {}

    def list(self) -> list:
        return sorted(self._load().values(), key=lambda p: str(p.get("created_at") or ""))

    def get(self, project_id: str) -> dict:
        if not PROJECT_ID_PATTERN.match(project_id or ""):
            raise ApiError(404, "not_found", "unknown project")
        found = self._load().get(project_id)
        if not isinstance(found, dict):
            raise ApiError(404, "not_found", "unknown project")
        return found

    def save(self, project: dict) -> dict:
        with self._lock:
            data = self._load()
            data[project["id"]] = project
            state.write_json_atomic(self.path, data)
        return project


def run_cli(script_rel: str, args: list, env_extra: dict, timeout: float = CLI_TIMEOUT_S) -> tuple:
    script = OMEGA_ROOT / script_rel
    if not script.is_file():
        raise Unavailable("%s is not installed" % script_rel)
    env = {name: os.environ[name] for name in ("PATH", "HOME", "LANG", "TMPDIR") if os.environ.get(name)}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.update({k: str(v) for k, v in env_extra.items() if v is not None})
    argv = ["/bin/sh", str(OMEGA_ROOT / "bin" / "launch.sh"), script_rel] + [str(a) for a in args]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=timeout,
                              cwd=str(OMEGA_ROOT), stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return 2, "", "%s timed out after %ss" % (script_rel, timeout)
    return done.returncode, done.stdout, done.stderr


async def _flush_text(buffer: list, hub: Hub, run_id: str) -> None:
    if buffer:
        hub.pub(run_id, _ev("text", delta="".join(buffer)))
        buffer.clear()


async def _killpg(proc, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass


async def start_run(run: dict, choice: Choice, env: dict, workspace: str, hub: Hub, cfg) -> None:
    run_id = run["run_id"]
    run_dir = Path(run["dir"])
    if choice.runtime == "claude":
        settings_path = Path(run["state_root"]) / "ui" / "claude-settings.json"
        state.write_json_atomic(settings_path, adapters.render_claude_settings(OMEGA_ROOT, absolute=True))
        argv = claude_argv(run["prompt"], choice.model or "", run["max_budget_usd"], str(settings_path),
                           run.get("permission_mode") or "acceptEdits", run.get("resume"))
        normalize = normalize_claude
    elif choice.runtime == "codex":
        argv = codex_argv(run["prompt"], choice.model, "workspace-write", str(run_dir / "last_message.txt"))
        normalize = normalize_codex
    else:
        hub.pub(run_id, _ev("error", message="no runtime for provider %s" % choice.provider))
        hub.pub(run_id, _ev("status", status="failed"))
        return
    limit = int(cfg.get("ui.events_limit_bytes", 8388608) or 8388608)
    timeout_s = float(cfg.get("ui.run_timeout_s", 3600) or 3600)
    hub.pub(run_id, _ev("status", status="running"))
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=workspace, env=env, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True, limit=limit)
    except FileNotFoundError:
        hub.pub(run_id, _ev("error", message="%s is not installed on PATH" % argv[0]))
        hub.pub(run_id, _ev("done", exit_code=127, is_error=True, cost_usd=None, session_id=None))
        hub.pub(run_id, _ev("status", status="failed"))
        return
    except OSError as exc:
        hub.pub(run_id, _ev("error", message="could not start %s: %s" % (argv[0], exc.__class__.__name__)))
        hub.pub(run_id, _ev("status", status="failed"))
        return
    hub.attach(run_id, proc)
    result: dict = {}

    async def pump_stdout() -> None:
        buffer: list = []
        last_flush = time.monotonic()
        with open(str(run_dir / "stdout.log"), "a", encoding="utf-8", opener=_private_opener) as raw_log:
            while True:
                try:
                    raw = await asyncio.wait_for(proc.stdout.readline(), TEXT_FLUSH_S * 2)
                except asyncio.TimeoutError:
                    await _flush_text(buffer, hub, run_id)
                    last_flush = time.monotonic()
                    continue
                except ValueError:
                    hub.pub(run_id, _ev("error", message="a stream line exceeded the %d byte limit" % limit))
                    continue
                if not raw:
                    break
                text = raw.decode("utf-8", "replace").strip()
                if not text:
                    continue
                raw_log.write(redaction.redact_text(text) + "\n")
                try:
                    parsed = json.loads(text)
                except ValueError:
                    parsed = {"type": "stdout_text", "text": text[:SUMMARY_LIMIT]}
                for event in normalize(parsed):
                    if event["kind"] == "text":
                        buffer.append(event["data"].get("delta", ""))
                        if time.monotonic() - last_flush >= TEXT_FLUSH_S or sum(len(b) for b in buffer) > 4000:
                            await _flush_text(buffer, hub, run_id)
                            last_flush = time.monotonic()
                        continue
                    await _flush_text(buffer, hub, run_id)
                    if event["kind"] == "done":
                        result.update(event["data"])
                        continue
                    hub.pub(run_id, event)
            await _flush_text(buffer, hub, run_id)

    async def pump_stderr() -> None:
        with open(str(run_dir / "stderr.log"), "a", encoding="utf-8", opener=_private_opener) as err_log:
            while True:
                raw = await proc.stderr.readline()
                if not raw:
                    break
                err_log.write(redaction.redact_text(raw.decode("utf-8", "replace").rstrip("\n")) + "\n")

    timed_out = False
    try:
        await asyncio.wait_for(asyncio.gather(pump_stdout(), pump_stderr()), timeout=timeout_s)
    except asyncio.TimeoutError:
        timed_out = True
        hub.pub(run_id, _ev("error", message="run timed out after %ss" % int(timeout_s)))
        await _killpg(proc, signal.SIGINT)
        try:
            await asyncio.wait_for(proc.wait(), TIMEOUT_GRACE_S)
        except asyncio.TimeoutError:
            await _killpg(proc, signal.SIGKILL)
    rc = await proc.wait()
    hub.detach(run_id)
    is_error = bool(result.get("is_error")) or rc != 0 or timed_out
    hub.pub(run_id, _ev("done", exit_code=rc, is_error=is_error, cost_usd=result.get("cost_usd"),
                        session_id=result.get("session_id")))
    if rc in (143, -signal.SIGTERM, -signal.SIGINT, 130):
        final = "cancelled"
    elif is_error:
        final = "failed"
    else:
        final = "done"
    hub.pub(run_id, _ev("status", status=final))


def _private_opener(path: str, flags: int) -> int:
    return os.open(path, flags, 0o600)


async def verify_hooks_fire(runtime: str, cfg, env: Optional[dict] = None, state_root: Optional[Path] = None) -> bool:
    if runtime not in ("claude", "codex") or not env:
        return False
    root = Path(state_root) if state_root else paths.state_root()
    probe_dir = Path(tempfile.mkdtemp(prefix="omega-probe-"))
    started = time.time()
    try:
        subprocess.run(["git", "init", "-q"], cwd=str(probe_dir), capture_output=True, timeout=30,
                       env=dict(env, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1"))
        probe_env = dict(env, OMEGA_STATE_DIR=str(root), OMEGA_WORKSPACE=str(probe_dir))
        probe_env.pop("OMEGA_HUMAN_LOG", None)
        if runtime == "claude":
            settings_path = root / "ui" / "claude-settings.json"
            state.write_json_atomic(settings_path, adapters.render_claude_settings(OMEGA_ROOT, absolute=True))
            argv = claude_argv(PROBE_PROMPT, cfg.get("cost.roles.utility.model", "claude-haiku-5-5"),
                               PROBE_BUDGET_USD, str(settings_path), "default", None)
        else:
            argv = codex_argv(PROBE_PROMPT, None, "read-only", str(probe_dir / "last.txt"))
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, cwd=str(probe_dir), env=probe_env, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL, start_new_session=True)
        except OSError:
            return False
        try:
            await asyncio.wait_for(proc.wait(), 120)
        except asyncio.TimeoutError:
            await _killpg(proc, signal.SIGKILL)
            return False
        observed = state.read_json(root / "observed" / ("%s.json" % runtime), {}) or {}
        stamp = transcript.parse_time(observed.get("SessionStart"))
        return bool(stamp and stamp.timestamp() >= int(started))
    finally:
        shutil.rmtree(str(probe_dir), ignore_errors=True)


DEFAULT_RUNNER = SimpleNamespace(start_run=start_run, verify_hooks_fire=verify_hooks_fire)


def _load_gate(module: str):
    import importlib
    try:
        return importlib.import_module(module)
    except Exception as exc:
        raise Unavailable("%s is not available (%s)" % (module, exc.__class__.__name__))


class Gates:
    def record(self, ctx, quote: str, turns: list) -> tuple:
        return _load_gate("hooks.contract_gate").record(ctx, quote, turns)

    def current_fingerprint(self, ctx, cfg) -> Optional[tuple]:
        try:
            return _load_gate("hooks.contract_gate").current_fingerprint(ctx, cfg)
        except Exception:
            return None


class UiState:
    def __init__(self, state_root: Path, cfg, manager: ProviderManager, runner, cli: Callable, gates,
                 token: str, origins: list, ping_interval_s: float, approval_poll_s: float):
        self.state_root = state_root
        self.cfg = cfg
        self.manager = manager
        self.runner = runner
        self.cli = cli
        self.gates = gates
        self.token = token
        self.origins = origins
        self.ping_interval_s = ping_interval_s
        self.approval_poll_s = approval_poll_s
        self.ui_dir = state_root / "ui"
        self.runs = RunStore(self.ui_dir / "runs")
        self.projects = ProjectStore(self.ui_dir / "projects.json")
        self.hub = Hub(self.runs, self.on_event, self.enrich)
        self.hooks_verified: dict = {"claude": None, "codex": None}
        self.runtime_versions: Optional[dict] = None
        self.prompts: dict = {}
        self.tasks: set = set()
        self.env_lock = threading.Lock()

    def check_token(self, presented: Optional[str]) -> bool:
        return bool(presented) and hmac.compare_digest(str(presented).encode("utf-8"), self.token.encode("utf-8"))

    def origin_ok(self, origin: Optional[str]) -> bool:
        return bool(origin) and origin.rstrip("/") in self.origins

    def on_event(self, run_id: str, row: dict) -> None:
        kind = row["kind"]
        data = row.get("data") or {}
        run = self.runs.get(run_id) or {}
        if kind == "status":
            fields: dict = {}
            status = data.get("status")
            current = run.get("status")
            if status and not (current in TERMINAL_STICKY and status != current):
                fields["status"] = status
                if status in ("done", "failed", "cancelled", "budget_exceeded"):
                    fields["ended_at"] = row["ts"]
            if data.get("session_id") and not run.get("session_id"):
                fields["session_id"] = data["session_id"]
            if fields:
                self.runs.update(run_id, **fields)
        elif kind == "done":
            fields = {"exit_code": data.get("exit_code")}
            if data.get("session_id") and not run.get("session_id"):
                fields["session_id"] = data["session_id"]
            if isinstance(data.get("cost_usd"), (int, float)):
                fields["cost_usd"] = data["cost_usd"]
            self.runs.update(run_id, **fields)
        elif kind == "usage":
            if isinstance(data.get("cumulative_usd"), (int, float)):
                self.runs.update(run_id, cost_usd=data["cumulative_usd"])
            if data.get("budget_status") == costledger.FAIL and run.get("status") in ACTIVE:
                self.hub.pub(run_id, _ev("error", message="budget exceeded: " + "; ".join(data.get("breaches") or [])))
                self.stop_run(run_id, "budget_exceeded")

    def enrich(self, run_id: str, run: dict, row: dict) -> dict:
        if row["kind"] != "usage":
            return row
        data = dict(row.get("data") or {})
        usage = {"id": "%s:%s" % (run_id, row["seq"]), "in": data.get("in"), "out": data.get("out"),
                 "cache_read": data.get("cache_read"), "cache_write": data.get("cache_write")}
        usd = data.get("usd") if isinstance(data.get("usd"), (int, float)) else None
        self.manager.record_usage(run, usage, usd, data.pop("source", None) or "cli_result")
        verdict = costledger.check(self.cfg, run_id=run_id, allow_unknown=True)
        data["cumulative_usd"] = round(float(verdict.sums.get("run") or 0.0), 6)
        data["budget_status"] = verdict.status
        data["breaches"] = verdict.breaches
        return dict(row, data=data)

    def stop_run(self, run_id: str, status: str) -> bool:
        self.runs.update(run_id, status=status, ended_at=_now_iso())
        self.hub.pub(run_id, _ev("status", status=status))
        proc = self.hub.procs.get(run_id)
        if proc is None or proc.returncode is not None:
            return False
        try:
            os.killpg(proc.pid, signal.SIGINT)
        except OSError:
            return False

        async def escalate() -> None:
            await asyncio.sleep(CANCEL_GRACE_S)
            if proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass

        self.spawn(escalate())
        return True

    def spawn(self, coro) -> asyncio.Task:
        task = asyncio.get_running_loop().create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def append_human(self, log_path: Path, kind: str, text: str, run_id: Optional[str]) -> dict:
        ts, ts_ns = state.stamp()
        row = {"ts": ts, "ts_ns": ts_ns, "uuid": str(uuid.uuid4()), "user_id": USER_ID, "kind": kind,
               "text": text, "run_id": run_id}
        row["sig"] = sign_row(self.manager.signing_key(), row)
        state.append_jsonl(log_path, row)
        return row

    def verified_turns(self, log_path: Path) -> tuple:
        rows = state.read_jsonl(log_path)
        good, bad = verify_rows(self.manager.signing_key(), rows)
        lines = [json.dumps(r) for r in good]
        return transcript.parse_ui_log(lines), bad

    def session_ctx(self, run: dict) -> Optional[state.SessionContext]:
        session_id = run.get("session_id")
        if not session_id or not run.get("workspace"):
            return None
        directory = state.session_path(run["workspace"], run.get("runtime") or "claude", session_id)
        directory.mkdir(parents=True, exist_ok=True)
        stored = state.read_json(directory / "context.json", {}) or {}
        return state.SessionContext(
            provider=run.get("runtime") or "claude", workspace=os.path.realpath(run["workspace"]),
            session_id=session_id, transcript_path=stored.get("transcript_path"), run_id=run.get("run_id"),
            dir=directory, harness_root=OMEGA_ROOT, cfg=config_mod.load(OMEGA_ROOT, run["workspace"]),
            model=run.get("model"))


def _session_dir_for(workspace: str, provider: Optional[str], session_id: Optional[str]) -> Optional[Path]:
    if not session_id:
        return None
    for prov in ([provider] if provider in ("claude", "codex") else ["claude", "codex"]):
        candidate = state.session_path(workspace, prov, session_id)
        if candidate.is_dir():
            return candidate
    return None


def _ledger_paths(workspace: str, cfg, provider: Optional[str], session_id: Optional[str]) -> list:
    directory = _session_dir_for(workspace, provider, session_id)
    if directory is None:
        return []
    ctx = state.SessionContext(provider=provider or "claude", workspace=workspace, session_id=session_id,
                               transcript_path=None, run_id=None, dir=directory, harness_root=OMEGA_ROOT, cfg=cfg)
    try:
        return ledger.paths(ctx)
    except Exception:
        return []


def clearance_view(workspace: str, cfg) -> dict:
    base = Path(workspace) / ".omega" / "clearances"
    out: dict = {}
    session = None
    for name in CLEARANCES:
        data = state.read_json(base / ("%s.json" % name), None)
        if not isinstance(data, dict):
            out[name] = None
            continue
        session = session or (data.get("provider"), data.get("session_id"))
        ledger_paths = _ledger_paths(workspace, cfg, data.get("provider"), data.get("session_id"))
        fresh, reason = hashing.fresh(data, workspace, ledger_paths)
        out[name] = {"fresh": bool(fresh), "reason": reason, "verified": bool(data.get("verified")),
                     "released": bool(data.get("released")), "overridden": bool(data.get("overridden")),
                     "files_digest": data.get("files_digest"), "clearance": data}
    out["last_stop"] = None
    if session:
        directory = _session_dir_for(workspace, session[0], session[1])
        last = state.read_json(directory / "last_stop.json", None) if directory else None
        if isinstance(last, dict):
            out["last_stop"] = {
                "ts": last.get("ts"), "attempt": last.get("attempt"), "verified": last.get("verified"),
                "released": last.get("released"), "overridden": last.get("overridden"),
                "files_digest": last.get("files_digest"), "blocking": last.get("blocking") or [],
                "results": [{"gate": r.get("gate"), "status": r.get("status"), "required": r.get("required"),
                             "detail": r.get("detail")} for r in last.get("results") or [] if isinstance(r, dict)],
            }
    return out


def contract_rows(workspace: str, cfg) -> list:
    rows = []
    for item in contracts.load_all(workspace, cfg):
        rows.append({"slug": item.slug, "title": item.title, "path": paths.rel(item.path, workspace),
                     "valid": contracts.is_valid(item), "errors": item.errors, "warnings": item.warnings,
                     "fingerprint": contracts.fingerprint(item), "seams": contracts.seam_counts(item),
                     "not_applicable": contracts.not_applicable(item)})
    return rows


def _scenarios(item) -> dict:
    out: dict = {}
    for seam in contracts.SEAMS:
        value = item.seams.get(seam)
        if isinstance(value, list):
            out[seam] = [s.name for s in value]
        elif isinstance(value, str):
            out[seam] = "not applicable: " + value[len(contracts.NOT_APPLICABLE_PREFIX):].strip()
        else:
            out[seam] = []
    return out


def pending_approvals(ui: UiState, run: dict) -> list:
    workspace = run.get("workspace")
    directory = _session_dir_for(workspace, run.get("runtime"), run.get("session_id")) if workspace else None
    if directory is None:
        return []
    request = state.read_json(directory / "contract_request.json", None)
    if not isinstance(request, dict):
        return []
    proposal = state.read_json(directory / "contract_proposal.json", {}) or {}
    approval = state.read_json(directory / "contract_approval.json", None)
    if isinstance(approval, dict) and approval.get("fingerprint") == request.get("fingerprint") and \
            approval.get("proposal_id", proposal.get("proposal_id")) == proposal.get("proposal_id"):
        return []
    files = [os.path.join(workspace, f) for f in proposal.get("files") or []]
    if not files:
        try:
            touched = (directory / "contracts_touched.txt").read_text(encoding="utf-8").splitlines()
        except OSError:
            touched = []
        files = sorted({t.strip() for t in touched if t.strip()})
    if not files:
        files = [c.path for c in contracts.load_all(workspace, config_mod.load(OMEGA_ROOT, workspace))]
    out = []
    for path in files:
        item = contracts.load_file(path, workspace)
        out.append({"slug": item.slug, "proposal_id": proposal.get("proposal_id"),
                    "fingerprint": contracts.fingerprint(item), "request_fingerprint": request.get("fingerprint"),
                    "asked_ts": request.get("ts"), "contract_path": paths.rel(path, workspace),
                    "title": item.title, "scenarios": _scenarios(item)})
    return out


async def _json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise ApiError(400, "bad_json", "the request body is not JSON")
    if not isinstance(body, dict):
        raise ApiError(400, "bad_json", "the request body must be a JSON object")
    return body


def _text_field(body: dict, name: str, limit: int, required: bool = True) -> Optional[str]:
    value = body.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ApiError(400, "invalid", "%s is required" % name)
    if len(value) > limit:
        raise ApiError(400, "invalid", "%s is longer than %d characters" % (name, limit))
    return value.strip()


def _load_token(ui_dir: Path) -> tuple:
    env_token = os.environ.get("OMEGA_UI_TOKEN")
    if env_token:
        return env_token, False
    path = ui_dir / "ui_token"
    try:
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing, False
    except OSError:
        pass
    token = secrets.token_urlsafe(32)
    ui_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, token.encode("utf-8"))
    finally:
        os.close(fd)
    return token, True


def _default_origins(cfg) -> list:
    port = int(cfg.get("ui.port", 8787) or 8787)
    hosts = {"127.0.0.1", "localhost", str(cfg.get("ui.host", "127.0.0.1") or "127.0.0.1")}
    origins = ["http://%s:%d" % (h, port) for h in sorted(hosts)]
    extra = os.environ.get("OMEGA_UI_ORIGINS", "")
    origins += [o.strip().rstrip("/") for o in extra.split(",") if o.strip()]
    return origins


def _configure_logging(ui_dir: Path) -> None:
    target = str(ui_dir / "server.log")
    for handler in log.handlers:
        if getattr(handler, "baseFilename", None) == target:
            return
    for handler in list(log.handlers):
        if isinstance(handler, logging.FileHandler):
            log.removeHandler(handler)
            handler.close()
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.close(fd)
    handler = logging.FileHandler(target, encoding="utf-8")
    handler.addFilter(redaction.RedactingFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False


def create_app(state_root: Optional[Path] = None, cfg=None, runner=None, manager: Optional[ProviderManager] = None,
               cli: Optional[Callable] = None, gates=None, token: Optional[str] = None,
               origins: Optional[list] = None, ping_interval_s: float = 20.0,
               approval_poll_s: float = 1.0) -> FastAPI:
    root = Path(state_root) if state_root else paths.state_root()
    cfg = cfg or config_mod.load(OMEGA_ROOT)
    ui_dir = root / "ui"
    ui_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(ui_dir), 0o700)
    _configure_logging(ui_dir)
    manager = manager or ProviderManager(root, cfg)
    generated = False
    if token is None:
        token, generated = _load_token(ui_dir)
    redaction.register_exact([token])
    ui = UiState(root, cfg, manager, runner or DEFAULT_RUNNER, cli or run_cli, gates or Gates(), token,
                 [o.rstrip("/") for o in (origins if origins is not None else _default_origins(cfg))],
                 ping_interval_s, approval_poll_s)
    for run in ui.runs.list():
        if run.get("status") in ACTIVE:
            ui.runs.update(run["run_id"], status="failed", ended_at=_now_iso(), error="server restarted")

    app = FastAPI(title="Omega", version=OMEGA_VERSION, docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.ui = ui
    app.state.token_generated = generated

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError):
        return _error(exc.status, exc.code, exc.message)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        return _error(exc.status_code, "http_%d" % exc.status_code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        return _error(400, "invalid", "the request is invalid")

    @app.middleware("http")
    async def _guard(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/"):
            header = request.headers.get("authorization", "")
            presented = header[7:].strip() if header.lower().startswith("bearer ") else ""
            if not ui.check_token(presented):
                response = _error(401, "unauthorized", "a valid bearer token is required")
            else:
                try:
                    response = await call_next(request)
                except ApiError as exc:
                    response = _error(exc.status, exc.code, exc.message)
                except Exception as exc:
                    log.error("unhandled error on %s: %s", path, exc.__class__.__name__)
                    response = _error(500, "internal", "internal error: %s" % exc.__class__.__name__)
            response.headers["Cache-Control"] = "no-store"
        else:
            response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        return response

    @app.get("/")
    async def index():
        return FileResponse(str(STATIC_DIR / "index.html"))

    @app.get("/favicon.ico")
    async def favicon():
        return Response(status_code=204)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def runtime_versions() -> dict:
        if ui.runtime_versions is None:
            found: dict = {}
            for name in ("claude", "codex"):
                exe = shutil.which(name)
                version = None
                if exe:
                    try:
                        done = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=5,
                                              stdin=subprocess.DEVNULL)
                        version = (done.stdout or done.stderr).strip().splitlines()[0][:80] if done.returncode == 0 else None
                    except (OSError, subprocess.TimeoutExpired, IndexError):
                        version = None
                found[name] = version
            ui.runtime_versions = found
        return ui.runtime_versions

    @app.get("/api/health")
    async def health():
        versions = await asyncio.to_thread(runtime_versions)
        return {"ok": True, "version": OMEGA_VERSION, "python": platform.python_version(), "runtimes": versions,
                "hooks_verified": {k: bool(v) for k, v in ui.hooks_verified.items()},
                "allow_unhooked": os.environ.get("OMEGA_ALLOW_UNHOOKED") == "1"}

    @app.get("/api/keys")
    async def list_keys():
        return ui.manager.list_keys(USER_ID)

    def _provider(provider: str) -> str:
        if provider not in PROVIDERS:
            raise ApiError(404, "not_found", "unknown provider")
        return provider

    @app.put("/api/keys/{provider}")
    async def put_key(provider: str, request: Request):
        _provider(provider)
        body = await _json_body(request)
        try:
            entry = ui.manager.set_key(USER_ID, provider, body.get("key"))
        except KeyRejected as exc:
            raise ApiError(400, "invalid_key", str(exc))
        log.info("stored %s key %s (last4 %s)", provider, "****", entry["last4"])
        return entry

    @app.delete("/api/keys/{provider}")
    async def delete_key(provider: str):
        _provider(provider)
        try:
            ui.manager.delete_key(USER_ID, provider)
        except KeyError:
            raise ApiError(404, "not_found", "no %s key is stored" % provider)
        log.info("deleted %s key", provider)
        return Response(status_code=204)

    @app.post("/api/keys/{provider}/verify")
    async def verify_key(provider: str):
        _provider(provider)
        try:
            return await asyncio.to_thread(ui.manager.verify_key, USER_ID, provider)
        except KeyError:
            raise ApiError(404, "not_found", "no %s key is stored" % provider)
        except PermissionError as exc:
            return {"status": "invalid", "detail": str(exc)}

    def project_view(project: dict, detail: bool) -> dict:
        view = dict(project)
        if detail:
            workspace = project["path"]
            pcfg = config_mod.load(OMEGA_ROOT, workspace)
            view["clearances"] = clearance_view(workspace, pcfg)
            view["contracts"] = contract_rows(workspace, pcfg)
        return view

    @app.get("/api/projects")
    async def list_projects():
        return ui.projects.list()

    @app.post("/api/projects")
    async def create_project(request: Request):
        body = await _json_body(request)
        name = _text_field(body, "name", 200)
        raw_path = _text_field(body, "path", 4096)
        if not os.path.isabs(raw_path):
            raise ApiError(400, "invalid", "path must be absolute")
        workspace = os.path.realpath(raw_path)
        if not os.path.isdir(workspace):
            raise ApiError(400, "invalid", "path is not an existing directory")
        if any(p["path"] == workspace for p in ui.projects.list()):
            raise ApiError(409, "exists", "a project already points at this path")
        project = {"id": "prj-" + secrets.token_hex(4), "name": name, "path": workspace, "created_at": _now_iso()}
        try:
            rc, out, err = await asyncio.to_thread(ui.cli, "scripts/install_workspace.py",
                                                   [workspace, "--provider", "both"],
                                                   {"OMEGA_STATE_DIR": str(ui.state_root)})
            project["installed"] = rc == 0
            project["install_detail"] = redaction.redact_text((err or out or "").strip()[-500:])
        except Unavailable as exc:
            project["installed"] = False
            project["install_detail"] = str(exc)
        ui.projects.save(project)
        log.info("project %s created", project["id"])
        return project_view(project, True)

    @app.get("/api/projects/{project_id}")
    async def get_project(project_id: str):
        return await asyncio.to_thread(project_view, ui.projects.get(project_id), True)

    @app.get("/api/projects/{project_id}/clearances")
    async def get_clearances(project_id: str):
        project = ui.projects.get(project_id)
        return await asyncio.to_thread(clearance_view, project["path"], config_mod.load(OMEGA_ROOT, project["path"]))

    async def ensure_hooks(choice: Choice, env: dict) -> None:
        if os.environ.get("OMEGA_ALLOW_UNHOOKED") == "1":
            return
        if ui.hooks_verified.get(choice.runtime) is None:
            try:
                ok = await ui.runner.verify_hooks_fire(choice.runtime, ui.cfg, env=env, state_root=ui.state_root)
            except Exception as exc:
                log.warning("hook probe failed: %s", exc.__class__.__name__)
                ok = False
            ui.hooks_verified[choice.runtime] = bool(ok)
        if not ui.hooks_verified.get(choice.runtime):
            raise ApiError(503, "hooks_unverified",
                           "hooks did not fire under --bare --settings; set OMEGA_ALLOW_UNHOOKED=1 to override")

    async def watch_approvals(run_id: str) -> None:
        seen: set = set()
        while True:
            await asyncio.sleep(ui.approval_poll_s)
            run = ui.runs.get(run_id) or {}
            if run.get("status") not in ACTIVE:
                return
            directory = _session_dir_for(run.get("workspace") or "", run.get("runtime"), run.get("session_id"))
            if directory is None:
                continue
            request = state.read_json(directory / "contract_request.json", None)
            if not isinstance(request, dict) or request.get("consumed") or request.get("ts_ns") in seen:
                continue
            seen.add(request.get("ts_ns"))
            proposal = state.read_json(directory / "contract_proposal.json", {}) or {}
            for item in pending_approvals(ui, run) or [{"slug": None, "proposal_id": proposal.get("proposal_id")}]:
                ui.hub.pub(run_id, _ev("approval_request", slug=item.get("slug"), proposal_id=item.get("proposal_id")))

    async def launch(run: dict, choice: Choice, env: dict) -> None:
        run_id = run["run_id"]
        try:
            await ui.runner.start_run(run, choice, env, run["workspace"], ui.hub, ui.cfg)
        except Exception as exc:
            log.error("run %s crashed: %s", run_id, exc.__class__.__name__)
            ui.hub.pub(run_id, _ev("error", message="the runner crashed: %s" % exc.__class__.__name__))
            ui.hub.pub(run_id, _ev("status", status="failed"))
        finally:
            ui.prompts.pop(run_id, None)
            current = ui.runs.get(run_id) or {}
            if current.get("status") in ACTIVE:
                ui.hub.pub(run_id, _ev("status", status="failed"))

    @app.post("/api/runs")
    async def create_run(request: Request):
        body = await _json_body(request)
        project = ui.projects.get(str(body.get("project_id") or ""))
        role = body.get("role") or "implementer"
        if role not in ROLES:
            raise ApiError(400, "invalid", "role must be one of %s" % ", ".join(ROLES))
        provider = body.get("provider")
        if provider is not None and provider not in PROVIDERS:
            raise ApiError(400, "invalid", "provider must be null or one of %s" % ", ".join(PROVIDERS))
        model = body.get("model")
        if model is not None and (not isinstance(model, str) or not re.match(r"^[\w.\-\[\]]{1,100}$", model)):
            raise ApiError(400, "invalid", "model is not a model id")
        prompt = _text_field(body, "prompt", MAX_PROMPT)
        permission_mode = body.get("permission_mode") or "acceptEdits"
        if permission_mode not in PERMISSION_MODES:
            raise ApiError(400, "invalid", "permission_mode must be one of %s" % ", ".join(PERMISSION_MODES))
        budget = body.get("budget_usd")
        if budget is not None and (isinstance(budget, bool) or not isinstance(budget, (int, float)) or budget <= 0):
            raise ApiError(400, "invalid", "budget_usd must be a positive number")
        if any(r.get("project_id") == project["id"] and r.get("status") in ACTIVE for r in ui.runs.list()):
            raise ApiError(409, "busy", "this project already has a running run")
        try:
            choice = ui.manager.choose(role, provider, model, user_id=USER_ID)
        except NoProvider as exc:
            raise ApiError(400, "no_provider", str(exc))
        run_id = ui.runs.new_id()
        try:
            budget_plan = ui.manager.preflight(choice, prompt, run_id=run_id, budget_usd=budget)
        except costledger.UnknownModel as exc:
            raise ApiError(400, "unknown_model", "no price for model %s; fix cost.prices" % exc.args[0])
        except BudgetExceeded as exc:
            log.info("run refused by tokentoll: %s", exc)
            raise ApiError(402, "budget_exceeded", str(exc))
        run_dir = ui.runs.root / run_id
        run = {"run_id": run_id, "project_id": project["id"], "role": role, "provider": choice.provider,
               "model": choice.model, "runtime": choice.runtime, "status": "queued", "started_at": _now_iso(),
               "ended_at": None, "cost_usd": None, "session_id": None, "exit_code": None,
               "budget_usd": budget_plan["max_budget_usd"], "est_usd": budget_plan["est_usd"],
               "workspace": project["path"], "permission_mode": permission_mode}
        env_run = dict(run, human_log=str(run_dir / "human_turns.jsonl"))
        env = ui.manager.env_for(USER_ID, choice, env_run)
        await ensure_hooks(choice, env)
        if any(r.get("project_id") == project["id"] and r.get("status") in ACTIVE for r in ui.runs.list()):
            raise ApiError(409, "busy", "this project already has a running run")
        ui.runs.create(run)
        ui.append_human(ui.runs.human_log(run_id), "prompt", prompt, run_id)
        live = dict(run, dir=str(run_dir), state_root=str(ui.state_root), prompt=prompt,
                    max_budget_usd=budget_plan["max_budget_usd"], human_log=env_run["human_log"])
        ui.prompts[run_id] = live
        ui.hub.pub(run_id, _ev("status", status="queued"))
        log.info("run %s queued on %s/%s (est $%.4f, budget $%.2f)", run_id, choice.provider, choice.model,
                 budget_plan["est_usd"], budget_plan["max_budget_usd"])
        ui.spawn(launch(live, choice, env))
        ui.spawn(watch_approvals(run_id))
        return {"run_id": run_id}

    @app.get("/api/runs")
    async def list_runs():
        return ui.runs.list()

    def _run(run_id: str) -> dict:
        run = ui.runs.get(run_id)
        if run is None:
            raise ApiError(404, "not_found", "unknown run")
        return run

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str):
        return _run(run_id)

    @app.post("/api/runs/{run_id}/cancel")
    async def cancel_run(run_id: str):
        run = _run(run_id)
        if run.get("status") not in ACTIVE:
            raise ApiError(409, "not_running", "the run is %s" % run.get("status"))
        ui.stop_run(run_id, "cancelled")
        return JSONResponse({"run_id": run_id, "status": "cancelled"}, status_code=202)

    @app.get("/api/runs/{run_id}/events")
    async def run_events(run_id: str, after: int = 0, limit: int = 500):
        _run(run_id)
        return ui.runs.events(run_id, max(0, after), max(1, min(limit, 5000)))

    @app.get("/api/runs/{run_id}/approvals")
    async def run_approvals(run_id: str):
        return await asyncio.to_thread(pending_approvals, ui, _run(run_id))

    def _record(ctx, quote: str, turns: list, log_path: Path) -> tuple:
        with ui.env_lock:
            previous = os.environ.get("OMEGA_HUMAN_LOG")
            os.environ["OMEGA_HUMAN_LOG"] = str(log_path)
            try:
                return ui.gates.record(ctx, quote, turns)
            finally:
                if previous is None:
                    os.environ.pop("OMEGA_HUMAN_LOG", None)
                else:
                    os.environ["OMEGA_HUMAN_LOG"] = previous

    @app.post("/api/runs/{run_id}/approvals")
    async def approve(run_id: str, request: Request):
        run = _run(run_id)
        body = await _json_body(request)
        text = _text_field(body, "text", MAX_TEXT)
        slug = body.get("slug")
        if slug is not None and (not isinstance(slug, str) or len(slug) > 200):
            raise ApiError(400, "invalid", "slug must be a string")
        log_path = ui.runs.human_log(run_id)
        ui.append_human(log_path, "approval", text, run_id)
        log.info("approval text recorded for run %s", run_id)
        turns, bad = ui.verified_turns(log_path)
        if bad:
            return {"accepted": False, "reason": "the human-turn log has %d row(s) whose signature does not verify; "
                                                 "refusing to record from a tampered log" % bad}
        ctx = ui.session_ctx(run)
        if ctx is None:
            return {"accepted": False, "reason": "the run has no agent session yet, so there is nothing to approve"}
        try:
            accepted, reason = await asyncio.to_thread(_record, ctx, text, turns, log_path)
        except Unavailable as exc:
            return {"accepted": False, "reason": str(exc)}
        return {"accepted": bool(accepted), "reason": redaction.redact_text(str(reason))}

    @app.post("/api/runs/{run_id}/override")
    async def override(run_id: str, request: Request):
        run = _run(run_id)
        body = await _json_body(request)
        reason = _text_field(body, "reason", MAX_TEXT)
        ctx = ui.session_ctx(run)
        if ctx is None:
            return {"accepted": False, "reason": "the run has no agent session yet"}
        token = state.read_override_token(ctx)
        if not token:
            return {"accepted": False, "reason": "this session has no override token"}
        log_path = ui.runs.human_log(run_id)
        ui.append_human(log_path, "override", token, run_id)
        _, bad = ui.verified_turns(log_path)
        if bad:
            return {"accepted": False, "reason": "the human-turn log has %d row(s) whose signature does not verify" % bad}
        env = {"OMEGA_STATE_DIR": str(ui.state_root), "OMEGA_WORKSPACE": ctx.workspace,
               "OMEGA_HUMAN_LOG": str(log_path), "OMEGA_PROVIDER": ctx.provider,
               "OMEGA_SESSION_ID": ctx.session_id, "OMEGA_RUN_ID": run_id}
        try:
            rc, out, err = await asyncio.to_thread(
                ui.cli, "bin/stop_orchestrator.py",
                ["override", "--session", ctx.session_id, "--token", token, "--reason", reason], env)
        except Unavailable as exc:
            return {"accepted": False, "reason": str(exc)}
        detail = (out or err or "").strip()
        return {"accepted": rc == 0, "reason": redaction.redact_text(detail[-1000:])}

    @app.post("/api/projects/{project_id}/ship")
    async def ship(project_id: str, request: Request):
        project = ui.projects.get(project_id)
        body = await _json_body(request)
        dry_run = body.get("dry_run", True) is not False
        base = body.get("base") or "main"
        if not isinstance(base, str) or not re.match(r"^[\w./\-]{1,100}$", base) or base.startswith("-"):
            raise ApiError(400, "invalid", "base is not a branch name")
        title = body.get("title")
        if title is not None and (not isinstance(title, str) or len(title) > 200):
            raise ApiError(400, "invalid", "title must be a short string")
        args = ["--workspace", project["path"], "--base", base, "--json"]
        if title:
            args += ["--title", title]
        env = {"OMEGA_STATE_DIR": str(ui.state_root), "OMEGA_WORKSPACE": project["path"]}
        if dry_run:
            args.append("--dry-run")
        else:
            runs = [r for r in ui.runs.list() if r.get("project_id") == project_id]
            log_path = ui.runs.human_log(runs[0]["run_id"]) if runs else ui.ui_dir / "projects" / project_id / "human_turns.jsonl"
            ui.append_human(log_path, "ship", "ship %s to %s" % (project["name"], base), runs[0]["run_id"] if runs else None)
            args.append("--yes")
            env.update({"GIT_ASKPASS": str(OMEGA_ROOT / "bin" / "git-askpass.sh"), "GIT_TERMINAL_PROMPT": "0",
                        "OMEGA_HUMAN_LOG": str(log_path)})
            if os.environ.get("OMEGA_GIT_TOKEN"):
                env["OMEGA_GIT_TOKEN"] = os.environ["OMEGA_GIT_TOKEN"]
            log.info("ship requested for project %s", project_id)
        try:
            rc, out, err = await asyncio.to_thread(ui.cli, "scripts/auto_ship.py", args, env)
        except Unavailable as exc:
            raise ApiError(503, "unavailable", str(exc))
        try:
            parsed = json.loads(out) if out.strip() else None
        except ValueError:
            parsed = None
        return {"rc": rc, "dry_run": dry_run, "result": redact_value(parsed),
                "stderr": redaction.redact_text((err or "")[-4000:])}

    @app.get("/api/cost/report")
    async def cost_report(month: Optional[str] = None, run_id: Optional[str] = None):
        if month is not None and not re.match(r"^\d{4}-\d{2}$", month):
            raise ApiError(400, "invalid", "month must be YYYY-MM")
        if run_id is not None and not RUN_ID_PATTERN.match(run_id):
            raise ApiError(400, "invalid", "run_id is not a run id")
        verdict = costledger.check(ui.cfg, run_id=run_id, month=month, allow_unknown=True)
        report = {"source": "costledger", "status": verdict.status, "breaches": verdict.breaches,
                  "warnings": verdict.warnings, "sums": verdict.sums, "caps": verdict.sums.get("caps")}
        args = ["report", "--json"] + (["--month", month] if month else []) + (["--run-id", run_id] if run_id else [])
        try:
            rc, out, _ = await asyncio.to_thread(ui.cli, "hooks/tokentoll_gate.py", args,
                                                 {"OMEGA_STATE_DIR": str(ui.state_root)}, 60)
            if out.strip():
                report["tokentoll"] = json.loads(out)
                report["tokentoll_rc"] = rc
        except (Unavailable, ValueError):
            pass
        return report

    @app.websocket("/ws/runs/{run_id}")
    async def ws_run(websocket: WebSocket, run_id: str):
        if not ui.check_token(websocket.query_params.get("token")):
            await websocket.close(code=4401)
            return
        if not ui.origin_ok(websocket.headers.get("origin")):
            await websocket.close(code=4403)
            return
        if ui.runs.get(run_id) is None:
            await websocket.close(code=4404)
            return
        try:
            after = max(0, int(websocket.query_params.get("after") or 0))
        except ValueError:
            after = 0
        queue = ui.hub.sub(run_id)
        await websocket.accept()
        receiver: Optional[asyncio.Task] = None
        getter: Optional[asyncio.Task] = None
        try:
            last = after
            for row in ui.runs.events(run_id, after):
                await websocket.send_json(row)
                last = row["seq"]
            receiver = asyncio.ensure_future(websocket.receive())
            while True:
                getter = asyncio.ensure_future(queue.get())
                done, _ = await asyncio.wait({receiver, getter}, timeout=ui.ping_interval_s,
                                             return_when=asyncio.FIRST_COMPLETED)
                if getter in done:
                    row = getter.result()
                    if row["seq"] > last:
                        await websocket.send_json(row)
                        last = row["seq"]
                else:
                    getter.cancel()
                if receiver in done:
                    message = receiver.result()
                    if message.get("type") == "websocket.disconnect":
                        break
                    receiver = asyncio.ensure_future(websocket.receive())
                if not done:
                    await websocket.send_json({"run_id": run_id, "seq": last, "ts": _now_iso(), "ts_ns": time.time_ns(),
                                               "role": None, "runtime": None, "kind": "ping", "data": {}})
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            ui.hub.unsub(run_id, queue)
            for task in (receiver, getter):
                if task is not None and not task.done():
                    task.cancel()

    return app


def main(argv: Optional[list] = None) -> int:
    import uvicorn
    cfg = config_mod.load(OMEGA_ROOT)
    parser = argparse.ArgumentParser(prog="python -m ui.server")
    parser.add_argument("--host", default=cfg.get("ui.host", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(cfg.get("ui.port", 8787)))
    args = parser.parse_args(argv)
    origins = ["http://%s:%d" % (h, args.port) for h in sorted({args.host, "127.0.0.1", "localhost"})]
    origins += [o.strip().rstrip("/") for o in os.environ.get("OMEGA_UI_ORIGINS", "").split(",") if o.strip()]
    app = create_app(cfg=cfg, origins=origins)
    server_config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info")
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).addFilter(redaction.RedactingFilter())
    url = "http://%s:%d/" % (args.host, args.port)
    if app.state.token_generated:
        sys.stderr.write("[omega-ui] open %s#token=%s (token stored 0600 in %s)\n"
                         % (url, app.state.ui.token, app.state.ui.ui_dir / "ui_token"))
    else:
        sys.stderr.write("[omega-ui] open %s and paste the token from OMEGA_UI_TOKEN or %s\n"
                         % (url, app.state.ui.ui_dir / "ui_token"))
    uvicorn.Server(server_config).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

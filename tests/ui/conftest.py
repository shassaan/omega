from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path

import pytest

from tests.conftest import OMEGA_ROOT, wait_for

try:
    import cryptography
    import fastapi
    import httpx
except ImportError:
    collect_ignore_glob = ["test_*.py"]
    TestClient = None
    server_mod = None
else:
    from fastapi.testclient import TestClient
    from ui import server as server_mod

TOKEN = "ui-test-token-" + "7f3a9c2e5b1d"
ORIGIN = "http://testserver"
TERMINAL = ("done", "failed", "cancelled", "budget_exceeded")


def synthetic_key(provider: str) -> str:
    body = secrets.token_urlsafe(60).replace("-", "q").replace("_", "z")
    if provider == "anthropic":
        return "sk-ant-api03-" + body
    if provider == "openai":
        return "sk-proj-" + body
    return "AIza" + body[:35]


def default_script(run_id_session="sess-ui-0001", usd=0.0123):
    async def script(run, hub, runner):
        run_id = run["run_id"]
        hub.pub(run_id, {"kind": "status", "data": {"status": "running", "session_id": run_id_session}})
        hub.pub(run_id, {"kind": "text", "data": {"delta": "Working on it"}})
        hub.pub(run_id, {"kind": "tool_call", "data": {"id": "toolu_1", "name": "Bash", "input_summary": "pytest -q"}})
        hub.pub(run_id, {"kind": "tool_result", "data": {"id": "toolu_1", "ok": True, "summary": "1 passed"}})
        await runner.gate()
        hub.pub(run_id, {"kind": "usage", "data": {"in": 100, "out": 20, "cache_read": 0, "cache_write": 0,
                                                   "usd": usd, "source": "cli_result"}})
        hub.pub(run_id, {"kind": "done", "data": {"exit_code": 0, "is_error": False, "cost_usd": usd,
                                                  "session_id": run_id_session}})
        hub.pub(run_id, {"kind": "status", "data": {"status": "done"}})
    return script


class StubRunner:
    def __init__(self, script=None, hooks_ok=True):
        self.calls: list = []
        self.probes: list = []
        self.script = script or default_script()
        self.hooks_ok = hooks_ok
        self.release = threading.Event()
        self.release.set()

    def hold(self) -> None:
        self.release.clear()

    async def gate(self) -> None:
        while not self.release.is_set():
            await asyncio.sleep(0.01)

    async def start_run(self, run, choice, env, workspace, hub, cfg):
        self.calls.append({"run": dict(run), "choice": choice, "env": dict(env), "workspace": workspace})
        await self.script(run, hub, self)

    async def verify_hooks_fire(self, runtime, cfg, env=None, state_root=None):
        self.probes.append(runtime)
        return self.hooks_ok


class StubCli:
    def __init__(self):
        self.calls: list = []
        self.results: dict = {}
        self.unavailable: set = {"hooks/tokentoll_gate.py"}

    def __call__(self, script_rel, args, env_extra, timeout=600):
        self.calls.append({"script": script_rel, "args": list(args), "env": dict(env_extra)})
        if script_rel in self.unavailable:
            raise server_mod.Unavailable("%s is not installed" % script_rel)
        return self.results.get(script_rel, (0, "{}", ""))


class StubGates:
    def __init__(self, accept=True):
        self.calls: list = []
        self.accept = accept

    def record(self, ctx, quote, turns):
        self.calls.append({"ctx": ctx, "quote": quote, "turns": list(turns),
                           "human_log": os.environ.get("OMEGA_HUMAN_LOG")})
        if callable(self.accept):
            return self.accept(ctx, quote, turns)
        return (True, "recorded") if self.accept else (False, "refused")


class UiHarness:
    def __init__(self, client, app, state_root, runner, cli, gates, workspace):
        self.client = client
        self.app = app
        self.state_root = state_root
        self.runner = runner
        self.cli = cli
        self.gates = gates
        self.workspace = workspace
        self.headers = {"Authorization": "Bearer " + TOKEN}

    @property
    def ui(self):
        return self.app.state.ui

    def get(self, path, **kw):
        return self.client.get(path, headers=self.headers, **kw)

    def post(self, path, body=None, **kw):
        return self.client.post(path, headers=self.headers, json=body if body is not None else {}, **kw)

    def put(self, path, body=None, **kw):
        return self.client.put(path, headers=self.headers, json=body if body is not None else {}, **kw)

    def delete(self, path, **kw):
        return self.client.delete(path, headers=self.headers, **kw)

    def add_key(self, provider: str, key=None) -> str:
        value = key or synthetic_key(provider)
        response = self.put("/api/keys/%s" % provider, {"key": value})
        assert response.status_code == 200, response.text
        return value

    def add_project(self, path=None, name="demo") -> dict:
        response = self.post("/api/projects", {"name": name, "path": str(path or self.workspace)})
        assert response.status_code == 200, response.text
        return response.json()

    def start_run(self, project_id: str, **body) -> str:
        payload = {"project_id": project_id, "role": "implementer", "prompt": "add a signup endpoint"}
        payload.update(body)
        response = self.post("/api/runs", payload)
        assert response.status_code == 200, response.text
        return response.json()["run_id"]

    def run(self, run_id: str) -> dict:
        return self.get("/api/runs/%s" % run_id).json()

    def wait_status(self, run_id: str, statuses=TERMINAL, timeout=20.0) -> dict:
        found = wait_for(lambda: self.run(run_id).get("status") in statuses, timeout=timeout)
        current = self.run(run_id)
        assert found, current
        return current

    def ws(self, run_id: str, after: int = 0, token: str = TOKEN, origin: str = ORIGIN):
        headers = {"origin": origin} if origin else {}
        url = "/ws/runs/%s?after=%d" % (run_id, after)
        if token is not None:
            url += "&token=%s" % token
        return self.client.websocket_connect(url, headers=headers)


def read_until(ws, kind: str, status=None, limit=200) -> list:
    seen = []
    for _ in range(limit):
        event = ws.receive_json()
        if event["kind"] == "ping":
            continue
        seen.append(event)
        if event["kind"] == kind and (status is None or event["data"].get("status") == status):
            return seen
    raise AssertionError("never saw %s: %r" % (kind, [e["kind"] for e in seen]))


@pytest.fixture
def fake_bin(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "fakebin"
    directory.mkdir()
    monkeypatch.setenv("PATH", "%s:/usr/bin:/bin" % directory)
    return directory


@pytest.fixture
def ui_factory(tmp_state, workspace, fake_bin, monkeypatch):
    monkeypatch.setenv("OMEGA_ALLOW_UNHOOKED", "1")
    opened: list = []

    def make(runner=None, cli=None, gates=None, **kw):
        runner = runner or StubRunner()
        cli = cli or StubCli()
        gates = gates or StubGates()
        app = server_mod.create_app(state_root=tmp_state, runner=runner, cli=cli, gates=gates, token=TOKEN,
                                    origins=[ORIGIN], ping_interval_s=kw.pop("ping_interval_s", 0.2),
                                    approval_poll_s=kw.pop("approval_poll_s", 0.05), **kw)
        client = TestClient(app)
        client.__enter__()
        opened.append(client)
        return UiHarness(client, app, tmp_state, runner, cli, gates, workspace)

    yield make
    for client in opened:
        client.__exit__(None, None, None)


@pytest.fixture
def ui(ui_factory) -> UiHarness:
    return ui_factory()


def write_executable(path: Path, body: str) -> Path:
    path.write_text("#!%s\n%s" % (sys.executable, body), encoding="utf-8")
    path.chmod(0o755)
    return path


def read_json_lines(path: Path) -> list:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def all_text_under(root: Path) -> str:
    chunks = []
    for item in root.rglob("*"):
        if item.is_file():
            chunks.append(item.read_bytes().decode("utf-8", "replace"))
    return "\n".join(chunks)


__all__ = ["TOKEN", "ORIGIN", "StubRunner", "StubCli", "StubGates", "default_script", "synthetic_key",
           "read_until", "write_executable", "read_json_lines", "all_text_under", "OMEGA_ROOT", "time"]

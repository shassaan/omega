from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import time
import uuid as uuid_mod
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

OMEGA_ROOT = Path(__file__).resolve().parents[1]
if str(OMEGA_ROOT) not in sys.path:
    sys.path.insert(0, str(OMEGA_ROOT))

FIXTURES = OMEGA_ROOT / "tests" / "fixtures"
GUARD_SCRIPTS = ("bin/pre_tool_use.py",)
SCRUBBED_ENV = ("OMEGA_STATE_DIR", "OMEGA_WORKSPACE", "OMEGA_PROVIDER", "OMEGA_SESSION_ID",
                "OMEGA_RUN_ID", "OMEGA_DEBUG", "OMEGA_DEV", "OMEGA_HUMAN_LOG", "OMEGA_SECRET",
                "OMEGA_UI_TOKEN", "OMEGA_GIT_TOKEN", "OMEGA_TDD_MODE", "OMEGA_BUDGET_PER_CALL_USD",
                "OMEGA_BUDGET_PER_SESSION_USD", "OMEGA_BUDGET_PER_RUN_USD", "OMEGA_BUDGET_MONTHLY_USD",
                "OMEGA_ALLOW_UNHOOKED", "CLAUDE_PROJECT_DIR", "VIRTUAL_ENV")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=omega-tests@example.com", "-c", "user.name=Harness Tests",
                    "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"] + list(args),
                   cwd=str(cwd), check=True, capture_output=True)


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path_factory):
    for name in SCRUBBED_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "0")
    default_state = tmp_path_factory.mktemp("default-state")
    monkeypatch.setenv("OMEGA_STATE_DIR", str(default_state))
    from hooks.lib import io as io_mod
    from hooks.lib import redaction
    io_mod.bind_session_dir(None)
    redaction.clear_registered()
    yield
    io_mod.bind_session_dir(None)
    redaction.clear_registered()


@pytest.fixture
def harness_root() -> Path:
    return OMEGA_ROOT


@pytest.fixture
def tmp_state(tmp_path, monkeypatch) -> Path:
    state_dir = Path(os.path.realpath(str(tmp_path))) / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("OMEGA_STATE_DIR", str(state_dir))
    return state_dir


@pytest.fixture
def workspace(tmp_path, monkeypatch, tmp_state) -> Path:
    ws = Path(os.path.realpath(str(tmp_path))) / "ws"
    for rel in ("src", "tests", "docs/contracts"):
        (ws / rel).mkdir(parents=True, exist_ok=True)
    (ws / ".gitignore").write_text(".omega/\n.venv/\n__pycache__/\n", encoding="utf-8")
    (ws / "README.md").write_text("# throwaway workspace\n", encoding="utf-8")
    (ws / "src" / "__init__.py").write_text("", encoding="utf-8")
    _git(ws, "init", "-q")
    _git(ws, "add", "-A")
    _git(ws, "commit", "-q", "-m", "init")
    (ws / ".omega").mkdir(exist_ok=True)
    (ws / ".omega" / "config.json").write_text(json.dumps({"tdd": {"debounce_s": 0.05}}), encoding="utf-8")
    monkeypatch.setenv("OMEGA_WORKSPACE", str(ws))
    return ws


def _payload(provider: str, event: str, overrides: dict) -> dict:
    source = FIXTURES / provider / ("%s.json" % event)
    data = json.loads(source.read_text(encoding="utf-8"))
    workspace_dir = os.environ.get("OMEGA_WORKSPACE")
    if workspace_dir:
        data["cwd"] = workspace_dir
        tool_input = data.get("tool_input")
        if isinstance(tool_input, dict) and isinstance(tool_input.get("file_path"), str):
            tool_input["file_path"] = tool_input["file_path"].replace("/workspace", workspace_dir, 1)
        response = data.get("tool_response")
        if isinstance(response, dict) and isinstance(response.get("filePath"), str):
            response["filePath"] = response["filePath"].replace("/workspace", workspace_dir, 1)
    data = copy.deepcopy(data)
    data.update(overrides)
    return data


@pytest.fixture
def claude_payload():
    def make(event: str, **overrides) -> dict:
        return _payload("claude", event, overrides)
    return make


@pytest.fixture
def codex_payload():
    def make(event: str, **overrides) -> dict:
        return _payload("codex", event, overrides)
    return make


class TranscriptWriter:
    def __init__(self, directory: Path, session_id: str = "sess-claude-0001"):
        self.path = Path(directory) / ("%s.jsonl" % session_id)
        self.session_id = session_id
        self.clock = datetime.now(timezone.utc) - timedelta(minutes=30)
        self.path.write_text("", encoding="utf-8")

    def _stamp(self, ts=None) -> str:
        if ts is not None:
            if isinstance(ts, datetime):
                return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            return str(ts)
        self.clock = max(self.clock + timedelta(milliseconds=5), datetime.now(timezone.utc))
        return self.clock.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def raw(self, row) -> Path:
        with open(str(self.path), "a", encoding="utf-8") as handle:
            handle.write((row if isinstance(row, str) else json.dumps(row)) + "\n")
        return self.path

    def _user(self, content, ts=None, **extra) -> Path:
        row = {"type": "user", "uuid": str(uuid_mod.uuid4()), "parentUuid": None, "sessionId": self.session_id,
               "timestamp": self._stamp(ts), "cwd": os.environ.get("OMEGA_WORKSPACE", "/workspace"),
               "isSidechain": False, "userType": "external", "entrypoint": "cli",
               "message": {"role": "user", "content": content}}
        row.update(extra)
        return self.raw(row)

    def human(self, text: str, ts=None, **extra) -> Path:
        extra.setdefault("promptSource", "typed")
        extra.setdefault("origin", {"kind": "human"})
        return self._user(text, ts, **extra)

    def sdk(self, text: str, ts=None, **extra) -> Path:
        extra.setdefault("promptSource", "sdk")
        extra.setdefault("entrypoint", "sdk-cli")
        return self._user(text, ts, **extra)

    def meta(self, text: str, ts=None, **extra) -> Path:
        extra.setdefault("isMeta", True)
        return self._user(text, ts, **extra)

    def assistant(self, text: str, usage=None, ts=None, message_id=None, model="claude-opus-5-5") -> Path:
        message = {"id": message_id or "msg_%s" % uuid_mod.uuid4().hex[:12], "role": "assistant", "model": model,
                   "content": [{"type": "text", "text": text}]}
        if usage is not None:
            message["usage"] = usage
        return self.raw({"type": "assistant", "uuid": str(uuid_mod.uuid4()), "timestamp": self._stamp(ts),
                         "isSidechain": False, "message": message})

    def tool_result(self, text: str, ts=None) -> Path:
        return self._user([{"type": "tool_result", "tool_use_id": "toolu_%s" % uuid_mod.uuid4().hex[:8],
                            "content": text, "is_error": False}], ts,
                          toolUseResult={"stdout": text}, sourceToolAssistantUUID=str(uuid_mod.uuid4()))

    def compact_summary(self, text: str, ts=None) -> Path:
        return self._user("This session is being continued from a previous conversation that ran out of "
                          "context. " + text, ts, isCompactSummary=True, isVisibleInTranscriptOnly=True)

    def slash(self, command: str, ts=None) -> Path:
        name = command.lstrip("/")
        return self._user("<command-name>/%s</command-name>\n<command-message>%s</command-message>\n"
                          "<command-args></command-args>" % (name, name), ts, promptSource="typed")

    def sidechain(self, text: str, ts=None) -> Path:
        return self._user(text, ts, isSidechain=True, promptSource="typed")

    def interrupt(self, ts=None) -> Path:
        return self._user([{"type": "text", "text": "[Request interrupted by user]"}], ts, promptSource="typed")


@pytest.fixture
def transcript_writer(tmp_path):
    def make(directory=None, session_id: str = "sess-claude-0001") -> TranscriptWriter:
        return TranscriptWriter(Path(directory) if directory else tmp_path, session_id)
    writer = TranscriptWriter(tmp_path)
    writer.make = make
    return writer


@pytest.fixture
def run_hook():
    def run(script_rel: str, payload, provider: str, env=None, args=None, timeout=120):
        command = ["/bin/sh", str(OMEGA_ROOT / "bin" / "launch.sh")]
        if script_rel in GUARD_SCRIPTS:
            command.append("--guard")
        command += [script_rel, "--provider", provider] + list(args or [])
        merged = dict(os.environ)
        merged.update(env or {})
        data = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return subprocess.run(command, input=data if isinstance(data, str) else data.decode("utf-8"),
                              capture_output=True, text=True, env=merged, timeout=timeout,
                              cwd=str(OMEGA_ROOT))
    return run


def make_session_context(provider: str = "claude", session_id=None, transcript_path=None, event="SessionStart"):
    from hooks.lib import event as event_mod
    from hooks.lib import state
    payload = _payload(provider, event, {})
    payload["session_id"] = session_id or payload["session_id"]
    payload["transcript_path"] = str(transcript_path) if transcript_path else None
    return state.configure(event_mod.normalize(payload, provider))


@pytest.fixture
def make_session(workspace):
    def make(provider: str = "claude", session_id=None, transcript_path=None):
        return make_session_context(provider, session_id, transcript_path)
    return make


@pytest.fixture
def session(workspace):
    return make_session_context("claude")


FAKE_TESTS = {
    "pass": "def test_fake():\n    assert 1 + 1 == 2\n",
    "fail": "def test_fake():\n    assert 1 + 1 == 3\n",
    "error": "import harness_missing_first_party_module\n\ndef test_fake():\n    assert True\n",
}


@pytest.fixture
def fake_pytest():
    def write(workspace_dir, outcome: str, rel: str = "tests/test_fake.py") -> Path:
        target = Path(workspace_dir) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(FAKE_TESTS[outcome], encoding="utf-8")
        return target
    return write


def wait_for(predicate, timeout: float = 30.0, interval: float = 0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return predicate()

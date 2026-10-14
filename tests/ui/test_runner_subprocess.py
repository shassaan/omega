from __future__ import annotations

import asyncio
import json

from cryptography.fernet import Fernet

from hooks.lib import config as config_mod
from hooks.lib import costledger
from tests.conftest import OMEGA_ROOT
from tests.ui.conftest import TOKEN, read_json_lines, read_until, write_executable
from ui import server as server_mod

FAKE_CLAUDE = r'''
import json, os, sys
with open(DUMP, "w") as handle:
    json.dump({"argv": sys.argv, "env": dict(os.environ), "cwd": os.getcwd()}, handle)
key = os.environ.get("ANTHROPIC_API_KEY", "")
lines = [
    {"type": "system", "subtype": "init", "session_id": "sess-fake-1", "model": "claude-sonnet-5-5", "tools": ["Bash"]},
    {"type": "stream_event", "event": {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hel"}}},
    {"type": "stream_event", "event": {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "lo, my key is " + key}}},
    {"type": "assistant", "message": {"id": "msg_1", "content": [{"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "pytest -q"}}]}},
    {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "1 passed", "is_error": False}]}},
    {"type": "mystery_event", "payload": "x" * 5000},
    {"type": "result", "subtype": "success", "is_error": False, "result": "done", "session_id": "sess-fake-1", "total_cost_usd": 0.0123, "usage": {"input_tokens": 100, "output_tokens": 20, "cache_read_input_tokens": 5, "cache_creation_input_tokens": 0}},
]
for line in lines:
    print(json.dumps(line), flush=True)
print("not json at all " + key, flush=True)
print("stderr chatter " + key, file=sys.stderr, flush=True)
'''

FAKE_CODEX = r'''
import json, os, sys
with open(DUMP, "w") as handle:
    json.dump({"argv": sys.argv, "env": dict(os.environ)}, handle)
lines = [
    {"type": "thread.started", "thread_id": "thread-fake-1"},
    {"type": "turn.started"},
    {"type": "item.started", "item": {"id": "item_0", "type": "command_execution", "command": "bash -lc ls", "status": "in_progress"}},
    {"type": "item.completed", "item": {"id": "item_0", "type": "command_execution", "command": "bash -lc ls", "aggregated_output": "src tests", "exit_code": 0, "status": "completed"}},
    {"type": "item.completed", "item": {"id": "item_1", "type": "agent_message", "text": "Done."}},
    {"type": "turn.completed", "usage": {"input_tokens": 2000, "cached_input_tokens": 500, "output_tokens": 100, "reasoning_output_tokens": 50}},
]
for line in lines:
    print(json.dumps(line), flush=True)
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
'''


def _install_fake(fake_bin, tmp_path, name, body):
    dump = tmp_path / ("%s-dump.json" % name)
    write_executable(fake_bin / name, "DUMP = %r\n%s" % (str(dump), body))
    return dump


def _real_runner_app(ui_factory):
    return ui_factory(runner=server_mod.DEFAULT_RUNNER)


def test_claude_key_travels_in_env_never_in_argv(ui_factory, fake_bin, tmp_path, monkeypatch):
    monkeypatch.setenv("OMEGA_SECRET", Fernet.generate_key().decode())
    monkeypatch.setenv("OMEGA_UI_TOKEN", "operator-token-should-not-leak")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-server-env-key-should-not-leak")
    dump = _install_fake(fake_bin, tmp_path, "claude", FAKE_CLAUDE)
    ui = _real_runner_app(ui_factory)
    key = ui.add_key("anthropic")
    project = ui.add_project()
    run_id = ui.start_run(project["id"], role="research")
    run = ui.wait_status(run_id)
    assert run["status"] == "done", run
    seen = json.loads(dump.read_text(encoding="utf-8"))
    assert all(key not in arg for arg in seen["argv"])
    assert seen["argv"][1:3] == ["-p", "add a signup endpoint"]
    assert "--bare" in seen["argv"] and "--settings" in seen["argv"]
    assert seen["argv"][seen["argv"].index("--model") + 1] == "claude-sonnet-5-5"
    assert float(seen["argv"][seen["argv"].index("--max-budget-usd") + 1]) == 3.0
    settings = json.loads(open(seen["argv"][seen["argv"].index("--settings") + 1]).read())
    assert "PreToolUse" in settings["hooks"] and str(OMEGA_ROOT) in json.dumps(settings)
    env = seen["env"]
    assert env["ANTHROPIC_API_KEY"] == key
    assert [k for k in env if k.endswith("_API_KEY")] == ["ANTHROPIC_API_KEY"]
    for forbidden in ("OMEGA_SECRET", "OMEGA_UI_TOKEN", "OMEGA_GIT_TOKEN", "OPENAI_API_KEY"):
        assert forbidden not in env
    assert env["OMEGA_RUN_ID"] == run_id and env["OMEGA_PROVIDER"] == "claude"
    assert env["OMEGA_HUMAN_LOG"].endswith("/ui/runs/%s/human_turns.jsonl" % run_id)
    assert seen["cwd"] == project["path"]
    run_dir = ui.state_root / "ui" / "runs" / run_id
    for name in ("events.jsonl", "stdout.log", "stderr.log", "run.json"):
        text = (run_dir / name).read_text(encoding="utf-8")
        assert key not in text, name
        assert "operator-token-should-not-leak" not in text
    assert "stderr chatter [REDACTED:" in (run_dir / "stderr.log").read_text(encoding="utf-8")
    events = read_json_lines(run_dir / "events.jsonl")
    kinds = [e["kind"] for e in events]
    assert kinds[:3] == ["status", "status", "status"]
    assert 1 <= kinds.count("text") <= 2
    text = "".join(e["data"]["delta"] for e in events if e["kind"] == "text")
    assert text.startswith("Hello, my key is [REDACTED:")
    assert [e["data"]["name"] for e in events if e["kind"] == "tool_call"] == ["Bash"]
    assert [e["data"]["ok"] for e in events if e["kind"] == "tool_result"] == [True]
    raws = [e for e in events if e["kind"] == "raw"]
    assert {r["data"]["type"] for r in raws} == {"mystery_event", "stdout_text"}
    assert all(len(r["data"]["truncated"]) <= server_mod.SUMMARY_LIMIT + 1 for r in raws)
    done = [e for e in events if e["kind"] == "done"][0]["data"]
    assert done == {"exit_code": 0, "is_error": False, "cost_usd": 0.0123, "session_id": "sess-fake-1"}
    assert run["session_id"] == "sess-fake-1" and run["cost_usd"] == 0.0123
    rows = [r for r in costledger.rows(ui.ui.cfg) if r.get("run_id") == run_id]
    assert len(rows) == 1 and rows[0]["source"] == "cli_result" and rows[0]["usd"] == 0.0123
    assert rows[0]["model"] == "claude-sonnet-5-5" and rows[0]["verified_price"] is True


def test_codex_run_is_normalized_and_priced_from_the_table(ui_factory, fake_bin, tmp_path):
    dump = _install_fake(fake_bin, tmp_path, "codex", FAKE_CODEX)
    ui = _real_runner_app(ui_factory)
    key = ui.add_key("openai")
    project = ui.add_project()
    run_id = ui.start_run(project["id"])
    with ui.ws(run_id) as ws:
        events = read_until(ws, "status", status="done")
    seen = json.loads(dump.read_text(encoding="utf-8"))
    assert seen["argv"][1:4] == ["exec", "--json", "--sandbox"]
    assert seen["argv"][-1] == "add a signup endpoint" and "-m" in seen["argv"]
    assert all(key not in arg for arg in seen["argv"]) and seen["env"]["OPENAI_API_KEY"] == key
    kinds = [e["kind"] for e in events]
    assert kinds == ["status", "status", "status", "tool_call", "tool_result", "text", "usage", "done", "status"]
    usage = [e for e in events if e["kind"] == "usage"][0]["data"]
    assert usage["in"] == 2000 and usage["out"] == 150 and usage["cache_read"] == 500
    rows = [r for r in costledger.rows(ui.ui.cfg) if r.get("run_id") == run_id]
    assert len(rows) == 1 and rows[0]["verified_price"] is False and rows[0]["usd"] > 0
    assert usage["cumulative_usd"] == round(rows[0]["usd"], 6)
    assert ui.run(run_id)["session_id"] == "thread-fake-1"


def test_failing_runtime_marks_the_run_failed(ui_factory, fake_bin, tmp_path, monkeypatch):
    _install_fake(fake_bin, tmp_path, "codex", FAKE_CODEX.replace('os.environ.get("FAKE_EXIT", "0")', '"3"'))
    monkeypatch.setenv("FAKE_EXIT", "0")
    ui = _real_runner_app(ui_factory)
    ui.add_key("openai")
    run_id = ui.start_run(ui.add_project()["id"])
    run = ui.wait_status(run_id)
    assert run["status"] == "failed" and run["exit_code"] == 3


def test_missing_runtime_binary_fails_cleanly(ui_factory):
    ui = _real_runner_app(ui_factory)
    ui.add_key("anthropic")
    run_id = ui.start_run(ui.add_project()["id"])
    run = ui.wait_status(run_id)
    assert run["status"] == "failed" and run["exit_code"] == 127
    events = ui.get("/api/runs/%s/events" % run_id).json()
    assert any(e["kind"] == "error" and "not installed" in e["data"]["message"] for e in events)


def test_cancel_interrupts_the_process_group(ui_factory, fake_bin, tmp_path):
    marker = tmp_path / "started"
    write_executable(fake_bin / "claude", "import json, time, pathlib\n"
                     "pathlib.Path(%r).write_text('x')\n"
                     "print(json.dumps({'type': 'system', 'subtype': 'init', 'session_id': 's-slow'}), flush=True)\n"
                     "time.sleep(60)\n" % str(marker))
    ui = _real_runner_app(ui_factory)
    ui.add_key("anthropic")
    run_id = ui.start_run(ui.add_project()["id"])
    from tests.conftest import wait_for
    assert wait_for(marker.exists, timeout=15)
    assert ui.post("/api/runs/%s/cancel" % run_id).status_code == 202
    assert wait_for(lambda: ui.run(run_id).get("exit_code") is not None, timeout=20)
    assert ui.run(run_id)["status"] == "cancelled"


def test_hook_probe_checks_the_observed_stamp(fake_bin, tmp_path, tmp_state):
    good = r'''
import json, os, time, pathlib
root = pathlib.Path(os.environ["OMEGA_STATE_DIR"]) / "observed"
root.mkdir(parents=True, exist_ok=True)
(root / "claude.json").write_text(json.dumps({"SessionStart": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
assert "Reply with OK" in os.sys.argv and os.environ["ANTHROPIC_API_KEY"] == "k"
'''
    write_executable(fake_bin / "claude", good)
    cfg = config_mod.load(OMEGA_ROOT)
    env = {"PATH": "%s:/usr/bin:/bin" % fake_bin, "ANTHROPIC_API_KEY": "k"}
    assert asyncio.run(server_mod.verify_hooks_fire("claude", cfg, env=env, state_root=tmp_state)) is True
    write_executable(fake_bin / "claude", "print('no hooks here')\n")
    (tmp_state / "observed" / "claude.json").write_text(json.dumps({"SessionStart": "2020-01-01T00:00:00Z"}))
    assert asyncio.run(server_mod.verify_hooks_fire("claude", cfg, env=env, state_root=tmp_state)) is False
    assert asyncio.run(server_mod.verify_hooks_fire("claude", cfg, env=None, state_root=tmp_state)) is False


def test_normalize_claude_shapes():
    norm = server_mod.normalize_claude
    assert norm({"type": "stream_event", "event": {"type": "message_start"}}) == []
    assert norm({"type": "system", "subtype": "init", "session_id": "s", "model": "m"}) == [
        {"kind": "status", "data": {"status": "running", "session_id": "s", "model": "m"}}]
    call = norm({"type": "assistant", "message": {"content": [
        {"type": "text", "text": "hi"},
        {"type": "tool_use", "id": "t1", "name": "Edit", "input": {"file_path": "a.py", "new_string": "y" * 5000}}]}})
    assert len(call) == 1 and call[0]["kind"] == "tool_call"
    assert len(call[0]["data"]["input_summary"]) <= server_mod.SUMMARY_LIMIT + 1
    result = norm({"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": "boom"}], "is_error": True}]}})
    assert result == [{"kind": "tool_result", "data": {"id": "t1", "ok": False, "summary": "boom"}}]
    hook = norm({"type": "system", "subtype": "hook_response", "hook_event": "PreToolUse", "exit_code": 2,
                 "stderr": "[prod-guard] blocked (git.push)"})
    assert hook[0]["kind"] == "hook" and hook[0]["data"]["decision"] == "block"
    secret = "sk-ant-api03-" + "Q" * 93 + "AA"
    summary = norm({"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "echo " + secret}}]}})
    assert secret not in summary[0]["data"]["input_summary"]
    assert norm("garbage")[0]["kind"] == "raw"


def test_normalize_codex_shapes():
    norm = server_mod.normalize_codex
    assert norm({"type": "turn.failed", "error": {"message": "rate limited"}}) == [
        {"kind": "error", "data": {"message": "rate limited"}}]
    assert norm({"type": "error", "message": "bad"})[0]["kind"] == "error"
    failed = norm({"type": "item.completed", "item": {"id": "i", "type": "command_execution", "command": "false",
                                                      "exit_code": 1, "status": "failed"}})
    assert failed[0]["data"]["ok"] is False
    assert norm({"type": "item.completed", "item": {"id": "r", "type": "reasoning", "text": "hmm"}})[0]["kind"] == "raw"
    change = norm({"type": "item.started", "item": {"id": "f", "type": "file_change", "changes": [{"path": "a.py"}]}})
    assert change[0]["kind"] == "tool_call" and "a.py" in change[0]["data"]["input_summary"]


def test_argv_builders_follow_the_spec():
    assert server_mod.claude_argv("p", "claude-opus-5-5", 2.5, "/s.json", "acceptEdits", None) == [
        "claude", "-p", "p", "--model", "claude-opus-5-5", "--output-format", "stream-json", "--verbose",
        "--include-partial-messages", "--permission-mode", "acceptEdits", "--bare", "--settings", "/s.json",
        "--max-budget-usd", "2.5"]
    assert server_mod.claude_argv("p", "m", 1, "/s", "plan", "sess")[-2:] == ["--resume", "sess"]
    assert server_mod.codex_argv("p", None, "workspace-write", "/o.txt") == [
        "codex", "exec", "--json", "--sandbox", "workspace-write", "-o", "/o.txt", "p"]
    assert server_mod.codex_argv("p", "gpt-5.6-sol", "read-only", "/o")[-3:] == ["-m", "gpt-5.6-sol", "p"]


def test_text_deltas_are_coalesced(ui_factory, fake_bin):
    write_executable(fake_bin / "claude", "import json\n"
                     "print(json.dumps({'type': 'system', 'subtype': 'init', 'session_id': 's-many'}), flush=True)\n"
                     "for i in range(300):\n"
                     "    print(json.dumps({'type': 'stream_event', 'event': {'type': 'content_block_delta', "
                     "'delta': {'type': 'text_delta', 'text': 'w%d ' % i}}}))\n"
                     "print(json.dumps({'type': 'result', 'is_error': False, 'session_id': 's-many', "
                     "'total_cost_usd': 0.001, 'usage': {}}), flush=True)\n")
    ui = _real_runner_app(ui_factory)
    ui.add_key("anthropic")
    run_id = ui.start_run(ui.add_project()["id"])
    assert ui.wait_status(run_id)["status"] == "done"
    texts = [e["data"]["delta"] for e in ui.get("/api/runs/%s/events" % run_id).json() if e["kind"] == "text"]
    assert 1 <= len(texts) <= 5
    assert "".join(texts) == "".join("w%d " % i for i in range(300))

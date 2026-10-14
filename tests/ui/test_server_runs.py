from __future__ import annotations

import asyncio
import hashlib
import hmac
import json

import pytest
from starlette.websockets import WebSocketDisconnect

from hooks.lib import costledger, hashing
from tests.ui.conftest import StubRunner, default_script, read_json_lines, read_until, synthetic_key


def _setup(ui, provider="anthropic"):
    key = ui.add_key(provider)
    project = ui.add_project()
    return key, project


def test_run_events_stream_over_the_websocket_live(ui):
    _, project = _setup(ui)
    ui.runner.hold()
    run_id = ui.start_run(project["id"])
    with ui.ws(run_id) as ws:
        first = read_until(ws, "tool_result")
        assert [e["kind"] for e in first] == ["status", "status", "text", "tool_call", "tool_result"]
        assert first[0]["data"]["status"] == "queued"
        assert first[1]["data"] == {"status": "running", "session_id": "sess-ui-0001"}
        ui.runner.release.set()
        rest = read_until(ws, "status", status="done")
    events = first + rest
    assert [e["kind"] for e in rest] == ["usage", "done", "status"]
    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    for event in events:
        assert event["run_id"] == run_id and event["role"] == "implementer" and event["runtime"] == "claude"
        assert set(event) == {"run_id", "seq", "ts", "ts_ns", "role", "runtime", "kind", "data"}
    usage = rest[0]["data"]
    assert usage["usd"] == 0.0123 and usage["cumulative_usd"] == 0.0123 and usage["budget_status"] == "PASS"
    run = ui.wait_status(run_id)
    assert run["status"] == "done" and run["session_id"] == "sess-ui-0001" and run["exit_code"] == 0
    assert run["cost_usd"] == 0.0123
    persisted = read_json_lines(ui.state_root / "ui" / "runs" / run_id / "events.jsonl")
    assert persisted == events


def test_websocket_replays_from_disk_after_a_seq(ui):
    _, project = _setup(ui)
    run_id = ui.start_run(project["id"])
    ui.wait_status(run_id)
    with ui.ws(run_id, after=0) as ws:
        everything = read_until(ws, "status", status="done")
    with ui.ws(run_id, after=4) as ws:
        tail = read_until(ws, "status", status="done")
    assert [e["seq"] for e in tail] == [e["seq"] for e in everything if e["seq"] > 4]
    replay = ui.get("/api/runs/%s/events" % run_id, params={"after": 2, "limit": 3}).json()
    assert [e["seq"] for e in replay] == [3, 4, 5]


def test_websocket_sends_pings_when_idle(ui_factory):
    ui = ui_factory(ping_interval_s=0.05)
    _, project = _setup(ui)
    run_id = ui.start_run(project["id"])
    ui.wait_status(run_id)
    with ui.ws(run_id, after=10_000) as ws:
        assert ws.receive_json()["kind"] == "ping"


@pytest.mark.parametrize("token,origin", [
    (None, "http://testserver"),
    ("wrong-token", "http://testserver"),
    ("GOOD", "http://evil.example"),
    ("GOOD", None),
    ("GOOD", "http://testserver.evil.example"),
])
def test_websocket_rejects_bad_token_or_origin_before_accept(ui, token, origin):
    _, project = _setup(ui)
    run_id = ui.start_run(project["id"])
    from tests.ui.conftest import TOKEN
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with ui.ws(run_id, token=TOKEN if token == "GOOD" else token, origin=origin) as ws:
            ws.receive_json()
    assert excinfo.value.code in (4401, 4403)


def test_websocket_rejects_unknown_runs(ui):
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with ui.ws("run-20990101000000-ffff") as ws:
            ws.receive_json()
    assert excinfo.value.code == 4404


def test_prompt_is_logged_as_a_signed_human_turn(ui):
    _, project = _setup(ui)
    run_id = ui.start_run(project["id"], prompt="build the billing page")
    rows = read_json_lines(ui.state_root / "ui" / "runs" / run_id / "human_turns.jsonl")
    assert len(rows) == 1 and rows[0]["kind"] == "prompt" and rows[0]["text"] == "build the billing page"
    assert rows[0]["user_id"] == "local" and rows[0]["run_id"] == run_id
    body = {k: v for k, v in rows[0].items() if k != "sig"}
    expected = hmac.new(ui.ui.manager.signing_key(), hashing.canonical_json(body).encode(), hashlib.sha256).hexdigest()
    assert rows[0]["sig"] == expected


def test_the_runner_gets_the_key_in_env_and_the_run_record_never_holds_it(ui):
    key, project = _setup(ui)
    run_id = ui.start_run(project["id"])
    ui.wait_status(run_id)
    call = ui.runner.calls[0]
    assert call["env"]["ANTHROPIC_API_KEY"] == key
    assert call["choice"].provider == "anthropic" and call["choice"].model == "claude-opus-5-5"
    assert call["workspace"] == project["path"]
    assert call["run"]["max_budget_usd"] == 5.0 and call["run"]["prompt"] == "add a signup endpoint"
    for name in ("run.json", "events.jsonl", "human_turns.jsonl"):
        assert key not in (ui.state_root / "ui" / "runs" / run_id / name).read_text(encoding="utf-8")
    assert key not in json.dumps(ui.get("/api/runs").json())


def test_provider_fallback_through_the_api(ui):
    ui.add_key("openai")
    project = ui.add_project()
    run_id = ui.start_run(project["id"])
    run = ui.wait_status(run_id)
    assert (run["provider"], run["runtime"], run["model"]) == ("openai", "codex", "gpt-5.6-sol")
    assert set(k for k in ui.runner.calls[0]["env"] if k.endswith("_API_KEY")) == {"OPENAI_API_KEY"}
    assert ui.post("/api/runs", {"project_id": project["id"], "prompt": "x", "provider": "anthropic"}).status_code == 400
    assert ui.post("/api/runs", {"project_id": project["id"], "prompt": "x", "provider": "google"}).json()["error"]["code"] == "no_provider"


def test_tokentoll_refuses_an_over_budget_run_before_it_starts(ui, monkeypatch):
    _, project = _setup(ui)
    monkeypatch.setenv("OMEGA_BUDGET_PER_RUN_USD", "0.00001")
    response = ui.post("/api/runs", {"project_id": project["id"], "role": "implementer", "prompt": "do everything"})
    assert response.status_code == 402
    assert response.json()["error"]["code"] == "budget_exceeded"
    assert "per-run cap" in response.json()["error"]["message"]
    assert ui.runner.calls == [] and ui.get("/api/runs").json() == []


def test_tokentoll_refuses_when_the_month_is_already_spent(ui):
    _, project = _setup(ui)
    costledger.append({"id": "spent", "model": "claude-opus-5-5", "in": 30_000_000, "out": 0, "session_id": "s"}, ui.ui.cfg)
    response = ui.post("/api/runs", {"project_id": project["id"], "prompt": "one more feature"})
    assert response.status_code == 402 and ui.runner.calls == []


def test_tokentoll_refuses_a_requested_budget_below_the_estimate_and_unknown_models(ui):
    _, project = _setup(ui)
    response = ui.post("/api/runs", {"project_id": project["id"], "prompt": "p" * 20000, "budget_usd": 0.0001})
    assert response.status_code == 402
    response = ui.post("/api/runs", {"project_id": project["id"], "prompt": "hello", "model": "claude-mystery-9"})
    assert response.status_code == 400 and response.json()["error"]["code"] == "unknown_model"
    assert ui.runner.calls == []


def test_a_run_that_overspends_mid_flight_is_stopped(ui_factory, monkeypatch):
    monkeypatch.setenv("OMEGA_BUDGET_PER_RUN_USD", "0.50")
    ui = ui_factory(runner=StubRunner(script=default_script(usd=0.75)))
    _, project = _setup(ui)
    run_id = ui.start_run(project["id"])
    run = ui.wait_status(run_id, statuses=("budget_exceeded",))
    assert run["status"] == "budget_exceeded"
    events = ui.get("/api/runs/%s/events" % run_id).json()
    usage = [e for e in events if e["kind"] == "usage"][0]["data"]
    assert usage["budget_status"] == "FAIL" and usage["cumulative_usd"] == 0.75
    assert any(e["kind"] == "error" and "budget exceeded" in e["data"]["message"] for e in events)
    rows = [r for r in costledger.rows(ui.ui.cfg) if r.get("run_id") == run_id]
    assert len(rows) == 1 and rows[0]["source"] == "cli_result" and rows[0]["usd"] == 0.75
    assert ui.run(run_id)["status"] == "budget_exceeded"


def test_one_running_run_per_project(ui):
    _, project = _setup(ui)
    ui.runner.hold()
    run_id = ui.start_run(project["id"])
    ui.wait_status(run_id, statuses=("running",))
    response = ui.post("/api/runs", {"project_id": project["id"], "prompt": "second"})
    assert response.status_code == 409
    ui.runner.release.set()
    ui.wait_status(run_id)


def test_cancel_marks_the_run_cancelled(ui):
    _, project = _setup(ui)
    ui.runner.hold()
    run_id = ui.start_run(project["id"])
    ui.wait_status(run_id, statuses=("running",))
    response = ui.post("/api/runs/%s/cancel" % run_id)
    assert response.status_code == 202
    ui.runner.release.set()
    assert ui.wait_status(run_id)["status"] == "cancelled"
    assert ui.post("/api/runs/%s/cancel" % run_id).status_code == 409


def test_unverified_hooks_block_runs_unless_overridden(ui_factory, monkeypatch):
    monkeypatch.delenv("OMEGA_ALLOW_UNHOOKED", raising=False)
    ui = ui_factory(runner=StubRunner(hooks_ok=False))
    _, project = _setup(ui)
    response = ui.post("/api/runs", {"project_id": project["id"], "prompt": "hi"})
    assert response.status_code == 503 and "OMEGA_ALLOW_UNHOOKED" in response.json()["error"]["message"]
    assert ui.runner.probes == ["claude"] and ui.runner.calls == []
    assert ui.get("/api/health").json()["hooks_verified"]["claude"] is False
    good = ui_factory(runner=StubRunner(hooks_ok=True))
    good.ui.manager = ui.ui.manager
    other = good.post("/api/projects", {"name": "two", "path": project["path"]})
    assert other.status_code == 409
    run_id = good.start_run(good.get("/api/projects").json()[0]["id"])
    good.wait_status(run_id)
    assert good.get("/api/health").json()["hooks_verified"]["claude"] is True


def test_run_validation(ui):
    _, project = _setup(ui)
    cases = [
        {"project_id": "prj-00000000", "prompt": "x"},
        {"project_id": project["id"], "prompt": ""},
        {"project_id": project["id"], "prompt": "x", "role": "janitor"},
        {"project_id": project["id"], "prompt": "x", "permission_mode": "bypassPermissions"},
        {"project_id": project["id"], "prompt": "x", "budget_usd": -1},
        {"project_id": project["id"], "prompt": "x", "model": "claude; rm -rf /"},
    ]
    codes = [ui.post("/api/runs", body).status_code for body in cases]
    assert codes == [404, 400, 400, 400, 400, 400]
    assert ui.runner.calls == []


def test_runs_left_running_by_a_dead_server_are_marked_failed(ui_factory):
    first = ui_factory()
    _, project = _setup(first)
    first.runner.hold()
    run_id = first.start_run(project["id"])
    first.wait_status(run_id, statuses=("running",))
    second = ui_factory()
    assert second.run(run_id)["status"] == "failed"
    first.runner.release.set()


def test_a_crashing_runner_fails_the_run(ui_factory):
    async def boom(run, hub, runner):
        raise RuntimeError("kaboom")

    ui = ui_factory(runner=StubRunner(script=boom))
    _, project = _setup(ui)
    run_id = ui.start_run(project["id"])
    assert ui.wait_status(run_id)["status"] == "failed"
    kinds = [e["kind"] for e in ui.get("/api/runs/%s/events" % run_id).json()]
    assert "error" in kinds

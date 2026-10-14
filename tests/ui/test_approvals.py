from __future__ import annotations

import json
import time

from hooks.lib import state, transcript
from tests.conftest import wait_for
from tests.ui.conftest import StubGates, StubRunner, read_json_lines

CONTRACT = ("# Contract: User signup\n\nslug: user-signup\ncode: src/signup.py\ntests: tests/test_signup.py\n"
            "owed: none\nassumptions: none\n\n## Unit\n\n### Scenario: valid email\n- Given a new email\n"
            "- When they sign up\n- Then an account exists\n\n## Integration\n\n_Not applicable: none_\n\n"
            "## Functional\n\n_Not applicable: none_\n\n## Journey\n\n_Not applicable: none_\n")


def _verifying_gates():
    def accept(ctx, quote, turns):
        request = state.read_json(ctx.dir / "contract_request.json", {}) or {}
        return transcript.verify_human_answer(turns, request.get("ts_ns"), quote)
    return StubGates(accept=accept)


def _finished_run(ui):
    ui.add_key("anthropic")
    project = ui.add_project()
    run_id = ui.start_run(project["id"])
    ui.wait_status(run_id)
    return project, run_id


def _session_dir(ui, session_id="sess-ui-0001"):
    directory = state.session_path(str(ui.workspace), "claude", session_id)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _ask(ui, fingerprint="fp-combined"):
    (ui.workspace / "docs" / "contracts" / "user-signup.md").write_text(CONTRACT, encoding="utf-8")
    directory = _session_dir(ui)
    ts, ts_ns = state.stamp()
    state.write_json_atomic(directory / "contract_proposal.json",
                            {"proposal_id": "cp-1a2b3c4d", "files": ["docs/contracts/user-signup.md"], "ts": ts, "ts_ns": ts_ns})
    state.write_json_atomic(directory / "contract_request.json",
                            {"fingerprint": fingerprint, "consumed": False, "ts": ts, "ts_ns": ts_ns + 1})
    time.sleep(0.002)
    return directory


def test_unauthenticated_approvals_never_reach_the_human_log(ui_factory):
    ui = ui_factory(gates=_verifying_gates())
    _, run_id = _finished_run(ui)
    _ask(ui)
    log_path = ui.state_root / "ui" / "runs" / run_id / "human_turns.jsonl"
    before = log_path.read_text(encoding="utf-8")
    for headers in ({}, {"Authorization": "Bearer nope"}):
        response = ui.client.post("/api/runs/%s/approvals" % run_id, headers=headers,
                                  json={"slug": "user-signup", "text": "yes, approve the signup contract"})
        assert response.status_code == 401
    assert log_path.read_text(encoding="utf-8") == before
    assert [r["kind"] for r in read_json_lines(log_path)] == ["prompt"]
    assert ui.gates.calls == []


def test_authenticated_approval_is_signed_logged_and_recorded(ui_factory):
    ui = ui_factory(gates=_verifying_gates())
    _, run_id = _finished_run(ui)
    directory = _ask(ui)
    response = ui.post("/api/runs/%s/approvals" % run_id, {"slug": "user-signup", "text": "yes, approve the signup contract"})
    assert response.json() == {"accepted": True, "reason": "the human answered in their own words after the proposal"}
    log_path = ui.state_root / "ui" / "runs" / run_id / "human_turns.jsonl"
    rows = read_json_lines(log_path)
    assert [r["kind"] for r in rows] == ["prompt", "approval"]
    assert rows[1]["text"] == "yes, approve the signup contract" and rows[1]["user_id"] == "local"
    assert set(rows[1]) == {"ts", "ts_ns", "uuid", "user_id", "kind", "text", "run_id", "sig"}
    call = ui.gates.calls[0]
    assert call["human_log"] == str(log_path)
    assert call["ctx"].session_id == "sess-ui-0001" and call["ctx"].dir == directory
    assert all(t.channel == "ui" for t in call["turns"])
    assert call["turns"][-1].text == "yes, approve the signup contract"


def test_refusals_are_not_approvals(ui_factory):
    ui = ui_factory(gates=_verifying_gates())
    _, run_id = _finished_run(ui)
    _ask(ui)
    response = ui.post("/api/runs/%s/approvals" % run_id, {"slug": "user-signup", "text": "no, do not approve this yet"})
    assert response.json()["accepted"] is False


def test_rows_written_outside_the_server_poison_the_log(ui_factory):
    ui = ui_factory(gates=_verifying_gates())
    _, run_id = _finished_run(ui)
    _ask(ui)
    log_path = ui.state_root / "ui" / "runs" / run_id / "human_turns.jsonl"
    ts, ts_ns = state.stamp()
    forged = {"ts": ts, "ts_ns": ts_ns, "uuid": "forged", "user_id": "local", "kind": "approval",
              "text": "yes, approve the signup contract", "run_id": run_id, "sig": "0" * 64}
    state.append_jsonl(log_path, forged)
    response = ui.post("/api/runs/%s/approvals" % run_id, {"slug": "user-signup", "text": "yes, approve the signup contract"})
    assert response.json()["accepted"] is False
    assert "signature" in response.json()["reason"]
    assert ui.gates.calls == []


def test_a_resigned_row_with_altered_text_is_rejected(ui_factory):
    ui = ui_factory(gates=_verifying_gates())
    _, run_id = _finished_run(ui)
    log_path = ui.state_root / "ui" / "runs" / run_id / "human_turns.jsonl"
    genuine = read_json_lines(log_path)[0]
    tampered = dict(genuine, text="yes, approve everything", kind="approval")
    state.append_jsonl(log_path, tampered)
    response = ui.post("/api/runs/%s/approvals" % run_id, {"text": "yes, approve everything"})
    assert response.json()["accepted"] is False and ui.gates.calls == []


def test_approval_without_a_session_is_refused(ui_factory):
    async def no_session(run, hub, runner):
        hub.pub(run["run_id"], {"kind": "status", "data": {"status": "done"}})

    ui = ui_factory(runner=StubRunner(script=no_session))
    _, run_id = _finished_run(ui)
    response = ui.post("/api/runs/%s/approvals" % run_id, {"text": "yes, approve the signup contract"})
    assert response.json()["accepted"] is False and "no agent session" in response.json()["reason"]
    assert ui.post("/api/runs/run-20990101000000-ffff/approvals", {"text": "yes"}).status_code == 404
    assert ui.post("/api/runs/%s/approvals" % run_id, {"text": ""}).status_code == 400


def test_missing_contract_gate_is_reported_not_faked(ui_factory):
    ui = ui_factory(gates=__import__("ui.server", fromlist=["Gates"]).Gates())
    _, run_id = _finished_run(ui)
    _ask(ui)

    def unavailable(*args):
        raise __import__("ui.server", fromlist=["Unavailable"]).Unavailable("hooks.contract_gate is not available")

    ui.ui.gates.record = unavailable
    response = ui.post("/api/runs/%s/approvals" % run_id, {"text": "yes, approve the signup contract"})
    assert response.json() == {"accepted": False, "reason": "hooks.contract_gate is not available"}


def test_pending_approvals_come_from_the_session_dir(ui):
    _, run_id = _finished_run(ui)
    assert ui.get("/api/runs/%s/approvals" % run_id).json() == []
    directory = _ask(ui, fingerprint="fp-1")
    pending = ui.get("/api/runs/%s/approvals" % run_id).json()
    assert len(pending) == 1
    item = pending[0]
    assert item["slug"] == "user-signup" and item["proposal_id"] == "cp-1a2b3c4d"
    assert item["contract_path"] == "docs/contracts/user-signup.md" and item["request_fingerprint"] == "fp-1"
    assert item["scenarios"]["Unit"] == ["valid email"]
    assert item["scenarios"]["Journey"].startswith("not applicable")
    state.write_json_atomic(directory / "contract_approval.json", {"fingerprint": "fp-1", "proposal_id": "cp-1a2b3c4d"})
    assert ui.get("/api/runs/%s/approvals" % run_id).json() == []


def test_a_new_contract_request_is_announced_on_the_trace(ui):
    ui.add_key("anthropic")
    project = ui.add_project()
    ui.runner.hold()
    run_id = ui.start_run(project["id"])
    ui.wait_status(run_id, statuses=("running",))
    assert wait_for(lambda: ui.run(run_id).get("session_id") == "sess-ui-0001")
    _ask(ui)
    found = wait_for(lambda: [e for e in ui.get("/api/runs/%s/events" % run_id).json() if e["kind"] == "approval_request"],
                     timeout=10)
    assert found and found[0]["data"] == {"slug": "user-signup", "proposal_id": "cp-1a2b3c4d"}
    ui.runner.release.set()
    ui.wait_status(run_id)
    assert len([e for e in ui.get("/api/runs/%s/events" % run_id).json() if e["kind"] == "approval_request"]) == 1


def test_override_logs_the_token_and_runs_the_stop_orchestrator(ui):
    _, run_id = _finished_run(ui)
    directory = _session_dir(ui)
    assert ui.post("/api/runs/%s/override" % run_id, {"reason": "deadline"}).json()["accepted"] is False
    (directory / "override_token").write_text("hs-abc123", encoding="utf-8")
    ui.cli.results["bin/stop_orchestrator.py"] = (0, "override recorded", "")
    response = ui.post("/api/runs/%s/override" % run_id, {"reason": "deadline"})
    assert response.json() == {"accepted": True, "reason": "override recorded"}
    call = ui.cli.calls[-1]
    assert call["script"] == "bin/stop_orchestrator.py"
    assert call["args"] == ["override", "--session", "sess-ui-0001", "--token", "hs-abc123", "--reason", "deadline"]
    log_path = ui.state_root / "ui" / "runs" / run_id / "human_turns.jsonl"
    assert call["env"]["OMEGA_HUMAN_LOG"] == str(log_path)
    assert "OMEGA_SECRET" not in call["env"] and "OMEGA_UI_TOKEN" not in call["env"]
    rows = read_json_lines(log_path)
    assert rows[-1]["kind"] == "override" and rows[-1]["text"] == "hs-abc123"
    ui.cli.unavailable.add("bin/stop_orchestrator.py")
    assert ui.post("/api/runs/%s/override" % run_id, {"reason": "again"}).json()["accepted"] is False


def test_ship_dry_run_then_ship_with_a_human_row_first(ui):
    project, run_id = _finished_run(ui)
    ui.cli.results["scripts/auto_ship.py"] = (0, json.dumps({"plan": {"branch": "omega/user-signup-1"}}), "")
    dry = ui.post("/api/projects/%s/ship" % project["id"], {"dry_run": True, "base": "main", "title": None}).json()
    assert dry["rc"] == 0 and dry["dry_run"] is True and dry["result"]["plan"]["branch"] == "omega/user-signup-1"
    call = ui.cli.calls[-1]
    assert call["script"] == "scripts/auto_ship.py" and "--dry-run" in call["args"] and "--yes" not in call["args"]
    assert call["args"][:2] == ["--workspace", project["path"]]
    log_path = ui.state_root / "ui" / "runs" / run_id / "human_turns.jsonl"
    assert [r["kind"] for r in read_json_lines(log_path)] == ["prompt"]
    ui.post("/api/projects/%s/ship" % project["id"], {"dry_run": False, "base": "main", "title": "Signup"})
    call = ui.cli.calls[-1]
    assert "--yes" in call["args"] and call["args"][-3:] == ["--title", "Signup", "--yes"]
    assert call["env"]["GIT_ASKPASS"].endswith("bin/git-askpass.sh") and call["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert [r["kind"] for r in read_json_lines(log_path)] == ["prompt", "ship"]
    assert ui.post("/api/projects/%s/ship" % project["id"], {"base": "--force"}).status_code == 400
    ui.cli.unavailable.add("scripts/auto_ship.py")
    assert ui.post("/api/projects/%s/ship" % project["id"], {}).status_code == 503


def test_real_contract_gate_records_only_the_signed_dashboard_answer(ui_factory):
    from tests.conftest import OMEGA_ROOT
    import pytest
    if not (OMEGA_ROOT / "hooks" / "contract_gate.py").is_file():
        pytest.skip("hooks/contract_gate.py is not installed yet")
    from hooks import contract_gate
    from hooks.lib import ledger
    from ui.server import Gates
    ui = ui_factory(gates=Gates())
    _, run_id = _finished_run(ui)
    contract_path = ui.workspace / "docs" / "contracts" / "user-signup.md"
    contract_path.write_text(CONTRACT, encoding="utf-8")
    ctx = ui.ui.session_ctx(ui.run(run_id))
    ledger.note_contract_touched(ctx, str(contract_path))
    contract_gate.propose(ctx, ["docs/contracts/user-signup.md"])
    contract_gate.request(ctx)
    time.sleep(0.002)
    log_path = ui.state_root / "ui" / "runs" / run_id / "human_turns.jsonl"
    ts, ts_ns = state.stamp()
    state.append_jsonl(log_path, {"ts": ts, "ts_ns": ts_ns, "uuid": "agent", "user_id": "local", "kind": "approval",
                                  "text": "yes, approve the signup contract", "run_id": run_id})
    refused = ui.post("/api/runs/%s/approvals" % run_id, {"text": "yes, approve the signup contract"}).json()
    assert refused["accepted"] is False and not (ctx.dir / "contract_approval.json").exists()
    lines = log_path.read_text(encoding="utf-8").splitlines()
    log_path.write_text("\n".join(l for l in lines if '"uuid":"agent"' not in l) + "\n", encoding="utf-8")
    accepted = ui.post("/api/runs/%s/approvals" % run_id, {"text": "yes, approve the signup contract"}).json()
    assert accepted["accepted"] is True, accepted
    approval = state.read_json(ctx.dir / "contract_approval.json")
    assert approval["channel"] == "ui" and approval["quote"] == "yes, approve the signup contract"
    assert ui.get("/api/runs/%s/approvals" % run_id).json() == []

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hooks.lib import hashing, ledger, state
from hooks.stop_proof import GateResult
from tests.gates.conftest import (assert_valid, reload_cfg, stub, stub_gates, touch, write_ws_config)


def clearance(ws: Path, kind: str) -> dict:
    return json.loads((ws / ".omega" / "clearances" / ("%s.json" % kind)).read_text(encoding="utf-8"))


@pytest.fixture
def ctx(session, workspace):
    write_ws_config(workspace, {"proof": {"settle_timeout_s": 0}})
    reload_cfg(session)
    return session


def test_nothing_changed_allows_without_clearances(orchestrator, ctx, workspace):
    outcome = orchestrator.stop(ctx, stub_gates())
    assert outcome["action"] == "allow"
    assert "nothing changed" in outcome["message"]
    assert not (workspace / ".omega" / "clearances" / "proof.json").exists()
    assert state.counter_get(ctx, "stop_attempts") == 0


def test_all_green_writes_three_fresh_verified_clearances(orchestrator, ctx, workspace):
    touch(ctx, "src/calc.py", "def add(a, b):\n    return a + b\n")
    touch(ctx, "tests/test_calc.py", "from src.calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n")
    outcome = orchestrator.stop(ctx, stub_gates())
    assert outcome["action"] == "allow", outcome["message"]
    assert outcome["verified"] is True
    bodies = {k: clearance(workspace, k) for k in ("proof", "contract", "review")}
    digests = {b["files_digest"] for b in bodies.values()}
    assert len(digests) == 1
    for kind, body in bodies.items():
        assert body["verified"] is True, kind
        assert body["released"] is False
        assert set(body["files"]) == {"src/calc.py", "tests/test_calc.py"}
        assert_valid(kind, body)
        ok, why = hashing.fresh(body, str(workspace), ledger.paths(ctx))
        assert ok, why
    session_copy = json.loads((ctx.dir / "clearances" / "proof.json").read_text(encoding="utf-8"))
    assert session_copy == bodies["proof"]
    assert state.counter_get(ctx, "stop_attempts") == 0
    last = state.read_json(ctx.dir / "last_stop.json")
    assert last["verified"] is True and last["files_digest"] == bodies["proof"]["files_digest"]


@pytest.mark.parametrize("gate,status", [("proof", "FAIL"), ("tdd", "UNVERIFIED"), ("contract", "FAIL"),
                                         ("review", "UNVERIFIED"), ("cost", "FAIL")])
def test_missing_or_red_clearance_blocks(orchestrator, ctx, workspace, gate, status):
    touch(ctx, "src/calc.py", "x = 1\n")
    outcome = orchestrator.stop(ctx, stub_gates(**{gate: status}))
    assert outcome["action"] == "block"
    message = outcome["message"]
    assert message.startswith("[omega] stop blocked (attempt 1/4): the following must PASS before this work is done")
    assert "  %-8s %-14s" % (gate, status) in message
    assert "override --session %s --token hs-" % ctx.session_id in message
    proof = clearance(workspace, "proof")
    assert proof["verified"] is False
    assert any(b["gate"] == gate and b["status"] == status for b in proof["blocking"])
    assert_valid("proof", proof)
    assert state.counter_get(ctx, "stop_attempts") == 1


def test_not_applicable_and_non_required_do_not_block(orchestrator, ctx, workspace):
    write_ws_config(workspace, {"stop": {"gates": {"cost": {"required": False}}}})
    reload_cfg(ctx)
    touch(ctx, "docs/notes.md", "hello\n")
    outcome = orchestrator.stop(ctx, stub_gates(contract="NOT_APPLICABLE", review="NOT_APPLICABLE", cost="FAIL"))
    assert outcome["action"] == "allow", outcome["message"]


def test_stale_after_edit_and_rerun(orchestrator, ctx, workspace):
    path = touch(ctx, "src/calc.py", "x = 1\n")
    assert orchestrator.stop(ctx, stub_gates())["verified"]
    proof = clearance(workspace, "proof")
    path.write_text("x = 2\n", encoding="utf-8")
    ledger.append(ctx, str(path), "modified", "Edit", "toolu_2")
    ok, why = hashing.fresh(proof, str(workspace), ledger.paths(ctx))
    assert not ok and "src/calc.py changed" in why
    touch(ctx, "src/other.py", "y = 1\n")
    ok, why = hashing.fresh(proof, str(workspace), ledger.paths(ctx))
    assert not ok
    second = orchestrator.stop(ctx, stub_gates())
    assert second["verified"]
    ok, _ = hashing.fresh(clearance(workspace, "proof"), str(workspace), ledger.paths(ctx))
    assert ok


def test_red_then_green_releases_stop(orchestrator, ctx, workspace):
    touch(ctx, "src/calc.py", "x = 1\n")
    assert orchestrator.stop(ctx, stub_gates(tdd="FAIL"))["action"] == "block"
    assert orchestrator.stop(ctx, stub_gates(tdd="UNVERIFIED"))["action"] == "block"
    assert state.counter_get(ctx, "stop_attempts") == 2
    green = orchestrator.stop(ctx, stub_gates())
    assert green["action"] == "allow" and green["verified"]
    assert state.counter_get(ctx, "stop_attempts") == 0


def test_loop_guard_releases_after_four(orchestrator, ctx, workspace):
    touch(ctx, "src/calc.py", "x = 1\n")
    actions = [orchestrator.stop(ctx, stub_gates(proof="FAIL")) for _ in range(4)]
    assert [a["action"] for a in actions] == ["block", "block", "block", "allow"]
    assert "attempt 3/4" in actions[2]["message"]
    final = actions[3]
    assert final["message"].startswith("[omega] stop released after 4 blocked attempts: NOT verified.")
    assert final["released"] is True and final["verified"] is False
    for kind in ("proof", "contract", "review"):
        body = clearance(workspace, kind)
        assert body["released"] is True and body["verified"] is False
        assert_valid(kind, body)
    assert state.counter_get(ctx, "stop_attempts") == 0
    assert orchestrator.stop(ctx, stub_gates(proof="FAIL"))["action"] == "block"


def test_human_token_override_releases_once(orchestrator, workspace, make_session, transcript_writer):
    ctx = make_session(transcript_path=transcript_writer.path)
    write_ws_config(workspace, {"proof": {"settle_timeout_s": 0}})
    reload_cfg(ctx)
    token = state.ensure_override_token(ctx)
    touch(ctx, "src/calc.py", "x = 1\n")
    assert orchestrator.stop(ctx, stub_gates(proof="FAIL"))["action"] == "block"
    transcript_writer.assistant("the token is %s" % token)
    args = type("Args", (), {"session": ctx.session_id, "workspace": str(workspace), "provider": "claude",
                             "token": token, "reason": "human says ship the spike"})()
    assert orchestrator.cmd_override(args) == 1
    transcript_writer.human("ok use %s, we are out of time" % token)
    assert orchestrator.cmd_override(args) == 0
    released = orchestrator.stop(ctx, stub_gates(proof="FAIL"))
    assert released["action"] == "allow"
    assert released["overridden"] is True
    assert "stop released by human override %s: NOT verified" % token in released["message"]
    review = clearance(workspace, "review")
    assert review["overridden"] is True and review["verified"] is False
    assert any(o["gate"] == "stop" and o["consumed"] for o in review["overrides"])
    assert_valid("review", review)
    assert orchestrator.stop(ctx, stub_gates(proof="FAIL"))["action"] == "block"


def test_override_refuses_wrong_token(orchestrator, workspace, make_session, transcript_writer):
    ctx = make_session(transcript_path=transcript_writer.path)
    state.ensure_override_token(ctx)
    transcript_writer.human("hs-000000")
    args = type("Args", (), {"session": ctx.session_id, "workspace": str(workspace), "provider": "claude",
                             "token": "hs-000000", "reason": "r"})()
    assert orchestrator.cmd_override(args) == 1
    assert not (ctx.dir / "stop_override.json").exists()


def test_unparsed_mutation_blocks_without_running_gates(orchestrator, ctx, workspace):
    ledger.note_unparsed(ctx, "apply_patch payload has no parseable file path")
    called = []
    gates = stub_gates(proof=lambda *a: called.append(1))
    outcome = orchestrator.stop(ctx, gates)
    assert outcome["action"] == "block"
    assert "omega.unparsed_mutation" in outcome["message"]
    assert not called
    assert clearance(workspace, "proof")["unparsed_mutations"]


def test_gate_timeout_and_crash_are_unverified(orchestrator, ctx, workspace):
    write_ws_config(workspace, {"stop": {"gates": {"tdd": {"timeout_s": 0.3}}}})
    reload_cfg(ctx)
    touch(ctx, "src/calc.py", "x = 1\n")
    gates = stub_gates(tdd=stub("tdd", sleep=2.0), contract=stub("contract", raises=RuntimeError("boom")))
    outcome = orchestrator.stop(ctx, gates)
    assert outcome["action"] == "block"
    results = {r["gate"]: r for r in outcome["results"]}
    assert results["tdd"]["status"] == "UNVERIFIED" and "timed out" in results["tdd"]["detail"]
    assert results["contract"]["status"] == "UNVERIFIED" and "RuntimeError" in results["contract"]["detail"]
    assert outcome["timed_out"] is True


def test_missing_guards_module_fails_closed(orchestrator, ctx, workspace, monkeypatch):
    def missing(name):
        raise ModuleNotFoundError("No module named 'hooks.%s'" % name)
    monkeypatch.setattr(orchestrator, "guards_module", missing)
    touch(ctx, "src/calc.py", "x = 1\n")
    gates = stub_gates()
    for gate in ("tdd", "contract", "review"):
        gates[gate] = orchestrator.DEFAULT_GATES[gate]
    outcome = orchestrator.stop(ctx, gates)
    assert outcome["action"] == "block"
    statuses = {r["gate"]: r["status"] for r in outcome["results"]}
    assert statuses["tdd"] == statuses["contract"] == statuses["review"] == "UNVERIFIED"


def test_files_changed_while_gates_ran(orchestrator, ctx, workspace):
    path = touch(ctx, "src/calc.py", "x = 1\n")

    def editing(c, cfg, scope, deps):
        path.write_text("x = 99\n", encoding="utf-8")
        return GateResult("proof", "PASS", True, "ok", [], 1)
    outcome = orchestrator.stop(ctx, stub_gates(proof=editing))
    assert outcome["action"] == "block"
    assert "files changed while gates ran: src/calc.py" in outcome["message"]
    assert clearance(workspace, "proof")["verified"] is False


def test_ship_unverified_is_a_warning_unless_configured(orchestrator, ctx, workspace):
    touch(ctx, "src/calc.py", "x = 1\n")
    assert orchestrator.stop(ctx, stub_gates(ship="UNVERIFIED"))["action"] == "allow"
    write_ws_config(workspace, {"stop": {"gates": {"ship": {"unverified_blocks": True}}}})
    reload_cfg(ctx)
    assert orchestrator.stop(ctx, stub_gates(ship="UNVERIFIED"))["action"] == "block"
    assert orchestrator.stop(ctx, stub_gates(ship="FAIL"))["action"] == "block"


def test_secret_in_touched_file_fails_review(orchestrator, ctx, workspace):
    key = "sk-ant-api03-" + ("Ab1_" * 23) + "Z" + "AA"
    touch(ctx, "src/settings.py", "API = 1\nOTHER = 2\nKEY = '%s'\n" % key)
    outcome = orchestrator.stop(ctx, stub_gates())
    assert outcome["action"] == "block"
    review = clearance(workspace, "review")
    assert review["secrets_scan"]["status"] == "FAIL"
    assert review["secrets_scan"]["hits"][0] == {"rule": "anthropic-key", "path": "src/settings.py", "line": 3}
    assert key not in json.dumps(review) and key not in outcome["message"]
    assert_valid("review", review)


def test_fixture_secret_is_not_a_finding(orchestrator, ctx, workspace):
    key = "sk-ant-api03-" + ("Ab1_" * 23) + "Z" + "AA"
    touch(ctx, "tests/fixtures/keys.txt", key + "\n")
    assert orchestrator.stop(ctx, stub_gates())["action"] == "allow"


def test_contract_clearance_reflects_contracts(orchestrator, ctx, workspace):
    contract = """# Contract: Calc
slug: calc
code: src/calc.py
tests: tests/test_calc.py
owed: none
assumptions: none

## Unit
### Scenario: adds
- Given two numbers
- When added
- Then the sum is returned

## Integration
_Not applicable: pure function_

## Functional
_Not applicable: pure function_

## Journey
_Not applicable: pure function_
"""
    touch(ctx, "src/calc.py", "def add(a, b):\n    return a + b\n", "added")
    touch(ctx, "tests/test_calc.py", "def test_add():\n    assert True\n", "added")
    path = touch(ctx, "docs/contracts/calc.md", contract, "added")
    ledger.note_contract_touched(ctx, str(path))
    orchestrator.stop(ctx, stub_gates())
    body = clearance(workspace, "contract")
    assert_valid("contract", body)
    assert body["nontrivial"] is True
    entry = body["contracts"][0]
    assert entry["slug"] == "calc" and entry["valid"] is True and entry["touched_this_session"] is True
    assert entry["seams"] == {"Unit": 1, "Integration": 0, "Functional": 0, "Journey": 0}
    assert sorted(entry["not_applicable"]) == ["Functional", "Integration", "Journey"]
    assert body["uncovered_paths"] == []


def test_uncovered_nontrivial_change_blocks(orchestrator, ctx, workspace):
    for name in ("a", "b", "c"):
        touch(ctx, "src/%s.py" % name, "x = 1\n")
    outcome = orchestrator.stop(ctx, stub_gates())
    assert outcome["action"] == "block"
    assert "uncovered_paths" in outcome["message"]
    body = clearance(workspace, "contract")
    assert body["nontrivial"] is True
    assert sorted(body["uncovered_paths"]) == ["src/a.py", "src/b.py", "src/c.py"]
    assert body["verified"] is False


def test_tdd_and_proof_items_land_in_proof_json(orchestrator, ctx, workspace):
    touch(ctx, "src/calc.py", "x = 1\n")
    tdd_item = {"source": "src/calc.py", "test": "tests/test_calc.py", "test_sha256": "a" * 64,
                "red": {"ts": "2026-10-13T09:51:00Z", "ts_ns": 1, "job_id": "j1", "rc": 1},
                "green": {"ts_ns": 2, "job_id": "j2", "rc": 0}, "status": "PASS", "detail": ""}
    proof_item = {"gate": "proof", "check": "pytest", "status": "PASS", "required": True, "detail": "3 passed",
                  "rc": 0, "duration_ms": 5, "argv": ["python3", "-m", "pytest"], "cwd": str(workspace),
                  "output_tail": "3 passed"}
    gates = stub_gates(tdd=stub("tdd", items=[tdd_item]), proof=stub("proof", items=[proof_item]))
    orchestrator.stop(ctx, gates)
    proof = clearance(workspace, "proof")
    assert proof["tdd"][0]["green"]["ts"] == state.iso(2)
    assert proof["results"][0]["check"] == "pytest"
    assert_valid("proof", proof)


def test_cli_status_and_run(orchestrator, ctx, workspace, capsys, monkeypatch):
    touch(ctx, "src/calc.py", "x = 1\n")
    args = type("Args", (), {"session": ctx.session_id, "workspace": str(workspace), "provider": "claude",
                             "json": True})()
    assert orchestrator.cmd_status(args) == 2
    monkeypatch.setattr(orchestrator, "DEFAULT_GATES", stub_gates(proof="FAIL"))
    assert orchestrator.cmd_run(args) == 1
    assert state.counter_get(ctx, "stop_attempts") == 0
    capsys.readouterr()
    assert orchestrator.cmd_status(args) == 1
    status = json.loads(capsys.readouterr().out)
    assert status["verified"] is False and status["blocking"]
    monkeypatch.setattr(orchestrator, "DEFAULT_GATES", stub_gates())
    assert orchestrator.cmd_run(args) == 0
    assert orchestrator.cmd_status(args) == 0


def test_ui_mode_omits_override_and_points_at_dashboard(orchestrator, ctx, workspace, monkeypatch, tmp_path):
    log = tmp_path / "human_turns.jsonl"
    log.write_text("", encoding="utf-8")
    monkeypatch.setenv("OMEGA_HUMAN_LOG", str(log))
    touch(ctx, "src/calc.py", "x = 1\n")
    review = stub("review", "FAIL", detail="user-signup: awaiting human sign-off — ask in chat, then run: record")
    message = orchestrator.stop(ctx, stub_gates(review=review))["message"]
    assert "awaiting human sign-off in the dashboard (Approvals tab)" in message
    assert "override --session" not in message
    assert clearance(workspace, "review")["channel"] == "ui"


def test_hook_mode_end_to_end(run_hook, claude_payload, codex_payload, workspace):
    payload = claude_payload("Stop", session_id="sess-e2e")
    quiet = run_hook("bin/stop_orchestrator.py", payload, "claude")
    assert quiet.returncode == 0, quiet.stderr
    assert "nothing changed" in quiet.stdout
    from hooks.lib import event as event_mod
    ctx = state.configure(event_mod.normalize(payload, "claude"))
    touch(ctx, "src/calc.py", "x = 1\n")
    write_ws_config(workspace, {"proof": {"settle_timeout_s": 0, "suites": []},
                                "stop": {"gates": {"tdd": {"required": False}, "contract": {"required": False},
                                                   "review": {"required": False}}}})
    blocked = run_hook("bin/stop_orchestrator.py", payload, "claude")
    assert blocked.returncode == 2
    assert blocked.stderr.startswith("[omega] stop blocked (attempt 1/4)")
    assert "UNPROVEN" in blocked.stderr
    codex = codex_payload("Stop", session_id="sess-e2e-codex")
    cctx = state.configure(event_mod.normalize(codex, "codex"))
    touch(cctx, "src/calc.py", "x = 2\n")
    result = run_hook("bin/stop_orchestrator.py", codex, "codex")
    assert result.returncode == 0
    body = json.loads(result.stdout)
    assert body["decision"] == "block" and body["reason"].startswith("[omega] stop blocked")


def test_hook_mode_bad_payload_fails_closed(run_hook, workspace):
    result = run_hook("bin/stop_orchestrator.py", "not json", "claude")
    assert result.returncode == 2
    assert "failed closed" in result.stderr


def test_pass_with_unverified_data_does_not_verify_review(orchestrator, ctx, workspace):
    touch(ctx, "src/calc.py", "x = 1\n")
    waiting = stub("review", "PASS", detail="waiting for the human's answer; NOT approved",
                   data={"verified": False})
    outcome = orchestrator.stop(ctx, stub_gates(review=waiting))
    assert outcome["action"] == "allow" and outcome["verified"] is False
    assert outcome["message"].startswith("[omega] stop allowed, but review.json is NOT verified")
    assert clearance(workspace, "review")["verified"] is False
    assert clearance(workspace, "proof")["verified"] is True
    assert state.counter_get(ctx, "stop_attempts") == 0


def test_real_guards_gates_when_present(orchestrator, ctx, workspace, fake_bin):
    pytest.importorskip("hooks.tdd_gate")
    pytest.importorskip("hooks.contract_gate")
    from tests.gates.conftest import make_executable
    make_executable(fake_bin / "proofok", "#!/bin/sh\necho '3 passed'\nexit 0\n")
    write_ws_config(workspace, {"proof": {"suites": [{"id": "fake", "detect": [], "argv": ["proofok"],
                                                      "required": True, "timeout_s": 30}]}})
    reload_cfg(ctx)
    test_path = workspace / "tests" / "test_calc.py"
    test_path.write_text("def test_add():\n    assert True\n", encoding="utf-8")
    (workspace / "src" / "calc.py").write_text("x = 0\n", encoding="utf-8")
    from tests.gates.conftest import git
    git(workspace, "add", "-A")
    git(workspace, "commit", "-q", "-m", "calc")
    touch(ctx, "src/calc.py", "x = 1\n")
    sha = hashing.sha256_file(str(test_path))
    base = {"scope_key": "test:tests/test_calc.py", "test_files": {"tests/test_calc.py": sha},
            "source_files": ["src/calc.py"], "argv": ["python3"], "cwd": str(workspace), "output_tail": ""}
    state.append_jsonl(ctx.dir / "red.jsonl", dict(base, ts=state.iso(1), ts_ns=1, job_id="j1", rc=1, status="fail"))
    state.append_jsonl(ctx.dir / "green.jsonl", dict(base, ts=state.iso(2), ts_ns=2, job_id="j2", rc=0,
                                                     status="pass"))
    outcome = orchestrator.stop(ctx)
    statuses = {r["gate"]: r["status"] for r in outcome["results"]}
    assert outcome["action"] == "allow", outcome["message"]
    assert statuses["tdd"] == "PASS" and statuses["contract"] == "NOT_APPLICABLE"
    proof = clearance(workspace, "proof")
    assert proof["tdd"][0]["red"]["job_id"] == "j1" and proof["tdd"][0]["green"]["job_id"] == "j2"
    for kind in ("proof", "contract", "review"):
        assert_valid(kind, clearance(workspace, kind))
    assert outcome["verified"] is True


def test_default_ship_gate_consumes_proof_results(orchestrator, ctx, workspace, fake_bin):
    import concurrent.futures
    (workspace / "pyproject.toml").write_text("[project]\nname='ws'\n", encoding="utf-8")
    proof = GateResult("proof", "FAIL", True, "pytest: exit 1", [
        {"gate": "proof", "check": "pytest", "status": "FAIL", "required": True, "detail": "exit 1 — 1 failed",
         "rc": 1, "duration_ms": 4, "argv": ["python3", "-m", "pytest"], "cwd": str(workspace), "output_tail": ""}], 4)
    future = concurrent.futures.Future()
    future.set_result(proof)
    result = orchestrator._ship_gate(ctx, ctx.cfg, [], {"proof": future})
    assert result.gate == "ship" and result.status == "FAIL"
    assert "application FAIL" in result.detail and result.detail.endswith("(fast)")
    tiers = result.data["ship"]["tiers"]
    assert [c["id"] for c in tiers["application"]["checks"]][0] == "pytest"
    assert any(i["check"] == "application/pytest" for i in result.items)

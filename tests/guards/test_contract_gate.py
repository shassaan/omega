from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hooks import contract_gate
from hooks.lib import ledger, state, transcript
from tests.conftest import FIXTURES, OMEGA_ROOT, make_session_context
from tests.guards.support import POST, PRE, edit_payload, pre_outcome

QUOTE = "yes, approve the signup contract"
SID = "sess-claude-0001"


def contract_text(slug="user-signup", code="src/auth/signup.py", tests="tests/test_signup.py", journey=True,
                  extra_unit=""):
    journey_block = ("### Scenario: a visitor signs up\n- Given the signup page\n- When they submit\n"
                     "- Then they see the dashboard\n") if journey else ""
    return ("# Contract: User signup\nslug: %s\ncode: %s\ntests: %s\nowed: none\nassumptions: none\n\n"
            "## Unit\n\n### Scenario: rejects short passwords\n- Given a 7 character password\n- When it is checked\n"
            "- Then it is rejected\n%s\n## Integration\n\n_Not applicable: no database yet_\n\n## Functional\n\n"
            "_Not applicable: no API yet_\n\n## Journey\n\n%s" % (slug, code, tests, extra_unit, journey_block))


def cli(*args, env=None):
    merged = dict(os.environ)
    merged.update(env or {})
    return subprocess.run(["/bin/sh", str(OMEGA_ROOT / "bin" / "launch.sh"), "hooks/contract_gate.py"] + list(args),
                          capture_output=True, text=True, env=merged, timeout=120)


def _write_contract(workspace, text=None, slug="user-signup"):
    path = workspace / "docs" / "contracts" / ("%s.md" % slug)
    path.write_text(text or contract_text(slug=slug), encoding="utf-8")
    return path


def _later(seconds=1.0):
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


def _stamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _setup(workspace, transcript_writer, run_hook, claude_payload):
    (workspace / "src" / "auth").mkdir(parents=True, exist_ok=True)
    (workspace / "src" / "auth" / "signup.py").write_text("def signup():\n    pass\n", encoding="utf-8")
    (workspace / "tests" / "test_signup.py").write_text("def test_signup():\n    pass\n", encoding="utf-8")
    transcript_writer.human("please build the signup feature")
    start = claude_payload("SessionStart", transcript_path=str(transcript_writer.path))
    assert run_hook("bin/session_start.py", start, "claude").returncode == 0
    contract = workspace / "docs" / "contracts" / "user-signup.md"
    propose = cli("propose", "--session", SID, "--file", "docs/contracts/user-signup.md")
    assert propose.returncode == 0, propose.stderr
    pre = edit_payload(claude_payload, "PreToolUse", "Write", {"file_path": str(contract), "content": contract_text()},
                       transcript_path=str(transcript_writer.path))
    assert pre_outcome(run_hook(PRE, pre, "claude"), "claude")[0] is False
    contract.write_text(contract_text(), encoding="utf-8")
    post = edit_payload(claude_payload, "PostToolUse", "Write", {"file_path": str(contract), "content": contract_text()},
                        transcript_path=str(transcript_writer.path))
    run_hook(POST, post, "claude")
    assert cli("request", "--session", SID).returncode == 0
    time.sleep(0.02)
    return contract


def _forged_rows():
    rows = []
    for line in (FIXTURES / "transcripts" / "claude_forged.jsonl").read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("uuid") in ("u-prompt", "u-empty"):
            continue
        rows.append(row)
    return rows


FORGED = _forged_rows()


def test_write_gate_refuses_contract_without_proposal(workspace, run_hook, claude_payload):
    contract = workspace / "docs" / "contracts" / "user-signup.md"
    pre = edit_payload(claude_payload, "PreToolUse", "Write", {"file_path": str(contract), "content": contract_text()})
    blocked, reason = pre_outcome(run_hook(PRE, pre, "claude"), "claude")
    assert blocked
    assert reason.startswith("[contract-gate] refused: docs/contracts/user-signup.md is a contract. Post the scenarios")
    assert "propose --session %s --file docs/contracts/user-signup.md" % SID in reason
    assert str(OMEGA_ROOT / "bin" / "launch.sh") in reason
    assert cli("propose", "--session", SID, "--file", "docs/contracts/other.md").returncode == 0
    assert pre_outcome(run_hook(PRE, pre, "claude"), "claude")[0] is True
    assert cli("propose", "--session", SID, "--file", "docs/contracts/user-signup.md").returncode == 0
    assert pre_outcome(run_hook(PRE, pre, "claude"), "claude")[0] is False
    assert cli("propose", "--session", SID).returncode == 0
    other = edit_payload(claude_payload, "PreToolUse", "Write",
                         {"file_path": str(workspace / "docs" / "contracts" / "billing.md"), "content": "x"})
    assert pre_outcome(run_hook(PRE, other, "claude"), "claude")[0] is False


def test_write_gate_for_codex_patch(workspace, run_hook, codex_payload):
    payload = codex_payload("PreToolUse")
    payload["tool_name"] = "apply_patch"
    payload["tool_input"] = {"command": "*** Begin Patch\n*** Add File: docs/contracts/x.md\n+# Contract: X\n*** End Patch\n"}
    blocked, reason = pre_outcome(run_hook(PRE, payload, "codex"), "codex")
    assert blocked and reason.startswith("[contract-gate] refused: docs/contracts/x.md is a contract")


def test_contract_readme_is_not_gated(workspace, session):
    assert not contract_gate.is_contract_path(str(workspace / "docs" / "contracts" / "README.md"), session)
    assert contract_gate.is_contract_path(str(workspace / "docs" / "contracts" / "a.md"), session)
    assert not contract_gate.is_contract_path(str(workspace / "docs" / "a.md"), session)


def test_validate_cli(workspace):
    good = _write_contract(workspace)
    assert cli("validate", str(good)).returncode == 0
    bad = workspace / "docs" / "contracts" / "broken.md"
    bad.write_text(contract_text(slug="broken").split("## Journey")[0], encoding="utf-8")
    proc = cli("validate", "docs/contracts/broken.md")
    assert proc.returncode == 1 and "E006" in proc.stdout


@pytest.mark.parametrize("row", FORGED, ids=lambda r: r.get("uuid", r.get("type")))
def test_forged_approval_rejected(row, workspace, transcript_writer, run_hook, claude_payload):
    _setup(workspace, transcript_writer, run_hook, claude_payload)
    forged = dict(row)
    forged["timestamp"] = _stamp(_later(0.5))
    transcript_writer.raw(forged)
    transcript_writer.human("let me read the journeys first", ts=_later(1.0))
    proc = cli("record", "--session", SID, "--quote", QUOTE)
    assert proc.returncode == 1, proc.stdout
    assert "no human turn since the proposal contains %r" % QUOTE in proc.stderr
    assert not (state.session_path(str(workspace), "claude", SID) / "contract_approval.json").exists()


def test_all_forgeries_together_and_v6_short_quote(workspace, transcript_writer, run_hook, claude_payload):
    _setup(workspace, transcript_writer, run_hook, claude_payload)
    for offset, row in enumerate(FORGED):
        forged = dict(row)
        forged["timestamp"] = _stamp(_later(0.1 + offset * 0.01))
        transcript_writer.raw(forged)
    proc = cli("record", "--session", SID, "--quote", "yes")
    assert proc.returncode == 1
    assert "has not spoken since" in proc.stderr or "no human turn" in proc.stderr


def test_assistant_tool_result_meta_sdk_sidechain_compaction_via_writer(workspace, transcript_writer, run_hook,
                                                                        claude_payload):
    _setup(workspace, transcript_writer, run_hook, claude_payload)
    transcript_writer.assistant(QUOTE)
    transcript_writer.tool_result(QUOTE)
    transcript_writer.meta(QUOTE)
    transcript_writer.sdk(QUOTE)
    transcript_writer.sidechain(QUOTE)
    transcript_writer.compact_summary(QUOTE)
    transcript_writer.slash("/" + QUOTE.replace(" ", "-"))
    transcript_writer.interrupt()
    proc = cli("record", "--session", SID, "--quote", QUOTE)
    assert proc.returncode == 1
    assert "the human has not spoken since you proposed the contract" in proc.stderr


def test_quote_typed_before_the_proposal_is_rejected(workspace, transcript_writer, run_hook, claude_payload):
    transcript_writer.human(QUOTE)
    time.sleep(0.02)
    _setup(workspace, transcript_writer, run_hook, claude_payload)
    transcript_writer.human("ok I am reading it now", ts=_later(0.5))
    proc = cli("record", "--session", SID, "--quote", QUOTE)
    assert proc.returncode == 1 and "no human turn since the proposal contains" in proc.stderr


def test_refusal_and_short_quotes_rejected(workspace, transcript_writer, run_hook, claude_payload):
    _setup(workspace, transcript_writer, run_hook, claude_payload)
    transcript_writer.human("yes, approve the signup contract — wait, not yet", ts=_later(0.5))
    proc = cli("record", "--session", SID, "--quote", QUOTE)
    assert proc.returncode == 1 and "reads as a refusal" in proc.stderr
    transcript_writer.human("ok fine, ship it all", ts=_later(1.0))
    proc = cli("record", "--session", SID, "--quote", "ok")
    assert proc.returncode == 1 and "too short" in proc.stderr


def test_genuine_human_turn_accepted_then_stale_after_edit(workspace, transcript_writer, run_hook, claude_payload):
    contract = _setup(workspace, transcript_writer, run_hook, claude_payload)
    transcript_writer.assistant("Do you approve the signup contract?")
    transcript_writer.human(QUOTE, ts=_later(0.5))
    proc = cli("record", "--session", SID, "--quote", QUOTE)
    assert proc.returncode == 0, proc.stderr
    approval = json.loads((state.session_path(str(workspace), "claude", SID) / "contract_approval.json").read_text())
    turns = transcript.parse_claude(transcript_writer.path.read_text().splitlines())
    assert approval["turn_uuid"] == turns[-1].uuid and approval["turn_source"] == "typed"
    assert approval["recorded_by"] == "contract_gate.record" and approval["quote"] == QUOTE
    ctx = make_session_context("claude", SID, transcript_writer.path, event="SessionStart")
    result = contract_gate.review(ctx, ctx.cfg)
    assert result.gate == "review" and result.status == "PASS" and result.data["verified"] is True
    assert result.items[0]["turn_uuid"] == approval["turn_uuid"] and result.items[0]["superseded"] is False
    contract.write_text(contract_text(extra_unit="\n### Scenario: accepts long passwords\n- Given a long password\n"
                                                 "- When it is checked\n- Then it is accepted\n"), encoding="utf-8")
    result = contract_gate.review(ctx, ctx.cfg)
    assert result.status == "FAIL" and "stale" in result.detail
    contract.write_text(contract_text().replace("# Contract: User signup", "# Contract: User sign-up flow"),
                        encoding="utf-8")
    assert contract_gate.review(ctx, ctx.cfg).status == "PASS"


def test_record_refused_when_contract_changed_after_request(workspace, transcript_writer, run_hook, claude_payload):
    contract = _setup(workspace, transcript_writer, run_hook, claude_payload)
    contract.write_text(contract_text(journey=False) + "_Not applicable: CLI only_\n", encoding="utf-8")
    transcript_writer.human(QUOTE, ts=_later(0.5))
    proc = cli("record", "--session", SID, "--quote", QUOTE)
    assert proc.returncode == 1 and "the contract changed after you asked" in proc.stderr


def test_codex_rollout_genuine_and_forged(workspace, codex_payload, tmp_path):
    rollout = tmp_path / "rollout-2026-10-13.jsonl"
    rollout.write_text("", encoding="utf-8")
    ctx = make_session_context("codex", "codex-sess", rollout, event="SessionStart")
    _write_contract(workspace)
    ledger.note_contract_touched(ctx, str(workspace / "docs" / "contracts" / "user-signup.md"))
    contract_gate.propose(ctx, ["docs/contracts/user-signup.md"])
    contract_gate.request(ctx)
    time.sleep(0.02)
    rows = [json.loads(line) for line in (FIXTURES / "transcripts" / "codex_rollout.jsonl").read_text().splitlines()]
    with open(str(rollout), "a", encoding="utf-8") as handle:
        for index, row in enumerate(rows):
            if row.get("payload", {}).get("id") in ("c-human-1", "c-human-2"):
                continue
            row["timestamp"] = _stamp(_later(0.1 + index * 0.01))
            handle.write(json.dumps(row) + "\n")
    ok, reason = contract_gate.record(ctx, QUOTE, transcript.read_human_turns(ctx))
    assert not ok and ("has not spoken" in reason or "no human turn" in reason)
    genuine = [r for r in rows if r.get("payload", {}).get("id") == "c-human-2"][0]
    genuine["timestamp"] = _stamp(_later(1.0))
    with open(str(rollout), "a", encoding="utf-8") as handle:
        handle.write(json.dumps(genuine) + "\n")
    ok, reason = contract_gate.record(ctx, QUOTE, transcript.read_human_turns(ctx))
    assert ok, reason


def test_ui_log_channel(workspace, tmp_path, monkeypatch):
    log = tmp_path / "human_turns.jsonl"
    log.write_text("", encoding="utf-8")
    monkeypatch.setenv("OMEGA_HUMAN_LOG", str(log))
    ctx = make_session_context("claude", "ui-sess", None, event="SessionStart")
    _write_contract(workspace)
    ledger.note_contract_touched(ctx, str(workspace / "docs" / "contracts" / "user-signup.md"))
    contract_gate.propose(ctx, [])
    contract_gate.request(ctx)
    later = time.time_ns() + 1000
    with open(str(log), "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"ts": state.iso(later), "ts_ns": later, "uuid": "ui-9", "user_id": "local",
                                 "kind": "assistant", "text": QUOTE, "run_id": "r", "sig": "00"}) + "\n")
    ok, _ = contract_gate.record(ctx, QUOTE, transcript.read_human_turns(ctx))
    assert not ok
    with open(str(log), "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"ts": state.iso(later + 1), "ts_ns": later + 1, "uuid": "ui-10", "user_id": "local",
                                 "kind": "approval", "text": QUOTE, "run_id": "r", "sig": "00"}) + "\n")
    ok, reason = contract_gate.record(ctx, QUOTE, transcript.read_human_turns(ctx))
    assert ok, reason
    approval = state.read_json(state.session_dir(ctx) / "contract_approval.json")
    assert approval["channel"] == "ui" and approval["turn_uuid"] == "ui-10"
    result = contract_gate.review(ctx, ctx.cfg)
    assert result.status == "PASS" and result.data["channel"] == "ui"


def test_override_requires_token_in_human_turn(workspace, transcript_writer, run_hook, claude_payload):
    _setup(workspace, transcript_writer, run_hook, claude_payload)
    token = (state.session_path(str(workspace), "claude", SID) / "override_token").read_text().strip()
    assert cli("override", "--session", SID, "--token", "hs-000000", "--reason", "x").returncode == 1
    transcript_writer.assistant("send me %s" % token)
    assert cli("override", "--session", SID, "--token", token, "--reason", "demo").returncode == 1
    transcript_writer.human("use %s, we accept the risk" % token, ts=_later(0.5))
    proc = cli("override", "--session", SID, "--token", token, "--reason", "demo deadline")
    assert proc.returncode == 0, proc.stderr
    ctx = make_session_context("claude", SID, transcript_writer.path, event="SessionStart")
    first = contract_gate.review(ctx, ctx.cfg)
    assert first.status == "PASS" and "NOT approved" in first.detail
    assert first.data["overrides"][0]["consumed"] is True
    second = contract_gate.review(ctx, ctx.cfg)
    assert "override" not in second.detail


def _ledger(ctx, workspace, rel, kind="modified"):
    path = workspace / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("x = 1\n", encoding="utf-8")
    ledger.append(ctx, str(path), kind, "Write", None)


def test_is_nontrivial_rules(workspace, session):
    cfg = session.cfg
    assert contract_gate.is_nontrivial(session, cfg)[0] is False
    _ledger(session, workspace, "src/a.py")
    assert contract_gate.is_nontrivial(session, cfg)[0] is False
    _ledger(session, workspace, "src/b.py", "added")
    assert contract_gate.is_nontrivial(session, cfg) == (True, "new source file src/b.py")
    other = make_session_context("claude", "other-sess")
    _ledger(other, workspace, "src/routes/users.py")
    assert contract_gate.is_nontrivial(other, cfg)[0] is True
    third = make_session_context("claude", "third-sess")
    for name in ("a", "b", "c"):
        _ledger(third, workspace, "src/%s.py" % name)
    assert contract_gate.is_nontrivial(third, cfg)[0] is True


def test_check_states(workspace, session):
    cfg = session.cfg
    _ledger(session, workspace, "src/a.py")
    result = contract_gate.check(session, cfg)
    assert result.gate == "contract" and result.status == "NOT_APPLICABLE"
    _ledger(session, workspace, "src/auth/signup.py", "added")
    result = contract_gate.check(session, cfg)
    assert result.status == "FAIL" and "no contract covers" in result.detail
    assert result.data["uncovered_paths"] == ["src/a.py", "src/auth/signup.py"]
    (workspace / "tests" / "test_signup.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    _write_contract(workspace, contract_text(code="src/auth/signup.py, src/a.py"))
    result = contract_gate.check(session, cfg)
    assert result.status == "PASS", result.detail
    entry = result.items[0]
    assert entry["slug"] == "user-signup" and entry["valid"] and entry["code_in_ledger"] == ["src/auth/signup.py", "src/a.py"]
    assert entry["seams"] == {"Unit": 1, "Integration": 0, "Functional": 0, "Journey": 1}
    assert entry["not_applicable"] == ["Integration", "Functional"]
    _write_contract(workspace, contract_text(code="src/auth/signup.py, src/a.py", journey=False))
    result = contract_gate.check(session, cfg)
    assert result.status == "FAIL" and "E007" in result.detail


def test_review_request_allows_one_stop_then_waiting_is_not_agreeing(workspace, session):
    cfg = session.cfg
    _write_contract(workspace)
    ledger.note_contract_touched(session, str(workspace / "docs" / "contracts" / "user-signup.md"))
    result = contract_gate.review(session, cfg)
    assert result.status == "FAIL" and "awaiting human sign-off" in result.detail and "record --session" in result.detail
    contract_gate.propose(session, [])
    contract_gate.request(session)
    first = contract_gate.review(session, cfg)
    assert first.status == "PASS" and first.data["pending_request"] is True and first.data["verified"] is False
    second = contract_gate.review(session, cfg)
    assert second.status == "FAIL" and "waiting is not agreeing" in second.detail


def test_review_superseded_by_newer_proposal(workspace, session):
    cfg = session.cfg
    _write_contract(workspace)
    ledger.note_contract_touched(session, str(workspace / "docs" / "contracts" / "user-signup.md"))
    contract_gate.propose(session, [])
    combined, per_slug = contract_gate.current_fingerprint(session, cfg)
    proposal = state.read_json(state.session_dir(session) / "contract_proposal.json")
    state.write_json_atomic(state.session_dir(session) / "contract_approval.json",
                            {"fingerprint": combined, "per_slug": per_slug, "proposal_id": proposal["proposal_id"],
                             "quote": QUOTE, "turn_uuid": "u", "turn_source": "typed", "channel": "transcript"})
    assert contract_gate.review(session, cfg).status == "PASS"
    contract_gate.propose(session, [])
    result = contract_gate.review(session, cfg)
    assert result.status == "FAIL" and "superseded" in result.detail and result.items[0]["superseded"] is True


def test_review_secret_and_pii_scans(workspace, session):
    cfg = session.cfg
    _ledger(session, workspace, "src/a.py")
    (workspace / "src" / "a.py").write_text("TOKEN = 'ghp_" + "a1B2c3D4e5" * 4 + "'\n", encoding="utf-8")
    result = contract_gate.review(session, cfg)
    assert result.status == "FAIL" and "secret github-token in src/a.py:1" in result.detail
    assert result.data["secrets_scan"]["status"] == "FAIL"
    assert "ghp_" not in json.dumps(result.data)
    (workspace / "src" / "a.py").write_text("OWNER = 'ada.lovelace@corp-mail.io'\n", encoding="utf-8")
    result = contract_gate.review(session, cfg)
    assert result.status == "FAIL" and result.data["pii_scan"]["status"] == "FAIL"
    (workspace / "src" / "a.py").write_text("OWNER = 'ada@example.com'\n", encoding="utf-8")
    assert contract_gate.review(session, cfg).status == "NOT_APPLICABLE"


def test_deleted_contract_stays_in_fingerprint(workspace, session):
    path = _write_contract(workspace)
    ledger.note_contract_touched(session, str(path))
    before, per_slug = contract_gate.current_fingerprint(session, session.cfg)
    assert per_slug["user-signup"] != "<deleted>"
    path.unlink()
    after, per_slug = contract_gate.current_fingerprint(session, session.cfg)
    assert per_slug == {"user-signup": "<deleted>"} and after != before


def test_status_cli_counts_human_turns(workspace, transcript_writer, run_hook, claude_payload):
    _setup(workspace, transcript_writer, run_hook, claude_payload)
    proc = cli("status", "--session", SID, "--json")
    assert proc.returncode == 0
    info = json.loads(proc.stdout)
    assert info["human_turns"] == 1 and info["request"]["consumed"] is False
    assert info["override"] is None and "token" not in json.dumps(info.get("override") or {})
    check = cli("check", "--session", SID, "--json")
    assert check.returncode == 0 and json.loads(check.stdout)["status"] == "PASS"

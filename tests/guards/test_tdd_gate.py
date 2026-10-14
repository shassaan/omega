from __future__ import annotations

import json
import subprocess
import time

import pytest

from hooks import tdd_gate
from hooks.lib import hashing, state
from hooks.lib.event import Mutation
from tests.conftest import OMEGA_ROOT, wait_for
from tests.guards.support import (POST, PRE, edit_payload, link_python, post_outcome, pre_outcome, read_jsonl,
                                  session_dir)

SID = "sess-claude-0001"
IMPL = "def add(a, b):\n    return a + b\n"
TEST_V1 = "from src.calc import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
TEST_V2 = TEST_V1 + "\n\ndef test_add_negative():\n    assert add(-1, -1) == -2\n"


def _pre_write(make, path, content):
    return edit_payload(make, "PreToolUse", "Write", {"file_path": str(path), "content": content})


def _post_write(make, path, content, created):
    payload = edit_payload(make, "PostToolUse", "Write", {"file_path": str(path), "content": content})
    payload["tool_response"] = {"filePath": str(path), "type": "create" if created else "update"}
    return payload


def _row_for(path, rel, sha):
    return [r for r in read_jsonl(path) if (r.get("test_files") or {}).get(rel) == sha]


def _tdd_cli(*args, env=None):
    import os
    merged = dict(os.environ)
    merged.update(env or {})
    return subprocess.run(["/bin/sh", str(OMEGA_ROOT / "bin" / "launch.sh"), "hooks/tdd_gate.py"] + list(args),
                          capture_output=True, text=True, env=merged, timeout=120)


def test_red_then_green_cycle_through_real_runner(workspace, run_hook, claude_payload):
    link_python(workspace)
    src = workspace / "src" / "calc.py"
    test = workspace / "tests" / "test_calc.py"
    directory = session_dir(workspace, "claude", SID)

    blocked, reason = pre_outcome(run_hook(PRE, _pre_write(claude_payload, src, IMPL), "claude"), "claude")
    assert blocked and reason.startswith("[tdd-gate] refused: src/calc.py has no test file yet")
    assert "tests/test_calc.py" in reason and "tdd.no_test_file" in reason

    blocked, _ = pre_outcome(run_hook(PRE, _pre_write(claude_payload, test, TEST_V1), "claude"), "claude")
    assert not blocked
    test.write_text(TEST_V1, encoding="utf-8")
    post = run_hook(POST, _post_write(claude_payload, test, TEST_V1, True), "claude")
    assert post.returncode in (0, 2)
    sha_v1 = hashing.sha256_file(str(test))
    assert wait_for(lambda: _row_for(directory / "red.jsonl", "tests/test_calc.py", sha_v1), timeout=60)
    changed = read_jsonl(directory / "changed.jsonl")
    assert changed[-1]["rel"] == "tests/test_calc.py" and changed[-1]["kind"] == "added"

    notes = workspace / "docs" / "plan.md"
    notes.write_text("plan\n", encoding="utf-8")
    post = run_hook(POST, _post_write(claude_payload, notes, "plan\n", True), "claude")
    flagged, text = post_outcome(post, "claude")
    assert flagged and "[tests] FAIL pytest tests/test_calc.py" in text and "observed red" in text
    assert post.returncode == 2

    blocked, reason = pre_outcome(run_hook(PRE, _pre_write(claude_payload, src, IMPL), "claude"), "claude")
    assert not blocked, reason
    src.write_text(IMPL, encoding="utf-8")
    run_hook(POST, _post_write(claude_payload, src, IMPL, True), "claude")
    assert wait_for(lambda: _row_for(directory / "green.jsonl", "tests/test_calc.py", sha_v1), timeout=60)

    status = _tdd_cli("status", "--session", SID, "--json")
    assert status.returncode == 0, status.stderr
    report = json.loads(status.stdout)
    assert report["status"] == "PASS"
    assert report["sources"][0]["source"] == "src/calc.py" and report["sources"][0]["red"] and report["sources"][0]["green"]

    test.write_text(TEST_V2, encoding="utf-8")
    run_hook(POST, _post_write(claude_payload, test, TEST_V2, False), "claude")
    sha_v2 = hashing.sha256_file(str(test))
    assert wait_for(lambda: _row_for(directory / "green.jsonl", "tests/test_calc.py", sha_v2), timeout=60)
    edit = edit_payload(claude_payload, "PreToolUse", "Edit",
                        {"file_path": str(src), "old_string": "a + b", "new_string": "b + a"})
    blocked, reason = pre_outcome(run_hook(PRE, edit, "claude"), "claude")
    assert blocked and "tdd.not_red" in reason
    assert "pass (the test passed without the change" in reason
    blocked, _ = pre_outcome(run_hook(PRE, edit, "claude", env={"OMEGA_TDD_MODE": "red-or-green"}), "claude")
    assert not blocked


def test_post_tool_use_feedback_for_codex_is_json(workspace, run_hook, codex_payload):
    link_python(workspace)
    test = workspace / "tests" / "test_fail.py"
    test.write_text("def test_x():\n    assert False\n", encoding="utf-8")
    payload = codex_payload("PostToolUse")
    payload["tool_input"] = {"command": "*** Begin Patch\n*** Add File: tests/test_fail.py\n+def test_x():\n+    assert False\n*** End Patch\n"}
    first = run_hook(POST, payload, "codex")
    assert first.returncode == 0
    directory = session_dir(workspace, "codex", payload["session_id"])
    assert wait_for(lambda: read_jsonl(directory / "red.jsonl"), timeout=60)
    time.sleep(0.1)
    (workspace / "docs" / "notes.md").write_text("n\n", encoding="utf-8")
    payload["tool_input"] = {"command": "*** Begin Patch\n*** Add File: docs/notes.md\n+n\n*** End Patch\n"}
    second = run_hook(POST, payload, "codex")
    blocked, reason = post_outcome(second, "codex")
    assert second.returncode == 0
    assert blocked and "[tests] FAIL" in reason


def test_cli_run_and_map(workspace, fake_pytest, session):
    link_python(workspace)
    fake_pytest(workspace, "fail", "tests/test_calc.py")
    mapped = _tdd_cli("map", "src/calc.py")
    assert mapped.returncode == 0 and "tests/test_calc.py" in mapped.stdout
    ran = _tdd_cli("run", "--session", session.session_id, "--test", "tests/test_calc.py", "--json")
    assert ran.returncode == 1, ran.stderr
    assert json.loads(ran.stdout)["state"] == "fail" and json.loads(ran.stdout)["red"] is True
    fake_pytest(workspace, "pass", "tests/test_calc.py")
    ran = _tdd_cli("run", "--session", session.session_id, "--test", "tests/test_calc.py")
    assert ran.returncode == 0
    missing = _tdd_cli("run", "--session", session.session_id, "--test", "tests/test_nope.py")
    assert missing.returncode == 2


def test_missing_pytest_is_never_red(workspace, session):
    target = workspace / ".venv" / "bin" / "python"
    target.parent.mkdir(parents=True)
    target.write_text("#!/bin/sh\necho \"/x/python: No module named pytest\" >&2\nexit 1\n", encoding="utf-8")
    target.chmod(0o755)
    (workspace / "tests" / "test_calc.py").write_text("def test_x():\n    assert False\n", encoding="utf-8")
    result = tdd_gate.run(session, session.cfg, "tests/test_calc.py")
    assert result["state"] == "skipped_env" and result["red"] is False
    decision = tdd_gate.judge([Mutation(str(workspace / "src" / "calc.py"), "added")], session, session.cfg)
    assert decision.action == "deny" and "skipped_env" in decision.reason


def _red(ctx, rel, sha, ts_ns, status="fail"):
    name = "red.jsonl" if status == "fail" else "green.jsonl"
    state.append_jsonl(state.session_dir(ctx) / name, {"ts": state.iso(ts_ns), "ts_ns": ts_ns, "job_id": "j-%d" % ts_ns,
                                                       "scope_key": "test:" + rel, "test_files": {rel: sha},
                                                       "status": status, "rc": 1 if status == "fail" else 0})


def _ledger(ctx, workspace, rel, kind="modified", content="x = 1\n"):
    from hooks.lib import ledger
    path = workspace / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    ledger.append(ctx, str(path), kind, "Write", "toolu_x")
    return path


def test_judge_unit_rules(workspace, session):
    cfg = session.cfg
    ws = str(workspace)
    allow = lambda rel, kind="modified": tdd_gate.judge([Mutation(ws + "/" + rel, kind)], session, cfg).action
    assert allow("docs/guide.md") == "allow"
    assert allow("migrations/001_init.sql") == "allow"
    assert allow("tests/test_calc.py") == "allow"
    assert allow("src/__init__.py") == "allow"
    assert allow("src/calc.py", "deleted") == "allow"
    assert allow("src/calc.py", "renamed_from") == "allow"
    assert allow("src/calc.py", "unknown") == "deny"
    assert allow("src/calc.py") == "deny"
    assert tdd_gate.judge([Mutation("/tmp/elsewhere.py", "modified")], session, cfg).action == "allow"
    test = workspace / "tests" / "test_calc.py"
    test.write_text("def test_x():\n    assert False\n", encoding="utf-8")
    decision = tdd_gate.judge([Mutation(ws + "/src/calc.py", "modified")], session, cfg)
    assert decision.action == "deny" and "none (run:" in decision.reason
    _red(session, "tests/test_calc.py", "0" * 64, time.time_ns())
    assert allow("src/calc.py") == "deny"
    _red(session, "tests/test_calc.py", hashing.sha256_file(str(test)), time.time_ns())
    assert allow("src/calc.py") == "allow"


def test_contract_mapping_any_test_red_suffices(workspace, session):
    contract = workspace / "docs" / "contracts" / "calc.md"
    contract.write_text("# Contract: Calc\nslug: calc\ncode: src/engine/calc.py\ntests: tests/unit/test_a.py, "
                        "tests/unit/test_b.py\nowed: none\nassumptions: none\n", encoding="utf-8")
    (workspace / "tests" / "unit").mkdir(parents=True)
    second = workspace / "tests" / "unit" / "test_b.py"
    second.write_text("def test_b():\n    assert False\n", encoding="utf-8")
    mutation = [Mutation(str(workspace / "src" / "engine" / "calc.py"), "added")]
    assert tdd_gate.judge(mutation, session, session.cfg).action == "deny"
    _red(session, "tests/unit/test_b.py", hashing.sha256_file(str(second)), time.time_ns())
    assert tdd_gate.judge(mutation, session, session.cfg).action == "allow"


def test_green_check_states(workspace, session):
    cfg = session.cfg
    result = tdd_gate.green_check(session, cfg)
    assert result.gate == "tdd" and result.status == "NOT_APPLICABLE"
    _ledger(session, workspace, "src/calc.py")
    result = tdd_gate.green_check(session, cfg)
    assert result.status == "FAIL" and "no test file" in result.detail
    test = workspace / "tests" / "test_calc.py"
    test.write_text("def test_x():\n    assert True\n", encoding="utf-8")
    result = tdd_gate.green_check(session, cfg)
    assert result.status == "FAIL" and "no red observed for the current test" in result.detail
    sha = hashing.sha256_file(str(test))
    red_ts = time.time_ns()
    _red(session, "tests/test_calc.py", sha, red_ts)
    result = tdd_gate.green_check(session, cfg)
    assert result.status == "FAIL" and "red observed, no green since" in result.detail
    assert result.detail.startswith("src/calc.py ← tests/test_calc.py@%s" % sha[:7])
    _red(session, "tests/test_calc.py", sha, red_ts - 10, status="pass")
    assert tdd_gate.green_check(session, cfg).status == "FAIL"
    _red(session, "tests/test_calc.py", sha, red_ts + 10, status="pass")
    result = tdd_gate.green_check(session, cfg)
    assert result.status == "PASS" and result.required is True
    item = result.items[0]
    assert item["source"] == "src/calc.py" and item["test"] == "tests/test_calc.py" and item["test_sha256"] == sha
    assert item["red"]["ts_ns"] == red_ts and item["green"]["ts_ns"] == red_ts + 10 and item["status"] == "PASS"
    test.write_text("def test_x():\n    assert 1\n", encoding="utf-8")
    assert tdd_gate.green_check(session, cfg).status == "FAIL"


def test_green_check_running_job_is_unverified(workspace, session):
    _ledger(session, workspace, "src/calc.py")
    test = workspace / "tests" / "test_calc.py"
    test.write_text("def test_x():\n    assert True\n", encoding="utf-8")
    sha = hashing.sha256_file(str(test))
    _red(session, "tests/test_calc.py", sha, time.time_ns())
    jobs = state.session_dir(session) / "jobs"
    jobs.mkdir(exist_ok=True)
    state.write_json_atomic(jobs / "test_tests_test_calc_py-1.job.json",
                            {"id": "test_tests_test_calc_py-1", "scope_key": "test:tests/test_calc.py", "kind": "test",
                             "ts_ns": time.time_ns(), "test_files": {"tests/test_calc.py": sha}})
    result = tdd_gate.green_check(session, session.cfg)
    assert result.status == "UNVERIFIED" and "green job still running" in result.detail


def test_green_check_red_or_green_mode(workspace, session, monkeypatch):
    monkeypatch.setenv("OMEGA_TDD_MODE", "red-or-green")
    from hooks.lib import config
    cfg = config.load(session.harness_root, session.workspace)
    _ledger(session, workspace, "src/calc.py")
    _ledger(session, workspace, "src/other.py")
    test = workspace / "tests" / "test_calc.py"
    test.write_text("def test_x():\n    assert True\n", encoding="utf-8")
    _red(session, "tests/test_calc.py", hashing.sha256_file(str(test)), time.time_ns(), status="pass")
    result = tdd_gate.green_check(session, cfg)
    assert result.status == "UNVERIFIED"
    statuses = {i["source"]: i["status"] for i in result.items}
    assert statuses == {"src/calc.py": "PASS", "src/other.py": "UNVERIFIED"}


def test_status_reports_pairs(workspace, session):
    _ledger(session, workspace, "src/calc.py")
    report = tdd_gate.status(session, session.cfg)
    assert report["mode"] == "strict" and report["sources"][0]["source"] == "src/calc.py"
    assert report["status"] == "FAIL"

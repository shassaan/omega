from __future__ import annotations

import json
import time
from pathlib import Path

from hooks import stop_proof
from hooks.lib import jobstore, state
from tests.gates.conftest import make_executable, reload_cfg, touch, write_ws_config


def suite(argv, sid="tool", required=True, timeout_s=20, detect=()):
    return {"id": sid, "detect": list(detect), "argv": argv, "required": required, "timeout_s": timeout_s}


def script(fake_bin: Path, name: str, rc: int, output: str = "", sleep: float = 0.0) -> str:
    (fake_bin / (name + ".out")).write_text(output + "\n", encoding="utf-8")
    body = "#!/bin/sh\n"
    if sleep:
        body += "sleep %s\n" % sleep
    body += "cat '%s'\nexit %d\n" % (fake_bin / (name + ".out"), rc)
    make_executable(fake_bin / name, body)
    return name


def test_pass_fail_and_tail(session, fake_bin):
    ok = stop_proof.run_capability(suite([script(fake_bin, "ok", 0, "12 passed in 0.1s")]), session, session.cfg, [])
    assert ok.status == "PASS" and ok.detail == "12 passed in 0.1s" and ok.rc == 0
    lines = "\n".join("line %d" % i for i in range(100))
    bad = stop_proof.run_capability(suite([script(fake_bin, "bad", 1, lines)]), session, session.cfg, [])
    assert bad.status == "FAIL" and bad.detail.startswith("exit 1 — line 99")
    assert bad.output_tail.splitlines()[0] == "line 60" and len(bad.output_tail.splitlines()) == 40


def test_missing_tool_is_unverified_never_pass(session):
    result = stop_proof.run_capability(suite(["definitely-not-a-real-tool-xyz"]), session, session.cfg, [])
    assert result.status == "UNVERIFIED" and "not installed" in result.detail


def test_missing_cwd_is_fail(session, tmp_path):
    session.workspace = str(tmp_path / "gone")
    result = stop_proof.run_capability(suite(["true"]), session, session.cfg, [])
    assert result.status == "FAIL" and result.detail == "cannot run: directory does not exist"


def test_timeout_is_fail(session, fake_bin):
    result = stop_proof.run_capability(suite([script(fake_bin, "slow", 0, "x", sleep=3)], timeout_s=0.5), session,
                                       session.cfg, [])
    assert result.status == "FAIL" and "timed out" in result.detail


def test_no_tests_and_environment_are_unverified(session, fake_bin):
    pytest_like = script(fake_bin, "pytest", 5, "collected 0 items\nno tests ran in 0.01s")
    no_tests = stop_proof.run_capability(suite([pytest_like]), session, session.cfg, [])
    assert no_tests.status == "UNVERIFIED" and "no tests" in no_tests.detail
    env = stop_proof.run_capability(suite([script(fake_bin, "envfail", 1, "No module named pytest")]), session,
                                    session.cfg, [])
    assert env.status == "UNVERIFIED"
    first_party = stop_proof.run_capability(suite([script(fake_bin, "firstparty", 1,
                                                          "ModuleNotFoundError: No module named 'src.calc'")]),
                                            session, session.cfg, [])
    assert first_party.status == "FAIL"


def test_changed_placeholder_expands_or_is_not_applicable(session, fake_bin, workspace):
    echo = make_executable(fake_bin / "echoargs", "#!/bin/sh\necho \"$@\"\nexit 0\n")
    none = stop_proof.run_capability(suite([echo.name, "{changed_py}"]), session, session.cfg, [])
    assert none.status == "NOT_APPLICABLE" and none.detail == "no changed files of this kind"
    path = touch(session, "src/calc.py", "x = 1\n")
    some = stop_proof.run_capability(suite([echo.name, "{changed_py}"]), session, session.cfg, [str(path)])
    assert some.status == "PASS" and some.argv == ["echoargs", "src/calc.py"]


def test_prove_with_nothing_detected_is_unproven(session, workspace):
    write_ws_config(workspace, {"proof": {"suites": [{"id": "vitest", "detect": ["vitest.config.ts"],
                                                      "argv": ["npx", "vitest"], "required": True}]}})
    reload_cfg(session)
    path = touch(session, "src/calc.py", "x = 1\n")
    result = stop_proof.prove(session, session.cfg, [str(path)])
    assert result.status == "UNVERIFIED"
    assert any("UNPROVEN" in i["detail"] and i["required"] for i in result.items)
    docs = touch(session, "docs/a.md", "hi\n")
    doc_only = stop_proof.prove(session, session.cfg, [str(docs)])
    assert doc_only.status == "PASS"
    assert any("UNPROVEN" in i["detail"] and not i["required"] for i in doc_only.items)


def test_prove_runs_real_pytest_in_workspace(session, workspace, fake_pytest):
    write_ws_config(workspace, {"proof": {"suites": [
        {"id": "pytest", "detect": ["tests/"], "argv": ["{python}", "-m", "pytest", "-q", "-p", "no:cacheprovider"],
         "required": True, "timeout_s": 120}]}})
    reload_cfg(session)
    fake_pytest(workspace, "pass")
    green = stop_proof.prove(session, session.cfg, [])
    assert green.status == "PASS", green.items
    fake_pytest(workspace, "fail")
    red = stop_proof.prove(session, session.cfg, [])
    assert red.status == "FAIL" and red.items[0]["rc"] == 1


def _job(ctx, scope_key, kind, argv, status=None, rc=None, cwd=None):
    directory = jobstore.jobs_dir(ctx)
    ts_ns = time.time_ns()
    job_id = jobstore.job_id_for(scope_key, ts_ns)
    spec = {"id": job_id, "scope_key": scope_key, "kind": kind, "label": "%s %s" % (argv[0], scope_key),
            "argv": argv, "cwd": cwd or ctx.workspace, "env_add": {}, "ts": state.iso(ts_ns), "ts_ns": ts_ns,
            "session_id": ctx.session_id, "timeout_s": 30, "test_files": {}, "source_files": []}
    state.write_json_atomic(directory / ("%s.job.json" % job_id), spec)
    if status is not None:
        jobstore.write_result(directory, {"id": job_id, "rc": rc, "status": status, "output": "out", "started_ns": 1,
                                          "finished_ns": 2, "duration_ms": 3, "test_files": {}, "cancelled_by": None})
    return job_id


def test_background_outcomes_newest_failure_counts(session, fake_bin):
    _job(session, "test:tests/test_a.py", "test", ["npx", "vitest", "run", "tests/a.test.ts"], "fail", 1)
    _job(session, "lint:src/a.py", "lint", ["ruff", "check", "src/a.py"], "pass", 0)
    rows = stop_proof.background_outcomes(session)
    by_check = {r.check: r for r in rows}
    test_row = [r for r in rows if "tests/test_a.py" in r.check][0]
    assert test_row.status == "FAIL" and test_row.required is True
    lint_row = [r for r in rows if "lint:src/a.py" in r.check][0]
    assert lint_row.status == "PASS" and lint_row.required is False
    assert len(by_check) == 2
    covered = stop_proof.background_outcomes(session, covered={"vitest", "ruff"})
    assert covered == []


def test_background_pending_job_is_rerun(session, fake_bin):
    tool = script(fake_bin, "flaky", 0, "1 passed")
    _job(session, "test:tests/test_b.py", "test", [tool, "tests/test_b.py"])
    rows = stop_proof.background_outcomes(session)
    assert rows[0].status == "PASS" and "rerun at Stop" in rows[0].detail


def test_skipped_background_job_is_unverified(session):
    _job(session, "test:tests/test_c.py", "test", ["python3", "-m", "pytest"], "skipped_env", 1)
    rows = stop_proof.background_outcomes(session)
    assert rows[0].status == "UNVERIFIED"


def test_cli_json(session, workspace, capsys, fake_bin):
    write_ws_config(workspace, {"proof": {"suites": [suite([script(fake_bin, "ok2", 0, "fine")], sid="ok2")]}})
    touch(session, "src/calc.py", "x = 1\n")
    code = stop_proof.main(["--session", session.session_id, "--workspace", str(workspace), "--json"])
    assert code == 0
    body = json.loads(capsys.readouterr().out)
    assert body["gate"] == "proof" and body["status"] == "PASS"

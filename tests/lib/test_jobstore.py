from __future__ import annotations

import json
import subprocess
import sys
import time

import pytest

from hooks.lib import hashing, jobstore, run_job, state
from tests.conftest import wait_for

PY = sys.executable


def done(ctx, scope_key, timeout=30.0):
    def finished():
        view = jobstore.newest(ctx, scope_key)
        return view if view and view["done"] else None
    return wait_for(finished, timeout)


def launch_py(ctx, workspace, code, scope="test:tests/test_x.py", kind="test", test_files=None, timeout_s=60):
    return jobstore.launch(ctx, scope, kind, "py " + scope, [PY, "-c", code], str(workspace),
                           test_files if test_files is not None else [], ["src/x.py"], timeout_s)


@pytest.mark.parametrize("rc,output,argv,expected", [
    (0, "", [], "pass"),
    (127, "x not installed", [], "not_installed"),
    (124, "timed out", [], "timeout"),
    (5, "", ["python", "-m", "pytest"], "skipped_no_tests"),
    (5, "", ["node"], "fail"),
    (1, "collected 0 items", [], "skipped_no_tests"),
    (1, "no tests ran in 0.01s", [], "skipped_no_tests"),
    (1, "No test files found", [], "skipped_no_tests"),
    (1, "ModuleNotFoundError: No module named 'httpx'", [], "skipped_env"),
    (1, "/x/python: No module named pytest", [], "skipped_env"),
    (1, "ModuleNotFoundError: No module named 'google.cloud'", [], "skipped_env"),
    (1, "ModuleNotFoundError: No module named 'myapp'", [], "fail"),
    (1, "ModuleNotFoundError: No module named 'src.calc'", [], "fail"),
    (1, "Temporary failure in name resolution", [], "skipped_env"),
    (1, "psycopg.OperationalError: Connection refused", [], "skipped_env"),
    (1, "could not connect to server", [], "skipped_env"),
    (1, "Max retries exceeded with url", [], "skipped_env"),
    (1, "ECONNREFUSED 127.0.0.1:5432", [], "skipped_env"),
    (4, "usage: pytest [options]\nerror: unrecognized arguments: --bogus", [], "error"),
    (4, "usage: x", [], "error"),
    (4, "some other rc 4", [], "fail"),
    (1, "AssertionError: assert 2 == 3", [], "fail"),
    (None, "", [], "error"),
])
def test_classify_table(rc, output, argv, expected, harness_root):
    from hooks.lib import config
    assert jobstore.classify(rc, output, argv, config.load(harness_root)) == expected


def test_cannot_find_module_depends_on_node_modules(tmp_path, harness_root):
    from hooks.lib import config
    cfg = config.load(harness_root)
    assert jobstore.is_environment_failure("Error: Cannot find module 'vitest'", cfg, str(tmp_path))
    (tmp_path / "node_modules").mkdir()
    assert not jobstore.is_environment_failure("Error: Cannot find module './calc'", cfg, str(tmp_path))
    assert jobstore.classify(1, "Error: Cannot find module './calc'", ["npx"], cfg, str(tmp_path)) == "fail"


def test_job_id_format():
    assert jobstore.job_id_for("test:tests/test_signup.py", 17) == "test_tests_test_signup_py-17"


def test_passing_test_job_writes_green_with_launch_hashes(session, workspace):
    test_file = workspace / "tests" / "test_x.py"
    test_file.write_text("def test_x(): pass\n")
    sha = hashing.sha256_file(str(test_file))
    spec = launch_py(session, workspace, "print('ok')", test_files=["tests/test_x.py"])
    job_json = json.loads((session.dir / "jobs" / ("%s.job.json" % spec["id"])).read_text())
    for key in ("id", "scope_key", "kind", "label", "argv", "cwd", "env_add", "ts", "ts_ns", "session_id",
                "timeout_s", "test_files", "source_files", "session_dir"):
        assert key in job_json
    assert job_json["test_files"] == {"tests/test_x.py": sha}
    view = done(session, "test:tests/test_x.py")
    result = view["result"]
    assert result["status"] == "pass" and result["rc"] == 0 and result["test_files"] == {"tests/test_x.py": sha}
    assert set(result) == {"id", "rc", "status", "output", "started_ns", "finished_ns", "duration_ms", "test_files", "cancelled_by"}
    green = state.read_jsonl(session.dir / "green.jsonl")
    assert len(green) == 1 and green[0]["test_files"] == {"tests/test_x.py": sha} and green[0]["status"] == "pass"
    assert not (session.dir / "red.jsonl").exists()


def test_failing_test_job_writes_red_with_redacted_tail(session, workspace):
    secret = "ghp_" + "Ab3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zC1234"
    code = "import sys; print('\\n'.join('line %d' % i for i in range(300))); print('" + secret + "'); sys.exit(1)"
    launch_py(session, workspace, code)
    view = done(session, "test:tests/test_x.py")
    assert view["result"]["status"] == "fail"
    assert secret not in view["result"]["output"] and "line 299" in view["result"]["output"]
    assert "line 50\n" not in view["result"]["output"]
    red = state.read_jsonl(session.dir / "red.jsonl")
    assert len(red) == 1 and red[0]["rc"] == 1 and secret not in red[0]["output_tail"]
    assert len(red[0]["output_tail"].splitlines()) <= 40


def test_lint_jobs_never_write_red_or_green(session, workspace):
    launch_py(session, workspace, "import sys; sys.exit(1)", scope="lint:src/x.py", kind="lint")
    assert done(session, "lint:src/x.py")["result"]["status"] == "fail"
    assert not (session.dir / "red.jsonl").exists() and not (session.dir / "green.jsonl").exists()


@pytest.mark.parametrize("argv_builder,status,rc", [
    (lambda ws: ["definitely-not-a-binary-4711"], "not_installed", 127),
    (lambda ws: [PY, "-c", "print('No module named \\'httpx\\''); raise SystemExit(1)"], "skipped_env", 1),
    (lambda ws: [PY, "-c", "print('collected 0 items'); raise SystemExit(5)"], "skipped_no_tests", 5),
])
def test_non_red_outcomes_are_never_credited(session, workspace, argv_builder, status, rc):
    jobstore.launch(session, "test:tests/test_y.py", "test", "y", argv_builder(workspace), str(workspace), [], [], 30)
    view = done(session, "test:tests/test_y.py")
    assert view["result"]["status"] == status and view["result"]["rc"] == rc
    assert not (session.dir / "red.jsonl").exists() and not (session.dir / "green.jsonl").exists()


def test_missing_cwd_is_an_error_not_a_missing_tool(session, workspace):
    jobstore.launch(session, "test:t", "test", "t", [PY, "-c", "pass"], str(workspace / "nope"), [], [], 30)
    result = done(session, "test:t")["result"]
    assert result["status"] == "error" and result["rc"] == 1
    assert "working directory does not exist" in result["output"]
    assert not (session.dir / "red.jsonl").exists()


def test_timeout(session, workspace):
    launch_py(session, workspace, "import time; time.sleep(10)", timeout_s=1)
    result = done(session, "test:tests/test_x.py")["result"]
    assert result["status"] == "timeout" and result["rc"] == 124


def test_newer_launch_cancels_older_running_job(session, workspace):
    first = launch_py(session, workspace, "import time; time.sleep(20)")
    wait_for(lambda: (session.dir / "jobs" / ("%s.pid" % first["id"])).exists(), 5)
    time.sleep(0.3)
    second = launch_py(session, workspace, "print('second')")
    first_result = state.read_json(session.dir / "jobs" / ("%s.result.json" % first["id"]))
    assert first_result["status"] == "cancelled" and first_result["cancelled_by"]
    view = done(session, "test:tests/test_x.py")
    assert view["id"] == second["id"] and view["result"]["status"] == "pass"
    green = state.read_jsonl(session.dir / "green.jsonl")
    assert [row["job_id"] for row in green] == [second["id"]]


def test_runner_exits_when_superseded_before_running(session, workspace):
    directory = jobstore.jobs_dir(session)
    older = {"id": "s-1", "scope_key": "test:s", "kind": "test", "argv": [PY, "-c", "raise SystemExit(1)"],
             "cwd": str(workspace), "ts_ns": 1, "debounce_s": 0, "session_dir": str(session.dir)}
    newer = dict(older, id="s-2", ts_ns=2)
    state.write_json_atomic(directory / "s-1.job.json", older)
    state.write_json_atomic(directory / "s-2.job.json", newer)
    assert run_job.run(directory / "s-1.job.json") == 0
    assert state.read_json(directory / "s-1.result.json")["status"] == "cancelled"
    assert not (session.dir / "red.jsonl").exists()
    assert run_job.main(["run_job.py"]) == 0
    assert run_job.main(["run_job.py", str(directory / "missing.job.json")]) == 0


def test_results_are_never_overwritten(tmp_path):
    assert jobstore.write_result(tmp_path, {"id": "j", "status": "cancelled"})
    assert not jobstore.write_result(tmp_path, {"id": "j", "status": "pass"})
    assert json.loads((tmp_path / "j.result.json").read_text())["status"] == "cancelled"
    assert [p.name for p in tmp_path.iterdir()] == ["j.result.json"]


def test_harvest_delivers_newest_per_scope_once(session, workspace):
    launch_py(session, workspace, "import sys; sys.exit(1)", scope="test:a")
    done(session, "test:a")
    launch_py(session, workspace, "pass", scope="test:a")
    done(session, "test:a")
    launch_py(session, workspace, "print('collected 0 items'); raise SystemExit(5)", scope="test:b")
    done(session, "test:b")
    launch_py(session, workspace, "import sys; sys.exit(3)", scope="lint:c", kind="lint")
    done(session, "lint:c")
    first = jobstore.harvest(session)
    assert [v["scope_key"] for v in first.passes] == ["test:a"]
    assert [v["scope_key"] for v in first.skipped] == ["test:b"]
    assert [v["scope_key"] for v in first.failures] == ["lint:c"]
    second = jobstore.harvest(session)
    assert second.passes == second.failures == second.skipped == []


def test_running_jobs_stay_deliverable_and_settle_waits(session, workspace):
    launch_py(session, workspace, "import time; time.sleep(1.0)", scope="test:slow")
    assert jobstore.running(session)
    assert jobstore.harvest(session).passes == []
    outcomes = jobstore.settle(session, 20)
    assert [o["state"] for o in outcomes] == ["pass"]
    assert jobstore.running(session) == [] and len(jobstore.results(session)) == 1
    assert jobstore.harvest(session).passes[0]["scope_key"] == "test:slow"
    assert jobstore.settle(session, 0)[0]["state"] == "pass"


def test_settle_reports_pending_after_timeout(session, workspace):
    launch_py(session, workspace, "import time; time.sleep(5)", scope="test:pending")
    outcomes = jobstore.settle(session, 0.1)
    assert outcomes[0]["state"] == "pending" and not outcomes[0]["done"]
    jobstore.cancel(session, outcomes[0]["id"])
    assert jobstore.newest(session, "test:pending")["state"] == "cancelled"


def test_launch_failure_writes_synthetic_error(session, workspace, monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("no fork for you")
    monkeypatch.setattr(subprocess, "Popen", boom)
    spec = launch_py(session, workspace, "pass", scope="test:boom")
    result = state.read_json(session.dir / "jobs" / ("%s.result.json" % spec["id"]))
    assert result["rc"] == 1 and result["status"] == "error" and "could not launch" in result["output"]


def test_red_binds_to_test_hash_at_launch(session, workspace):
    test_file = workspace / "tests" / "test_x.py"
    test_file.write_text("v1\n")
    launch_sha = hashing.sha256_file(str(test_file))
    launch_py(session, workspace, "import time, sys; time.sleep(0.5); sys.exit(1)", test_files=["tests/test_x.py"])
    test_file.write_text("v2 edited while the job ran\n")
    done(session, "test:tests/test_x.py")
    red = state.read_jsonl(session.dir / "red.jsonl")
    assert red[0]["test_files"]["tests/test_x.py"] == launch_sha != hashing.sha256_file(str(test_file))


def test_real_pytest_red_then_green(session, workspace, fake_pytest):
    fake_pytest(workspace, "fail", "tests/test_calc.py")
    argv = [PY, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "tests/test_calc.py"]
    jobstore.launch(session, "test:tests/test_calc.py", "test", "pytest", argv, str(workspace), ["tests/test_calc.py"], ["src/calc.py"], 120)
    assert done(session, "test:tests/test_calc.py", 60)["result"]["status"] == "fail"
    fake_pytest(workspace, "pass", "tests/test_calc.py")
    jobstore.launch(session, "test:tests/test_calc.py", "test", "pytest", argv, str(workspace), ["tests/test_calc.py"], ["src/calc.py"], 120)
    wait_for(lambda: (session.dir / "green.jsonl").exists(), 60)
    assert state.read_jsonl(session.dir / "green.jsonl")[0]["status"] == "pass"
    fake_pytest(workspace, "error", "tests/test_calc.py")
    jobstore.launch(session, "test:tests/test_calc.py", "test", "pytest", argv, str(workspace), ["tests/test_calc.py"], [], 120)
    wait_for(lambda: len(state.read_jsonl(session.dir / "red.jsonl")) == 2, 60)
    assert state.read_jsonl(session.dir / "red.jsonl")[1]["status"] == "fail"

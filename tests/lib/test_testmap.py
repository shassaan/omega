from __future__ import annotations

import json
import os
import sys

import pytest

from hooks.lib import testmap


@pytest.mark.parametrize("rel,is_test,is_source", [
    ("src/calc.py", False, True),
    ("app/api/routes.py", False, True),
    ("tests/test_calc.py", True, False),
    ("pkg/test_calc.py", True, False),
    ("pkg/calc_test.py", True, False),
    ("src/conftest.py", True, False),
    ("web/a.test.ts", True, False),
    ("web/a.spec.tsx", True, False),
    ("web/__tests__/a.ts", True, False),
    ("web/a.ts", False, True),
    ("web/types.d.ts", False, False),
    ("src/__init__.py", False, False),
    ("migrations/0001_init.py", False, False),
    ("scripts/deploy.py", False, False),
    ("docs/readme.md", False, False),
    ("vite.config.ts", False, False),
    ("README.md", False, False),
    ("../outside.py", False, False),
    ("/abs/x.py", False, False),
])
def test_classification(session, rel, is_test, is_source):
    assert testmap.is_test(rel, session.cfg) is is_test
    assert testmap.is_source(rel, session.cfg) is is_source


def test_python_mapping_candidates_and_existing(session, workspace):
    mapped = testmap.map_test("src/auth/signup.py", session, session.cfg, contracts=[])
    assert mapped.candidates == ["tests/auth/test_signup.py", "tests/test_signup.py",
                                 "src/auth/tests/test_signup.py", "src/auth/test_signup.py"]
    assert mapped.existing is None and mapped.lang == "python" and not mapped.from_contract
    (workspace / "tests" / "test_signup.py").write_text("def test_x(): pass\n")
    assert testmap.map_test("src/auth/signup.py", session, session.cfg, contracts=[]).existing == "tests/test_signup.py"


def test_top_level_and_src_python_mapping(session):
    assert testmap.map_test("calc.py", session, session.cfg, contracts=[]).candidates == [
        "tests/test_calc.py", "test_calc.py"]
    assert testmap.map_test("src/calc.py", session, session.cfg, contracts=[]).candidates == [
        "tests/test_calc.py", "src/tests/test_calc.py", "src/test_calc.py"]


def test_ts_mapping(session):
    mapped = testmap.map_test("web/src/button.tsx", session, session.cfg, contracts=[])
    assert mapped.candidates == ["web/src/button.test.tsx", "web/src/button.spec.tsx",
                                 "web/src/__tests__/button.test.tsx", "web/src/__tests__/button.tsx"]
    assert mapped.lang == "ts"


def test_overrides_take_precedence(session, workspace):
    (workspace / ".omega" / "config.json").write_text(json.dumps(
        {"tdd": {"overrides": {"src/calc.py": ["tests/special/test_math.py"]}}}))
    from hooks.lib import config
    cfg = config.load(session.harness_root, session.workspace)
    mapped = testmap.map_test("src/calc.py", session, cfg, contracts=[])
    assert mapped.candidates == ["tests/special/test_math.py"]


def test_contract_mapping_beats_patterns(session, workspace):
    (workspace / "docs" / "contracts" / "calc.md").write_text(CONTRACT)
    (workspace / "tests" / "unit_calc_check.py").write_text("def test_x(): pass\n")
    mapped = testmap.map_test("src/calc.py", session, session.cfg)
    assert mapped.from_contract and mapped.candidates == ["tests/unit_calc_check.py", "tests/test_calc_flow.py"]
    assert mapped.existing == "tests/unit_calc_check.py"


def test_runner_for_python_uses_the_workspace_interpreter(session, workspace):
    argv = testmap.runner_for("tests/test_calc.py", session, session.cfg)
    assert argv == ["python3", "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "tests/test_calc.py"]
    venv = workspace / ".venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").write_text("#!/bin/sh\n")
    os.chmod(str(venv / "python"), 0o755)
    argv = testmap.runner_for("tests/test_calc.py", session, session.cfg)
    assert argv[0] == str(venv / "python") and argv[0] != sys.executable


def test_workspace_python_respects_virtual_env(tmp_path, monkeypatch):
    env_dir = tmp_path / "venv-elsewhere" / "bin"
    env_dir.mkdir(parents=True)
    (env_dir / "python").write_text("#!/bin/sh\n")
    os.chmod(str(env_dir / "python"), 0o755)
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "venv-elsewhere"))
    assert testmap.workspace_python(str(tmp_path / "ws")) == str(env_dir / "python")


def test_js_runner_detection(session, workspace):
    assert testmap.js_runner(str(workspace)) is None
    assert testmap.runner_for("web/a.test.ts", session, session.cfg) is None
    (workspace / "package.json").write_text(json.dumps({"devDependencies": {"jest": "^29"}}))
    assert testmap.js_runner(str(workspace)) == "jest"
    assert testmap.runner_for("web/a.test.ts", session, session.cfg) == ["npx", "jest", "--ci", "web/a.test.ts"]
    (workspace / "vitest.config.ts").write_text("export default {}")
    assert testmap.js_runner(str(workspace)) == "vitest"
    assert testmap.runner_for("web/a.test.ts", session, session.cfg)[:3] == ["npx", "vitest", "run"]
    assert testmap.runner_for("README.md", session, session.cfg) is None


def test_scope_key():
    assert testmap.scope_key("./tests/test_a.py") == "test:tests/test_a.py"


CONTRACT = """# Contract: Calculator
slug: calc
code: src/calc.py
tests: tests/unit_calc_check.py, tests/test_calc_flow.py
owed: none
assumptions: none

## Unit
### Scenario: adds
- Given 1 and 2
- When added
- Then 3

## Integration
_Not applicable: pure function_

## Functional
_Not applicable: no API_

## Journey
_Not applicable: no UI_
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

PROBE = """import os, sys
print(sys.version_info >= (3, 9), sys.flags.isolated, sys.flags.dont_write_bytecode,
      os.environ.get("OMEGA_HOME"), os.environ.get("PYTHONDONTWRITEBYTECODE"), " ".join(sys.argv[1:]))
"""


@pytest.fixture
def fake_root(tmp_path, harness_root):
    root = Path(os.path.realpath(str(tmp_path))) / "harness"
    (root / "bin").mkdir(parents=True)
    shutil.copy(str(harness_root / "bin" / "launch.sh"), str(root / "bin" / "launch.sh"))
    (root / "probe.py").write_text(PROBE)
    return root


def sh(root, args, env=None, cwd=None):
    merged = dict(os.environ)
    merged.update(env or {})
    return subprocess.run(["/bin/sh", str(root / "bin" / "launch.sh")] + args, capture_output=True, text=True,
                          env=merged, cwd=str(cwd or root), timeout=60)


def test_runs_script_isolated_with_harness_home(fake_root, tmp_path):
    result = sh(fake_root, ["probe.py", "a", "b c"], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["True", "1", "1", str(fake_root), "1", "a", "b", "c"]


def test_guard_without_interpreter_blocks(fake_root):
    result = sh(fake_root, ["--guard", "probe.py"], env={"PATH": "/nonexistent"})
    assert result.returncode == 2
    assert "probe.py NOT run: no Python 3.9+ found" in result.stderr


def test_non_guard_without_interpreter_is_a_visible_error(fake_root):
    result = sh(fake_root, ["probe.py"], env={"PATH": "/nonexistent"})
    assert result.returncode == 1 and "NOT run" in result.stderr


def test_missing_script_argument(fake_root):
    assert sh(fake_root, ["--guard"]).returncode == 2
    assert sh(fake_root, []).returncode == 1


def test_harness_venv_is_preferred(fake_root, tmp_path):
    venv_bin = fake_root / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    marker = tmp_path / "venv-used"
    (venv_bin / "python").write_text("#!/bin/sh\nif [ \"$1\" = \"-c\" ]; then exit 0; fi\necho venv > \"%s\"\n" % marker)
    os.chmod(str(venv_bin / "python"), 0o755)
    result = sh(fake_root, ["probe.py"])
    assert result.returncode == 0 and marker.read_text().strip() == "venv"


def test_pythonpath_and_cwd_cannot_inject_modules(fake_root, tmp_path):
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "json.py").write_text("raise SystemExit('hijacked')\n")
    (fake_root / "uses_json.py").write_text("import json\nprint(json.dumps({'ok': True}))\n")
    result = sh(fake_root, ["uses_json.py"], env={"PYTHONPATH": str(evil)}, cwd=evil)
    assert result.returncode == 0 and result.stdout.strip() == '{"ok": true}'


def test_real_launcher_bootstraps_harness_imports(harness_root, tmp_path):
    result = subprocess.run(["/bin/sh", str(harness_root / "bin" / "launch.sh"), "hooks/lib/run_job.py"],
                            capture_output=True, text=True, cwd=str(tmp_path), timeout=60)
    assert result.returncode == 0, result.stderr

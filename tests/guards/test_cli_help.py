from __future__ import annotations

import os
import subprocess

import pytest

from tests.conftest import OMEGA_ROOT

SCRIPTS = ("bin/session_start.py", "bin/pre_tool_use.py", "bin/post_tool_use.py", "hooks/prod_guard.py",
           "hooks/bash_write_guard.py", "hooks/tdd_gate.py", "hooks/contract_gate.py")


@pytest.mark.parametrize("script", SCRIPTS)
def test_help_exits_zero(script, workspace):
    proc = subprocess.run(["/bin/sh", str(OMEGA_ROOT / "bin" / "launch.sh"), script, "--help"],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL, env=dict(os.environ), timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "usage" in proc.stdout.lower()

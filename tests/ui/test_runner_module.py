from __future__ import annotations

import pytest

pytest.importorskip("fastapi")


def test_runner_module_exposes_the_spec_api():
    from ui import runner, server
    for name in ("start_run", "claude_argv", "codex_argv", "normalize_claude", "normalize_codex", "Hub",
                 "verify_hooks_fire"):
        assert getattr(runner, name) is getattr(server, name)

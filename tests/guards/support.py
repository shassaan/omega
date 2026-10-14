from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from tests.conftest import OMEGA_ROOT

PROVIDERS = ("claude", "codex")
PRE = "bin/pre_tool_use.py"
POST = "bin/post_tool_use.py"
START = "bin/session_start.py"


def bash_payload(make, command: str, **extra) -> dict:
    payload = make("PreToolUse")
    payload["tool_name"] = "Bash"
    payload["tool_input"] = {"command": command}
    payload.update(extra)
    return payload


def edit_payload(make, event: str, tool: str, tool_input: dict, **extra) -> dict:
    payload = make(event)
    payload["hook_event_name"] = event
    payload["tool_name"] = tool
    payload["tool_input"] = tool_input
    if event == "PostToolUse":
        payload["tool_response"] = {"filePath": tool_input.get("file_path"), "success": True}
    else:
        payload.pop("tool_response", None)
    payload.update(extra)
    return payload


def pre_outcome(proc, provider: str) -> tuple:
    if provider == "claude":
        assert proc.returncode in (0, 2), (proc.returncode, proc.stdout, proc.stderr)
        if proc.returncode == 2:
            return True, proc.stderr.strip()
        assert proc.stdout.strip() == "" or json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"
        return False, proc.stdout.strip()
    assert proc.returncode in (0, 2), (proc.returncode, proc.stdout, proc.stderr)
    data = json.loads(proc.stdout or "{}")
    output = data.get("hookSpecificOutput") or {}
    if output.get("permissionDecision") == "deny":
        assert output.get("permissionDecisionReason")
        return True, output["permissionDecisionReason"]
    assert proc.returncode == 0
    return False, proc.stdout.strip()


def post_outcome(proc, provider: str) -> tuple:
    assert proc.returncode in (0, 2), (proc.returncode, proc.stdout, proc.stderr)
    if provider == "claude":
        if proc.returncode == 2:
            return True, proc.stderr
        return False, proc.stdout
    data = json.loads(proc.stdout or "{}")
    if data.get("decision") == "block":
        return True, data.get("reason", "")
    return False, (data.get("hookSpecificOutput") or {}).get("additionalContext", "")


def session_dir(workspace, provider: str, session_id: str) -> Path:
    from hooks.lib import state
    return state.session_path(str(workspace), provider, session_id)


def read_jsonl(path: Path) -> list:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def link_python(workspace) -> Path:
    target = Path(workspace) / ".venv" / "bin" / "python"
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_text("#!/bin/sh\nexec %s \"$@\"\n" % sys.executable, encoding="utf-8")
        target.chmod(0o755)
    return target


def corpus() -> dict:
    return json.loads((OMEGA_ROOT / "tests" / "fixtures" / "shell" / "corpus.json").read_text(encoding="utf-8"))

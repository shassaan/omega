from __future__ import annotations

import json

import pytest

from tests.guards.support import PRE, PROVIDERS, edit_payload, pre_outcome

ANTHROPIC_KEY = "sk-ant-api03-" + "A1b2C3d4E5" * 9 + "xyz" + "AA"
AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH"


def _write(make, path, content="x = 1\n", **extra):
    return edit_payload(make, "PreToolUse", "Write", {"file_path": str(path), "content": content}, **extra)


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("rel", [".claude/settings.json", ".codex/hooks.json", ".omega/clearances/proof.json",
                                 ".git/hooks/pre-commit", ".git/config", ".gitleaks.toml",
                                 ".github/workflows/gauntlet.yml", ".omega/config.json"])
def test_protected_workspace_paths_refused(rel, provider, workspace, run_hook, claude_payload, codex_payload):
    make = claude_payload if provider == "claude" else codex_payload
    proc = run_hook(PRE, _write(make, workspace / rel, "{}"), provider)
    blocked, reason = pre_outcome(proc, provider)
    assert blocked, proc.stdout
    assert reason.startswith("[omega] refused: %s is a protected path" % rel), reason
    assert "omega.protected_path" in reason


def test_harness_root_protected_unless_dev(workspace, run_hook, claude_payload, harness_root):
    payload = edit_payload(claude_payload, "PreToolUse", "Edit",
                           {"file_path": str(harness_root / "hooks" / "prod_guard.py"), "old_string": "a",
                            "new_string": "b"})
    blocked, reason = pre_outcome(run_hook(PRE, payload, "claude"), "claude")
    assert blocked and "hooks/prod_guard.py is a protected path" in reason
    blocked, _ = pre_outcome(run_hook(PRE, payload, "claude", env={"OMEGA_DEV": "1"}), "claude")
    assert not blocked
    workspace_payload = _write(claude_payload, workspace / ".claude" / "settings.json", "{}")
    blocked, _ = pre_outcome(run_hook(PRE, workspace_payload, "claude", env={"OMEGA_DEV": "1"}), "claude")
    assert blocked


def test_state_dir_and_transcript_protected(workspace, tmp_state, run_hook, claude_payload, transcript_writer):
    transcript_writer.human("hello")
    blocked, reason = pre_outcome(run_hook(PRE, _write(claude_payload, tmp_state / "x.json", "{}"), "claude"), "claude")
    assert blocked and "protected path" in reason
    payload = _write(claude_payload, transcript_writer.path, "{}", transcript_path=str(transcript_writer.path))
    blocked, reason = pre_outcome(run_hook(PRE, payload, "claude"), "claude")
    assert blocked and "protected path" in reason


def test_protected_path_via_multiedit_and_notebook(workspace, run_hook, claude_payload):
    multi = edit_payload(claude_payload, "PreToolUse", "MultiEdit",
                         {"file_path": str(workspace / ".git" / "HEAD"), "edits": [{"old_string": "a", "new_string": "b"}]})
    assert pre_outcome(run_hook(PRE, multi, "claude"), "claude")[0]
    notebook = edit_payload(claude_payload, "PreToolUse", "NotebookEdit",
                            {"notebook_path": str(workspace / ".omega" / "n.ipynb"), "new_source": "x"})
    assert pre_outcome(run_hook(PRE, notebook, "claude"), "claude")[0]


def test_codex_apply_patch_protected_path(workspace, run_hook, codex_payload):
    payload = codex_payload("PreToolUse")
    payload["tool_name"] = "apply_patch"
    payload["tool_input"] = {"command": "*** Begin Patch\n*** Update File: .codex/hooks.json\n@@\n-a\n+b\n*** End Patch\n"}
    blocked, reason = pre_outcome(run_hook(PRE, payload, "codex"), "codex")
    assert blocked and ".codex/hooks.json is a protected path" in reason


@pytest.mark.parametrize("provider", PROVIDERS)
def test_unparsed_patch_fails_closed(provider, workspace, run_hook, claude_payload, codex_payload):
    make = claude_payload if provider == "claude" else codex_payload
    payload = make("PreToolUse")
    payload["tool_name"] = "apply_patch"
    payload["tool_input"] = {"command": "*** Begin Patch\n+just text\n*** End Patch\n"}
    blocked, reason = pre_outcome(run_hook(PRE, payload, provider), provider)
    assert blocked and "omega.unparsed_mutation" in reason


def test_edit_without_file_path_fails_closed(workspace, run_hook, claude_payload):
    payload = edit_payload(claude_payload, "PreToolUse", "Write", {"content": "x"})
    blocked, reason = pre_outcome(run_hook(PRE, payload, "claude"), "claude")
    assert blocked and "Write payload has no file path" in reason


@pytest.mark.parametrize("secret,rule", [(ANTHROPIC_KEY, "anthropic-key"), (AWS_KEY, "aws-access-key"),
                                         ("ghp_" + "a1B2c3D4e5" * 4, "github-token")])
def test_secret_in_edit_refused_without_echoing_it(secret, rule, workspace, run_hook, claude_payload):
    content = "import os\n\nKEY = '%s'\n" % secret
    proc = run_hook(PRE, _write(claude_payload, workspace / "docs" / "notes.md", content), "claude")
    blocked, reason = pre_outcome(proc, "claude")
    assert blocked
    assert reason.startswith("[omega] refused: the new content contains what looks like a %s secret at line 3" % rule)
    assert secret not in proc.stderr and secret not in proc.stdout


def test_secret_in_edit_new_string_and_codex_patch(workspace, run_hook, claude_payload, codex_payload):
    edit = edit_payload(claude_payload, "PreToolUse", "Edit",
                        {"file_path": str(workspace / "docs" / "a.md"), "old_string": "x", "new_string": AWS_KEY})
    assert "secrets.in_edit" in pre_outcome(run_hook(PRE, edit, "claude"), "claude")[1]
    payload = codex_payload("PreToolUse")
    payload["tool_name"] = "apply_patch"
    payload["tool_input"] = {"command": "*** Begin Patch\n*** Add File: docs/creds.md\n+key %s\n*** End Patch\n" % AWS_KEY}
    assert "secrets.in_edit" in pre_outcome(run_hook(PRE, payload, "codex"), "codex")[1]


def test_secret_allowed_in_fixture_paths_and_dummies(workspace, run_hook, claude_payload):
    fixture = _write(claude_payload, workspace / "tests" / "fixtures" / "keys.md", "KEY = '%s'\n" % AWS_KEY)
    assert not pre_outcome(run_hook(PRE, fixture, "claude"), "claude")[0]
    dummy = _write(claude_payload, workspace / "docs" / "aws.md", "AKIAIOSFODNN7EXAMPLE\n")
    assert not pre_outcome(run_hook(PRE, dummy, "claude"), "claude")[0]


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("stdin", ["", "not json", "[1, 2]", "{\"truncated\": "])
def test_unreadable_stdin_fails_closed(stdin, provider, workspace, run_hook):
    proc = run_hook(PRE, stdin, provider)
    assert proc.returncode == 2
    data = json.loads(proc.stdout)
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "failed closed" in data["hookSpecificOutput"]["permissionDecisionReason"]
    assert "failed closed" in proc.stderr


def test_bash_without_command_fails_closed(workspace, run_hook, claude_payload):
    payload = claude_payload("PreToolUse")
    payload["tool_input"] = {}
    blocked, reason = pre_outcome(run_hook(PRE, payload, "claude"), "claude")
    assert blocked and "dynamic.parse_failure" in reason


def test_other_tools_pass_through(workspace, run_hook, claude_payload, codex_payload):
    payload = claude_payload("PreToolUse")
    payload["tool_name"] = "Read"
    payload["tool_input"] = {"file_path": str(workspace / ".claude" / "settings.json")}
    proc = run_hook(PRE, payload, "claude")
    assert proc.returncode == 0 and proc.stdout.strip() == ""
    payload = codex_payload("PreToolUse")
    payload["tool_name"] = "web_search"
    proc = run_hook(PRE, payload, "codex")
    assert proc.returncode == 0 and json.loads(proc.stdout) == {}


def test_pre_tool_use_records_observed_event(workspace, tmp_state, run_hook, claude_payload):
    run_hook(PRE, claude_payload("PreToolUse"), "claude")
    observed = json.loads((tmp_state / "observed" / "claude.json").read_text())
    assert "PreToolUse" in observed

from __future__ import annotations

from pathlib import Path

from hooks.lib import adapters


def test_hook_table_shape():
    events = [spec.event for spec in adapters.HOOK_TABLE]
    assert events == ["SessionStart", "PreToolUse", "PostToolUse", "PostToolUseFailure", "Stop"]
    guards = [spec.script for spec in adapters.HOOK_TABLE if spec.guard]
    assert guards == ["bin/pre_tool_use.py"]
    stop = next(spec for spec in adapters.HOOK_TABLE if spec.event == "Stop")
    assert stop.timeout_s >= 600


def test_harness_command_is_absolute(harness_root):
    assert adapters.harness_command("hooks/tdd_gate.py") == 'sh "%s/bin/launch.sh" hooks/tdd_gate.py' % harness_root
    assert adapters.harness_command("x.py", Path("/opt/h")).startswith('sh "/opt/h/bin/launch.sh"')
    odd = adapters.harness_command("x.py", Path('/tmp/we"ird$dir'))
    assert '\\"' in odd and "\\$" in odd


def test_claude_settings_dogfood_form(harness_root):
    settings = adapters.render_claude_settings(harness_root, absolute=False)
    pre = settings["hooks"]["PreToolUse"][0]
    assert pre["matcher"] == "Bash|Edit|Write|MultiEdit|NotebookEdit"
    command = pre["hooks"][0]["command"]
    assert command == 'sh "$CLAUDE_PROJECT_DIR/bin/launch.sh" --guard bin/pre_tool_use.py --provider claude'
    assert "matcher" not in settings["hooks"]["Stop"][0]
    assert settings["hooks"]["Stop"][0]["hooks"][0]["timeout"] == 900
    assert "--guard" not in settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    assert "PostToolUseFailure" in settings["hooks"]
    for rule in ("Bash(git push *)", "Bash(git commit *)", "Bash(gh pr merge *)", "Bash(terraform apply *)",
                 "Bash(terraform destroy *)", "Bash(kubectl delete *)"):
        assert rule in settings["permissions"]["deny"]
    for groups in settings["hooks"].values():
        for group in groups:
            for hook in group["hooks"]:
                assert hook["type"] == "command" and hook["timeout"] > 0


def test_claude_settings_absolute_form(harness_root):
    settings = adapters.render_claude_settings(harness_root, absolute=True)
    command = settings["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    assert command == 'sh "%s/bin/launch.sh" bin/session_start.py --provider claude' % harness_root
    assert "$CLAUDE_PROJECT_DIR" not in str(settings)


def test_codex_hooks_forms(harness_root):
    dogfood = adapters.render_codex_hooks(harness_root, absolute=False)
    assert set(dogfood["hooks"]) == {"SessionStart", "PreToolUse", "PostToolUse", "Stop"}
    pre = dogfood["hooks"]["PreToolUse"][0]
    assert pre["matcher"] == "^(Bash|apply_patch|Edit|Write|MultiEdit|NotebookEdit)$"
    assert pre["hooks"][0]["command"] == ("sh -c 'R=\"$(git rev-parse --show-toplevel)\"; exec sh \"$R/bin/launch.sh\" "
                                          "--guard bin/pre_tool_use.py --provider codex'")
    assert "CLAUDE_PROJECT_DIR" not in str(dogfood)
    absolute = adapters.render_codex_hooks(harness_root, absolute=True)
    assert absolute["hooks"]["Stop"][0]["hooks"][0]["command"] == \
        'sh "%s/bin/launch.sh" bin/stop_orchestrator.py --provider codex' % harness_root
    assert adapters.render_codex_config_toml() == "[features]\nhooks = true\n"


def test_every_hook_script_path_is_under_bin():
    for spec in adapters.HOOK_TABLE:
        assert spec.script.startswith("bin/") and spec.script.endswith(".py")

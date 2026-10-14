from __future__ import annotations

import json
import subprocess
import sys

from tests.conftest import OMEGA_ROOT

from hooks.lib import adapters

SCRIPT = str(OMEGA_ROOT / "scripts" / "install_workspace.py")


def run(*args):
    return subprocess.run([sys.executable, "-I", "-B", SCRIPT] + list(args), capture_output=True, text=True)


def test_fresh_install_renders_absolute_configs(workspace):
    proc = run(str(workspace), "--provider", "both")
    assert proc.returncode == 0, proc.stderr
    settings = json.loads((workspace / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert settings == adapters.render_claude_settings(OMEGA_ROOT, absolute=True)
    hooks = json.loads((workspace / ".codex" / "hooks.json").read_text(encoding="utf-8"))
    assert hooks == adapters.render_codex_hooks(OMEGA_ROOT, absolute=True)
    assert (workspace / ".codex" / "config.toml").read_text(encoding="utf-8") == adapters.render_codex_config_toml()
    assert str(OMEGA_ROOT / "bin" / "launch.sh") in json.dumps(settings)


def test_merge_keeps_foreign_keys_and_hooks_and_is_idempotent(workspace):
    claude_dir = workspace / ".claude"
    claude_dir.mkdir()
    foreign_hook = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine", "timeout": 5}]}
    (claude_dir / "settings.json").write_text(json.dumps({
        "model": "opus", "permissions": {"allow": ["Bash(ls)"], "deny": ["Bash(rm *)"]},
        "hooks": {"PreToolUse": [foreign_hook], "Notification": [{"hooks": [{"type": "command", "command": "say hi"}]}]}}),
        encoding="utf-8")
    codex_dir = workspace / ".codex"
    codex_dir.mkdir()
    (codex_dir / "config.toml").write_text('model = "gpt-5.6-sol"\n\n[features]\nweb_search = true\n', encoding="utf-8")
    for _ in range(2):
        proc = run(str(workspace))
        assert proc.returncode == 0, proc.stderr
    settings = json.loads((claude_dir / "settings.json").read_text(encoding="utf-8"))
    assert settings["model"] == "opus"
    assert settings["permissions"]["allow"] == ["Bash(ls)"]
    assert "Bash(rm *)" in settings["permissions"]["deny"] and "Bash(git push *)" in settings["permissions"]["deny"]
    assert len(settings["permissions"]["deny"]) == len(set(settings["permissions"]["deny"]))
    assert settings["hooks"]["Notification"] == [{"hooks": [{"type": "command", "command": "say hi"}]}]
    pre = settings["hooks"]["PreToolUse"]
    assert pre[0] == foreign_hook
    ours = [g for g in pre if "launch.sh" in json.dumps(g)]
    assert len(ours) == 1 and "--guard bin/pre_tool_use.py" in json.dumps(ours[0])
    toml = (codex_dir / "config.toml").read_text(encoding="utf-8")
    assert toml.count("hooks = true") == 1 and 'model = "gpt-5.6-sol"' in toml and "web_search = true" in toml
    assert toml.count("[features]") == 1


def test_provider_selection_and_gitignore(workspace):
    (workspace / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    proc = run(str(workspace), "--provider", "claude")
    assert proc.returncode == 0, proc.stderr
    assert (workspace / ".claude" / "settings.json").is_file()
    assert not (workspace / ".codex").exists()
    assert (workspace / ".gitignore").read_text(encoding="utf-8").splitlines() == ["node_modules/", ".omega/"]
    run(str(workspace), "--provider", "codex")
    assert (workspace / ".gitignore").read_text(encoding="utf-8").count(".omega/") == 1
    assert (workspace / ".codex" / "hooks.json").is_file()


def test_refuses_missing_directory_and_corrupt_settings(tmp_path, workspace):
    proc = run(str(tmp_path / "nope"))
    assert proc.returncode == 1 and "not a directory" in proc.stderr
    (workspace / ".claude").mkdir()
    (workspace / ".claude" / "settings.json").write_text("{not json", encoding="utf-8")
    proc = run(str(workspace), "--provider", "claude")
    assert proc.returncode == 2 and "settings.json" in proc.stderr
    assert (workspace / ".claude" / "settings.json").read_text(encoding="utf-8") == "{not json"


def test_help_exits_zero():
    proc = run("--help")
    assert proc.returncode == 0 and "--provider" in proc.stdout

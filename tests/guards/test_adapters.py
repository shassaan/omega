from __future__ import annotations

import json
import re

import pytest

from hooks.lib import adapters
from tests.conftest import OMEGA_ROOT

CLAUDE_EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
CODEX_EDIT_TOOLS = ("apply_patch", "Edit", "Write")
TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")


def _load(rel: str) -> dict:
    return json.loads((OMEGA_ROOT / rel).read_text(encoding="utf-8"))


def _commands(config: dict, event: str) -> list:
    found = []
    for group in config["hooks"].get(event, []):
        for hook in group["hooks"]:
            found.append((group.get("matcher"), hook))
    return found


def test_checked_in_files_equal_renderer_output():
    assert _load(".claude/settings.json") == adapters.render_claude_settings(OMEGA_ROOT, False)
    assert _load(".codex/hooks.json") == adapters.render_codex_hooks(OMEGA_ROOT, False)


@pytest.mark.parametrize("spec", adapters.HOOK_TABLE, ids=lambda s: s.event)
def test_hook_table_scripts_exist(spec):
    assert (OMEGA_ROOT / spec.script).is_file(), spec.script


@pytest.mark.parametrize("rel,provider", [(".claude/settings.json", "claude"), (".codex/hooks.json", "codex")])
def test_every_hook_registered_with_guard_and_timeout(rel, provider):
    config = _load(rel)
    for spec in adapters.HOOK_TABLE:
        matcher = spec.matcher_claude if provider == "claude" else spec.matcher_codex
        if provider == "codex" and spec.event not in adapters.CODEX_EVENTS:
            assert spec.event not in config["hooks"]
            continue
        entries = _commands(config, spec.event)
        assert entries, "%s missing from %s" % (spec.event, rel)
        scripts = [h for _, h in entries if spec.script in h["command"]]
        assert scripts, "%s not registered for %s" % (spec.script, spec.event)
        for hook in scripts:
            assert hook["type"] == "command"
            assert isinstance(hook.get("timeout"), int) and hook["timeout"] > 0
            assert ("--guard" in hook["command"].split()) == spec.guard
            assert "--provider %s" % provider in hook["command"]
            assert "launch.sh" in hook["command"]
        if spec.event == "Stop":
            assert all(h["timeout"] >= 600 for h in scripts)
        assert [m for m, _ in entries] == [matcher]


def test_guard_hooks_use_guard_flag_and_nothing_else_does():
    for rel in (".claude/settings.json", ".codex/hooks.json"):
        for event, groups in _load(rel)["hooks"].items():
            for group in groups:
                for hook in group["hooks"]:
                    assert ("--guard" in hook["command"]) == (event == "PreToolUse"), (rel, event)


@pytest.mark.parametrize("event", TOOL_EVENTS)
def test_matchers_cover_every_edit_tool(event):
    claude = [g.get("matcher") for g in _load(".claude/settings.json")["hooks"].get(event, [])]
    for matcher in claude:
        pattern = re.compile("^(?:%s)$" % matcher)
        assert all(pattern.match(tool) for tool in CLAUDE_EDIT_TOOLS), (event, matcher)
    if event == "PreToolUse":
        assert all(re.match("^(?:%s)$" % m, "Bash") for m in claude)
    codex = [g.get("matcher") for g in _load(".codex/hooks.json")["hooks"].get(event, [])]
    for matcher in codex:
        pattern = re.compile(matcher)
        assert all(pattern.search(tool) for tool in CODEX_EDIT_TOOLS), (event, matcher)
        if event == "PreToolUse":
            assert pattern.search("Bash")


def test_permission_deny_belt_and_braces():
    deny = _load(".claude/settings.json")["permissions"]["deny"]
    for rule in ("Bash(git push *)", "Bash(git commit *)", "Bash(gh pr merge *)", "Bash(terraform apply *)",
                 "Bash(terraform destroy *)", "Bash(kubectl delete *)"):
        assert rule in deny


def test_subagent_stop_and_precompact_not_registered():
    for rel in (".claude/settings.json", ".codex/hooks.json"):
        hooks = _load(rel)["hooks"]
        assert "SubagentStop" not in hooks and "PreCompact" not in hooks


def test_dogfood_commands_use_project_relative_launcher():
    for _, hook in _commands(_load(".claude/settings.json"), "PreToolUse"):
        assert hook["command"] == 'sh "$CLAUDE_PROJECT_DIR/bin/launch.sh" --guard bin/pre_tool_use.py --provider claude'
    for _, hook in _commands(_load(".codex/hooks.json"), "PreToolUse"):
        assert hook["command"].startswith("sh -c 'R=\"$(git rev-parse --show-toplevel)\"; exec sh \"$R/bin/launch.sh\" --guard")

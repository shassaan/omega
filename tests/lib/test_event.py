from __future__ import annotations

import os

import pytest

from hooks.lib import event as ev

PATCH = """*** Begin Patch
*** Add File: src/new.py
+print('x')
*** Update File: src/old.py
@@
-a
+b
*** Delete File: src/gone.py
*** Update File: src/moved_from.py
*** Move to: src/moved_to.py
@@
-x
+y
*** End Patch
"""


def test_provider_of_precedence(monkeypatch):
    assert ev.provider_of({}, "codex") == "codex"
    assert ev.provider_of({}) == "claude"
    assert ev.provider_of({"tool_name": "apply_patch"}) == "codex"
    assert ev.provider_of({"transcript_path": "/Users/x/.codex/sessions/rollout-1.jsonl"}) == "codex"
    assert ev.provider_of({"transcript_path": "/Users/x/.claude/projects/p/s.jsonl"}) == "claude"
    monkeypatch.setenv("OMEGA_PROVIDER", "codex")
    assert ev.provider_of({}) == "codex"
    assert ev.provider_of({}, "claude") == "claude"
    assert ev.provider_of({}, "gemini") == "codex"


def test_write_kind_depends_on_existence_and_response(workspace, claude_payload):
    target = workspace / "src" / "calc.py"
    pre = claude_payload("PreToolUse", tool_name="Write", tool_input={"file_path": str(target), "content": "x"})
    assert ev.mutations_of(pre) == ([ev.Mutation(str(target), "added")], None)
    target.write_text("x")
    assert ev.mutations_of(pre)[0][0].kind == "modified"
    post = claude_payload("PostToolUse")
    assert ev.mutations_of(post)[0][0].kind == "added"
    post["tool_response"]["type"] = "update"
    assert ev.mutations_of(post)[0][0].kind == "modified"


def test_edit_multiedit_notebook_paths(workspace, claude_payload):
    a, b = str(workspace / "src" / "a.py"), str(workspace / "src" / "b.py")
    edit = claude_payload("PreToolUse", tool_name="Edit", tool_input={"file_path": a, "old_string": "1", "new_string": "2"})
    assert ev.mutations_of(edit) == ([ev.Mutation(a, "modified")], None)
    multi = claude_payload("PreToolUse", tool_name="MultiEdit",
                           tool_input={"file_path": a, "edits": [{"old_string": "1", "new_string": "2"},
                                                                 {"file_path": b, "old_string": "1", "new_string": "2"},
                                                                 {"file_path": a}]})
    assert [m.path for m in ev.mutations_of(multi)[0]] == [a, b]
    nb = claude_payload("PreToolUse", tool_name="NotebookEdit", tool_input={"notebook_path": str(workspace / "n.ipynb")})
    assert ev.mutations_of(nb)[0][0].path == str(workspace / "n.ipynb")
    fallback = claude_payload("PreToolUse", tool_name="NotebookEdit", tool_input={"file_path": a})
    assert ev.mutations_of(fallback)[0][0].path == a


@pytest.mark.parametrize("tool,tool_input", [
    ("Edit", {}),
    ("Write", {"file_path": ""}),
    ("Write", {"file_path": None, "content": "x"}),
    ("MultiEdit", {"edits": []}),
    ("NotebookEdit", {"cell_id": "1"}),
    ("Edit", "not-a-dict"),
])
def test_edit_tool_without_path_is_unparsed(claude_payload, tool, tool_input):
    payload = claude_payload("PreToolUse", tool_name=tool, tool_input=tool_input)
    mutations, reason = ev.mutations_of(payload)
    assert mutations == [] and reason == "%s payload has no file path" % tool
    assert ev.normalize(payload, "claude").unparsed_mutation == reason


def test_relative_paths_resolve_against_cwd(workspace, claude_payload):
    payload = claude_payload("PreToolUse", tool_name="Edit", tool_input={"file_path": "src/a.py"})
    assert ev.mutations_of(payload)[0][0].path == os.path.join(str(workspace), "src", "a.py")


def test_parse_apply_patch_kinds_and_renames(tmp_path):
    found = ev.parse_apply_patch(PATCH, str(tmp_path))
    rel = [(os.path.relpath(m.path, str(tmp_path)), m.kind) for m in found]
    assert rel == [("src/new.py", "added"), ("src/old.py", "modified"), ("src/gone.py", "deleted"),
                   ("src/moved_from.py", "renamed_from"), ("src/moved_to.py", "renamed_to")]


def test_parse_apply_patch_absolute_and_dedupe(tmp_path):
    text = "*** Begin Patch\n*** Update File: /abs/x.py\n*** Update File: /abs/x.py\n*** End Patch"
    assert ev.parse_apply_patch(text, str(tmp_path)) == [ev.Mutation("/abs/x.py", "modified")]
    assert ev.parse_apply_patch("*** Begin Patch\n*** End Patch", str(tmp_path)) == []
    assert ev.parse_apply_patch("*** Move to: x.py", str(tmp_path)) == []


def test_codex_apply_patch_event(workspace, codex_payload):
    event = ev.normalize(codex_payload("PostToolUse"), "codex")
    assert event.is_patch and event.tool_name == "apply_patch"
    assert event.mutations == [ev.Mutation(os.path.join(str(workspace), "src", "calc.py"), "added")]
    assert "+def add" in event.command


def test_apply_patch_with_list_command_and_unparseable_patch(workspace, codex_payload):
    payload = codex_payload("PreToolUse", tool_name="apply_patch",
                            tool_input={"command": ["apply_patch", "*** Begin Patch\n*** Update File: a.py\n*** End Patch"]})
    assert ev.normalize(payload, "codex").mutations[0].path.endswith("/a.py")
    broken = codex_payload("PreToolUse", tool_name="apply_patch", tool_input={"command": "garbage"})
    event = ev.normalize(broken, "codex")
    assert event.mutations == [] and event.unparsed_mutation == "apply_patch payload has no parseable file path"


def test_bash_heredoc_patch_is_a_patch(workspace, codex_payload):
    command = "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: src/x.py\n+x = 1\n*** End Patch\nEOF"
    event = ev.normalize(codex_payload("PreToolUse", tool_input={"command": command}), "codex")
    assert event.is_patch and event.mutations[0].kind == "added"
    plain = ev.normalize(codex_payload("PreToolUse"), "codex")
    assert not plain.is_patch and plain.mutations == [] and plain.unparsed_mutation is None
    assert plain.command == "git status"


def test_bash_list_command_is_joined_for_guards(codex_payload):
    event = ev.normalize(codex_payload("PreToolUse", tool_input={"command": ["bash", "-lc", "git push"]}), "codex")
    assert event.command == "bash -lc 'git push'"


def test_normalize_fields(workspace, claude_payload, monkeypatch):
    monkeypatch.setenv("OMEGA_RUN_ID", "run-1")
    event = ev.normalize(claude_payload("Stop", stop_hook_active=True, transcript_path="/t.jsonl"), "claude")
    assert event.provider == "claude" and event.name == "Stop" and event.stop_hook_active
    assert event.workspace == str(workspace) and event.run_id == "run-1" and event.transcript_path == "/t.jsonl"
    assert event.tool_name is None and event.mutations == [] and event.raw["hook_event_name"] == "Stop"
    compact = ev.normalize({"hook_event_name": "PreCompact", "trigger": "auto", "session_id": "s"}, "claude")
    assert compact.source == "auto"


def test_normalize_rejects_non_dict():
    with pytest.raises(ValueError):
        ev.normalize(["not", "a", "dict"])


def test_new_content_covers_every_edit_shape(claude_payload, codex_payload, workspace):
    write = ev.normalize(claude_payload("PreToolUse", tool_name="Write", tool_input={"file_path": "/x", "content": "C"}))
    edit = ev.normalize(claude_payload("PreToolUse", tool_name="Edit", tool_input={"file_path": "/x", "new_string": "N"}))
    multi = ev.normalize(claude_payload("PreToolUse", tool_name="MultiEdit",
                                        tool_input={"file_path": "/x", "edits": [{"new_string": "A"}, {"new_string": "B"}]}))
    nb = ev.normalize(claude_payload("PreToolUse", tool_name="NotebookEdit",
                                     tool_input={"notebook_path": "/x", "new_source": "S"}))
    patch = ev.normalize(codex_payload("PostToolUse"), "codex")
    assert ev.new_content(write) == ["C"] and ev.new_content(edit) == ["N"]
    assert ev.new_content(multi) == ["A", "B"] and ev.new_content(nb) == ["S"]
    assert ev.new_content(patch) == ["def add(a, b):\n    return a + b"]

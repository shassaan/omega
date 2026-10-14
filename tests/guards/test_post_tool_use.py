from __future__ import annotations

import json

from hooks.lib import hashing
from tests.guards.support import POST, edit_payload, post_outcome, read_jsonl, session_dir

SID = "sess-claude-0001"


def test_write_is_ledgered_with_hash(workspace, run_hook, claude_payload):
    target = workspace / "docs" / "guide.md"
    target.write_text("guide\n", encoding="utf-8")
    payload = edit_payload(claude_payload, "PostToolUse", "Write", {"file_path": str(target), "content": "guide\n"})
    payload["tool_response"] = {"filePath": str(target), "type": "create"}
    proc = run_hook(POST, payload, "claude")
    assert proc.returncode == 0 and proc.stderr == ""
    rows = read_jsonl(session_dir(workspace, "claude", SID) / "changed.jsonl")
    assert len(rows) == 1
    row = rows[0]
    assert row["rel"] == "docs/guide.md" and row["kind"] == "added" and row["tool"] == "Write"
    assert row["sha256_after"] == hashing.sha256_file(str(target)) and row["tool_use_id"] == payload["tool_use_id"]


def test_ignored_and_outside_paths_not_ledgered(workspace, run_hook, claude_payload, tmp_path):
    for path in (workspace / "node_modules" / "x.js", tmp_path / "elsewhere.txt"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
        payload = edit_payload(claude_payload, "PostToolUse", "Write", {"file_path": str(path), "content": "x"})
        assert run_hook(POST, payload, "claude").returncode == 0
    assert read_jsonl(session_dir(workspace, "claude", SID) / "changed.jsonl") == []


def test_codex_patch_ledgered_and_unparsed_noted(workspace, run_hook, codex_payload):
    (workspace / "docs" / "a.md").write_text("a\n", encoding="utf-8")
    payload = codex_payload("PostToolUse")
    payload["tool_input"] = {"command": "*** Begin Patch\n*** Add File: docs/a.md\n+a\n*** Delete File: docs/old.md\n*** End Patch\n"}
    proc = run_hook(POST, payload, "codex")
    assert proc.returncode == 0 and json.loads(proc.stdout) == {}
    directory = session_dir(workspace, "codex", payload["session_id"])
    kinds = {r["rel"]: r["kind"] for r in read_jsonl(directory / "changed.jsonl")}
    assert kinds == {"docs/a.md": "added", "docs/old.md": "deleted"}
    payload["tool_input"] = {"command": "*** Begin Patch\n+orphan\n*** End Patch\n"}
    run_hook(POST, payload, "codex")
    assert "no parseable file path" in (directory / "unparsed_mutation.txt").read_text()


def test_contract_touch_recorded(workspace, run_hook, claude_payload):
    contract = workspace / "docs" / "contracts" / "x.md"
    contract.write_text("# Contract: X\n", encoding="utf-8")
    payload = edit_payload(claude_payload, "PostToolUse", "Edit",
                           {"file_path": str(contract), "old_string": "a", "new_string": "b"})
    run_hook(POST, payload, "claude")
    touched = (session_dir(workspace, "claude", SID) / "contracts_touched.txt").read_text().split()
    assert touched == [str(contract)]


def test_failure_event_only_harvests(workspace, run_hook, claude_payload):
    payload = claude_payload("PostToolUseFailure")
    proc = run_hook(POST, payload, "claude")
    assert proc.returncode == 0
    assert read_jsonl(session_dir(workspace, "claude", SID) / "changed.jsonl") == []


def test_garbage_stdin_never_blocks(workspace, run_hook):
    for provider in ("claude", "codex"):
        proc = run_hook(POST, "{not json", provider)
        assert proc.returncode == 0 and "failed closed" in proc.stderr


def test_harvest_reports_pass_lines_without_interrupting(workspace, run_hook, claude_payload, session):
    from hooks.lib import jobstore, state
    jobs = jobstore.jobs_dir(session)
    state.write_json_atomic(jobs / "test_x-1.job.json", {"id": "test_x-1", "scope_key": "test:tests/test_x.py",
                                                         "kind": "test", "label": "pytest tests/test_x.py",
                                                         "ts_ns": 1, "argv": ["python3"]})
    jobstore.write_result(jobs, {"id": "test_x-1", "rc": 0, "status": "pass", "output": "1 passed",
                                 "duration_ms": 1900, "test_files": {}})
    state.write_json_atomic(jobs / "lint_y-2.job.json", {"id": "lint_y-2", "scope_key": "lint:src/y.ts", "kind": "lint",
                                                         "label": "eslint src/y.ts", "ts_ns": 2, "argv": ["npx"]})
    jobstore.write_result(jobs, {"id": "lint_y-2", "rc": 1, "status": "skipped_env",
                                 "output": "Error: Cannot find module 'eslint'", "duration_ms": 10, "test_files": {}})
    proc = run_hook(POST, claude_payload("PostToolUseFailure"), "claude")
    blocked, text = post_outcome(proc, "claude")
    assert not blocked
    assert "[tests] PASS pytest tests/test_x.py (1.9s)" in text
    assert "[lint] skipped eslint: node_modules missing (run npm ci)" in text
    proc = run_hook(POST, claude_payload("PostToolUseFailure"), "claude")
    assert proc.stdout.strip() == ""

from __future__ import annotations

import os

from hooks.lib import gitsnap, ledger, state
from tests.conftest import make_session_context


def test_deltas_is_pure():
    before = {"/r": {"/r/a": "1", "/r/b": "2"}, "/gone": None}
    after = {"/r": {"/r/a": "1", "/r/b": "3", "/r/c": "4"}, "/gone": {"/gone/x": "1"}}
    assert gitsnap.deltas(before, after) == ["/r/b", "/r/c"]
    assert gitsnap.deltas({"/r": {"/r/a": "1"}}, {"/r": {}}) == ["/r/a"]


def test_baseline_is_written_once(session):
    gitsnap.ensure_baseline(session)
    first = state.read_json(session.dir / "baseline.json")
    assert first["state"] == {session.workspace: {}} and first["ts_ns"] > 0
    (session.dir / "baseline.json").write_text('{"marker": 1}')
    gitsnap.ensure_baseline(session)
    assert state.read_json(session.dir / "baseline.json") == {"marker": 1}


def test_shell_write_is_reconciled_into_scope(session, workspace):
    gitsnap.ensure_baseline(session)
    (workspace / "src" / "sneaky.py").write_text("print('written by a shell')\n")
    (workspace / "README.md").write_text("changed by a formatter\n")
    result = gitsnap.reconcile(session)
    assert sorted(result.found) == sorted([str(workspace / "src" / "sneaky.py"), str(workspace / "README.md")])
    assert result.unreadable == [] and result.note is None
    kinds = {row["rel"]: row["kind"] for row in state.read_jsonl(session.dir / "reconciled.jsonl")}
    assert kinds == {"src/sneaky.py": "reconciled", "README.md": "reconciled"}
    assert str(workspace / "src" / "sneaky.py") in ledger.paths(session)
    assert gitsnap.reconcile(session).found == []


def test_deleted_tracked_file_is_reconciled_as_deleted(session, workspace):
    gitsnap.ensure_baseline(session)
    os.remove(str(workspace / "README.md"))
    gitsnap.reconcile(session)
    rows = state.read_jsonl(session.dir / "reconciled.jsonl")
    assert [(r["rel"], r["kind"], r["sha256_after"]) for r in rows] == [("README.md", "deleted", "<deleted>")]


def test_ledgered_and_other_session_paths_are_explained(session, workspace):
    gitsnap.ensure_baseline(session)
    mine = workspace / "src" / "mine.py"
    mine.write_text("x")
    ledger.append(session, str(mine), "added", "Write", None)
    other = make_session_context("codex", "other-session")
    theirs = workspace / "src" / "theirs.py"
    theirs.write_text("y")
    ledger.append(other, str(theirs), "added", "apply_patch", None)
    assert gitsnap.reconcile(session).found == []


def test_ignored_and_harness_paths_are_not_snapshotted(session, workspace):
    gitsnap.ensure_baseline(session)
    (workspace / "node_modules").mkdir()
    (workspace / "node_modules" / "x.js").write_text("x")
    (workspace / ".omega" / "clearances").mkdir(parents=True)
    (workspace / ".omega" / "clearances" / "proof.json").write_text("{}")
    (workspace / ".gitignore").write_text("")
    found = gitsnap.reconcile(session).found
    assert found == [str(workspace / ".gitignore")]


def test_pre_dirty_files_count_only_when_changed_again(session, workspace):
    (workspace / "src" / "draft.py").write_text("v1")
    gitsnap.ensure_baseline(session)
    assert gitsnap.reconcile(session).found == []
    (workspace / "src" / "draft.py").write_text("v2")
    assert gitsnap.reconcile(session).found == [str(workspace / "src" / "draft.py")]


def test_missing_baseline_creates_one_and_notes_it(session):
    result = gitsnap.reconcile(session)
    assert result.found == [] and "no session-start baseline" in result.note
    assert (session.dir / "baseline.json").exists()
    (session.dir / "baseline.json").write_text("{bad")
    assert "unreadable" in gitsnap.reconcile(session).note


def test_non_git_workspace_is_unreadable_not_guessed(tmp_path, monkeypatch, tmp_state):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.setenv("OMEGA_WORKSPACE", str(plain))
    ctx = make_session_context("claude", "plain-session")
    gitsnap.ensure_baseline(ctx)
    (plain / "x.py").write_text("x")
    result = gitsnap.reconcile(ctx)
    assert result.found == [] and result.unreadable == [str(plain.resolve())]
    assert "not a git checkout" in result.note


def test_subdirectory_of_a_repo_is_not_a_root(workspace):
    assert gitsnap.dirty_state(str(workspace / "src")) is None
    assert gitsnap.dirty_state(str(workspace)) == {}

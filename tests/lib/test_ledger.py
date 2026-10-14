from __future__ import annotations

import json

from hooks.lib import hashing, ledger, paths
from tests.conftest import make_session_context


def test_append_row_shape(session, workspace):
    target = workspace / "src" / "calc.py"
    target.write_text("x = 1\n")
    ledger.append(session, str(target), "added", "Write", "toolu_1")
    row = json.loads((session.dir / "changed.jsonl").read_text().splitlines()[0])
    assert set(row) == {"ts", "ts_ns", "path", "rel", "kind", "tool", "tool_use_id", "provider", "session_id", "sha256_after"}
    assert row["rel"] == "src/calc.py" and row["kind"] == "added" and row["provider"] == "claude"
    assert row["sha256_after"] == hashing.sha256_file(str(target))
    ledger.append(session, str(workspace / "src" / "x.py"), "weird", None, None)
    assert ledger.rows(session)[-1]["kind"] == "unknown"
    assert ledger.rows(session)[-1]["sha256_after"] == "<deleted>"


def test_paths_keep_deleted_and_renamed_in_first_seen_order(session, workspace):
    a, b, c = (str(workspace / "src" / n) for n in ("a.py", "b.py", "c.py"))
    (workspace / "src" / "c.py").write_text("c")
    ledger.append(session, a, "added", "Write", None)
    ledger.append(session, b, "renamed_from", "apply_patch", None)
    ledger.append(session, c, "renamed_to", "apply_patch", None)
    ledger.append(session, a, "deleted", "apply_patch", None)
    ledger.append_reconciled(session, str(workspace / "src" / "d.py"), "deleted")
    assert ledger.paths(session) == [a, b, c, str(workspace / "src" / "d.py")]
    assert ledger.existing(session) == [c]
    assert [r["kind"] for r in ledger.rows(session)] == ["added", "renamed_from", "renamed_to", "deleted", "deleted"]


def test_source_paths_are_workspace_relative_sources(session, workspace):
    for rel in ("src/calc.py", "tests/test_calc.py", "docs/x.md", "src/__init__.py"):
        (workspace / rel).write_text("x")
        ledger.append(session, str(workspace / rel), "modified", "Edit", None)
    assert ledger.source_paths(session) == ["src/calc.py"]
    assert ledger.source_paths(session, session.cfg) == ["src/calc.py"]


def test_unparsed_and_contracts_touched(session, workspace):
    assert ledger.unparsed(session) == []
    ledger.note_unparsed(session, "apply_patch payload\nhas no path")
    assert ledger.unparsed(session) == ["apply_patch payload has no path"]
    contract = str(workspace / "docs" / "contracts" / "x.md")
    ledger.note_contract_touched(session, contract)
    ledger.note_contract_touched(session, contract)
    assert ledger.contracts_touched(session) == [contract]


def test_touched_since_spans_sessions(workspace):
    first = make_session_context("claude", "s1")
    second = make_session_context("codex", "s2")
    ledger.append(first, str(workspace / "src" / "a.py"), "added", "Write", None)
    cutoff = ledger.rows(first)[0]["ts_ns"] + 1
    ledger.append(second, str(workspace / "src" / "b.py"), "added", "apply_patch", None)
    ledger.append_reconciled(second, str(workspace / "src" / "c.py"), "reconciled")
    found = ledger.touched_since(paths.state_root(), paths.workspace_hash(str(workspace)), cutoff)
    assert found == {str(workspace / "src" / "b.py"), str(workspace / "src" / "c.py")}
    assert ledger.touched_since(paths.state_root(), "0" * 16, 0) == set()

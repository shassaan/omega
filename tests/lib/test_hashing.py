from __future__ import annotations

import hashlib

from hooks.lib import hashing


def test_sha256_file_variants(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"hello")
    assert hashing.sha256_file(str(f)) == hashlib.sha256(b"hello").hexdigest()
    assert hashing.sha256_file(str(tmp_path / "missing")) == "<deleted>"
    assert hashing.sha256_file(str(tmp_path)) == "<dir>"


def test_canonical_json_is_sorted_compact_and_unicode():
    assert hashing.canonical_json({"b": 1, "a": [2, {"d": "é", "c": None}]}) == '{"a":[2,{"c":null,"d":"é"}],"b":1}'


def test_snapshot_accepts_relative_and_absolute_paths(workspace):
    (workspace / "src" / "a.py").write_text("x = 1\n")
    files = hashing.snapshot(str(workspace), ["src/a.py", str(workspace / "src" / "a.py"), "./src/gone.py"])
    assert set(files) == {"src/a.py", "src/gone.py"}
    assert files["src/gone.py"] == "<deleted>"
    assert files["src/a.py"] == hashing.sha256_text("x = 1\n")


def test_files_digest_is_order_independent():
    assert hashing.files_digest({"a": "1", "b": "2"}) == hashing.files_digest({"b": "2", "a": "1"})
    assert hashing.files_digest({}) == hashing.sha256_text("{}")


def _clearance(workspace, rels):
    files = hashing.snapshot(str(workspace), rels)
    return {"files": files, "files_digest": hashing.files_digest(files)}


def test_fresh_until_any_cleared_file_changes(workspace):
    (workspace / "src" / "a.py").write_text("x = 1\n")
    clearance = _clearance(workspace, ["src/a.py", "src/old.py"])
    assert hashing.fresh(clearance, str(workspace), [str(workspace / "src" / "a.py")])[0]
    (workspace / "src" / "a.py").write_text("x = 2\n")
    ok, reason = hashing.fresh(clearance, str(workspace), [])
    assert not ok and "src/a.py changed" in reason


def test_fresh_detects_recreated_deleted_file(workspace):
    clearance = _clearance(workspace, ["src/old.py"])
    assert clearance["files"]["src/old.py"] == "<deleted>"
    (workspace / "src" / "old.py").write_text("back\n")
    assert not hashing.fresh(clearance, str(workspace), [])[0]


def test_fresh_requires_every_ledger_path_to_be_covered(workspace):
    (workspace / "src" / "a.py").write_text("x = 1\n")
    clearance = _clearance(workspace, ["src/a.py"])
    ok, reason = hashing.fresh(clearance, str(workspace), ["src/a.py", "src/b.py"])
    assert not ok and "src/b.py" in reason


def test_fresh_rejects_tampered_digest_and_bad_shapes(workspace):
    (workspace / "src" / "a.py").write_text("x = 1\n")
    clearance = _clearance(workspace, ["src/a.py"])
    clearance["files_digest"] = "0" * 64
    assert not hashing.fresh(clearance, str(workspace), [])[0]
    assert not hashing.fresh([], str(workspace), [])[0]
    assert not hashing.fresh({"files": None}, str(workspace), [])[0]

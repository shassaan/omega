from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from hooks.lib import hashing

jsonschema = pytest.importorskip("jsonschema")

ROOT = Path(__file__).resolve().parents[2]
NAMES = ("proof", "contract", "review")


def schema(name):
    return json.loads((ROOT / "schemas" / ("%s.schema.json" % name)).read_text())


def golden(name):
    return json.loads((ROOT / "tests" / "fixtures" / "clearances" / ("%s.json" % name)).read_text())


def errors(name, document):
    validator = jsonschema.Draft202012Validator(schema(name))
    return [e.message for e in validator.iter_errors(document)]


@pytest.mark.parametrize("name", NAMES)
def test_schemas_are_valid_draft_2020_12(name):
    jsonschema.Draft202012Validator.check_schema(schema(name))


@pytest.mark.parametrize("name", NAMES)
def test_golden_clearance_validates(name):
    assert errors(name, golden(name)) == []


def test_golden_triple_shares_files_and_digest():
    triple = [golden(n) for n in NAMES]
    assert len({json.dumps(t["files"], sort_keys=True) for t in triple}) == 1
    assert len({t["files_digest"] for t in triple}) == 1
    assert triple[0]["files_digest"] == hashing.files_digest(triple[0]["files"])


@pytest.mark.parametrize("name,mutate", [
    ("proof", lambda d: d.update(schema="omega/proof/2")),
    ("proof", lambda d: d.update(verified="yes")),
    ("proof", lambda d: d.pop("files_digest")),
    ("proof", lambda d: d.update(extra_key=1)),
    ("proof", lambda d: d["files"].update({"/abs/path.py": "0" * 64})),
    ("proof", lambda d: d["files"].update({"src/x.py": "not-a-hash"})),
    ("proof", lambda d: d["results"][0].update(status="GREEN")),
    ("proof", lambda d: d["results"][0].update(output_tail="x" * 4097)),
    ("proof", lambda d: d["blocking"].append({"gate": "proof", "check": "pytest", "status": "PASS", "detail": ""})),
    ("contract", lambda d: d["contracts"][0].update(slug="Not_A_Slug")),
    ("contract", lambda d: d["contracts"][0]["seams"].pop("Journey")),
    ("contract", lambda d: d["contracts"][0].update(errors=["missing code prefix"])),
    ("contract", lambda d: d["contracts"][0].update(not_applicable=["Unit"])),
    ("review", lambda d: d["approvals"][0].update(proposal_id="tp-1a2b3c4d")),
    ("review", lambda d: d["approvals"][0].update(quote="")),
    ("review", lambda d: d["approvals"][0].update(recorded_by="agent")),
    ("review", lambda d: d["overrides"][0].update(token="hs-XYZ")),
    ("review", lambda d: d["secrets_scan"]["hits"].append({"rule": "github-token", "path": "src/a.py", "line": 3, "value": "ghp_x"})),
    ("review", lambda d: d.update(channel="email")),
])
def test_tampered_documents_fail(name, mutate):
    document = copy.deepcopy(golden(name))
    mutate(document)
    assert errors(name, document)


def test_override_without_ts_ns_is_still_valid():
    document = copy.deepcopy(golden("review"))
    document["overrides"][0].pop("ts_ns")
    assert errors("review", document) == []

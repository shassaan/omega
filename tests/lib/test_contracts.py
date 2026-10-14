from __future__ import annotations

import pytest

from hooks.lib import contracts

GOOD = """# Contract: Signup
slug: signup
code: src/auth/signup.py, src/api/routes/signup.py
tests: tests/test_signup.py
owed: none
assumptions:
  - emails are unique
  - tokens expire

## Unit
### Scenario: rejects short passwords
- Given a 7 character password
- When it is evaluated
- Then it is rejected
- And the reason does not echo it

Some prose that the parser ignores.

## Integration
### Scenario: duplicate email refused
- Given a user exists
- When a second signup arrives
- Then the insert fails

## Functional
_Not applicable: library only_

## Journey
### Scenario: user signs up
- Given a browser
- When the user submits
- Then the dashboard greets them
"""


def parse(text, name="signup.md"):
    return contracts.parse(text, "docs/contracts/" + name)


def test_good_contract_parses_cleanly():
    c = parse(GOOD)
    assert c.errors == [] and c.title == "Signup" and c.slug == "signup"
    assert c.code == ["src/auth/signup.py", "src/api/routes/signup.py"] and c.tests == ["tests/test_signup.py"]
    assert c.assumptions == "- emails are unique\n- tokens expire"
    assert contracts.seam_counts(c) == {"Unit": 1, "Integration": 1, "Functional": 0, "Journey": 1}
    assert contracts.not_applicable(c) == ["Functional"]
    assert c.seams["Functional"] == "not_applicable:library only"
    assert [s.keyword for s in c.seams["Unit"][0].steps] == ["Given", "When", "Then", "And"]


def test_shipped_example_is_valid(harness_root):
    example = harness_root / "docs" / "contracts" / "example-user-signup.md"
    c = contracts.load_file(str(example), str(harness_root))
    assert c.errors == [] and contracts.is_valid(c)


def mutate(old, new, text=GOOD):
    assert old in text
    return text.replace(old, new, 1)


@pytest.mark.parametrize("text,name,code", [
    (mutate("# Contract: Signup\n", ""), "signup.md", "E001: missing title line"),
    (GOOD, "other.md", "E002: slug does not match file name"),
    (mutate("owed: none\n", ""), "signup.md", "E003: missing metadata key owed"),
    (mutate("## Journey", "## Nope"), "signup.md", "E006: seam missing Journey"),
    (mutate("_Not applicable: library only_", "nothing here"), "signup.md", "E007: seam Functional has no scenario"),
    (mutate("- When it is evaluated\n", ""), "signup.md", "E008: scenario rejects short passwords lacks When"),
    (mutate("### Scenario: user signs up", "### Scenario: Rejects  short passwords"), "signup.md",
     "E009: duplicate scenario name Rejects  short passwords"),
    (mutate("- Given a user exists\n- When a second signup arrives\n",
            "- When a second signup arrives\n- Given a user exists\n"), "signup.md",
     "E010: step out of order in duplicate email refused"),
    (mutate("## Journey", "## Extra\n## Journey"), "signup.md", "E011: unknown section Extra"),
    (mutate("- Given a browser", "- And a browser\n- Given a browser"), "signup.md",
     "E012: And without a preceding step in user signs up"),
    (mutate("## Integration", "slug: late\n## Integration"), "signup.md", "E013: metadata line after the first section"),
    (mutate("### Scenario: rejects short passwords\n- Given a 7 character password\n- When it is evaluated\n- Then it is rejected\n- And the reason does not echo it\n",
            "_Not applicable: nothing to test_\n"), "signup.md", "E014: Unit seam cannot be not-applicable"),
    (mutate("tests: tests/test_signup.py", "tests: , ,"), "signup.md", "E015: empty code or tests list"),
])
def test_validation_codes(text, name, code):
    assert code in parse(text, name).errors


def test_duplicate_seam_is_an_error():
    assert any(e.startswith("E011") for e in parse(mutate("## Journey", "## Unit\n## Journey")).errors)


def test_existence_codes_strict_and_lenient(tmp_path):
    c = parse(GOOD)
    lenient = contracts.validate(c, str(tmp_path), strict_existence=False)
    assert "W004: code path not found src/auth/signup.py" in lenient.warnings
    assert "W005: tests path not found tests/test_signup.py" in lenient.warnings
    assert not any(e.startswith("E004") for e in lenient.errors)
    strict = contracts.validate(lenient, str(tmp_path), strict_existence=True)
    assert "E004: code path not found src/auth/signup.py" in strict.errors
    assert not any(w.startswith("W004") for w in strict.warnings)
    for rel in c.code + c.tests:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    assert contracts.validate(c, str(tmp_path), strict_existence=True).errors == []


def test_paths_escaping_the_workspace_are_errors(tmp_path):
    bad = parse(mutate("code: src/auth/signup.py, src/api/routes/signup.py", "code: ../../etc/passwd"))
    assert "E004: code path not found ../../etc/passwd" in contracts.validate(bad, str(tmp_path), False).errors


@pytest.mark.parametrize("old,new", [
    ("# Contract: Signup", "# Contract: Signup flow (renamed)"),
    ("owed: none", "owed: rate limiting"),
    ("Some prose that the parser ignores.", "Different prose entirely."),
    ("- Then it is rejected", "-   Then   it is   REJECTED"),
    ("code: src/auth/signup.py, src/api/routes/signup.py", "code: src/api/routes/signup.py, src/auth/signup.py"),
])
def test_fingerprint_ignores_noise(old, new):
    assert contracts.fingerprint(parse(GOOD)) == contracts.fingerprint(parse(mutate(old, new)))


def test_fingerprint_ignores_seam_order_but_not_seam_contents():
    base = parse(GOOD)
    moved = GOOD.replace("## Functional\n_Not applicable: library only_\n\n", "") + "\n## Functional\n_Not applicable: library only_\n"
    assert parse(moved).errors == []
    assert contracts.fingerprint(base) == contracts.fingerprint(parse(moved))
    swapped = parse(GOOD.replace("## Unit", "## TMP").replace("## Journey", "## Unit").replace("## TMP", "## Journey"))
    assert contracts.fingerprint(base) != contracts.fingerprint(swapped)


@pytest.mark.parametrize("old,new", [
    ("- Then it is rejected", "- Then it is accepted"),
    ("### Scenario: user signs up", "### Scenario: user registers"),
    ("tests: tests/test_signup.py", "tests: tests/test_signup.py, tests/test_more.py"),
    ("  - tokens expire", "  - tokens never expire"),
    ("_Not applicable: library only_", "_Not applicable: covered elsewhere_"),
    ("- Then the dashboard greets them\n", "- Then the dashboard greets them\n- And an email is sent\n"),
])
def test_fingerprint_changes_with_structure(old, new):
    assert contracts.fingerprint(parse(GOOD)) != contracts.fingerprint(parse(mutate(old, new)))


def test_load_all_skips_readme_and_covering(tmp_path, harness_root):
    from hooks.lib import config
    directory = tmp_path / "docs" / "contracts"
    directory.mkdir(parents=True)
    (directory / "README.md").write_text("# not a contract")
    (directory / "signup.md").write_text(GOOD)
    loaded = contracts.load_all(str(tmp_path), config.load(harness_root))
    assert [c.slug for c in loaded] == ["signup"]
    assert contracts.covering(loaded, "./src/auth/signup.py") == loaded
    assert contracts.covering(loaded, "src/other.py") == []
    assert contracts.load_all(str(tmp_path / "missing"), config.load(harness_root)) == []

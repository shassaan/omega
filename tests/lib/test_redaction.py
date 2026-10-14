from __future__ import annotations

import base64
import logging
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from hooks.lib import config, redaction

ALNUM = "Ab3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zC"


def stretch(n: int, alphabet: str = ALNUM) -> str:
    return (alphabet * (n // len(alphabet) + 1))[:n]


ANTHROPIC_STRICT = "sk-ant-api03-" + stretch(93) + "AA"
ANTHROPIC_RELAXED = "sk-ant-api03-" + stretch(85)
OPENAI_PROJ = "sk-proj-" + stretch(48)
OPENAI_LEGACY = "sk-" + stretch(20) + "T3BlbkFJ" + stretch(20)
AWS_ID = "AKIA" + "QWERTYUIOPASDFGH"
GITHUB = "ghp_" + stretch(36)
GOOGLE = "AIza" + stretch(35)
STRIPE_LIVE = "sk_" + "live_" + stretch(24)
STRIPE_TEST = "sk_" + "test_" + stretch(24)
SLACK = "xoxb-" + "123456789012-" + stretch(24)
SLACK_HOOK = "https://hooks.slack.com/services/" + stretch(44, "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789/")
JWT = "eyJ" + stretch(20) + ".eyJ" + stretch(24) + "." + stretch(30)
PEM = "-----BEGIN RSA PRIVATE KEY-----\n" + stretch(80) + "\n" + stretch(80) + "\n-----END RSA PRIVATE KEY-----"


@pytest.mark.parametrize("rule,value", [
    ("anthropic-key", ANTHROPIC_STRICT),
    ("anthropic-key", ANTHROPIC_RELAXED),
    ("openai-key", OPENAI_PROJ),
    ("openai-key", OPENAI_LEGACY),
    ("aws-access-key", AWS_ID),
    ("github-token", GITHUB),
    ("google-api-key", GOOGLE),
    ("stripe-key", STRIPE_LIVE),
    ("stripe-key", STRIPE_TEST),
    ("slack-token", SLACK),
    ("slack-webhook", SLACK_HOOK),
    ("jwt", JWT),
    ("private-key", PEM),
])
def test_secret_shapes_are_redacted_with_typed_placeholders(rule, value):
    text, hits = redaction.redact("prefix %s suffix" % value)
    assert value not in text
    assert "[REDACTED:%s]" % rule in text
    assert rule in hits
    assert text.startswith("prefix ") and text.endswith(" suffix")


def test_group_rules_redact_only_the_secret_value():
    db = "postgres://app:s3cretPass99@db.internal:5432/app"
    text, hits = redaction.redact(db)
    assert "s3cretPass99" not in text and text.startswith("postgres://app:") and "@db.internal" in text
    bearer = "Authorization: Bearer " + stretch(32)
    text, hits = redaction.redact(bearer)
    assert stretch(32) not in text and "Authorization: Bearer [REDACTED:bearer]" == text
    aws_secret = "aws_secret_access_key = " + stretch(40, "abcdefghijklmnopqrstuvwxyz0123456789/+")
    text, hits = redaction.redact(aws_secret)
    assert "aws-secret-assign" in hits


def test_generic_assignment_needs_entropy():
    secret = "SERVICE_TOKEN=" + stretch(24)
    text, hits = redaction.redact(secret)
    assert "generic-assign" in hits and stretch(24) not in text
    assert redaction.redact("TOKEN_URL=https://example.org/token")[1] == []
    assert redaction.redact("PASSWORD=aaaaaaaaaaaaaaaaaaaa")[1] == []


@pytest.mark.parametrize("value", [
    "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "API_KEY=changeme-changeme-changeme",
    "SECRET_KEY=placeholder_placeholder_value",
    "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "contact noreply@anthropic.com",
    "ada@example.com and grace@mail.example.org",
    "card 4111 1111 1111 1112",
    "order 1234567890123",
    "released on 2026-10-13",
    "version 1.2.3.4",
    "id 123e4567-e89b-12d3-a456-426614174000",
    "commit 3f786850e387550fdab836ed7e6dc881de23001b",
    "pk_live_" + stretch(24),
])
def test_negatives_are_left_alone(value):
    assert redaction.redact(value) == (value, [])


@pytest.mark.parametrize("rule,value", [
    ("email", "write to ada.lovelace@gmail.com today"),
    ("ssn", "ssn 123-45-6789"),
    ("card", "card 4111 1111 1111 1111"),
    ("iban", "iban GB82 WEST 1234 5698 7654 32"),
    ("phone-e164", "call +44 20 7946 0958"),
    ("phone-us", "call (415) 555-2671"),
])
def test_pii_shapes(rule, value):
    text, hits = redaction.redact(value)
    assert rule in hits
    assert "[REDACTED:%s]" % rule in text
    assert redaction.redact(value, pii=False)[1] == []


def test_redaction_is_idempotent():
    once, _ = redaction.redact("db postgres://u:hunter2222@h/x key " + GITHUB + " mail a@gmail.com")
    twice, hits = redaction.redact(once)
    assert twice == once
    assert hits == []


def test_scan_reports_rule_and_line_never_value():
    text = "line one\nkey = " + GOOGLE + "\nmail bob@gmail.com\n"
    hits = redaction.scan(text)
    assert [(h.rule, h.line) for h in hits] == [("google-api-key", 2), ("email", 3)]
    assert all(not hasattr(h, "value") for h in hits)


def test_strict_secret_hits_only_fire_on_strict_forms():
    assert [h.rule for h in redaction.strict_secret_hits("x " + ANTHROPIC_STRICT)] == ["anthropic-key"]
    assert redaction.strict_secret_hits("x " + ANTHROPIC_RELAXED) == []
    assert [h.rule for h in redaction.strict_secret_hits(STRIPE_LIVE)] == ["stripe-key"]
    assert redaction.strict_secret_hits(STRIPE_TEST) == []
    assert redaction.strict_secret_hits("AKIAIOSFODNN7EXAMPLE") == []
    assert redaction.strict_secret_hits("bob@gmail.com 123-45-6789") == []
    rules = {h.rule for h in redaction.strict_secret_hits("\n".join([OPENAI_PROJ, OPENAI_LEGACY, AWS_ID, GITHUB, GOOGLE, SLACK, PEM]))}
    assert rules == {"openai-key", "aws-access-key", "github-token", "google-api-key", "slack-token", "private-key"}
    hits = redaction.strict_secret_hits("a\nb\nc " + GITHUB)
    assert hits[0].line == 3


def test_scan_file_sets_path_and_skips_binary(tmp_path):
    src = tmp_path / "config.py"
    src.write_text("TOKEN = '" + GITHUB + "'\n")
    hits = redaction.scan_file(str(src))
    assert hits and hits[0].path == str(src) and hits[0].line == 1
    blob = tmp_path / "x.bin"
    blob.write_bytes(b"\x00\x01" + GITHUB.encode())
    assert redaction.scan_file(str(blob)) == []
    assert redaction.scan_file(str(tmp_path / "missing")) == []


def test_register_exact_scrubs_value_and_encoded_variants():
    value = "plain-injected-secret-value-42"
    redaction.register_exact([value, "short"])
    for variant in (value, base64.b64encode(value.encode()).decode(), quote(value, safe="")):
        text, hits = redaction.redact("x=" + variant)
        assert variant not in text and "registered" in hits
    assert redaction.redact("short words")[1] == []


def test_redacting_filter_scrubs_log_records():
    records = []

    class Keep(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = logging.getLogger("omega-redaction-test")
    logger.handlers = [Keep()]
    logger.addFilter(redaction.RedactingFilter())
    logger.propagate = False
    logger.warning("key %s for %s", GITHUB, "bob@gmail.com")
    assert records == ["key [REDACTED:github-token] for [REDACTED:email]"]


def test_is_fixture(harness_root):
    cfg = config.load(harness_root)
    assert redaction.is_fixture("tests/fixtures/transcripts/x.jsonl", cfg)
    assert redaction.is_fixture("app/fixtures/users.json", cfg)
    assert redaction.is_fixture(".env.example", cfg)
    assert not redaction.is_fixture("src/settings.py", cfg)

from __future__ import annotations

import base64
import logging
import math
import re
import threading
from collections import Counter
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote

SECRET_RULES = [
    ("aws-access-key", re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b")),
    ("aws-secret-assign", re.compile(r"(?i)\baws_?secret_?(?:access_?)?key\b[\"'\s:=]{1,6}([A-Za-z0-9/+=]{40})\b")),
    ("github-token", re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{36,251}|github_pat_\w{82})\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}")),
    ("google-api-key", re.compile(r"\bAIza[\w\-]{35}\b")),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b")),
    ("slack-token", re.compile(r"\bxox[abprso]-[0-9A-Za-z\-]{10,72}")),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}")),
    ("jwt", re.compile(r"\bey[A-Za-z0-9_\-]{17,}\.ey[A-Za-z0-9_\-/\\]{17,}\.(?:[A-Za-z0-9_\-/\\]{10,}={0,2})?")),
    ("private-key", re.compile(r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]{64,8000}?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----|-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----")),
    ("db-url-password", re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:/@]+:)([^\s@/]{3,})(@)")),
    ("bearer", re.compile(r"(?i)\b(authorization[\"']?\s*[:=]\s*[\"']?bearer\s+)([A-Za-z0-9._~+/\-]{20,}=*)")),
    ("generic-assign", re.compile(r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Z0-9_]*)\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=.]{16,})[\"']?")),
]

PII_RULES = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")),
    ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")),
    ("card", re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")),
    ("phone-e164", re.compile(r"(?<![\w.])\+[1-9]\d{0,2}[ .\-]?\(?\d{1,4}\)?(?:[ .\-]?\d{2,4}){2,4}(?!\d)")),
    ("phone-us", re.compile(r"(?<![\w.\-])(?:\+?1[ .\-]?)?\(?[2-9]\d{2}\)?[ .\-]\d{3}[ .\-]\d{4}(?!\d)")),
]

STRICT_RULES = [
    ("anthropic-key", re.compile(r"\bsk-ant-api03-[a-zA-Z0-9_\-]{93}AA")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|\bsk-proj-[A-Za-z0-9_\-]{40,}")),
    ("aws-access-key", re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b")),
    ("github-token", re.compile(r"\b(ghp_[0-9A-Za-z]{36,251}|github_pat_\w{82})\b")),
    ("google-api-key", re.compile(r"\bAIza[\w\-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[abp]-[0-9A-Za-z\-]{10,72}")),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{10,99}\b")),
    ("private-key", re.compile(r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]{64,8000}?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----")),
]

GROUP_VALUE_RULES = {"aws-secret-assign": 1, "db-url-password": 2, "bearer": 2, "generic-assign": 2}
DUMMY_VALUES = ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
DUMMY_MARKERS = ("example", "changeme", "placeholder", "<your-", "xxxx")
EMAIL_ALLOW = ("noreply@anthropic.com",)
EMAIL_ALLOW_DOMAINS = ("example.com", "example.org")
PLACEHOLDER_PREFIX = "[REDACTED"
REGISTERED_RULE = "registered"
MIN_REGISTERED_LEN = 8

_registered: set = set()
_registered_lock = threading.Lock()


@dataclass
class Hit:
    rule: str
    start: int
    end: int
    path: Optional[str] = None
    line: Optional[int] = None


def luhn(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def iban_ok(s: str) -> bool:
    compact = s.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34:
        return False
    try:
        numeric = "".join(str(int(c, 36)) for c in compact[4:] + compact[:4])
    except ValueError:
        return False
    return int(numeric) % 97 == 1


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in counts.values())


def is_dummy(value: str) -> bool:
    if value in DUMMY_VALUES:
        return True
    lowered = value.lower()
    return any(marker in lowered for marker in DUMMY_MARKERS)


def _email_allowed(value: str) -> bool:
    lowered = value.lower()
    if lowered in EMAIL_ALLOW:
        return True
    domain = lowered.rsplit("@", 1)[-1]
    return any(domain == d or domain.endswith("." + d) for d in EMAIL_ALLOW_DOMAINS) or is_dummy(lowered)


def _secret_hits(text: str, rules) -> list:
    hits: list = []
    for name, rx in rules:
        group = GROUP_VALUE_RULES.get(name, 0)
        for m in rx.finditer(text):
            value = m.group(group) if group else m.group(0)
            if value is None:
                continue
            start = m.start(group) if group else m.start()
            end = m.end(group) if group else m.end()
            if value.startswith(PLACEHOLDER_PREFIX) or is_dummy(value):
                continue
            if name == "generic-assign" and entropy(value) < 3.0:
                continue
            hits.append(Hit(name, start, end))
    return hits


def _pii_hits(text: str) -> list:
    hits: list = []
    for name, rx in PII_RULES:
        for m in rx.finditer(text):
            value = m.group(0)
            if name == "email" and _email_allowed(value):
                continue
            if name == "iban" and not iban_ok(value):
                continue
            if name == "card" and not luhn(value):
                continue
            hits.append(Hit(name, m.start(), m.end()))
    return hits


def _registered_hits(text: str) -> list:
    with _registered_lock:
        values = sorted(_registered, key=len, reverse=True)
    hits: list = []
    for value in values:
        start = text.find(value)
        while start != -1:
            hits.append(Hit(REGISTERED_RULE, start, start + len(value)))
            start = text.find(value, start + len(value))
    return hits


def _resolve(hits: list) -> list:
    ordered = sorted(hits, key=lambda h: (h.start, -(h.end - h.start)))
    kept: list = []
    last_end = -1
    for hit in ordered:
        if hit.start >= last_end:
            kept.append(hit)
            last_end = hit.end
        elif hit.end > last_end and kept:
            kept[-1] = Hit(kept[-1].rule, kept[-1].start, hit.end)
            last_end = hit.end
    return kept


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan(text: str, pii: bool = True) -> list:
    if not text:
        return []
    resolved = _resolve(_registered_hits(text) + _secret_hits(text, SECRET_RULES))
    if pii:
        spans = [(h.start, h.end) for h in resolved]
        extra = [h for h in _pii_hits(text)
                 if not any(h.start < end and start < h.end for start, end in spans)]
        resolved = _resolve(resolved + extra)
    for hit in resolved:
        hit.line = _line_of(text, hit.start)
    return resolved


def redact(text: str, pii: bool = True) -> tuple:
    if not isinstance(text, str) or not text:
        return text, []
    hits = scan(text, pii=pii)
    if not hits:
        return text, []
    pieces: list = []
    cursor = 0
    for hit in hits:
        pieces.append(text[cursor:hit.start])
        pieces.append("[REDACTED:%s]" % hit.rule)
        cursor = hit.end
    pieces.append(text[cursor:])
    return "".join(pieces), [hit.rule for hit in hits]


def redact_text(text: str, pii: bool = True) -> str:
    return redact(text, pii=pii)[0]


def strict_secret_hits(text: str) -> list:
    if not text:
        return []
    hits = _resolve(_secret_hits(text, STRICT_RULES))
    for hit in hits:
        hit.line = _line_of(text, hit.start)
    return hits


def scan_file(path: str, pii: bool = True) -> list:
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return []
    if b"\x00" in data[:8192]:
        return []
    text = data.decode("utf-8", errors="replace")
    hits = scan(text, pii=pii)
    for hit in hits:
        hit.path = str(path)
    return hits


def _variants(value: str) -> list:
    raw = value.encode("utf-8")
    forms = {value, quote(value, safe=""), quote(value, safe="/")}
    for encoder in (base64.b64encode, base64.urlsafe_b64encode):
        encoded = encoder(raw).decode("ascii")
        forms.add(encoded)
        forms.add(encoded.rstrip("="))
    return [f for f in forms if len(f) >= MIN_REGISTERED_LEN]


def register_exact(values: list) -> None:
    fresh: set = set()
    for value in values or []:
        if isinstance(value, str) and len(value.strip()) >= MIN_REGISTERED_LEN:
            fresh.update(_variants(value.strip()))
    with _registered_lock:
        _registered.update(fresh)


def clear_registered() -> None:
    with _registered_lock:
        _registered.clear()


def is_fixture(path_rel: str, cfg) -> bool:
    from . import paths as paths_mod
    globs = cfg.get("redaction.fixture_globs", []) if cfg is not None else []
    return paths_mod.match_globs(path_rel, globs)


class RedactingFilter(logging.Filter):
    def __init__(self, pii: bool = True, name: str = ""):
        super().__init__(name)
        self.pii = pii

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        record.msg = redact(message, pii=self.pii)[0]
        record.args = None
        if record.exc_info:
            formatted = logging.Formatter().formatException(record.exc_info)
            record.exc_text = redact(formatted, pii=self.pii)[0]
        return True

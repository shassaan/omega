from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from hooks.lib import config, costledger


@pytest.fixture
def cfg(harness_root, tmp_state):
    return config.load(harness_root)


def month_row(cfg, **extra):
    row = {"ts": costledger.current_month() + "-01T00:00:00Z", "ts_ns": 1, "provider": "anthropic",
           "model": "claude-opus-5-5", "session_id": "s1", "run_id": None, "in": 0, "out": 0, "source": "api"}
    row.update(extra)
    return row


@pytest.mark.parametrize("name,expected", [
    ("claude-opus-5-5", "claude-opus-5-5"),
    ("opus", "claude-opus-5-5"),
    ("claude-sonnet-5-5-20261001", "claude-sonnet-5-5"),
    ("claude-opus-5-5[1m]", "claude-opus-5-5"),
    ("CLAUDE-HAIKU-5-5", "claude-haiku-5-5"),
    ("fable", "claude-fable-5-1"),
    ("gpt-5.6-sol", "gpt-5.6-sol"),
    ("unknown-x", None),
    ("", None),
    (None, None),
])
def test_resolve_model(cfg, name, expected):
    assert costledger.resolve_model(name, cfg) == expected


def test_price_and_successor_schedule(cfg):
    opus = costledger.price("opus", cfg)
    assert (opus.in_usd, opus.out_usd, opus.cache_read, opus.cache_write_5m, opus.verified) == (4.0, 20.0, 0.2, 5.0, True)
    flash_now = costledger.price("gemini-3.8-flash", cfg, on_date="2026-10-13")
    flash_later = costledger.price("gemini-3.8-flash", cfg, on_date="2027-01-02")
    assert (flash_now.in_usd, flash_now.out_usd) == (0.75, 3.75)
    assert (flash_later.in_usd, flash_later.out_usd) == (1.5, 7.5)
    sol = costledger.price("gpt-5.6-sol", cfg)
    assert sol.verified is False and sol.cache_write_5m == 5.0 * 1.25
    assert costledger.price("nope", cfg) is None


def test_estimates(cfg):
    assert costledger.estimate_usd("claude-opus-5-5", 1_000_000, 100_000, cfg) == 6.0
    assert costledger.estimate_usd("sonnet", 0, 0, cfg, cache_read=1_000_000, cache_write=1_000_000) == 2.6
    with pytest.raises(costledger.UnknownModel):
        costledger.estimate_usd("unknown-x", 1, 1, cfg)
    tokens = costledger.estimate_tokens("x" * 400, cfg)
    assert tokens >= 100


def test_append_is_idempotent_and_fills_usd(cfg, tmp_state):
    costledger.append(month_row(cfg, id="s1:msg_1", **{"in": 1_000_000}), cfg)
    costledger.append(month_row(cfg, id="s1:msg_1", **{"in": 1_000_000}), cfg)
    rows = costledger.rows(cfg)
    assert len(rows) == 1 and rows[0]["usd"] == 4.0 and rows[0]["verified_price"] is True
    assert rows[0]["price_version"] == "2026-10-13"
    costledger.append(month_row(cfg, model="unknown-x"), cfg)
    assert costledger.rows(cfg)[-1]["usd"] is None and costledger.rows(cfg)[-1]["id"]
    assert (tmp_state / "cost" / "ledger.jsonl").exists() and (tmp_state / "cost" / "ledger.lock").exists()


def test_concurrent_appends_do_not_interleave(cfg):
    def write(n):
        costledger.append(month_row(cfg, id="id-%d" % n, usd=0.01), cfg)
    threads = [threading.Thread(target=write, args=(n,)) for n in range(25)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len({r["id"] for r in costledger.rows(cfg)}) == 25


def test_sums_and_check(cfg):
    costledger.append(month_row(cfg, usd=0.4), cfg)
    costledger.append(month_row(cfg, usd=0.45, session_id="s2", run_id="r1"), cfg)
    costledger.append(month_row(cfg, usd=0.3, ts="2001-01-01T00:00:00Z"), cfg)
    totals = costledger.sums(cfg, session_id="s1", run_id="r1")
    assert totals["session"] == 0.7 and totals["run"] == 0.45 and totals["month"] == 0.85
    assert totals["max_call"] == 0.45 and totals["corrupt_lines"] == 0 and totals["unknown_models"] == []
    assert costledger.check(cfg, session_id="s1").status == "PASS"
    costledger.append(month_row(cfg, usd=0.6, session_id="s2"), cfg)
    verdict = costledger.check(cfg, session_id="s2")
    assert verdict.status == "FAIL" and any("single call" in b for b in verdict.breaches)
    assert costledger.check(cfg, session_id="s1").status == "PASS"


def test_session_cap_breach_and_warning(cfg, monkeypatch):
    for n in range(10):
        costledger.append(month_row(cfg, id="w%d" % n, usd=0.45), cfg)
    verdict = costledger.check(cfg, session_id="s1")
    assert verdict.status == "PASS" and any("session at 90%" in w for w in verdict.warnings)
    costledger.append(month_row(cfg, id="over-1", usd=0.45), cfg)
    costledger.append(month_row(cfg, id="over-2", usd=0.45), cfg)
    verdict = costledger.check(cfg, session_id="s1")
    assert verdict.status == "FAIL" and any(b.startswith("session $5.40") for b in verdict.breaches)
    monkeypatch.setenv("OMEGA_BUDGET_PER_SESSION_USD", "50")
    assert costledger.caps(cfg)["per_session_usd"] == 50.0
    assert costledger.check(cfg, session_id="s1").status == "PASS"


def test_unknown_model_fails_closed_unless_allowed(cfg):
    costledger.append(month_row(cfg, model="unknown-x", usd=0.01), cfg)
    verdict = costledger.check(cfg)
    assert verdict.status == "UNVERIFIED" and verdict.sums["unknown_models"] == ["unknown-x"]
    assert costledger.check(cfg, allow_unknown=True).status == "PASS"


def test_corrupt_ledger_fails_closed(cfg, tmp_state):
    costledger.append(month_row(cfg, usd=0.01), cfg)
    with open(str(tmp_state / "cost" / "ledger.jsonl"), "a") as handle:
        handle.write("{not json\n")
    verdict = costledger.check(cfg)
    assert verdict.status == "UNVERIFIED" and verdict.sums["corrupt_line_numbers"] == [2]


def test_explicit_ledger_path_and_cap_overrides(cfg, tmp_path):
    path = str(tmp_path / "ci-ledger.jsonl")
    costledger.append(month_row(cfg, usd=3.0), cfg, path=path)
    assert costledger.rows(cfg) == []
    assert costledger.check(cfg, path=path).status == "FAIL"
    assert costledger.check(cfg, path=path, cap_overrides={"per_call_usd": 10.0}).status == "PASS"
    assert costledger.check(cfg, path=path, cap_overrides={"per_call_usd": 10.0, "monthly_usd": 2.0}).status == "FAIL"
    assert json.loads(Path(path).read_text().splitlines()[0])["usd"] == 3.0

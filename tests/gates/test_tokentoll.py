from __future__ import annotations

import json
from pathlib import Path

import pytest

from hooks import tokentoll_gate
from hooks.lib import costledger, state


def usage(inp, out, read=0, write=0):
    return {"input_tokens": inp, "output_tokens": out, "cache_read_input_tokens": read,
            "cache_creation_input_tokens": write}


@pytest.fixture
def ctx(workspace, make_session, transcript_writer):
    return make_session(transcript_path=transcript_writer.path)


def test_under_caps_passes_and_ingestion_is_idempotent(ctx, transcript_writer):
    transcript_writer.assistant("a", usage=usage(10000, 2000), message_id="msg_1")
    transcript_writer.assistant("b", usage=usage(5000, 1000), message_id="msg_2")
    first = tokentoll_gate.stop_check(ctx, ctx.cfg)
    assert first.status == "PASS", first.detail
    again = tokentoll_gate.stop_check(ctx, ctx.cfg)
    entry = again.data["cost"]
    assert entry["session_usd"] == pytest.approx((15000 * 4 + 3000 * 20) / 1e6)
    assert len(costledger.rows(ctx.cfg)) == 2
    assert again.detail.startswith("session $0.12 / $5.00; month $0.12 / $100.00")
    assert state.read_json(ctx.dir / "cost_cursor.json")["last_message_id"] == "msg_2"


def test_per_call_breach(ctx, transcript_writer):
    transcript_writer.assistant("big", usage=usage(50000, 20000), message_id="msg_big")
    result = tokentoll_gate.stop_check(ctx, ctx.cfg)
    assert result.status == "FAIL"
    assert "single call $0.60 exceeds cap $0.50" in result.detail


def test_per_session_breach(ctx, transcript_writer):
    for number in range(12):
        transcript_writer.assistant("m", usage=usage(20000, 20000), message_id="msg_%d" % number)
    result = tokentoll_gate.stop_check(ctx, ctx.cfg)
    assert result.status == "FAIL"
    assert "session $5.76 exceeds cap $5.00" in result.detail


def test_monthly_breach_from_other_sessions(ctx, transcript_writer):
    for number in range(3):
        costledger.append({"id": "other-%d" % number, "model": "claude-opus-5-5", "session_id": "someone-else",
                           "in": 0, "out": 0, "usd": 40.0, "source": "api"}, ctx.cfg)
    transcript_writer.assistant("small", usage=usage(100, 100), message_id="msg_small")
    result = tokentoll_gate.stop_check(ctx, ctx.cfg)
    assert result.status == "FAIL"
    assert "month $120.00 exceeds cap $100.00" in result.detail


def test_unknown_model_is_unverified(ctx, transcript_writer):
    transcript_writer.assistant("x", usage=usage(10, 10), message_id="msg_u", model="mystery-model-9")
    result = tokentoll_gate.stop_check(ctx, ctx.cfg)
    assert result.status == "UNVERIFIED"
    assert "mystery-model-9" in result.detail


def test_env_cap_override(ctx, transcript_writer, monkeypatch):
    transcript_writer.assistant("a", usage=usage(10000, 2000), message_id="msg_1")
    monkeypatch.setenv("OMEGA_BUDGET_PER_SESSION_USD", "0.05")
    assert tokentoll_gate.stop_check(ctx, ctx.cfg).status == "FAIL"


def test_codex_terminal_is_not_applicable(workspace, make_session):
    ctx = make_session(provider="codex")
    result = tokentoll_gate.stop_check(ctx, ctx.cfg)
    assert result.status == "NOT_APPLICABLE"
    assert result.detail == "codex: usage is recorded by the UI runner from turn.completed"


def run_cli(args, capsys):
    code = tokentoll_gate.main(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_record_check_exit_codes(workspace, capsys, tmp_state):
    code, _, _ = run_cli(["record", "--model", "claude-opus-5-5", "--in", "2000000", "--out", "500000",
                          "--session", "S"], capsys)
    assert code == 0
    code, out, _ = run_cli(["check", "--session", "S", "--json"], capsys)
    body = json.loads(out)
    assert code == 1 and body["status"] == "FAIL"
    assert any("session $18.00 exceeds cap $5.00" in b for b in body["breaches"])
    code, _, _ = run_cli(["check", "--session", "S", "--per-session", "100", "--per-call", "100"], capsys)
    assert code == 0
    run_cli(["record", "--model", "unknown-x", "--in", "1", "--out", "1", "--session", "T"], capsys)
    code, _, _ = run_cli(["check", "--session", "T"], capsys)
    assert code == 3
    code, _, _ = run_cli(["check", "--session", "T", "--allow-unknown"], capsys)
    assert code == 0
    ledger_file = tmp_state / "cost" / "ledger.jsonl"
    with open(str(ledger_file), "a", encoding="utf-8") as handle:
        handle.write("{not json\n")
    code, _, err = run_cli(["check", "--session", "S"], capsys)
    assert code == 2


def test_cli_check_explicit_ledger(tmp_path, capsys):
    ledger_file = tmp_path / "ci-ledger.jsonl"
    ledger_file.write_text(json.dumps({"id": "a", "ts": "2026-10-01T00:00:00Z", "model": "claude-haiku-5-5",
                                       "in": 1000, "out": 1000, "usd": 0.001}) + "\n", encoding="utf-8")
    code, out, _ = run_cli(["check", "--ledger", str(ledger_file), "--month", "2026-10", "--json"], capsys)
    assert code == 0 and json.loads(out)["month_usd"] == pytest.approx(0.001)
    code, _, _ = run_cli(["check", "--ledger", str(tmp_path)], capsys)
    assert code == 2


def test_cli_estimate_and_report(capsys, tmp_path):
    code, out, _ = run_cli(["estimate", "--model", "sonnet", "--input-text", "x" * 400, "--max-tokens", "1000",
                            "--json"], capsys)
    body = json.loads(out)
    assert code == 0 and body["model"] == "claude-sonnet-5-5"
    assert body["worst_case_usd"] == pytest.approx((body["in_tokens"] * 2 + 1000 * 10) / 1e6)
    code, _, _ = run_cli(["estimate", "--model", "nope", "--input-text", "x"], capsys)
    assert code == 3
    run_cli(["record", "--model", "claude-haiku-5-5", "--in", "1000", "--out", "1000", "--session", "R"], capsys)
    code, out, _ = run_cli(["report", "--json"], capsys)
    assert code == 0 and "claude-haiku-5-5" in json.loads(out)["by_model"]


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_static_scan(tmp_path, capsys):
    app = tmp_path / "app"
    write(app, "svc/classify.py", 'import anthropic\nclient = anthropic.Anthropic()\n\ndef go(x):\n'
                                  '    return client.messages.create(\n        model="claude-haiku-5-5",\n'
                                  '        max_tokens=200,\n        messages=[{"role": "user", "content": x}],\n    )\n')
    write(app, "node_modules/pkg/index.js", "client.messages.create({model: 'unknown'})\n")
    code, out, _ = run_cli(["scan", "--path", str(app), "--json"], capsys)
    body = json.loads(out)
    assert code == 0 and body["status"] == "PASS"
    assert len(body["sites"]) == 1 and body["sites"][0]["model"] == "claude-haiku-5-5"
    expected = 10000 * (50 * 0.10 + 200 * 0.50) / 1e6
    assert body["total_monthly_usd"] == pytest.approx(expected, rel=1e-3)
    code, out, _ = run_cli(["scan", "--path", str(app), "--calls-per-month", "100000000", "--json"], capsys)
    assert code == 1 and json.loads(out)["status"] == "FAIL"
    write(app, "svc/other.ts", "const r = await openai.chat.completions.create({ model: modelName, messages })\n")
    code, out, _ = run_cli(["scan", "--path", str(app), "--json"], capsys)
    assert code == 3 and "<unresolved>" in json.loads(out)["unknown_models"]

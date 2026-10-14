from __future__ import annotations

import json
import os
import stat
import threading

import pytest

from hooks.lib import event as ev
from hooks.lib import io as hio
from hooks.lib import paths, state


def test_configure_builds_session_dir_and_records_evidence(workspace, tmp_state, claude_payload):
    event = ev.normalize(claude_payload("SessionStart", transcript_path="/t/s.jsonl"), "claude")
    ctx = state.configure(event)
    expected = tmp_state / paths.workspace_hash(str(workspace)) / "claude" / "sess-claude-0001"
    assert ctx.dir == expected and expected.is_dir()
    assert ctx.workspace == str(workspace) and ctx.cfg.get("tdd.debounce_s") == 0.05
    assert hio.bound_session_dir() == expected
    observed = json.loads((tmp_state / "observed" / "claude.json").read_text())
    assert "SessionStart" in observed
    context = json.loads((expected / "context.json").read_text())
    assert context["transcript_path"] == "/t/s.jsonl" and context["model"] == "claude-opus-5-5"
    assert set(context) == {"provider", "workspace", "session_id", "transcript_path", "run_id", "created_ts", "model"}


def test_configure_keeps_context_but_fills_missing_transcript(workspace, claude_payload):
    first = state.configure(ev.normalize(claude_payload("SessionStart"), "claude"))
    assert first.transcript_path is None
    state.configure(ev.normalize(claude_payload("Stop", transcript_path="/t/later.jsonl"), "claude"))
    third = state.configure(ev.normalize(claude_payload("PreToolUse"), "claude"))
    assert third.transcript_path == "/t/later.jsonl"


@pytest.mark.parametrize("sid", ["../../etc", "..", ".", "a/b", "", "x\x00y"])
def test_session_id_cannot_escape_the_state_root(workspace, tmp_state, claude_payload, sid):
    ctx = state.configure(ev.normalize(claude_payload("SessionStart", session_id=sid), "claude"))
    assert str(ctx.dir).startswith(str(tmp_state) + os.sep)
    assert ctx.dir.parent.name == "claude"


def test_load_context_by_id_and_latest(workspace, claude_payload, codex_payload, monkeypatch):
    ctx = state.configure(ev.normalize(claude_payload("SessionStart"), "claude"))
    with pytest.raises(state.AmbiguousSession):
        state.latest_session(str(workspace))
    (ctx.dir / "changed.jsonl").write_text("")
    assert state.latest_session(str(workspace)) == "sess-claude-0001"
    loaded = state.load_context(None, str(workspace))
    assert loaded.provider == "claude" and loaded.dir == ctx.dir
    other = state.configure(ev.normalize(codex_payload("SessionStart"), "codex"))
    (other.dir / "changed.jsonl").write_text("")
    with pytest.raises(state.AmbiguousSession) as info:
        state.latest_session(str(workspace))
    assert len(info.value.candidates) == 2
    assert state.latest_session(str(workspace), "codex") == other.session_id
    assert state.load_context(other.session_id, str(workspace)).provider == "codex"
    monkeypatch.setenv("OMEGA_SESSION_ID", "sess-claude-0001")
    assert state.load_context(None, str(workspace)).provider == "claude"


def test_load_context_same_id_under_two_providers_needs_disambiguation(workspace, claude_payload, codex_payload, monkeypatch):
    state.configure(ev.normalize(claude_payload("SessionStart", session_id="dup"), "claude"))
    state.configure(ev.normalize(codex_payload("SessionStart", session_id="dup"), "codex"))
    with pytest.raises(state.AmbiguousSession):
        state.load_context("dup", str(workspace))
    monkeypatch.setenv("OMEGA_PROVIDER", "codex")
    assert state.load_context("dup", str(workspace)).provider == "codex"


def test_atomic_json_and_jsonl(tmp_path):
    target = tmp_path / "deep" / "x.json"
    state.write_json_atomic(target, {"a": 1})
    assert state.read_json(target) == {"a": 1}
    assert not [p for p in target.parent.iterdir() if p.name.startswith(".")]
    assert state.read_json(tmp_path / "missing", {"d": 1}) == {"d": 1}
    (tmp_path / "bad.json").write_text("{")
    assert state.read_json(tmp_path / "bad.json") is None
    rows = tmp_path / "rows.jsonl"
    state.append_jsonl(rows, {"n": 1})
    state.append_jsonl(rows, {"n": 2})
    with open(str(rows), "a") as handle:
        handle.write("garbage\n")
    assert state.read_jsonl(rows) == [{"n": 1}, {"n": 2}]


def test_counters_are_atomic(session):
    assert state.counter_get(session, "stop_attempts") == 0
    threads = [threading.Thread(target=state.counter_incr, args=(session, "stop_attempts")) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert state.counter_get(session, "stop_attempts") == 20
    state.counter_reset(session, "stop_attempts")
    assert state.counter_get(session, "stop_attempts") == 0
    (session.dir / "stop_attempts").write_text("junk")
    assert state.counter_get(session, "stop_attempts") == 0
    assert state.counter_incr(session, "stop_attempts") == 1


def test_override_token_is_stable_private_and_well_formed(session):
    token = state.ensure_override_token(session)
    assert state.TOKEN_PATTERN.match(token)
    assert state.ensure_override_token(session) == token
    mode = stat.S_IMODE(os.stat(str(session.dir / "override_token")).st_mode)
    assert mode == 0o600
    (session.dir / "override_token").write_text("forged")
    replaced = state.ensure_override_token(session)
    assert replaced != "forged" and state.TOKEN_PATTERN.match(replaced)


def test_stamp_and_iso_format():
    ts, ts_ns = state.stamp()
    assert len(ts) == 20 and ts.endswith("Z") and ts_ns > 0
    assert state.iso(0) == "1970-01-01T00:00:00Z"

from __future__ import annotations

import io as stdio
import json

import pytest

from hooks.lib import io as hio

GITHUB = "ghp_" + "Ab3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zC1234"


def render(provider, event, **kwargs):
    return hio.render(provider, event, hio.Decision(**kwargs))


def test_claude_pretooluse_matrix():
    assert render("claude", "PreToolUse", action="allow") == ("", "", 0)
    out, err, code = render("claude", "PreToolUse", action="allow", context="note")
    assert code == 0 and json.loads(out) == {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                                    "permissionDecision": "allow",
                                                                    "additionalContext": "note"}}
    assert render("claude", "PreToolUse", action="deny", reason="no") == ("", "no", 2)


def test_codex_pretooluse_matrix():
    assert render("codex", "PreToolUse", action="allow") == ("{}", "", 0)
    out, err, code = render("codex", "PreToolUse", action="deny", reason="blocked x")
    assert code == 0 and err == ""
    assert json.loads(out) == {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                      "permissionDecision": "deny",
                                                      "permissionDecisionReason": "blocked x"}}
    out, _, _ = render("codex", "PreToolUse", action="allow", context="ctx")
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_posttooluse_matrix():
    assert render("claude", "PostToolUse", action="allow", context="[tests] PASS") == ("[tests] PASS", "", 0)
    assert render("claude", "PostToolUse", action="feedback", reason="[tests] FAIL") == ("", "[tests] FAIL", 2)
    assert render("claude", "PostToolUseFailure", action="feedback", reason="x") == ("", "x", 2)
    assert render("codex", "PostToolUse", action="allow") == ("{}", "", 0)
    out, _, code = render("codex", "PostToolUse", action="allow", context="pass")
    assert code == 0 and json.loads(out) == {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                                    "additionalContext": "pass"}}
    out, _, code = render("codex", "PostToolUse", action="feedback", reason="fail")
    assert code == 0 and json.loads(out) == {"decision": "block", "reason": "fail"}


def test_stop_matrix():
    assert render("claude", "Stop", action="allow", context="summary") == ("summary", "", 0)
    assert render("claude", "Stop", action="block", reason="blocked") == ("", "blocked", 2)
    assert render("claude", "SubagentStop", action="block", reason="b") == ("", "b", 2)
    assert render("codex", "Stop", action="allow", context="summary") == ("{}", "", 0)
    out, _, code = render("codex", "Stop", action="block", reason="blocked")
    assert code == 0 and json.loads(out) == {"decision": "block", "reason": "blocked"}


def test_session_start_matrix_never_blocks():
    assert render("claude", "SessionStart", action="allow", context="hello") == ("hello", "", 0)
    out, _, code = render("codex", "SessionStart", action="allow", context="hello")
    assert code == 0 and json.loads(out) == {"hookSpecificOutput": {"hookEventName": "SessionStart",
                                                                    "additionalContext": "hello"}}
    assert render("claude", "SessionStart", action="block", reason="x")[2] == 0
    assert render("codex", "SessionStart", action="allow") == ("{}", "", 0)


def test_codex_block_always_has_a_reason():
    out, _, _ = render("codex", "Stop", action="block")
    assert json.loads(out)["reason"] == hio.UNSTATED
    assert render("claude", "PreToolUse", action="deny")[1] == hio.UNSTATED


def test_never_emits_ask_defer_or_continue():
    for provider in ("claude", "codex"):
        for event in ("PreToolUse", "PostToolUse", "Stop", "SessionStart"):
            for action in hio.ACTIONS:
                out, err, _ = render(provider, event, action=action, reason="r", context="c")
                for forbidden in ('"ask"', '"defer"', '"continue"', "suppressOutput"):
                    assert forbidden not in out


def test_emit_redacts_reason_and_context(capsys):
    code = hio.emit("claude", "PreToolUse", hio.Decision("deny", reason="token " + GITHUB))
    captured = capsys.readouterr()
    assert code == 2 and GITHUB not in captured.err and "[REDACTED:github-token]" in captured.err
    hio.emit("codex", "PostToolUse", hio.Decision("allow", context="mail bob@gmail.com"))
    assert "bob@gmail.com" not in capsys.readouterr().out


@pytest.mark.parametrize("raw", ["", "   \n", "not json", "[1,2]", "42", '"str"'])
def test_read_payload_rejects_non_objects(raw):
    with pytest.raises(hio.PayloadError):
        hio.read_payload(stdio.StringIO(raw))


def test_read_payload_accepts_object():
    assert hio.read_payload(stdio.StringIO('{"a": 1}')) == {"a": 1}


def test_fail_closed_on_guards_and_stop(capsys, tmp_path):
    hio.bind_session_dir(tmp_path)
    code = hio.fail_closed("claude", "PreToolUse", RuntimeError("boom " + GITHUB), "bin/pre_tool_use.py")
    captured = capsys.readouterr()
    assert code == 2
    body = json.loads(captured.out)
    reason = body["hookSpecificOutput"]["permissionDecisionReason"]
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert reason.startswith("[omega] bin/pre_tool_use.py failed closed: RuntimeError: boom")
    assert GITHUB not in reason and str(tmp_path / "hooks.log") in reason
    assert reason in captured.err
    code = hio.fail_closed("codex", "Stop", ValueError("x"), "bin/stop_orchestrator.py")
    captured = capsys.readouterr()
    assert code == 2 and json.loads(captured.out)["decision"] == "block"


def test_fail_closed_on_advisory_events_warns_and_exits_zero(capsys):
    for event in ("PostToolUse", "SessionStart"):
        assert hio.fail_closed("claude", event, KeyError("k"), "bin/x.py") == 0
        captured = capsys.readouterr()
        assert captured.out == "" and "failed closed" in captured.err


def test_debug_writes_only_when_enabled(tmp_path, monkeypatch):
    hio.bind_session_dir(tmp_path)
    hio.debug("quiet")
    assert not (tmp_path / "hooks.log").exists()
    monkeypatch.setenv("OMEGA_DEBUG", "1")
    hio.debug("loud " + GITHUB)
    text = (tmp_path / "hooks.log").read_text()
    assert "loud [REDACTED:github-token]" in text

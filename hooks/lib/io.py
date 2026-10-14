from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import redaction

ALLOW = "allow"
DENY = "deny"
BLOCK = "block"
FEEDBACK = "feedback"
ACTIONS = (ALLOW, DENY, BLOCK, FEEDBACK)
FAILING = (DENY, BLOCK, FEEDBACK)
CONTEXT_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionStart",
                  "UserPromptSubmit", "SubagentStart", "PermissionRequest")
BLOCK_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit", "Stop",
                "SubagentStop")
FAIL_CLOSED_EVENTS = ("PreToolUse", "Stop", "SubagentStop")
UNSTATED = "[omega] blocked without a stated reason"
MAX_STDIN_BYTES = 16 * 1024 * 1024

_session_dir: Optional[Path] = None


class PayloadError(ValueError):
    pass


@dataclass
class Decision:
    action: str
    reason: str = ""
    context: str = ""
    system_message: str = ""

    @property
    def failing(self) -> bool:
        return self.action in FAILING


def bind_session_dir(path) -> None:
    global _session_dir
    _session_dir = Path(path) if path else None


def bound_session_dir() -> Optional[Path]:
    return _session_dir


def read_payload(stream=None) -> dict:
    source = stream if stream is not None else sys.stdin
    try:
        raw = source.read(MAX_STDIN_BYTES + 1)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PayloadError("stdin is unreadable: %s" % exc.__class__.__name__)
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if raw is None or not raw.strip():
        raise PayloadError("stdin is empty: expected one JSON object")
    if len(raw) > MAX_STDIN_BYTES:
        raise PayloadError("stdin is larger than %d bytes" % MAX_STDIN_BYTES)
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise PayloadError("stdin is not JSON: %s" % exc)
    if not isinstance(payload, dict):
        raise PayloadError("stdin is JSON but not an object")
    return payload


def _clean(text: str) -> str:
    if not text:
        return ""
    return redaction.redact(str(text))[0]


def _dump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)


def _write(stream, text: str) -> None:
    if not text:
        return
    stream.write(text if text.endswith("\n") else text + "\n")
    stream.flush()


def render(provider: str, event_name: str, decision: Decision) -> tuple:
    reason = _clean(decision.reason)
    context = _clean(decision.context)
    system_message = _clean(decision.system_message)
    failing = decision.action in FAILING
    codex = provider == "codex"
    if event_name == "SessionStart":
        text = context or (reason if failing else "")
        if codex:
            if text:
                return _dump({"hookSpecificOutput": {"hookEventName": "SessionStart",
                                                     "additionalContext": text}}), "", 0
            return "{}", "", 0
        return text, "", 0
    if failing:
        reason = reason or UNSTATED
        if codex:
            if event_name == "PreToolUse":
                return _dump({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                     "permissionDecision": "deny",
                                                     "permissionDecisionReason": reason}}), "", 0
            if event_name in BLOCK_EVENTS:
                return _dump({"decision": "block", "reason": reason}), "", 0
            return _dump({"systemMessage": reason}), "", 0
        return "", reason, 2
    if codex:
        if event_name in ("Stop", "SubagentStop"):
            return "{}", "", 0
        if context and event_name in CONTEXT_EVENTS:
            out = {"hookSpecificOutput": {"hookEventName": event_name, "additionalContext": context}}
            if event_name == "PreToolUse":
                out["hookSpecificOutput"]["permissionDecision"] = "allow"
            return _dump(out), "", 0
        if system_message:
            return _dump({"systemMessage": system_message}), "", 0
        return "{}", "", 0
    if event_name == "PreToolUse":
        if context:
            return _dump({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                 "permissionDecision": "allow",
                                                 "additionalContext": context}}), "", 0
        return "", "", 0
    return context, "", 0


def emit(provider: str, event_name: str, decision: Decision) -> int:
    stdout_text, stderr_text, code = render(provider, event_name, decision)
    _write(sys.stdout, stdout_text)
    _write(sys.stderr, stderr_text)
    return code


def _log_hint() -> str:
    if _session_dir is not None:
        return str(_session_dir / "hooks.log")
    return "<session_dir>/hooks.log"


def failure_reason(exc: BaseException, script: str) -> str:
    message = str(exc).replace("\n", " ")[:200]
    return ("[omega] %s failed closed: %s: %s — fix the harness or set OMEGA_DEBUG=1 and read %s"
            % (script, exc.__class__.__name__, message, _log_hint()))


def fail_closed(provider: str, event: str, exc: BaseException, script: str) -> int:
    reason = _clean(failure_reason(exc, script))
    debug(reason)
    if event in FAIL_CLOSED_EVENTS:
        if event == "PreToolUse":
            body = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                           "permissionDecision": "deny",
                                           "permissionDecisionReason": reason}}
        else:
            body = {"decision": "block", "reason": reason}
        _write(sys.stdout, _dump(body))
        _write(sys.stderr, reason)
        return 2
    _write(sys.stderr, reason)
    return 0


def debug(msg: str) -> None:
    if os.environ.get("OMEGA_DEBUG", "") != "1":
        return
    target = _session_dir
    if target is None:
        return
    try:
        target.mkdir(parents=True, exist_ok=True)
        line = "%s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), _clean(str(msg)))
        with open(str(target / "hooks.log"), "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass

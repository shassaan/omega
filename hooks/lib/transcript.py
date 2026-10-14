from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

HUMAN_PROMPT_SOURCES = ("typed", "suggestion_accepted", "queued")
SDK_HUMAN_ENTRYPOINTS = ("claude-vscode", "claude-desktop")
CODEX_HUMAN_SOURCES = ("user", "typed", "queued", "suggestion_accepted")
UI_KINDS = ("prompt", "approval", "override", "ship")
SYNTH = re.compile(r"^\s*<(local-command-stdout|local-command-caveat|bash-stdout|bash-stderr|bash-input|task-notification|system-reminder|command-name|command-message|command-args|agent-message)\b")
REFUSAL = re.compile(r"(?<![\w'])(no|nope|nah|don'?t|do not|doesn'?t|not yet|not now|reject(?:ed)?|hold off|wait|stop|cancel|decline|disagree|never)(?![\w'])", re.IGNORECASE)
MIN_QUOTE_CHARS = 8
FORBIDDEN_KEYS = ("toolUseResult", "sourceToolUseID", "sourceToolAssistantUUID")
FALSY_FLAGS = ("isSidechain", "isMeta", "isCompactSummary", "isVisibleInTranscriptOnly")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass
class Turn:
    text: str
    ts: Optional[datetime]
    ts_ns: Optional[int]
    source: str
    uuid: str
    provider: str
    channel: str


def parse_time(value) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    match = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(.*)$", text)
    if match and match.group(2):
        text = match.group(1) + "." + (match.group(2) + "000000")[:6] + match.group(3)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def to_ns(moment: Optional[datetime]) -> Optional[int]:
    if moment is None:
        return None
    delta = moment - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def from_ns(ts_ns: Optional[int]) -> Optional[datetime]:
    if ts_ns is None:
        return None
    return datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc)


def _records(lines):
    for line in lines or []:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        if not isinstance(line, str):
            continue
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            yield record


def _claude_text(message) -> Optional[str]:
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list = []
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_result":
                return None
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return "\n".join(p for p in parts if p)
    return None


def _origin_kind(record: dict) -> Optional[str]:
    origin = record.get("origin")
    if isinstance(origin, dict):
        kind = origin.get("kind")
        return kind if isinstance(kind, str) else None
    return None


def _positive_evidence(record: dict, accept_unlabelled: bool) -> bool:
    source = record.get("promptSource")
    kind = _origin_kind(record)
    if source in HUMAN_PROMPT_SOURCES:
        return True
    if kind == "human" and source not in ("sdk", "system"):
        return True
    if source == "sdk" and kind == "human" and record.get("entrypoint") in SDK_HUMAN_ENTRYPOINTS:
        return True
    if accept_unlabelled and source is None and "origin" not in record:
        return True
    return False


def is_human_record(record: dict, accept_unlabelled: bool = False) -> bool:
    if not isinstance(record, dict) or record.get("type") != "user":
        return False
    if any(record.get(flag) for flag in FALSY_FLAGS):
        return False
    if any(key in record for key in FORBIDDEN_KEYS):
        return False
    text = _claude_text(record.get("message"))
    if text is None or not text.strip():
        return False
    if text.lstrip().startswith("[Request interrupted"):
        return False
    if SYNTH.match(text):
        return False
    return _positive_evidence(record, accept_unlabelled)


def parse_claude(lines, accept_unlabelled: bool = False) -> list:
    turns: list = []
    for record in _records(lines):
        if not is_human_record(record, accept_unlabelled):
            continue
        moment = parse_time(record.get("timestamp"))
        turns.append(Turn(
            text=_claude_text(record.get("message")) or "",
            ts=moment,
            ts_ns=to_ns(moment),
            source=str(record.get("promptSource") or _origin_kind(record) or "unlabelled"),
            uuid=str(record.get("uuid") or ""),
            provider="claude",
            channel="transcript",
        ))
    return turns


def parse_codex(lines) -> list:
    turns: list = []
    for record in _records(lines):
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue
        kind = record.get("type")
        if kind == "response_item":
            metadata = payload.get("internal_chat_message_metadata_passthrough")
            kinds = metadata.get("content_item_kinds") if isinstance(metadata, dict) else None
            content = payload.get("content")
            if not (payload.get("type") == "message" and payload.get("role") == "user"
                    and isinstance(kinds, list) and "user.text" in kinds and isinstance(content, list)):
                continue
            text = "\n".join(item.get("text", "") for item in content
                             if isinstance(item, dict) and item.get("type") == "input_text"
                             and isinstance(item.get("text"), str))
            if not text.strip():
                continue
            moment = parse_time(record.get("timestamp"))
            turns.append(Turn(text, moment, to_ns(moment), "user",
                              str(payload.get("id") or record.get("id") or ""), "codex", "transcript"))
            continue
        if kind != "event_msg" or payload.get("type") != "user_message":
            continue
        if payload.get("is_automatic") or payload.get("isMeta"):
            continue
        source = str(payload.get("source") or "user")
        if source not in CODEX_HUMAN_SOURCES:
            continue
        text = payload.get("message") if payload.get("message") is not None else payload.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        moment = parse_time(record.get("timestamp") or payload.get("timestamp"))
        turns.append(Turn(text, moment, to_ns(moment), source,
                          str(payload.get("id") or record.get("id") or record.get("uuid") or ""),
                          "codex", "transcript"))
    return turns


def parse_ui_log(lines) -> list:
    turns: list = []
    for row in _records(lines):
        if row.get("kind") not in UI_KINDS:
            continue
        text = row.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        raw_ns = row.get("ts_ns")
        ts_ns = raw_ns if isinstance(raw_ns, int) and not isinstance(raw_ns, bool) else None
        moment = from_ns(ts_ns) if ts_ns is not None else parse_time(row.get("ts"))
        if ts_ns is None:
            ts_ns = to_ns(moment)
        turns.append(Turn(text, moment, ts_ns, "ui", str(row.get("uuid") or ""), "ui", "ui"))
    return turns


def _read_lines(path: Optional[str]) -> Optional[list]:
    if not path or not isinstance(path, str):
        return None
    expanded = os.path.expanduser(path)
    if not os.path.isfile(expanded):
        return None
    try:
        with open(expanded, "r", encoding="utf-8", errors="replace") as handle:
            return handle.readlines()
    except OSError:
        return None


def channel_of(ctx=None) -> str:
    return "ui" if os.environ.get("OMEGA_HUMAN_LOG") else "transcript"


def read_human_turns(ctx) -> list:
    human_log = os.environ.get("OMEGA_HUMAN_LOG")
    if human_log:
        lines = _read_lines(human_log)
        return parse_ui_log(lines) if lines is not None else []
    lines = _read_lines(getattr(ctx, "transcript_path", None))
    if lines is None:
        return []
    if getattr(ctx, "provider", "claude") == "codex":
        return parse_codex(lines)
    cfg = getattr(ctx, "cfg", None)
    accept = bool(cfg.get("transcript.accept_unlabelled_user_turns", False)) if cfg is not None else False
    return parse_claude(lines, accept_unlabelled=accept)


def turns_after(turns: list, ts_ns: Optional[int]) -> list:
    if ts_ns is None:
        return list(turns)
    return [t for t in turns if t.ts_ns is not None and t.ts_ns > ts_ns]


def normalise(text: str) -> str:
    return " ".join(str(text or "").split()).casefold()


def quoted_turn(turns: list, quote: str) -> Optional[Turn]:
    needle = normalise(quote)
    if not needle:
        return None
    for turn in turns:
        if needle in normalise(turn.text):
            return turn
    return None


def quoted_whole_words(turns: list, quote: str) -> Optional[Turn]:
    needle = normalise(quote)
    if not needle:
        return None
    pattern = re.compile(r"(?<!\w)" + re.escape(needle) + r"(?!\w)")
    for turn in turns:
        if pattern.search(normalise(turn.text)):
            return turn
    return None


def last_human_turn(turns: list) -> Optional[Turn]:
    return turns[-1] if turns else None


def verify_human_answer(turns: list, asked_at_ns: Optional[int], quote: str,
                        min_chars: int = MIN_QUOTE_CHARS) -> tuple:
    if not quote or not quote.strip():
        return False, ("no --quote was given. Quote the words the human actually used to agree, "
                       "so the sign-off records their answer and not your reading of it")
    if not turns:
        return False, ("this session's transcript shows no human turn at all, so their answer "
                       "cannot be confirmed")
    later = turns_after(turns, asked_at_ns)
    if not later:
        return False, ("the human has not spoken since you proposed the contract — you are "
                       "recording an answer they have not given yet")
    match = quoted_whole_words(later, quote)
    if match is None:
        return False, ("no human turn since the proposal contains %r — quote what they actually "
                       "wrote, verbatim" % quote.strip()[:60])
    refusal = REFUSAL.search(match.text)
    if refusal:
        return False, ("their reply contains %r, which reads as a refusal or a condition — ask "
                       "again and record an unambiguous yes" % refusal.group(0))
    whole = normalise(match.text).strip(" .!")
    needle = normalise(quote).strip(" .!")
    if needle != whole and len(needle) < min_chars:
        return False, ("%r is too short to carry a yes on its own — quote the whole sentence they "
                       "agreed with" % quote.strip())
    return True, "the human answered in their own words after the proposal"


def matching_turn(turns: list, asked_at_ns: Optional[int], quote: str) -> Optional[Turn]:
    return quoted_whole_words(turns_after(turns, asked_at_ns), quote)


def _usage_int(usage: dict, key: str) -> int:
    value = usage.get(key)
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    return 0


def assistant_usage(ctx) -> list:
    if getattr(ctx, "provider", "claude") == "codex":
        return []
    lines = _read_lines(getattr(ctx, "transcript_path", None))
    if lines is None:
        return []
    by_id: dict = {}
    order: list = []
    for record in _records(lines):
        if record.get("type") != "assistant":
            continue
        message = record.get("message")
        if not isinstance(message, dict):
            continue
        message_id = message.get("id")
        usage = message.get("usage")
        if not isinstance(message_id, str) or not message_id or not isinstance(usage, dict):
            continue
        moment = parse_time(record.get("timestamp"))
        row = {
            "message_id": message_id,
            "model": message.get("model"),
            "in": _usage_int(usage, "input_tokens"),
            "out": _usage_int(usage, "output_tokens"),
            "cache_read": _usage_int(usage, "cache_read_input_tokens"),
            "cache_write": _usage_int(usage, "cache_creation_input_tokens"),
            "ts_ns": to_ns(moment),
            "uuid": record.get("uuid"),
        }
        if message_id not in by_id:
            order.append(message_id)
        by_id[message_id] = row
    return [by_id[m] for m in order]

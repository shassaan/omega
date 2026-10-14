import json, re
SYNTH = re.compile(r"^\s*<(local-command-stdout|local-command-caveat|bash-stdout|bash-stderr|task-notification|system-reminder|command-name|command-message|agent-message)\b")
def is_human_prompt(e: dict) -> bool:
    if e.get("type") != "user" or e.get("isSidechain"): return False
    if e.get("isMeta") or e.get("isCompactSummary") or e.get("isVisibleInTranscriptOnly"): return False
    if e.get("toolUseResult") is not None or e.get("sourceToolUseID") or e.get("sourceToolAssistantUUID"): return False
    origin = e.get("origin")
    if isinstance(origin, dict) and origin.get("kind") not in (None, "human"): return False
    c = (e.get("message") or {}).get("content")
    if isinstance(c, list):
        if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in c): return False
        c = "".join(b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text")
    if not isinstance(c, str) or not c.strip(): return False
    if c.startswith("[Request interrupted"): return False
    if SYNTH.match(c) : return False      # slash-command line itself is classified separately below
    return True
def slash_command(e):                     # human-typed command (not a prompt)
    c = (e.get("message") or {}).get("content")
    m = isinstance(c, str) and re.search(r"<command-name>(/[^<]+)</command-name>", c)
    return m.group(1) if m else None

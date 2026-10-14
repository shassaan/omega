from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Optional

from . import paths

EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit", "apply_patch")
PATCH_MARKER = "*** Begin Patch"
KINDS = ("added", "modified", "deleted", "renamed_from", "renamed_to", "unknown")
PROVIDERS = ("claude", "codex")

_PATCH_HEADER = re.compile(r"^\*\*\*\s+(Add File|Update File|Delete File|Move to):\s*(.*?)\s*$")
_PATCH_KIND = {"Add File": "added", "Update File": "modified", "Delete File": "deleted",
               "Move to": "renamed_to"}


@dataclass
class Mutation:
    path: str
    kind: str


@dataclass
class Event:
    provider: str
    name: str
    session_id: str
    transcript_path: Optional[str]
    cwd: str
    workspace: str
    tool_name: Optional[str]
    tool_input: dict
    tool_response: Optional[dict]
    tool_use_id: Optional[str]
    command: Optional[str]
    is_patch: bool
    mutations: list
    unparsed_mutation: Optional[str]
    stop_hook_active: bool
    last_assistant_message: Optional[str]
    source: Optional[str]
    prompt: Optional[str]
    permission_mode: Optional[str]
    model: Optional[str]
    run_id: Optional[str]
    raw: dict = field(default_factory=dict)


def _str(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def provider_of(payload: dict, explicit: Optional[str] = None) -> str:
    if explicit in PROVIDERS:
        return explicit
    env = os.environ.get("OMEGA_PROVIDER")
    if env in PROVIDERS:
        return env
    payload = payload if isinstance(payload, dict) else {}
    if payload.get("tool_name") == "apply_patch":
        return "codex"
    transcript = payload.get("transcript_path")
    if isinstance(transcript, str) and ("/.codex/" in transcript or "rollout" in transcript):
        return "codex"
    return "claude"


def is_edit_tool(tool_name: Optional[str]) -> bool:
    return tool_name in EDIT_TOOLS


def _command_text(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
        patch = [v for v in value if PATCH_MARKER in v]
        if patch:
            return "\n".join(patch)
        return shlex.join(list(value))
    return str(value)


def _tool_input(payload: dict) -> dict:
    value = payload.get("tool_input")
    return value if isinstance(value, dict) else {}


def patch_text(payload: dict) -> Optional[str]:
    tool_input = _tool_input(payload)
    for key in ("command", "patch", "input"):
        text = _command_text(tool_input.get(key))
        if text:
            return text
    raw = payload.get("tool_input")
    if isinstance(raw, str):
        return raw
    return None


def _resolve(path: str, cwd: str) -> str:
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        expanded = os.path.join(cwd, expanded)
    return os.path.abspath(expanded)


def parse_apply_patch(text: str, cwd: str) -> list:
    found: list = []
    seen: set = set()
    last: Optional[Mutation] = None
    for line in (text or "").splitlines():
        m = _PATCH_HEADER.match(line.strip())
        if not m:
            continue
        label, raw_path = m.group(1), m.group(2).strip().strip("\"'")
        if not raw_path:
            continue
        mutation = Mutation(_resolve(raw_path, cwd), _PATCH_KIND[label])
        if label == "Move to":
            if last is not None and last.kind == "modified":
                seen.discard((last.path, last.kind))
                last.kind = "renamed_from"
                seen.add((last.path, last.kind))
            elif last is None:
                continue
        key = (mutation.path, mutation.kind)
        if key in seen:
            last = next((f for f in found if (f.path, f.kind) == key), mutation)
            continue
        seen.add(key)
        found.append(mutation)
        last = mutation
    return found


def _write_kind(payload: dict, path: str) -> str:
    response = payload.get("tool_response")
    if payload.get("hook_event_name") in ("PostToolUse", "PostToolUseFailure") and isinstance(response, dict):
        kind = response.get("type")
        if kind == "create":
            return "added"
        if kind == "update":
            return "modified"
    return "modified" if os.path.exists(path) else "added"


def mutations_of(payload: dict) -> tuple:
    payload = payload if isinstance(payload, dict) else {}
    tool = payload.get("tool_name")
    tool_input = _tool_input(payload)
    cwd = _str(payload.get("cwd")) or paths.workspace_of(payload)
    if tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        candidates: list = []
        if tool == "NotebookEdit":
            candidates.append(tool_input.get("notebook_path") or tool_input.get("file_path"))
        else:
            candidates.append(tool_input.get("file_path"))
        if tool == "MultiEdit":
            for edit in tool_input.get("edits") or []:
                if isinstance(edit, dict) and edit.get("file_path"):
                    candidates.append(edit.get("file_path"))
        found: list = []
        seen: set = set()
        for raw in candidates:
            if not isinstance(raw, str) or not raw.strip():
                continue
            path = _resolve(raw.strip(), cwd)
            if path in seen:
                continue
            seen.add(path)
            kind = _write_kind(payload, path) if tool == "Write" else "modified"
            found.append(Mutation(path, kind))
        if not found:
            return [], "%s payload has no file path" % tool
        return found, None
    text = None
    if tool == "apply_patch":
        text = patch_text(payload)
    elif tool == "Bash":
        command = _command_text(tool_input.get("command"))
        if command and PATCH_MARKER in command:
            text = command
    if tool == "apply_patch" or text is not None:
        mutations = parse_apply_patch(text or "", cwd)
        if not mutations:
            return [], "%s payload has no parseable file path" % (tool or "patch")
        return mutations, None
    return [], None


def normalize(payload: dict, provider: Optional[str] = None) -> Event:
    if not isinstance(payload, dict):
        raise ValueError("hook payload is not a JSON object")
    resolved_provider = provider_of(payload, provider)
    tool = _str(payload.get("tool_name"))
    tool_input = _tool_input(payload)
    workspace = paths.workspace_of(payload)
    cwd = _str(payload.get("cwd")) or workspace
    command: Optional[str] = None
    is_patch = False
    if tool == "apply_patch":
        command = patch_text(payload)
        is_patch = True
    elif tool == "Bash":
        command = _command_text(tool_input.get("command"))
        is_patch = bool(command and PATCH_MARKER in command)
    if is_edit_tool(tool) or is_patch:
        mutations, unparsed = mutations_of(payload)
    else:
        mutations, unparsed = [], None
    response = payload.get("tool_response")
    source = payload.get("source") if payload.get("source") is not None else payload.get("trigger")
    return Event(
        provider=resolved_provider,
        name=_str(payload.get("hook_event_name")) or "",
        session_id=_str(payload.get("session_id")) or "",
        transcript_path=_str(payload.get("transcript_path")) or None,
        cwd=cwd,
        workspace=workspace,
        tool_name=tool,
        tool_input=tool_input,
        tool_response=response if isinstance(response, dict) else None,
        tool_use_id=_str(payload.get("tool_use_id")),
        command=command,
        is_patch=is_patch,
        mutations=mutations,
        unparsed_mutation=unparsed,
        stop_hook_active=bool(payload.get("stop_hook_active")),
        last_assistant_message=_str(payload.get("last_assistant_message")),
        source=_str(source),
        prompt=_str(payload.get("prompt")),
        permission_mode=_str(payload.get("permission_mode")),
        model=_str(payload.get("model")),
        run_id=os.environ.get("OMEGA_RUN_ID") or None,
        raw=dict(payload),
    )


def new_content(event: Event) -> list:
    tool = event.tool_name
    tool_input = event.tool_input or {}
    chunks: list = []
    if tool == "Write":
        chunks.append(tool_input.get("content"))
    elif tool == "Edit":
        chunks.append(tool_input.get("new_string"))
    elif tool == "MultiEdit":
        for edit in tool_input.get("edits") or []:
            if isinstance(edit, dict):
                chunks.append(edit.get("new_string"))
    elif tool == "NotebookEdit":
        chunks.append(tool_input.get("new_source"))
    if event.is_patch and event.command:
        added = [line[1:] for line in event.command.splitlines()
                 if line.startswith("+") and not line.startswith("+++")]
        chunks.append("\n".join(added))
    return [c for c in chunks if isinstance(c, str) and c]

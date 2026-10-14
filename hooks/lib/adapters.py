from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import paths


@dataclass
class HookSpec:
    event: str
    matcher_claude: Optional[str]
    matcher_codex: Optional[str]
    script: str
    guard: bool
    timeout_s: int


HOOK_TABLE = [
    HookSpec("SessionStart", "startup|resume|clear|compact", "startup|resume|clear|compact", "bin/session_start.py", False, 20),
    HookSpec("PreToolUse", "Bash|Edit|Write|MultiEdit|NotebookEdit", "^(Bash|apply_patch|Edit|Write|MultiEdit|NotebookEdit)$", "bin/pre_tool_use.py", True, 30),
    HookSpec("PostToolUse", "Edit|Write|MultiEdit|NotebookEdit", "^(apply_patch|Edit|Write|MultiEdit|NotebookEdit)$", "bin/post_tool_use.py", False, 30),
    HookSpec("PostToolUseFailure", "Edit|Write|MultiEdit|NotebookEdit", None, "bin/post_tool_use.py", False, 15),
    HookSpec("Stop", None, None, "bin/stop_orchestrator.py", False, 900),
]

CODEX_EVENTS = ("SessionStart", "PreToolUse", "PostToolUse", "Stop", "SubagentStop", "UserPromptSubmit",
                "PreCompact", "PostCompact", "PermissionRequest", "SessionEnd", "SubagentStart", "Interrupt")
CLAUDE_PERMISSION_DENY = [
    "Bash(git push *)",
    "Bash(git commit *)",
    "Bash(gh pr merge *)",
    "Bash(terraform apply *)",
    "Bash(terraform destroy *)",
    "Bash(kubectl delete *)",
]
CODEX_CONFIG_TOML = "[features]\nhooks = true\n"


def _dq(text: str) -> str:
    escaped = str(text).replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    return '"' + escaped + '"'


def _root(root: Optional[Path]) -> Path:
    return Path(root).resolve() if root is not None else paths.harness_root()


def harness_command(script: str, root: Optional[Path] = None) -> str:
    return "sh %s %s" % (_dq(str(_root(root) / "bin" / "launch.sh")), script)


def _tail(spec: HookSpec, provider: str) -> str:
    guard = "--guard " if spec.guard else ""
    return "%s%s --provider %s" % (guard, spec.script, provider)


def claude_command(spec: HookSpec, root: Path, absolute: bool) -> str:
    if absolute:
        launcher = _dq(str(_root(root) / "bin" / "launch.sh"))
    else:
        launcher = '"$CLAUDE_PROJECT_DIR/bin/launch.sh"'
    return "sh %s %s" % (launcher, _tail(spec, "claude"))


def codex_command(spec: HookSpec, root: Path, absolute: bool) -> str:
    if absolute:
        return "sh %s %s" % (_dq(str(_root(root) / "bin" / "launch.sh")), _tail(spec, "codex"))
    return "sh -c 'R=\"$(git rev-parse --show-toplevel)\"; exec sh \"$R/bin/launch.sh\" %s'" % _tail(spec, "codex")


def _group(matcher: Optional[str], command: str, timeout_s: int) -> dict:
    group: dict = {}
    if matcher is not None:
        group["matcher"] = matcher
    group["hooks"] = [{"type": "command", "command": command, "timeout": int(timeout_s)}]
    return group


def render_claude_settings(root: Path, absolute: bool) -> dict:
    hooks: dict = {}
    for spec in HOOK_TABLE:
        hooks.setdefault(spec.event, []).append(
            _group(spec.matcher_claude, claude_command(spec, root, absolute), spec.timeout_s))
    return {"hooks": hooks, "permissions": {"deny": list(CLAUDE_PERMISSION_DENY)}}


def render_codex_hooks(root: Path, absolute: bool) -> dict:
    hooks: dict = {}
    for spec in HOOK_TABLE:
        if spec.event not in CODEX_EVENTS:
            continue
        hooks.setdefault(spec.event, []).append(
            _group(spec.matcher_codex, codex_command(spec, root, absolute), spec.timeout_s))
    return {"hooks": hooks}


def render_codex_config_toml() -> str:
    return CODEX_CONFIG_TOML

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

import json
import os
from typing import Optional

try:
    from hooks.lib import event as event_mod
    from hooks.lib import io as io_mod
    from hooks.lib import paths, redaction, state
    from hooks import bash_write_guard, contract_gate, prod_guard, tdd_gate
    IMPORT_ERROR = None
except Exception as import_exc:
    IMPORT_ERROR = import_exc

SCRIPT = "bin/pre_tool_use.py"
EVENT = "PreToolUse"


def import_failure(exc: BaseException) -> int:
    reason = ("[omega] %s failed closed: %s: %s — fix the harness or set OMEGA_DEBUG=1 and read "
              "<session_dir>/hooks.log" % (SCRIPT, exc.__class__.__name__, str(exc).replace("\n", " ")[:200]))
    sys.stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": EVENT, "permissionDecision": "deny",
                                                        "permissionDecisionReason": reason}}) + "\n")
    sys.stderr.write(reason + "\n")
    return 2


USAGE = ("usage: sh bin/launch.sh --guard bin/pre_tool_use.py --provider claude|codex < payload.json\n\nPreToolUse guard: reads one hook payload on stdin and denies dangerous commands, governed shell writes, protected paths, uncovered contracts, secrets in edits and untested source edits.\n")


def wants_help(argv: list) -> bool:
    return any(token in ("-h", "--help") for token in argv[1:])


def _provider_arg(argv: list) -> Optional[str]:
    for index, token in enumerate(argv):
        if token == "--provider" and index + 1 < len(argv):
            return argv[index + 1]
        if token.startswith("--provider="):
            return token.split("=", 1)[1]
    return None


def _deny(text: str) -> io_mod.Decision:
    return io_mod.Decision("deny", reason=text)


def _display(path: str, ctx) -> str:
    for root in (ctx.workspace, str(ctx.harness_root)):
        relative = paths.rel(path, root)
        if not relative.startswith("/"):
            return relative
    return path


def guard_context(event, ctx) -> prod_guard.GuardContext:
    return prod_guard.GuardContext(ctx.workspace, ctx.harness_root, ctx.cfg, dict(os.environ),
                                   event.cwd or ctx.workspace, ctx.transcript_path)


def shell_decision(event, ctx) -> Optional[io_mod.Decision]:
    command = event.command
    if not isinstance(command, str) or not command.strip():
        return _deny("[prod-guard] blocked (dynamic.parse_failure): the Bash payload carries no command text. "
                     "Spell the command out as a literal.")
    guard = guard_context(event, ctx)
    verdict = prod_guard.judge(command, guard)
    if verdict.blocked:
        return _deny(verdict.reason)
    verdict = bash_write_guard.judge(command, guard)
    if verdict.blocked:
        return _deny(verdict.reason)
    return None


def _all_fixtures(event, ctx) -> bool:
    if not event.mutations:
        return False
    for mutation in event.mutations:
        relative = paths.rel(mutation.path, ctx.workspace)
        if relative.startswith("/") or not redaction.is_fixture(relative, ctx.cfg):
            return False
    return True


def secret_decision(event, ctx) -> Optional[io_mod.Decision]:
    if _all_fixtures(event, ctx):
        return None
    for chunk in event_mod.new_content(event):
        hits = redaction.strict_secret_hits(chunk)
        if hits:
            hit = hits[0]
            return _deny("[omega] refused: the new content contains what looks like a %s secret at line %s. Put "
                         "secrets in the environment or a secret manager and reference them by name. "
                         "[secrets.in_edit]" % (hit.rule, hit.line))
    return None


def edit_decision(event, ctx) -> Optional[io_mod.Decision]:
    if event.unparsed_mutation:
        return _deny("[omega] refused: %s, so the harness cannot record or gate this change. Name every file "
                     "explicitly (apply_patch *** Add/Update/Delete File headers, or the Edit/Write file_path). "
                     "[omega.unparsed_mutation]" % event.unparsed_mutation)
    for mutation in event.mutations:
        if paths.is_protected(mutation.path, ctx):
            return _deny("[omega] refused: %s is a protected path (hook configuration, git internals or harness "
                         "state). Ask the human to change it. [omega.protected_path]" % _display(mutation.path, ctx))
    decision = contract_gate.write_gate(event, ctx)
    if decision.failing:
        return decision
    decision = secret_decision(event, ctx)
    if decision:
        return decision
    decision = tdd_gate.judge(event.mutations, ctx, ctx.cfg)
    if decision.failing:
        return decision
    return None


def decide(event, ctx) -> io_mod.Decision:
    if event.tool_name == "Bash":
        decision = shell_decision(event, ctx)
        if decision:
            return decision
    if event_mod.is_edit_tool(event.tool_name) or event.is_patch:
        decision = edit_decision(event, ctx)
        if decision:
            return decision
    return io_mod.Decision("allow")


def main(argv: list) -> int:
    if wants_help(argv):
        sys.stdout.write(USAGE)
        return 0
    if IMPORT_ERROR is not None:
        return import_failure(IMPORT_ERROR)
    provider = _provider_arg(argv)
    name = provider if provider in ("claude", "codex") else (os.environ.get("OMEGA_PROVIDER") or "claude")
    try:
        payload = io_mod.read_payload()
        event = event_mod.normalize(payload, provider if provider in ("claude", "codex") else None)
        name = event.provider
        ctx = state.configure(event)
        decision = decide(event, ctx)
        if decision.failing:
            io_mod.debug("deny %s: %s" % (event.tool_name, decision.reason))
        return io_mod.emit(name, EVENT, decision)
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        return io_mod.fail_closed(name, EVENT, exc, SCRIPT)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

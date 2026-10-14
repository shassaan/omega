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
    import hooks.lib as lib
    from hooks.lib import adapters, gitsnap, paths, state, transcript
    from hooks.lib import event as event_mod
    from hooks.lib import io as io_mod
    IMPORT_ERROR = None
except Exception as import_exc:
    IMPORT_ERROR = import_exc

SCRIPT = "bin/session_start.py"
FRAMING_CAP = 600
COMMANDS_CAP = 1200
FACTS_CAP = 1500
DEFAULT_CAP = 12000
WALK_LIMIT = 4000


USAGE = ("usage: sh bin/launch.sh bin/session_start.py --provider claude|codex < payload.json\n\nSessionStart hook: reads one hook payload on stdin, records the git baseline and override token and prints the session context (at most 12 KB).\n")


def wants_help(argv: list) -> bool:
    return any(token in ("-h", "--help") for token in argv[1:])


def _provider_arg(argv: list) -> Optional[str]:
    for index, token in enumerate(argv):
        if token == "--provider" and index + 1 < len(argv):
            return argv[index + 1]
        if token.startswith("--provider="):
            return token.split("=", 1)[1]
    return None


def _bytes(text: str) -> int:
    return len(text.encode("utf-8"))


def cut_lines(text: str, cap: int) -> str:
    if _bytes(text) <= cap:
        return text
    kept: list = []
    used = 0
    for line in text.splitlines():
        size = _bytes(line) + 1
        if used + size > cap:
            break
        kept.append(line)
        used += size
    return "\n".join(kept)


def framing(ctx) -> str:
    version = getattr(lib, "OMEGA_VERSION", "0.1.0")
    return ("[omega] Omega %s · provider %s · workspace %s · session %s. Laws: contract-first "
            "(docs/contracts/<slug>.md, propose before writing), observed-red TDD (write the failing test first), "
            "signed git (commit/push only as the trusted signing identity; never override it), Stop waits for "
            "proof (proof · tdd · contract · review · cost · ship). Shell writes into the workspace are refused; use "
            "Edit/Write." % (version, ctx.provider, ctx.workspace, ctx.session_id))


def commands(ctx) -> str:
    sid = ctx.session_id
    root = ctx.harness_root
    lines = [
        ("hooks/contract_gate.py", "propose --session %s --file docs/contracts/<slug>.md" % sid),
        ("hooks/contract_gate.py", "request --session %s" % sid),
        ("hooks/contract_gate.py", "record --session %s --quote \"<their words>\"" % sid),
        ("hooks/contract_gate.py", "status --session %s" % sid),
        ("hooks/tdd_gate.py", "status --session %s" % sid),
        ("hooks/tdd_gate.py", "run --session %s --test <tests/test_x.py>" % sid),
        ("bin/stop_orchestrator.py", "status --session %s" % sid),
        ("hooks/tokentoll_gate.py", "report --session %s" % sid),
        ("hooks/ship_readiness.py", "run"),
        ("scripts/auto_ship.py", "--dry-run --session %s" % sid),
    ]
    full = ["Commands:"] + ["  %s %s" % (adapters.harness_command(script, root), rest) for script, rest in lines]
    text = "\n".join(full)
    if _bytes(text) <= COMMANDS_CAP:
        return text
    prefix = adapters.harness_command("", root).rstrip()
    short = ["Commands (prefix each with: %s):" % prefix] + ["  %s %s" % (script, rest) for script, rest in lines]
    return cut_lines("\n".join(short), COMMANDS_CAP)


def _files(workspace: str, ignored: list) -> list:
    found: list = []
    skip = set(str(i).strip("/").split("/")[-1] for i in ignored or []) | {".git", ".omega"}
    for current, dirs, names in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in names:
            found.append(os.path.relpath(os.path.join(current, name), workspace).replace(os.sep, "/"))
            if len(found) >= WALK_LIMIT:
                return found
    return found


def detect_stacks(ctx) -> list:
    tiers = ctx.cfg.get("ship_readiness.tiers", {}) or {}
    files = _files(ctx.workspace, ctx.cfg.get("workspace.ignored_dirs", []) or [])
    found: list = []
    for tier, spec in tiers.items():
        globs = (spec or {}).get("detect", []) or []
        if any(paths.match_globs(f, globs) for f in files):
            found.append(tier)
    return found


def _open_reds(ctx) -> list:
    directory = state.session_dir(ctx)
    greens = state.read_jsonl(directory / "green.jsonl")
    reds: list = []
    for row in state.read_jsonl(directory / "red.jsonl"):
        files = row.get("test_files") or {}
        later = [g for g in greens if int(g.get("ts_ns") or 0) > int(row.get("ts_ns") or 0)
                 and (g.get("test_files") or {}) == files]
        if not later:
            for test in files:
                if test not in reds:
                    reds.append(test)
    return reds


def facts(ctx, source: Optional[str]) -> str:
    lines: list = ["Workspace facts:"]
    warnings: list = []
    try:
        stacks = detect_stacks(ctx)
        lines.append("  stacks: %s" % (", ".join(stacks) or "none detected"))
    except Exception as exc:
        warnings.append("stack detection failed: %s" % exc.__class__.__name__)
    try:
        from hooks.lib import contracts as contracts_mod
        names = [Path(c.path).stem for c in contracts_mod.load_all(ctx.workspace, ctx.cfg)]
        lines.append("  contracts: %s" % (", ".join(names[:12]) + (" (+%d)" % (len(names) - 12) if len(names) > 12 else "")
                                          if names else "none yet"))
    except Exception as exc:
        warnings.append("contracts unreadable: %s" % exc.__class__.__name__)
    req = state.read_json(state.session_dir(ctx) / "contract_request.json", None)
    if isinstance(req, dict) and not req.get("consumed"):
        lines.append("  pending sign-off: a contract request (fingerprint %s) awaits the human's answer"
                     % str(req.get("fingerprint", ""))[:12])
    reds = _open_reds(ctx)
    if reds:
        lines.append("  open reds without green: %s" % ", ".join(reds[:8]))
    last = state.read_json(state.session_dir(ctx) / "last_stop.json", None)
    if isinstance(last, dict):
        verdict = "verified" if last.get("verified") else ("released (NOT verified)" if last.get("released") else "blocked")
        lines.append("  last Stop: %s (attempt %s)" % (verdict, last.get("attempt", "?")))
    try:
        from hooks.lib import costledger
        sums = costledger.sums(ctx.cfg, session_id=ctx.session_id)
        caps = costledger.caps(ctx.cfg)
        lines.append("  cost: session $%.2f / $%.2f; month $%.2f / $%.2f" % (
            float(sums.get("session") or 0), float(caps.get("per_session_usd") or 0),
            float(sums.get("month") or 0), float(caps.get("monthly_usd") or 0)))
    except Exception as exc:
        warnings.append("cost ledger unreadable: %s" % exc.__class__.__name__)
    if paths.is_dev():
        warnings.append("OMEGA_DEV=1 lifts harness protection: bin/, hooks/, schemas/, scripts/ are editable")
    if sys.version_info < (3, 10):
        warnings.append("python %d.%d: mutation gate unavailable" % sys.version_info[:2])
    if os.environ.get("OMEGA_HUMAN_LOG") or ctx.run_id:
        warnings.append("UI mode: human sign-off is given in the dashboard; record/override are run by the server")
    try:
        if source in ("resume", "compact", "clear") and ctx.transcript_path and \
                os.path.isfile(os.path.expanduser(ctx.transcript_path)) and not transcript.read_human_turns(ctx):
            warnings.append("transcript: no human turn found yet")
    except Exception:
        warnings.append("transcript: unreadable")
    for warning in warnings:
        lines.append("  warning: %s" % warning)
    return cut_lines("\n".join(lines), FACTS_CAP)


def injected(ctx, budget: int) -> str:
    parts: list = []
    used = 0
    for rel in ctx.cfg.get("session_start.inject", []) or []:
        target = Path(ctx.harness_root) / rel
        try:
            text = target.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            note = "[omega] %s is missing" % rel
            if used + _bytes(note) + 2 <= budget:
                parts.append(note)
                used += _bytes(note) + 2
            continue
        block = "--- %s ---\n%s" % (rel, text)
        if used + _bytes(block) + 2 <= budget:
            parts.append(block)
            used += _bytes(block) + 2
            continue
        note = "[omega] %s did not fit in the session context; read it with the Read tool: %s" % (rel, target)
        if used + _bytes(note) + 2 <= budget:
            parts.append(note)
            used += _bytes(note) + 2
    return "\n\n".join(parts)


def compose(ctx, source: Optional[str]) -> str:
    cap = int(ctx.cfg.get("session_start.context_cap_bytes", DEFAULT_CAP) or DEFAULT_CAP)
    sections = [cut_lines(framing(ctx), FRAMING_CAP), commands(ctx), facts(ctx, source)]
    head = "\n\n".join(s for s in sections if s)
    if source != "compact":
        remaining = cap - _bytes(head) - 2
        if remaining > 200:
            extra = injected(ctx, remaining)
            if extra:
                head = head + "\n\n" + extra
    return cut_lines(head, cap)


def ensure_excluded(workspace: str) -> None:
    git_dir = os.path.join(workspace, ".git")
    if not os.path.isdir(git_dir):
        return
    info = os.path.join(git_dir, "info")
    os.makedirs(info, exist_ok=True)
    target = os.path.join(info, "exclude")
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as handle:
            existing = handle.read()
    except OSError:
        existing = ""
    if any(line.strip() in (".omega/", ".omega", "/.omega/", "/.omega") for line in existing.splitlines()):
        return
    with open(target, "a", encoding="utf-8") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        handle.write(".omega/\n")


def run(event) -> str:
    warnings: list = []
    ctx = state.configure(event)
    steps = []
    if event.source != "compact":
        steps.append(("baseline", lambda: gitsnap.ensure_baseline(ctx)))
    steps.append(("git exclude", lambda: ensure_excluded(ctx.workspace)))
    steps.append(("override token", lambda: state.ensure_override_token(ctx)))
    for label, step in steps:
        try:
            step()
        except Exception as exc:
            warnings.append("[omega] warning: %s failed (%s: %s)" % (label, exc.__class__.__name__, str(exc)[:120]))
    text = compose(ctx, event.source)
    if warnings:
        text = "\n".join(warnings) + "\n" + text
        text = cut_lines(text, int(ctx.cfg.get("session_start.context_cap_bytes", DEFAULT_CAP) or DEFAULT_CAP))
    return text


def main(argv: list) -> int:
    if wants_help(argv):
        sys.stdout.write(USAGE)
        return 0
    if IMPORT_ERROR is not None:
        sys.stdout.write("[omega] warning: %s could not start (%s: %s); hooks may be degraded\n"
                         % (SCRIPT, IMPORT_ERROR.__class__.__name__, IMPORT_ERROR))
        return 0
    provider = _provider_arg(argv)
    name = provider if provider in ("claude", "codex") else (os.environ.get("OMEGA_PROVIDER") or "claude")
    try:
        payload = io_mod.read_payload()
        event = event_mod.normalize(payload, provider if provider in ("claude", "codex") else None)
        name = event.provider
        text = run(event)
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        text = "[omega] warning: session start failed (%s: %s); the harness guards still run" % (
            exc.__class__.__name__, str(exc)[:200])
    try:
        return io_mod.emit(name, "SessionStart", io_mod.Decision("allow", context=text))
    except Exception:
        sys.stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text}})
                         if name == "codex" else text)
        sys.stdout.write("\n")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

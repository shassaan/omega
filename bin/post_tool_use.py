from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

import os
from typing import Optional

try:
    from hooks.lib import event as event_mod
    from hooks.lib import io as io_mod
    from hooks.lib import jobstore, ledger, paths, state, testmap
    from hooks import contract_gate, tdd_gate
    IMPORT_ERROR = None
except Exception as import_exc:
    IMPORT_ERROR = import_exc

SCRIPT = "bin/post_tool_use.py"
TAIL_LINES = 40
LAUNCH_KINDS = ("added", "modified", "renamed_to")
RUFF_CONFIGS = ("ruff.toml", ".ruff.toml")
ESLINT_CONFIGS = ("eslint.config.js", "eslint.config.mjs", "eslint.config.cjs", "eslint.config.ts", ".eslintrc.json",
                  ".eslintrc.cjs", ".eslintrc.js", ".eslintrc.yml", ".eslintrc.yaml", ".eslintrc")


USAGE = ("usage: sh bin/launch.sh bin/post_tool_use.py --provider claude|codex < payload.json\n\nPostToolUse hook: reads one hook payload on stdin, records the change ledger, launches background test and lint jobs and reports finished jobs.\n")


def wants_help(argv: list) -> bool:
    return any(token in ("-h", "--help") for token in argv[1:])


def _provider_arg(argv: list) -> Optional[str]:
    for index, token in enumerate(argv):
        if token == "--provider" and index + 1 < len(argv):
            return argv[index + 1]
        if token.startswith("--provider="):
            return token.split("=", 1)[1]
    return None


def _relative(path: str, ctx) -> Optional[str]:
    relative = paths.rel(path, ctx.workspace)
    if relative.startswith("/") or relative in (".", ""):
        return None
    return relative


def _ruff_configured(workspace: str) -> bool:
    if any(os.path.isfile(os.path.join(workspace, name)) for name in RUFF_CONFIGS):
        return True
    try:
        with open(os.path.join(workspace, "pyproject.toml"), "r", encoding="utf-8", errors="replace") as handle:
            return "[tool.ruff" in handle.read()
    except OSError:
        return False


def _eslint_configured(workspace: str) -> bool:
    return any(os.path.isfile(os.path.join(workspace, name)) for name in ESLINT_CONFIGS)


def record(event, ctx) -> list:
    ledgered: list = []
    if event.unparsed_mutation:
        ledger.note_unparsed(ctx, event.unparsed_mutation)
    for mutation in event.mutations:
        if contract_gate.is_contract_path(mutation.path, ctx):
            ledger.note_contract_touched(ctx, mutation.path)
        if _relative(mutation.path, ctx) is None or not paths.is_governed(mutation.path, ctx):
            continue
        ledger.append(ctx, mutation.path, mutation.kind, event.tool_name, event.tool_use_id)
        ledgered.append(mutation)
    return ledgered


def launch_jobs(mutations: list, ctx) -> list:
    cfg = ctx.cfg
    launched: list = []
    scopes: set = set()
    contracts_cache: list = []
    for mutation in mutations:
        if mutation.kind not in LAUNCH_KINDS or not os.path.isfile(mutation.path):
            continue
        relative = _relative(mutation.path, ctx)
        if relative is None:
            continue
        tests: list = []
        sources: list = []
        if testmap.is_test(relative, cfg):
            if os.path.basename(relative) != "conftest.py":
                tests.append(relative)
        elif testmap.is_source(relative, cfg) and not paths.is_exempt(mutation.path, ctx):
            if not contracts_cache:
                from hooks.lib import contracts as contracts_mod
                try:
                    contracts_cache.append(contracts_mod.load_all(ctx.workspace, cfg))
                except OSError:
                    contracts_cache.append([])
            mapped = testmap.map_test(relative, ctx, cfg, contracts_cache[0])
            tests.extend(c for c in mapped.candidates if os.path.isfile(os.path.join(ctx.workspace, c)))
            sources.append(relative)
        for test in tests:
            key = testmap.scope_key(test)
            if key in scopes:
                continue
            scopes.add(key)
            spec = tdd_gate.launch_test(ctx, cfg, test, sources)
            if spec:
                launched.append(spec)
        launched.extend(_lint(relative, ctx, scopes))
    return launched


def _lint(relative: str, ctx, scopes: set) -> list:
    key = "lint:" + relative
    if key in scopes:
        return []
    ext = os.path.splitext(relative)[1]
    argv = None
    label = None
    if ext == ".py" and _ruff_configured(ctx.workspace):
        argv = [testmap.workspace_python(ctx.workspace), "-m", "ruff", "check", relative]
        label = "ruff %s" % relative
    elif ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs") and _eslint_configured(ctx.workspace):
        argv = ["npx", "eslint", "--max-warnings", "0", relative]
        label = "eslint %s" % relative
    if argv is None:
        return []
    scopes.add(key)
    return [jobstore.launch(ctx, key, "lint", label, argv, ctx.workspace, [], [relative], 60)]


def _tag(view: dict) -> str:
    return "[lint]" if view.get("kind") == "lint" else "[tests]"


def _seconds(result: dict) -> str:
    try:
        return "%.1fs" % (float(result.get("duration_ms") or 0) / 1000.0)
    except (TypeError, ValueError):
        return "?s"


def _tail(text: str) -> str:
    return "\n".join((text or "").rstrip().splitlines()[-TAIL_LINES:])


def _skip_reason(view: dict, ctx) -> str:
    result = view.get("result") or {}
    status = result.get("status") or view.get("state")
    argv = view.get("argv") or ["?"]
    if status == "not_installed":
        return "%s not installed" % argv[0]
    if status == "skipped_no_tests":
        return "no tests collected"
    output = result.get("output", "")
    if "Cannot find module" in output and not os.path.isdir(os.path.join(ctx.workspace, "node_modules")):
        return "node_modules missing (run npm ci)"
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-1][:160] if lines else "environment problem"


def feedback(harvest, ctx) -> io_mod.Decision:
    failures: list = []
    for view in harvest.failures:
        result = view.get("result") or {}
        header = "%s FAIL %s (exit %s, %s)" % (_tag(view), view.get("label", "?"), result.get("rc"), _seconds(result))
        if view.get("kind") == "test" and result.get("status") == "fail":
            header += " — observed red for %s" % ", ".join(sorted((view.get("test_files") or {}).keys()))
        failures.append(header + "\n" + _tail(result.get("output", "")))
    lines: list = []
    for view in harvest.passes:
        result = view.get("result") or {}
        lines.append("%s PASS %s (%s)" % (_tag(view), view.get("label", "?"), _seconds(result)))
    for view in harvest.skipped:
        label = (view.get("label") or "?").split(" ", 1)[0]
        lines.append("%s skipped %s: %s" % (_tag(view), label, _skip_reason(view, ctx)))
    if failures:
        return io_mod.Decision("feedback", reason="\n".join(failures + lines), context="\n".join(lines))
    return io_mod.Decision("allow", context="\n".join(lines))


def handle(event, ctx) -> io_mod.Decision:
    if event.name != "PostToolUseFailure":
        ledgered = record(event, ctx)
        try:
            launch_jobs(ledgered, ctx)
        except Exception as exc:
            io_mod.debug("launch failed: %s: %s" % (exc.__class__.__name__, exc))
    return feedback(jobstore.harvest(ctx), ctx)


def main(argv: list) -> int:
    if wants_help(argv):
        sys.stdout.write(USAGE)
        return 0
    if IMPORT_ERROR is not None:
        sys.stderr.write("[omega] %s could not start: %s: %s\n" % (SCRIPT, IMPORT_ERROR.__class__.__name__, IMPORT_ERROR))
        return 0
    provider = _provider_arg(argv)
    name = provider if provider in ("claude", "codex") else (os.environ.get("OMEGA_PROVIDER") or "claude")
    event_name = "PostToolUse"
    try:
        payload = io_mod.read_payload()
        event = event_mod.normalize(payload, provider if provider in ("claude", "codex") else None)
        name = event.provider
        event_name = event.name if event.name in ("PostToolUse", "PostToolUseFailure") else "PostToolUse"
        ctx = state.configure(event)
        return io_mod.emit(name, event_name, handle(event, ctx))
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        return io_mod.fail_closed(name, event_name, exc, SCRIPT)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import time
import uuid
from typing import Optional

from hooks.lib import config as config_mod
from hooks.lib import costledger, paths, state, transcript
from hooks.stop_proof import FAIL, NOT_APPLICABLE, PASS, UNVERIFIED, GateResult

CURSOR = "cost_cursor.json"
EXIT_OK, EXIT_BREACH, EXIT_CORRUPT, EXIT_UNKNOWN = 0, 1, 2, 3
SCAN_EXTS = (".py", ".ts", ".tsx", ".js")
CALL_PATTERNS = re.compile(r"messages\.create\(|chat\.completions\.create\(|responses\.create\(|generate_content\(|"
                           r"generateContent\(|anthropic\.messages|openai\.chat")
MODEL_LITERAL = re.compile(r"model\s*[:=]\s*[\"']([\w.\-\[\]]+)[\"']")
MAX_TOKENS_LITERAL = re.compile(r"(?:max_tokens|maxTokens|max_output_tokens|maxOutputTokens)\s*[:=]\s*(\d+)")
STRING_LITERAL = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'")
WINDOW_LINES = 40
MIN_PROMPT_CHARS = 200
UNRESOLVED_MODEL = "<unresolved>"


def provider_for_model(model: Optional[str]) -> str:
    name = str(model or "").lower()
    if name.startswith("gpt") or name.startswith("o1") or name.startswith("o3") or "openai" in name:
        return "openai"
    if name.startswith("gemini"):
        return "google"
    return "anthropic"


def _cursor_path(ctx) -> Path:
    return state.session_dir(ctx) / CURSOR


def ingest(ctx, cfg) -> int:
    rows = transcript.assistant_usage(ctx)
    if not rows:
        return 0
    cursor = state.read_json(_cursor_path(ctx), {}) or {}
    last = cursor.get("last_message_id")
    ids = [r["message_id"] for r in rows]
    start = ids.index(last) + 1 if last in ids else 0
    added = 0
    workspace_hash = paths.workspace_hash(ctx.workspace)
    for row in rows[start:]:
        ts_ns = row.get("ts_ns") or time.time_ns()
        costledger.append({
            "ts": state.iso(ts_ns), "ts_ns": ts_ns,
            "id": "%s:%s" % (ctx.session_id, row["message_id"]),
            "source": "transcript", "provider": provider_for_model(row.get("model")),
            "model": row.get("model"), "role": None, "session_id": ctx.session_id,
            "run_id": ctx.run_id, "workspace_hash": workspace_hash,
            "in": row.get("in", 0), "out": row.get("out", 0),
            "cache_read": row.get("cache_read", 0), "cache_write": row.get("cache_write", 0),
            "usd": None, "est_usd": None,
        }, cfg)
        added += 1
    state.write_json_atomic(_cursor_path(ctx), {"last_message_id": rows[-1]["message_id"],
                                                "last_uuid": rows[-1].get("uuid"), "ts": state.iso()})
    return added


def _money(value) -> str:
    return "n/a" if value is None else "$%.2f" % float(value)


def cost_entry(verdict, run_id: Optional[str] = None) -> dict:
    sums = verdict.sums or {}
    limits = sums.get("caps") or {}
    status = verdict.status if verdict.status in (PASS, FAIL, UNVERIFIED, NOT_APPLICABLE) else UNVERIFIED
    return {
        "status": status,
        "session_usd": sums.get("session"),
        "run_usd": sums.get("run") if run_id else None,
        "month_usd": sums.get("month"),
        "max_call_usd": sums.get("max_call"),
        "caps": {k: float(limits.get(k, 0.0) or 0.0) for k in
                 ("per_call_usd", "per_session_usd", "per_run_usd", "monthly_usd")},
        "breaches": list(verdict.breaches),
        "warnings": list(verdict.warnings),
        "unknown_models": list(sums.get("unknown_models") or []),
    }


def summary_line(entry: dict) -> str:
    caps = entry.get("caps") or {}
    parts = []
    if entry.get("session_usd") is not None:
        parts.append("session %s / %s" % (_money(entry["session_usd"]), _money(caps.get("per_session_usd"))))
    if entry.get("run_usd") is not None:
        parts.append("run %s / %s" % (_money(entry["run_usd"]), _money(caps.get("per_run_usd"))))
    parts.append("month %s / %s" % (_money(entry.get("month_usd")), _money(caps.get("monthly_usd"))))
    text = "; ".join(parts)
    if entry.get("breaches"):
        text += " — " + "; ".join(entry["breaches"])
    elif entry.get("unknown_models"):
        text += " — unknown model(s) with no price: %s (fix cost.prices)" % ", ".join(entry["unknown_models"])
    return text


def not_applicable_entry(cfg, detail: str) -> dict:
    return {"status": NOT_APPLICABLE, "session_usd": None, "run_usd": None, "month_usd": None,
            "max_call_usd": None, "caps": costledger.caps(cfg), "breaches": [], "warnings": [detail],
            "unknown_models": []}


def stop_check(ctx, cfg) -> GateResult:
    started = time.monotonic()
    cfg = cfg if cfg is not None else ctx.cfg
    required = bool(cfg.get("stop.gates.cost.required", True))
    if ctx.provider == "codex" and not ctx.run_id:
        detail = "codex: usage is recorded by the UI runner from turn.completed"
        entry = not_applicable_entry(cfg, detail)
        return GateResult("cost", NOT_APPLICABLE, required, detail, [entry],
                          int((time.monotonic() - started) * 1000), {"cost": entry})
    ingest(ctx, cfg)
    verdict = costledger.check(cfg, session_id=ctx.session_id, run_id=ctx.run_id)
    entry = cost_entry(verdict, ctx.run_id)
    return GateResult("cost", entry["status"], required, summary_line(entry), [entry],
                      int((time.monotonic() - started) * 1000), {"cost": entry})


def _out(args, payload: dict, text: str) -> None:
    if getattr(args, "json", False):
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        if text:
            sys.stderr.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")


def cmd_estimate(args, cfg) -> int:
    if args.input_file:
        try:
            text = Path(args.input_file).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            sys.stderr.write("[tokentoll] cannot read %s: %s\n" % (args.input_file, exc.__class__.__name__))
            return EXIT_CORRUPT
    else:
        text = args.input_text or ""
    max_tokens = args.max_tokens if args.max_tokens is not None else int(cfg.get("cost.static.default_max_tokens", 1024))
    tokens = costledger.estimate_tokens(text, cfg)
    try:
        usd = costledger.estimate_usd(args.model, tokens, max_tokens, cfg)
    except costledger.UnknownModel:
        _out(args, {"model": args.model, "error": "unknown model"},
             "[tokentoll] unknown model %s: add it to cost.prices" % args.model)
        return EXIT_UNKNOWN
    found = costledger.price(args.model, cfg)
    payload = {"model": found.model if found else args.model, "in_tokens": tokens, "max_out_tokens": max_tokens,
               "worst_case_usd": usd, "verified_price": bool(found and found.verified)}
    _out(args, payload, "%s: ~%d input tokens, worst case %d output tokens: $%.6f%s" % (
        payload["model"], tokens, max_tokens, usd, "" if payload["verified_price"] else " (unverified price)"))
    return EXIT_OK


def cmd_record(args, cfg) -> int:
    session_id = args.session or os.environ.get("OMEGA_SESSION_ID") or None
    run_id = args.run_id or os.environ.get("OMEGA_RUN_ID") or None
    workspace = os.environ.get("OMEGA_WORKSPACE")
    ts, ts_ns = state.stamp()
    row = {"ts": ts, "ts_ns": ts_ns, "id": args.id or str(uuid.uuid4()), "source": args.source,
           "provider": provider_for_model(args.model), "model": args.model, "role": args.role,
           "session_id": session_id, "run_id": run_id,
           "workspace_hash": paths.workspace_hash(workspace) if workspace else None,
           "in": args.in_tokens, "out": args.out_tokens, "cache_read": args.cache_read,
           "cache_write": args.cache_write, "usd": args.usd, "est_usd": None}
    found = costledger.price(args.model, cfg)
    row["verified_price"] = bool(found and found.verified)
    costledger.append(row, cfg)
    known = found is not None
    _out(args, {"id": row["id"], "model": args.model, "known_model": known},
         "[tokentoll] recorded %s (%s)%s" % (row["id"], args.model, "" if known else " — unknown model: no price"))
    return EXIT_OK


def verdict_exit(verdict, allow_unknown: bool) -> int:
    sums = verdict.sums or {}
    if sums.get("corrupt_lines"):
        return EXIT_CORRUPT
    if verdict.status == FAIL:
        return EXIT_BREACH
    if sums.get("unknown_models") and not allow_unknown:
        return EXIT_UNKNOWN
    if verdict.status == UNVERIFIED:
        return EXIT_CORRUPT
    return EXIT_OK


def cmd_check(args, cfg) -> int:
    ledger_file = args.ledger
    if ledger_file and os.path.exists(ledger_file) and not os.path.isfile(ledger_file):
        sys.stderr.write("[tokentoll] ledger %s is not a file\n" % ledger_file)
        return EXIT_CORRUPT
    overrides = {"per_call_usd": args.per_call, "per_session_usd": args.per_session,
                 "per_run_usd": args.per_run, "monthly_usd": args.monthly}
    verdict = costledger.check(cfg, session_id=args.session, run_id=args.run_id, month=args.month,
                               allow_unknown=args.allow_unknown, path=ledger_file, cap_overrides=overrides)
    entry = cost_entry(verdict, args.run_id)
    code = verdict_exit(verdict, args.allow_unknown)
    lines = ["[tokentoll] %s %s" % (entry["status"], summary_line(entry))]
    lines += ["  warning: %s" % w for w in entry["warnings"]]
    entry["exit"] = code
    _out(args, entry, "\n".join(lines))
    return code


def cmd_report(args, cfg) -> int:
    found, corrupt = costledger.read_ledger(cfg)
    month = args.month or costledger.current_month()
    by_model: dict = {}
    by_session: dict = {}
    total = 0.0
    for row in found:
        if not str(row.get("ts", "")).startswith(month):
            continue
        if args.session and row.get("session_id") != args.session:
            continue
        if args.run_id and row.get("run_id") != args.run_id:
            continue
        usd = row.get("usd")
        if not isinstance(usd, (int, float)) or isinstance(usd, bool):
            try:
                usd = costledger.estimate_usd(row.get("model"), row.get("in", 0) or 0, row.get("out", 0) or 0, cfg,
                                              row.get("cache_read", 0) or 0, row.get("cache_write", 0) or 0)
            except (costledger.UnknownModel, TypeError, ValueError):
                usd = 0.0
        model = str(row.get("model"))
        session = str(row.get("session_id"))
        by_model[model] = round(by_model.get(model, 0.0) + usd, 6)
        by_session[session] = round(by_session.get(session, 0.0) + usd, 6)
        total += usd
    verdict = costledger.check(cfg, session_id=args.session, run_id=args.run_id, month=month)
    payload = {"month": month, "total_usd": round(total, 6), "by_model": by_model, "by_session": by_session,
               "caps": costledger.caps(cfg), "corrupt_line_numbers": corrupt, "status": verdict.status,
               "breaches": verdict.breaches, "warnings": verdict.warnings}
    lines = ["[tokentoll] %s spend $%.2f / $%.2f (%s)" % (month, total, payload["caps"]["monthly_usd"], verdict.status)]
    lines += ["  %-28s $%.4f" % (m, v) for m, v in sorted(by_model.items())]
    if corrupt:
        lines.append("  corrupt ledger line(s): %s" % ", ".join(str(n) for n in corrupt))
    _out(args, payload, "\n".join(lines))
    return 0 if not corrupt else EXIT_CORRUPT


def _ignored(rel: str, ignored: list) -> bool:
    parts = rel.split("/")
    for entry in ignored:
        wanted = [p for p in str(entry).strip("/").split("/") if p]
        width = len(wanted)
        for start in range(0, len(parts) - width + 1):
            if width and parts[start:start + width] == wanted:
                return True
    return False


def scan_files(root: str, cfg) -> list:
    ignored = list(cfg.get("workspace.ignored_dirs", []) or []) + [".omega"]
    found: list = []
    for directory, dirs, files in os.walk(root):
        rel_dir = os.path.relpath(directory, root)
        rel_dir = "" if rel_dir == "." else Path(rel_dir).as_posix()
        dirs[:] = sorted(d for d in dirs if not _ignored((rel_dir + "/" + d).lstrip("/"), ignored))
        for name in sorted(files):
            if name.endswith(SCAN_EXTS):
                found.append(os.path.join(directory, name))
    return found


def _call_text(lines: list, index: int) -> str:
    depth = 0
    chunks: list = []
    for line in lines[index:index + WINDOW_LINES]:
        chunks.append(line)
        depth += line.count("(") - line.count(")")
        if depth <= 0 and chunks:
            break
    return "\n".join(chunks)


def _nearest(lines: list, index: int, pattern) -> Optional[str]:
    for offset in range(0, WINDOW_LINES + 1):
        for position in (index + offset, index - offset):
            if 0 <= position < len(lines):
                match = pattern.search(lines[position])
                if match:
                    return match.group(1)
    return None


def scan(root: str, cfg, calls_per_month: Optional[int] = None, max_monthly: Optional[float] = None) -> dict:
    calls = int(calls_per_month if calls_per_month is not None else cfg.get("cost.static.calls_per_month", 10000))
    limit = float(max_monthly if max_monthly is not None else cfg.get("cost.static.max_monthly_usd", 500.0))
    default_max = int(cfg.get("cost.static.default_max_tokens", 1024))
    sites: list = []
    unknown: list = []
    total = 0.0
    root = os.path.realpath(root)
    for path in scan_files(root, cfg):
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        seen_lines: set = set()
        for index, line in enumerate(lines):
            if not CALL_PATTERNS.search(line) or index in seen_lines:
                continue
            seen_lines.add(index)
            call = _call_text(lines, index)
            model = _nearest(lines, index, MODEL_LITERAL) or UNRESOLVED_MODEL
            max_tokens_text = _nearest(lines, index, MAX_TOKENS_LITERAL)
            max_tokens = int(max_tokens_text) if max_tokens_text else default_max
            literal_chars = sum(max(0, len(m.group(0)) - 2) for m in STRING_LITERAL.finditer(call))
            prompt_chars = max(MIN_PROMPT_CHARS, literal_chars)
            in_tokens = int(math.ceil(prompt_chars / 4.0))
            found = costledger.price(model, cfg) if model != UNRESOLVED_MODEL else None
            monthly = None
            if found is None:
                if model not in unknown:
                    unknown.append(model)
            else:
                monthly = round(calls * costledger.estimate_usd(model, in_tokens, max_tokens, cfg), 4)
                total += monthly
            sites.append({"path": Path(os.path.relpath(path, root)).as_posix(), "line": index + 1, "model": model,
                          "monthly_usd": monthly, "verified_price": bool(found and found.verified)})
    status = FAIL if total > limit else PASS
    result = {"sites": sites, "total_monthly_usd": round(total, 4), "unknown_models": unknown, "status": status,
              "calls_per_month": calls, "max_monthly_usd": limit}
    binary = shutil.which("tokentoll")
    if binary:
        try:
            proc = subprocess.run([binary, "scan", "--format", "json"], cwd=root, capture_output=True, timeout=60)
            text = proc.stdout.decode("utf-8", "replace")
            try:
                result["tokentoll"] = json.loads(text)
            except ValueError:
                result["tokentoll"] = {"rc": proc.returncode, "output": text[-2000:]}
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["tokentoll"] = {"error": exc.__class__.__name__}
    return result


def scan_exit(result: dict, cfg) -> int:
    if result.get("status") == FAIL:
        return EXIT_BREACH
    if result.get("unknown_models") and bool(cfg.get("cost.static.block_unknown_models", True)):
        return EXIT_UNKNOWN
    return EXIT_OK


def cmd_scan(args, cfg) -> int:
    if not os.path.isdir(args.path):
        sys.stderr.write("[tokentoll] %s is not a directory\n" % args.path)
        return EXIT_CORRUPT
    result = scan(args.path, cfg, args.calls_per_month, args.max_monthly)
    code = scan_exit(result, cfg)
    lines = ["[tokentoll] scan %s: %d call site(s), $%.2f / month (cap $%.2f)" % (
        result["status"], len(result["sites"]), result["total_monthly_usd"], result["max_monthly_usd"])]
    for site in result["sites"][:50]:
        lines.append("  %s:%d %s %s" % (site["path"], site["line"], site["model"],
                                        "n/a" if site["monthly_usd"] is None else "$%.2f" % site["monthly_usd"]))
    if result["unknown_models"]:
        lines.append("  unknown or unresolved model(s): %s" % ", ".join(result["unknown_models"]))
    result["exit"] = code
    _out(args, result, "\n".join(lines))
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tokentoll_gate.py", description="LLM cost estimates, ledger and caps.")
    sub = parser.add_subparsers(dest="command")
    est = sub.add_parser("estimate")
    est.add_argument("--model", required=True)
    group = est.add_mutually_exclusive_group(required=True)
    group.add_argument("--input-file")
    group.add_argument("--input-text")
    est.add_argument("--max-tokens", type=int)
    est.add_argument("--json", action="store_true")
    rec = sub.add_parser("record")
    rec.add_argument("--model", required=True)
    rec.add_argument("--in", dest="in_tokens", type=int, required=True)
    rec.add_argument("--out", dest="out_tokens", type=int, required=True)
    rec.add_argument("--cache-read", type=int, default=0)
    rec.add_argument("--cache-write", type=int, default=0)
    rec.add_argument("--usd", type=float)
    rec.add_argument("--role")
    rec.add_argument("--session")
    rec.add_argument("--run-id")
    rec.add_argument("--source", choices=("api", "cli_result", "estimate"), default="api")
    rec.add_argument("--id")
    rec.add_argument("--json", action="store_true")
    chk = sub.add_parser("check")
    chk.add_argument("--session")
    chk.add_argument("--run-id")
    chk.add_argument("--month")
    chk.add_argument("--ledger")
    chk.add_argument("--per-call", type=float)
    chk.add_argument("--per-session", type=float)
    chk.add_argument("--per-run", type=float)
    chk.add_argument("--monthly", type=float)
    chk.add_argument("--allow-unknown", action="store_true")
    chk.add_argument("--json", action="store_true")
    rep = sub.add_parser("report")
    rep.add_argument("--month")
    rep.add_argument("--session")
    rep.add_argument("--run-id")
    rep.add_argument("--json", action="store_true")
    scn = sub.add_parser("scan")
    scn.add_argument("--path", required=True)
    scn.add_argument("--calls-per-month", type=int)
    scn.add_argument("--max-monthly", type=float)
    scn.add_argument("--json", action="store_true")
    return parser


def main(argv: list) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return 2
    workspace = os.environ.get("OMEGA_WORKSPACE")
    cfg = config_mod.load(workspace=workspace)
    handlers = {"estimate": cmd_estimate, "record": cmd_record, "check": cmd_check, "report": cmd_report,
                "scan": cmd_scan}
    try:
        return handlers[args.command](args, cfg)
    except Exception as exc:
        sys.stderr.write("[tokentoll] internal error: %s: %s\n" % (exc.__class__.__name__, str(exc)[:200]))
        return EXIT_CORRUPT


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

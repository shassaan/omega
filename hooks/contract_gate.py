from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

import argparse
import json
import os
import secrets
import time
from typing import Optional

from hooks.lib import adapters, contracts, hashing, ledger, paths, redaction, state, testmap, transcript
from hooks.lib.io import Decision
from hooks.tdd_gate import FAIL, NOT_APPLICABLE, PASS, UNVERIFIED, GateResult

SCRIPT = "hooks/contract_gate.py"
PROPOSAL = "contract_proposal.json"
REQUEST = "contract_request.json"
APPROVAL = "contract_approval.json"
OVERRIDE = "contract_override.json"
DELETED = "<deleted>"
PII_RULE_NAMES = ("email", "ssn", "iban", "card", "phone-e164", "phone-us")


def _command(ctx) -> str:
    return adapters.harness_command(SCRIPT, getattr(ctx, "harness_root", None))


def _dir(ctx) -> Path:
    return state.session_dir(ctx)


def _read(ctx, name: str) -> Optional[dict]:
    data = state.read_json(_dir(ctx) / name, None)
    return data if isinstance(data, dict) else None


def _write(ctx, name: str, obj: dict) -> None:
    state.write_json_atomic(_dir(ctx) / name, obj)


def _contracts_root(ctx) -> str:
    rel_dir = ctx.cfg.get("contracts.dir", contracts.DEFAULT_DIR) if getattr(ctx, "cfg", None) is not None \
        else contracts.DEFAULT_DIR
    return os.path.normpath(os.path.join(ctx.workspace, rel_dir or contracts.DEFAULT_DIR))


def is_contract_path(path: str, ctx) -> bool:
    if not path or not str(path).lower().endswith(".md"):
        return False
    if os.path.basename(str(path)).lower() == "readme.md":
        return False
    root = _contracts_root(ctx)
    for form in {os.path.abspath(str(path)), os.path.realpath(str(path))}:
        for base in {root, os.path.realpath(root)}:
            if form.startswith(base.rstrip("/") + "/"):
                return True
    return False


def _posix(value: str) -> str:
    text = Path(str(value)).as_posix()
    while text.startswith("./"):
        text = text[2:]
    return text


def _rel(ctx, path: str) -> str:
    return paths.rel(path, ctx.workspace)


def _clean_rel(ctx, value: str) -> str:
    text = str(value)
    if os.path.isabs(os.path.expanduser(text)):
        return _rel(ctx, os.path.expanduser(text))
    text = Path(text).as_posix()
    while text.startswith("./"):
        text = text[2:]
    return text


def _covers(proposal: Optional[dict], rel: str) -> bool:
    if not proposal:
        return False
    files = proposal.get("files")
    if not isinstance(files, list):
        return False
    return not files or rel in files


def _refusal(ctx, rel: str) -> str:
    return ("[contract-gate] refused: %s is a contract. Post the scenarios in chat, say which are new, changed or "
            "removed and every judgment call, ask the human, then run: %s propose --session %s --file %s"
            % (rel, _command(ctx), ctx.session_id, rel))


def write_gate(event, ctx) -> Decision:
    proposal = None
    loaded = False
    for mutation in getattr(event, "mutations", None) or []:
        if not is_contract_path(mutation.path, ctx):
            continue
        if not loaded:
            proposal = _read(ctx, PROPOSAL)
            loaded = True
        rel = _rel(ctx, mutation.path)
        if not _covers(proposal, rel):
            return Decision("deny", reason=_refusal(ctx, rel))
    return Decision("allow")


def propose(ctx, files: list) -> dict:
    ts, ts_ns = state.stamp()
    rels: list = []
    for item in files or []:
        rel = _clean_rel(ctx, item)
        if rel and rel not in rels:
            rels.append(rel)
    proposal = {"proposal_id": "cp-" + secrets.token_hex(4), "files": rels, "ts": ts, "ts_ns": ts_ns,
                "session_id": ctx.session_id}
    _write(ctx, PROPOSAL, proposal)
    return proposal


def _touched(ctx) -> list:
    return [p for p in ledger.contracts_touched(ctx)]


def in_scope(ctx, cfg) -> list:
    found: list = []
    for path in _touched(ctx):
        absolute = os.path.abspath(path)
        if absolute not in found:
            found.append(absolute)
    sources = set(ledger.source_paths(ctx, cfg))
    if sources:
        for contract in contracts.load_all(ctx.workspace, cfg):
            if set(_posix(p) for p in contract.code) & sources:
                absolute = os.path.abspath(contract.path)
                if absolute not in found:
                    found.append(absolute)
    return found


def _slug_key(path: str, contract=None) -> str:
    if contract is not None and contract.slug:
        return contract.slug
    return Path(path).stem


def _load(ctx, path: str, strict: bool):
    if not os.path.isfile(path):
        return None
    return contracts.load_file(path, ctx.workspace, strict_existence=strict)


def combine(per_slug: dict) -> str:
    return hashing.sha256_text("\n".join("%s:%s" % (slug, fp) for slug, fp in sorted(per_slug.items())))


def current_fingerprint(ctx, cfg) -> tuple:
    per_slug: dict = {}
    for path in in_scope(ctx, cfg):
        contract = _load(ctx, path, False)
        if contract is None:
            per_slug[_slug_key(path)] = DELETED
        else:
            per_slug[_slug_key(path, contract)] = contracts.fingerprint(contract)
    return combine(per_slug), per_slug


def request(ctx) -> dict:
    combined, per_slug = current_fingerprint(ctx, ctx.cfg)
    proposal = _read(ctx, PROPOSAL)
    ts, ts_ns = state.stamp()
    obj = {"fingerprint": combined, "per_slug": per_slug, "proposal_id": proposal.get("proposal_id") if proposal else None,
           "consumed": False, "ts": ts, "ts_ns": ts_ns}
    _write(ctx, REQUEST, obj)
    return obj


def _ui_mode(ctx) -> bool:
    return bool(os.environ.get("OMEGA_HUMAN_LOG")) or bool(getattr(ctx, "run_id", None))


def binding_problem(ctx, cfg, proposal: Optional[dict], req: Optional[dict]) -> Optional[str]:
    if req:
        combined, _ = current_fingerprint(ctx, cfg)
        if req.get("fingerprint") != combined:
            return ("the contract changed after you asked — show the human the current scenarios, run %s request "
                    "--session %s and ask again" % (_command(ctx), ctx.session_id))
        if proposal and int(proposal.get("ts_ns") or 0) > int(req.get("ts_ns") or 0):
            return ("a newer proposal exists than your request — run %s request --session %s and ask the human about "
                    "the current version" % (_command(ctx), ctx.session_id))
    return None


def record(ctx, quote: str, turns: list) -> tuple:
    cfg = ctx.cfg
    proposal = _read(ctx, PROPOSAL)
    req = _read(ctx, REQUEST)
    if not proposal and not req:
        return False, ("nothing was proposed — post the scenarios, run %s propose --session %s and ask the human "
                       "before recording an answer" % (_command(ctx), ctx.session_id))
    problem = binding_problem(ctx, cfg, proposal, req)
    if problem:
        return False, problem
    asked_at = max(int((proposal or {}).get("ts_ns") or 0), int((req or {}).get("ts_ns") or 0))
    min_chars = int(cfg.get("contracts.min_quote_chars", transcript.MIN_QUOTE_CHARS) or transcript.MIN_QUOTE_CHARS)
    accepted, reason = transcript.verify_human_answer(turns, asked_at, quote, min_chars)
    if not accepted:
        return False, reason
    turn = transcript.matching_turn(turns, asked_at, quote)
    if turn is None:
        return False, "no human turn since the proposal contains %r" % quote.strip()[:60]
    combined, per_slug = current_fingerprint(ctx, cfg)
    ts, ts_ns = state.stamp()
    approval = {
        "fingerprint": combined,
        "per_slug": per_slug,
        "proposal_id": (proposal or {}).get("proposal_id"),
        "quote": quote.strip()[:400],
        "turn_uuid": turn.uuid,
        "turn_ts": turn.ts.strftime("%Y-%m-%dT%H:%M:%SZ") if turn.ts else None,
        "turn_ts_ns": turn.ts_ns,
        "turn_source": turn.source,
        "channel": turn.channel,
        "asked_at_ns": asked_at,
        "recorded_ts": ts,
        "ts": ts,
        "ts_ns": ts_ns,
        "recorded_by": "contract_gate.record",
    }
    _write(ctx, APPROVAL, approval)
    return True, reason


def override(ctx, token: str, reason: str, turns: list) -> tuple:
    stored = state.read_override_token(ctx)
    if not token or not stored or token.strip() != stored:
        return False, "that is not this session's override token — only the human can relay it"
    if not reason or not reason.strip():
        return False, "give a --reason that says why the human released the contract gate"
    turn = transcript.quoted_turn(turns, stored)
    if turn is None:
        return False, ("the token does not appear in any human turn of this session — the human must send it in "
                       "chat themselves")
    ts, ts_ns = state.stamp()
    _write(ctx, OVERRIDE, {"token": stored, "reason": reason.strip()[:400], "turn_uuid": turn.uuid, "ts": ts,
                           "ts_ns": ts_ns, "consumed": False})
    return True, "override recorded: the next Stop passes the contract and review gates without approval (NOT approved)"


def is_nontrivial(ctx, cfg) -> tuple:
    nontrivial = cfg.get("contracts.nontrivial", {}) or {}
    threshold = int(nontrivial.get("min_source_files", 3) or 3)
    sources = ledger.source_paths(ctx, cfg)
    if len(sources) >= threshold:
        return True, "%d source files changed (threshold %d)" % (len(sources), threshold)
    globs = nontrivial.get("always_globs", []) or []
    for path in ledger.paths(ctx):
        rel = _rel(ctx, path)
        if rel.startswith("/"):
            continue
        if paths.match_globs(rel, globs) and not is_contract_path(path, ctx):
            return True, "%s is a sensitive path (contracts.nontrivial.always_globs)" % rel
    if nontrivial.get("new_source_file_counts", True):
        for row in ledger.rows(ctx):
            if row.get("kind") != "added":
                continue
            rel = row.get("rel") or _rel(ctx, row.get("path", ""))
            if not str(rel).startswith("/") and testmap.is_source(rel, cfg):
                return True, "new source file %s" % rel
    return False, "%d existing source file(s) changed" % len(sources)


def _entry(ctx, cfg, path: str, sources: set, touched: set) -> dict:
    contract = _load(ctx, path, True)
    rel = _rel(ctx, path)
    if contract is None:
        return {"slug": Path(path).stem, "path": rel, "fingerprint": DELETED, "valid": True, "errors": [],
                "warnings": ["W000: contract deleted in this session"], "code": [], "tests": [], "seams": {},
                "not_applicable": [], "code_in_ledger": [], "touched_this_session": path in touched}
    code = [_posix(p) for p in contract.code]
    return {"slug": contract.slug or Path(path).stem, "path": rel, "fingerprint": contracts.fingerprint(contract),
            "valid": contracts.is_valid(contract), "errors": list(contract.errors), "warnings": list(contract.warnings),
            "code": code, "tests": [_posix(p) for p in contract.tests],
            "seams": contracts.seam_counts(contract), "not_applicable": contracts.not_applicable(contract),
            "code_in_ledger": [c for c in code if c in sources], "touched_this_session": path in touched}


def report(ctx, cfg) -> dict:
    nontrivial, why = is_nontrivial(ctx, cfg)
    sources = set(ledger.source_paths(ctx, cfg))
    touched = set(os.path.abspath(p) for p in _touched(ctx))
    entries = [_entry(ctx, cfg, path, sources, touched) for path in in_scope(ctx, cfg)]
    covered: set = set()
    for entry in entries:
        covered.update(entry.get("code") or [])
    uncovered = sorted(s for s in sources if s not in covered) if nontrivial else []
    errors = ["%s: %s" % (e["slug"], err) for e in entries for err in e["errors"] if err.startswith("E")]
    return {"nontrivial": nontrivial, "reason": why, "contracts": entries, "uncovered_paths": uncovered,
            "errors": errors, "touched": sorted(_rel(ctx, p) for p in touched)}


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _consume_override(ctx) -> Optional[dict]:
    found = _read(ctx, OVERRIDE)
    if not found or found.get("consumed"):
        return None
    return found


def check(ctx, cfg) -> GateResult:
    started = time.monotonic()
    required = bool(cfg.get("stop.gates.contract.required", True))
    body = report(ctx, cfg)
    entries = body["contracts"]
    overridden = _consume_override(ctx)
    if not body["nontrivial"] and not body["touched"]:
        return GateResult("contract", NOT_APPLICABLE, required, "trivial change (%s); no contract touched" % body["reason"],
                          entries, _ms(started), dict(body, verified=True))
    problems: list = []
    for error in body["errors"]:
        problems.append(error)
    if body["uncovered_paths"]:
        problems.append("no contract covers %s (non-trivial: %s) — write docs/contracts/<slug>.md listing it under code:"
                        % (", ".join(body["uncovered_paths"]), body["reason"]))
    if problems and overridden:
        return GateResult("contract", PASS, required, "released by human override %s: NOT verified (%s)" %
                          (overridden.get("token"), problems[0]), entries, _ms(started),
                          dict(body, verified=False, overridden=True))
    if problems:
        detail = problems[0] + ("" if len(problems) == 1 else " (+%d more)" % (len(problems) - 1))
        return GateResult("contract", FAIL, required, detail, entries, _ms(started), dict(body, verified=False))
    names = ", ".join(e["slug"] for e in entries) or "none"
    return GateResult("contract", PASS, required, "%d contract(s) valid and covering: %s" % (len(entries), names),
                      entries, _ms(started), dict(body, verified=True))


def _scan(ctx, cfg) -> tuple:
    secrets_hits: list = []
    pii_hits: list = []
    pii_globs = cfg.get("redaction.pii_fail_globs", []) or []
    pii_fail = False
    for path in ledger.existing(ctx):
        rel = _rel(ctx, path)
        if rel.startswith("/") or redaction.is_fixture(rel, cfg):
            continue
        for hit in redaction.scan_file(path, pii=True):
            row = {"rule": hit.rule, "path": rel, "line": hit.line}
            if hit.rule in PII_RULE_NAMES:
                pii_hits.append(row)
                if paths.match_globs(rel, pii_globs):
                    pii_fail = True
            else:
                secrets_hits.append(row)
    secrets_scan = {"status": FAIL if secrets_hits else PASS, "hits": secrets_hits[:200]}
    pii_scan = {"status": FAIL if pii_fail else PASS, "hits": pii_hits[:200]}
    return secrets_scan, pii_scan


def _awaiting(ctx) -> str:
    if _ui_mode(ctx):
        return "awaiting human sign-off in the dashboard (Approvals tab)"
    return ("awaiting human sign-off — ask in chat, then run: %s record --session %s --quote \"<their words>\""
            % (_command(ctx), ctx.session_id))


def _approvals(ctx, approval: Optional[dict], per_slug: dict, newest_id: Optional[str]) -> list:
    if not approval:
        return []
    rows: list = []
    approved = approval.get("per_slug") or {}
    for slug in sorted(set(approved) | set(per_slug)):
        superseded = (approval.get("proposal_id") != newest_id) or approved.get(slug) != per_slug.get(slug)
        rows.append({"slug": slug, "fingerprint": approved.get(slug) or "", "proposal_id": approval.get("proposal_id") or "",
                     "quote": approval.get("quote", ""), "turn_uuid": approval.get("turn_uuid", ""),
                     "turn_ts": approval.get("turn_ts") or "", "turn_source": approval.get("turn_source", ""),
                     "channel": approval.get("channel", "transcript"), "recorded_ts": approval.get("recorded_ts", ""),
                     "recorded_by": approval.get("recorded_by", "contract_gate.record"), "superseded": bool(superseded)})
    return rows


def review(ctx, cfg) -> GateResult:
    started = time.monotonic()
    required = bool(cfg.get("stop.gates.review.required", True))
    secrets_scan, pii_scan = _scan(ctx, cfg)
    body = report(ctx, cfg)
    combined, per_slug = current_fingerprint(ctx, cfg)
    proposal = _read(ctx, PROPOSAL)
    newest_id = (proposal or {}).get("proposal_id")
    approval = _read(ctx, APPROVAL)
    req = _read(ctx, REQUEST)
    found_override = _read(ctx, OVERRIDE)
    data = {"approvals": _approvals(ctx, approval, per_slug, newest_id),
            "overrides": [found_override] if found_override else [],
            "secrets_scan": secrets_scan, "pii_scan": pii_scan, "channel": transcript.channel_of(ctx),
            "fingerprint": combined, "per_slug": per_slug, "verified": False, "pending_request": False}
    items = list(data["approvals"])
    scan_problems: list = []
    if secrets_scan["status"] == FAIL:
        first = secrets_scan["hits"][0]
        scan_problems.append("secret %s in %s:%s" % (first["rule"], first["path"], first["line"]))
    if pii_scan["status"] == FAIL:
        first = next(h for h in pii_scan["hits"] if paths.match_globs(h["path"], cfg.get("redaction.pii_fail_globs", []) or []))
        scan_problems.append("PII %s in %s:%s" % (first["rule"], first["path"], first["line"]))
    if scan_problems:
        detail = "; ".join(scan_problems) + " — remove it and reference secrets by name"
        return GateResult("review", FAIL, required, detail, items, _ms(started), data)
    if not body["nontrivial"] and not body["touched"]:
        data["verified"] = True
        return GateResult("review", NOT_APPLICABLE, required, "no contract needs sign-off (secret and PII scans pass)",
                          items, _ms(started), data)
    if not per_slug:
        return GateResult("review", FAIL, required, "no contract in scope to sign off — write one first",
                          items, _ms(started), data)
    pending_override = _consume_override(ctx)
    if pending_override:
        ts, ts_ns = state.stamp()
        consumed = dict(pending_override, consumed=True, consumed_ts=ts, consumed_ts_ns=ts_ns)
        _write(ctx, OVERRIDE, consumed)
        data["overrides"] = [consumed]
        return GateResult("review", PASS, required, "released by human override %s: NOT approved (%s)" %
                          (pending_override.get("token"), pending_override.get("reason", "")), items, _ms(started),
                          dict(data, overridden=True))
    if approval and approval.get("fingerprint") == combined:
        if approval.get("proposal_id") == newest_id:
            data["verified"] = True
            return GateResult("review", PASS, required, "approved by the human (%s): %r" %
                              (approval.get("turn_source", "?"), approval.get("quote", "")[:60]), items, _ms(started), data)
        return GateResult("review", FAIL, required, "superseded: a newer proposal (%s) replaced the approved one — ask "
                          "again. %s" % (newest_id, _awaiting(ctx)), items, _ms(started), data)
    if req and req.get("fingerprint") == combined:
        if not req.get("consumed"):
            ts, ts_ns = state.stamp()
            _write(ctx, REQUEST, dict(req, consumed=True, consumed_ts=ts, consumed_ts_ns=ts_ns))
            data["pending_request"] = True
            return GateResult("review", PASS, required, "waiting for the human's answer: this Stop is allowed once "
                              "while you wait; NOT approved", items, _ms(started), data)
        return GateResult("review", FAIL, required, "waiting is not agreeing: the request was already used to end one "
                          "turn. %s" % _awaiting(ctx), items, _ms(started), data)
    if approval:
        return GateResult("review", FAIL, required, "stale: the contract changed after approval. %s" % _awaiting(ctx),
                          items, _ms(started), data)
    slugs = ", ".join(sorted(per_slug))
    return GateResult("review", FAIL, required, "%s: %s" % (slugs, _awaiting(ctx)), items, _ms(started), data)


def status(ctx) -> dict:
    cfg = ctx.cfg
    combined, per_slug = current_fingerprint(ctx, cfg)
    body = report(ctx, cfg)
    turns = transcript.read_human_turns(ctx)
    approval = _read(ctx, APPROVAL)
    proposal = _read(ctx, PROPOSAL)
    req = _read(ctx, REQUEST)
    found_override = _read(ctx, OVERRIDE)
    approved = bool(approval and approval.get("fingerprint") == combined and
                    approval.get("proposal_id") == (proposal or {}).get("proposal_id"))
    return {"session_id": ctx.session_id, "workspace": ctx.workspace, "provider": ctx.provider,
            "fingerprint": combined, "per_slug": per_slug, "nontrivial": body["nontrivial"], "reason": body["reason"],
            "contracts": body["contracts"], "uncovered_paths": body["uncovered_paths"], "errors": body["errors"],
            "touched": body["touched"], "proposal": proposal, "request": req, "approval": approval,
            "override": {k: v for k, v in found_override.items() if k != "token"} if found_override else None,
            "approved": approved, "human_turns": len(turns), "channel": transcript.channel_of(ctx),
            "transcript_path": ctx.transcript_path}


def _print_status(info: dict) -> None:
    out = sys.stdout
    out.write("[contract-gate] session %s · %s · %s\n" % (info["session_id"], "non-trivial" if info["nontrivial"] else "trivial",
                                                      info["reason"]))
    for entry in info["contracts"]:
        out.write("  %-28s %s %s\n" % (entry["slug"], "valid" if entry["valid"] else "INVALID",
                                       "; ".join(entry["errors"][:3])))
    if info["uncovered_paths"]:
        out.write("  uncovered: %s\n" % ", ".join(info["uncovered_paths"]))
    out.write("  proposal: %s · request: %s · approved: %s · human turns: %d\n" % (
        (info["proposal"] or {}).get("proposal_id", "none"),
        "consumed" if (info["request"] or {}).get("consumed") else ("open" if info["request"] else "none"),
        "yes" if info["approved"] else "no", info["human_turns"]))


def _context(args):
    return state.load_context(args.session, args.workspace, args.provider)


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--session", dest="sub_session")
    parser.add_argument("--workspace", dest="sub_workspace")
    parser.add_argument("--provider", dest="sub_provider", choices=("claude", "codex"))


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="contract_gate.py", description="Contract-first gate and human sign-off.")
    parser.add_argument("--session")
    parser.add_argument("--workspace")
    parser.add_argument("--provider", choices=("claude", "codex"))
    sub = parser.add_subparsers(dest="cmd")
    p_propose = sub.add_parser("propose")
    p_propose.add_argument("--file", action="append", default=[])
    _common(p_propose)
    p_request = sub.add_parser("request")
    _common(p_request)
    p_record = sub.add_parser("record")
    p_record.add_argument("--quote", required=True)
    _common(p_record)
    p_status = sub.add_parser("status")
    p_status.add_argument("--json", action="store_true")
    _common(p_status)
    p_override = sub.add_parser("override")
    p_override.add_argument("--token", required=True)
    p_override.add_argument("--reason", required=True)
    _common(p_override)
    p_check = sub.add_parser("check")
    p_check.add_argument("--json", action="store_true")
    _common(p_check)
    p_validate = sub.add_parser("validate")
    p_validate.add_argument("file")
    p_validate.add_argument("--json", action="store_true")
    _common(p_validate)
    args = parser.parse_args(argv[1:])
    args.session = getattr(args, "sub_session", None) or args.session
    args.workspace = getattr(args, "sub_workspace", None) or args.workspace
    args.provider = getattr(args, "sub_provider", None) or args.provider
    command = args.cmd or "status"
    try:
        if command == "validate":
            workspace = os.path.realpath(args.workspace or paths.workspace_of({}))
            target = args.file if os.path.isabs(args.file) else os.path.join(workspace, args.file)
            contract = contracts.load_file(target, workspace, strict_existence=False)
            if not os.path.isfile(target):
                sys.stderr.write("[contract-gate] %s does not exist\n" % args.file)
                return 1
            if getattr(args, "json", False):
                sys.stdout.write(json.dumps({"path": args.file, "valid": contracts.is_valid(contract),
                                             "errors": contract.errors, "warnings": contract.warnings,
                                             "fingerprint": contracts.fingerprint(contract)}) + "\n")
            else:
                for line in contract.errors + contract.warnings:
                    sys.stdout.write("%s\n" % line)
                sys.stdout.write("[contract-gate] %s: %s\n" % (args.file, "valid" if contracts.is_valid(contract) else "INVALID"))
            return 0 if contracts.is_valid(contract) else 1
        ctx = _context(args)
        if command == "propose":
            proposal = propose(ctx, args.file)
            scope = ", ".join(proposal["files"]) or "every contract"
            sys.stdout.write("[contract-gate] proposal %s covers %s. Write the contract, then run: %s request --session %s\n"
                             % (proposal["proposal_id"], scope, _command(ctx), ctx.session_id))
            return 0
        if command == "request":
            req = request(ctx)
            sys.stdout.write("[contract-gate] sign-off requested for fingerprint %s. Ask the human to approve in their own "
                             "words, then run: %s record --session %s --quote \"<their words>\"\n"
                             % (req["fingerprint"][:12], _command(ctx), ctx.session_id))
            return 0
        if command == "record":
            ok, reason = record(ctx, args.quote, transcript.read_human_turns(ctx))
            if ok:
                sys.stdout.write("[contract-gate] recorded: %s\n" % reason)
                return 0
            sys.stderr.write("[contract-gate] refused: %s\n" % reason)
            return 1
        if command == "override":
            ok, reason = override(ctx, args.token, args.reason, transcript.read_human_turns(ctx))
            if ok:
                sys.stdout.write("[contract-gate] %s\n" % reason)
                return 0
            sys.stderr.write("[contract-gate] refused: %s\n" % reason)
            return 1
        if command == "check":
            result = check(ctx, ctx.cfg)
            if getattr(args, "json", False):
                sys.stdout.write(json.dumps({"gate": result.gate, "status": result.status, "detail": result.detail,
                                             "items": result.items, "data": result.data}) + "\n")
            else:
                sys.stdout.write("[contract-gate] %s %s\n" % (result.status, result.detail))
            return 1 if result.status in (FAIL, UNVERIFIED) else 0
        info = status(ctx)
        if getattr(args, "json", False):
            sys.stdout.write(json.dumps(info, default=str) + "\n")
        else:
            _print_status(info)
        return 0
    except state.AmbiguousSession as exc:
        sys.stderr.write("[contract-gate] %s\n" % exc)
        return 2
    except Exception as exc:
        sys.stderr.write("[contract-gate] error: %s: %s\n" % (exc.__class__.__name__, exc))
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

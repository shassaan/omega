from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import concurrent.futures
import dataclasses
import importlib
import json
import os
import re
import time
from typing import Optional

from hooks import ship_readiness, stop_proof, tokentoll_gate
from hooks.lib import OMEGA_VERSION, adapters, contracts, event, gitsnap, hashing, jobstore, ledger, paths
from hooks.lib import io as io_mod
from hooks.lib import redaction, state, testmap, transcript
from hooks.stop_proof import FAIL, NOT_APPLICABLE, PASS, UNVERIFIED, GateResult

STATUSES = (PASS, FAIL, UNVERIFIED, NOT_APPLICABLE)
GATE_ORDER = ("proof", "tdd", "contract", "review", "cost", "ship")
OMEGA_GATE = "harness"
SCRIPT = "bin/stop_orchestrator.py"
ATTEMPTS = "stop_attempts"
LAST_STOP = "last_stop.json"
STOP_OVERRIDE = "stop_override.json"
CONTRACT_OVERRIDE = "contract_override.json"
CONTRACT_APPROVAL = "contract_approval.json"
CONTRACT_PROPOSAL = "contract_proposal.json"
CLEARANCE_KINDS = ("proof", "contract", "review")
MAX_ITEM_LINES = 12
SHA = re.compile(r"^[0-9a-f]{64}$")
FILE_HASH = re.compile(r"^([0-9a-f]{64}|<deleted>|<dir>)$")
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CODE = re.compile(r"^[EW]0\d{2}: .+$")
PROPOSAL = re.compile(r"^cp-[0-9a-f]{8}$")
TOKEN = re.compile(r"^hs-[0-9a-f]{6}$")
PII_RULES = tuple(name for name, _ in redaction.PII_RULES)
UI_REVIEW_DETAIL = "awaiting human sign-off in the dashboard (Approvals tab)"


def one_line(text, limit: int = 400) -> str:
    return redaction.redact_text(" ".join(str(text or "").split())[:limit])


def command_for(script: str) -> str:
    return adapters.harness_command(script)


def ui_mode() -> bool:
    return transcript.channel_of() == "ui"


def _attr(raw, name: str, default=None):
    if isinstance(raw, dict):
        return raw.get(name, default)
    return getattr(raw, name, default)


def _plain(item):
    if isinstance(item, dict):
        return item
    if dataclasses.is_dataclass(item) and not isinstance(item, type):
        return dataclasses.asdict(item)
    if hasattr(item, "__dict__"):
        return dict(vars(item))
    return {"value": str(item)}


def coerce(gate: str, raw, required: bool, duration_ms: int) -> GateResult:
    if raw is None:
        return GateResult(gate, UNVERIFIED, required, "gate returned no result", [], duration_ms)
    status = _attr(raw, "status")
    detail = _attr(raw, "detail", "")
    if status not in STATUSES:
        detail = "gate returned an unknown status %r" % (status,)
        status = UNVERIFIED
    items = [_plain(i) for i in (_attr(raw, "items", None) or [])]
    data = _attr(raw, "data", None)
    return GateResult(gate=gate, status=status, required=required, detail=one_line(detail), items=items,
                      duration_ms=int(_attr(raw, "duration_ms", None) or duration_ms),
                      data=dict(data) if isinstance(data, dict) else {})


def gate_required(cfg, gate: str) -> bool:
    return bool(cfg.get("stop.gates.%s.required" % gate, True))


def gate_timeout(cfg, gate: str) -> float:
    return float(cfg.get("stop.gates.%s.timeout_s" % gate, 60) or 60)


def guards_module(name: str):
    return importlib.import_module("hooks.%s" % name)


def _proof_gate(ctx, cfg, scope, deps):
    return stop_proof.prove(ctx, cfg, scope)


def _tdd_gate(ctx, cfg, scope, deps):
    return guards_module("tdd_gate").green_check(ctx, cfg)


def _contract_gate(ctx, cfg, scope, deps):
    return guards_module("contract_gate").check(ctx, cfg)


def _review_gate(ctx, cfg, scope, deps):
    return guards_module("contract_gate").review(ctx, cfg)


def _cost_gate(ctx, cfg, scope, deps):
    return tokentoll_gate.stop_check(ctx, cfg)


def ship_gate_result(result: dict, required: bool, duration_ms: int) -> GateResult:
    overall = result.get("status")
    status = FAIL if overall == FAIL else ship_readiness.worst_tier(result)
    items = []
    for tier in ship_readiness.TIERS:
        body = (result.get("tiers") or {}).get(tier) or {}
        for check in body.get("checks") or []:
            if check.get("status") in (FAIL, UNVERIFIED):
                items.append({"check": "%s/%s" % (tier, check.get("id")), "status": check.get("status"),
                              "detail": check.get("detail", ""), "required": check.get("required", True),
                              "hint": check.get("hint", "")})
    return GateResult("ship", status, required, ship_readiness.summary(result), items, duration_ms, {"ship": result})


def _ship_gate(ctx, cfg, scope, deps):
    started = time.monotonic()
    application_results = None
    proof_future = deps.get("proof")
    if proof_future is not None:
        try:
            proof = proof_future.result(timeout=gate_timeout(cfg, "proof"))
            application_results = list(_attr(proof, "items", None) or []) or None
        except Exception:
            application_results = None
    mode = str(cfg.get("stop.gates.ship.mode", "fast") or "fast")
    result = ship_readiness.run(ctx.workspace, cfg, mode=mode, application_results=application_results)
    return ship_gate_result(result, gate_required(cfg, "ship"), int((time.monotonic() - started) * 1000))


DEFAULT_GATES = {"proof": _proof_gate, "tdd": _tdd_gate, "contract": _contract_gate, "review": _review_gate,
                 "cost": _cost_gate, "ship": _ship_gate}


def run_gates(ctx, cfg, scope: list, gate_fns: Optional[dict] = None) -> tuple:
    fns = dict(DEFAULT_GATES)
    fns.update(gate_fns or {})
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=6)
    started = time.monotonic()
    futures: dict = {}
    timed_out = False
    try:
        for gate in GATE_ORDER:
            futures[gate] = pool.submit(fns[gate], ctx, cfg, scope, futures)
        results: list = []
        for gate in GATE_ORDER:
            required = gate_required(cfg, gate)
            limit = gate_timeout(cfg, gate)
            remaining = max(0.0, started + limit - time.monotonic())
            try:
                raw = futures[gate].result(timeout=remaining)
                results.append(coerce(gate, raw, required, int((time.monotonic() - started) * 1000)))
            except concurrent.futures.TimeoutError:
                timed_out = True
                results.append(GateResult(gate, UNVERIFIED, required, "gate timed out after %ds" % int(limit), [],
                                          int(limit * 1000)))
            except Exception as exc:
                results.append(GateResult(gate, UNVERIFIED, required, one_line("gate crashed: %s: %s" % (
                    exc.__class__.__name__, exc)), [], int((time.monotonic() - started) * 1000)))
    finally:
        pool.shutdown(wait=False)
    return results, timed_out


def scope_of(ctx) -> list:
    found: list = []
    for item in ledger.paths(ctx) + ledger.contracts_touched(ctx):
        if item not in found:
            found.append(item)
    return found


def split_scope(ctx, scope: list) -> tuple:
    inside: list = []
    outside: list = []
    for item in scope:
        relative = paths.rel(item, ctx.workspace)
        if relative.startswith("/") or relative == ".":
            outside.append(item)
        else:
            inside.append(item)
    return inside, outside


def blocks(result: GateResult, cfg) -> bool:
    if not result.required or result.status not in (FAIL, UNVERIFIED):
        return False
    if result.gate == "ship" and result.status == UNVERIFIED:
        return bool(cfg.get("stop.gates.ship.unverified_blocks", False))
    return True


def blocker_entries(result: GateResult) -> list:
    entries: list = []
    for item in result.items:
        if not isinstance(item, dict):
            continue
        status = item.get("status")
        if status not in (FAIL, UNVERIFIED) or item.get("required") is False:
            continue
        name = item.get("check") or item.get("id") or item.get("source") or item.get("slug") or result.gate
        entries.append({"gate": result.gate, "check": str(name), "status": status,
                        "detail": one_line(item.get("detail") or result.detail)})
    if not entries:
        entries.append({"gate": result.gate, "check": result.gate,
                        "status": result.status if result.status in (FAIL, UNVERIFIED) else FAIL,
                        "detail": one_line(result.detail)})
    return entries


def item_text(gate: str, item: dict) -> Optional[str]:
    status = item.get("status")
    if status in (PASS, NOT_APPLICABLE):
        return None
    if "source" in item:
        test = item.get("test") or "(no test)"
        sha = str(item.get("test_sha256") or "")[:7]
        return "%s ← %s%s: %s" % (item.get("source"), test, ("@" + sha) if sha and sha[0] != "<" else "",
                                  item.get("detail") or status)
    if "check" in item:
        return "%s %s %s" % (item.get("check"), status or "", item.get("detail") or "")
    if "slug" in item:
        errors = item.get("errors") or []
        return "%s: %s" % (item.get("slug"), "; ".join(errors[:3]) if errors else (item.get("detail") or status))
    if "reason" in item:
        return str(item.get("reason"))
    return json.dumps(item, ensure_ascii=False, sort_keys=True)[:200]


def summary_lines(results: list) -> list:
    lines: list = []
    order = {g: i for i, g in enumerate(GATE_ORDER + (OMEGA_GATE,))}
    for result in sorted(results, key=lambda r: order.get(r.gate, 99)):
        detail = result.detail
        if result.gate == "review" and ui_mode() and result.status in (FAIL, UNVERIFIED) \
                and ("record" in detail or "sign-off" in detail):
            detail = UI_REVIEW_DETAIL
        lines.append(("  %-8s %-14s %s" % (result.gate, result.status, detail)).rstrip())
        if result.status in (FAIL, UNVERIFIED):
            texts = [t for t in (item_text(result.gate, i) for i in result.items if isinstance(i, dict)) if t]
            for text in texts[:MAX_ITEM_LINES]:
                lines.append("      " + one_line(text, 240))
            if len(texts) > MAX_ITEM_LINES:
                lines.append("      … %d more" % (len(texts) - MAX_ITEM_LINES))
    return lines


def block_message(ctx, results: list, attempt: int, max_attempts: int) -> str:
    lines = ["[omega] stop blocked (attempt %d/%d): the following must PASS before this work is done"
             % (attempt, max_attempts)]
    lines += summary_lines(results)
    lines.append("Fix these and stop again. Commands: %s status · %s status · %s status" % (
        command_for("hooks/contract_gate.py"), command_for("hooks/tdd_gate.py"), command_for(SCRIPT)))
    if not ui_mode():
        token = state.read_override_token(ctx) or state.ensure_override_token(ctx)
        lines.append("A human can end this early by sending the token %s in chat; then run:" % token)
        lines.append('  %s override --session %s --token %s --reason "<why>"' % (command_for(SCRIPT), ctx.session_id,
                                                                                token))
    return "\n".join(lines)


def _job_ref(value) -> Optional[dict]:
    if not isinstance(value, dict):
        return None
    ts_ns = value.get("ts_ns")
    job_id = value.get("job_id")
    if not isinstance(ts_ns, int) or isinstance(ts_ns, bool) or ts_ns < 0 or not job_id:
        return None
    ts = value.get("ts") if isinstance(value.get("ts"), str) and ISO.match(value.get("ts")) else state.iso(ts_ns)
    rc = value.get("rc")
    return {"ts": ts, "ts_ns": ts_ns, "job_id": str(job_id), "rc": rc if isinstance(rc, int) else None}


def tdd_pairs(result: Optional[GateResult]) -> list:
    pairs: list = []
    for item in (result.items if result else []):
        if not isinstance(item, dict):
            continue
        source = item.get("source")
        if not isinstance(source, str) or not source or source.startswith("/"):
            continue
        sha = item.get("test_sha256")
        status = item.get("status") if item.get("status") in STATUSES else UNVERIFIED
        pairs.append({"source": source, "test": item.get("test") if isinstance(item.get("test"), str) else None,
                      "test_sha256": sha if isinstance(sha, str) and FILE_HASH.match(sha) else None,
                      "red": _job_ref(item.get("red")), "green": _job_ref(item.get("green")), "status": status,
                      "detail": one_line(item.get("detail") or "")})
    return pairs


def check_rows(result: Optional[GateResult]) -> list:
    rows: list = []
    for item in (result.items if result else []):
        if not isinstance(item, dict) or "check" not in item:
            continue
        rc = item.get("rc")
        rows.append({"gate": item.get("gate") if item.get("gate") in GATE_ORDER + (OMEGA_GATE,) else "proof",
                     "check": str(item.get("check") or "check"),
                     "status": item.get("status") if item.get("status") in STATUSES else UNVERIFIED,
                     "required": bool(item.get("required", True)), "detail": one_line(item.get("detail") or ""),
                     "rc": rc if isinstance(rc, int) and not isinstance(rc, bool) else None,
                     "duration_ms": max(0, int(item.get("duration_ms") or 0)),
                     "argv": [str(a) for a in item.get("argv") or []], "cwd": str(item.get("cwd") or ""),
                     "output_tail": redaction.redact_text(str(item.get("output_tail") or ""))[-4096:]})
    return rows


def cost_body(ctx, cfg, result: Optional[GateResult]) -> dict:
    entry = (result.data or {}).get("cost") if result else None
    if not isinstance(entry, dict):
        for item in (result.items if result else []):
            if isinstance(item, dict) and "caps" in item and "status" in item:
                entry = item
                break
    if not isinstance(entry, dict):
        entry = tokentoll_gate.not_applicable_entry(cfg, "cost gate did not run")
        entry["status"] = result.status if result else UNVERIFIED
    keys = ("status", "session_usd", "run_usd", "month_usd", "max_call_usd", "caps", "breaches", "warnings",
            "unknown_models")
    body = {k: entry.get(k) for k in keys}
    if body["status"] not in STATUSES:
        body["status"] = UNVERIFIED
    caps = body.get("caps") or {}
    body["caps"] = {k: float(caps.get(k, 0.0) or 0.0) for k in
                    ("per_call_usd", "per_session_usd", "per_run_usd", "monthly_usd")}
    for key in ("session_usd", "run_usd", "month_usd", "max_call_usd"):
        value = body.get(key)
        body[key] = float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None
    for key in ("breaches", "warnings", "unknown_models"):
        body[key] = [str(v) for v in body.get(key) or []]
    return body


def empty_ship(workspace: str, status: str = UNVERIFIED) -> dict:
    return {"schema": ship_readiness.SCHEMA, "ts": state.iso(), "workspace": workspace, "mode": "fast",
            "strict": False, "status": status,
            "tiers": {t: {"status": NOT_APPLICABLE, "applicable": False, "detected": [], "checks": []}
                      for t in ship_readiness.TIERS}}


def ship_body(ctx, result: Optional[GateResult]) -> dict:
    data = (result.data or {}).get("ship") if result else None
    if isinstance(data, dict) and data.get("schema") == ship_readiness.SCHEMA and isinstance(data.get("tiers"), dict):
        return data
    return empty_ship(ctx.workspace, UNVERIFIED if result is None or result.status != NOT_APPLICABLE else PASS)


def nontrivial(ctx, cfg) -> tuple:
    try:
        return tuple(guards_module("contract_gate").is_nontrivial(ctx, cfg))
    except Exception:
        pass
    reasons: list = []
    sources = ledger.source_paths(ctx, cfg)
    minimum = int(cfg.get("contracts.nontrivial.min_source_files", 3))
    if len(sources) >= minimum:
        reasons.append("%d source files touched" % len(sources))
    always = cfg.get("contracts.nontrivial.always_globs", []) or []
    rels = [paths.rel(p, ctx.workspace) for p in ledger.paths(ctx)]
    hits = [r for r in rels if not r.startswith("/") and paths.match_globs(r, always)]
    if hits:
        reasons.append("sensitive paths touched: %s" % ", ".join(hits[:5]))
    if cfg.get("contracts.nontrivial.new_source_file_counts", True):
        added = [r.get("rel") for r in ledger.rows(ctx) if r.get("kind") == "added"
                 and testmap.is_source(str(r.get("rel") or ""), cfg)]
        if added:
            reasons.append("new source file(s): %s" % ", ".join(added[:5]))
    return bool(reasons), "; ".join(reasons) if reasons else "trivial change"


def _slug(contract) -> str:
    value = contract.slug if SLUG.match(contract.slug or "") else re.sub(r"[^a-z0-9]+", "-",
                                                                         Path(contract.path).stem.lower()).strip("-")
    return value or "contract"


def _rels(items) -> list:
    out: list = []
    for item in items or []:
        text = Path(str(item)).as_posix()
        while text.startswith("./"):
            text = text[2:]
        if text and not text.startswith("/") and text not in out:
            out.append(text)
    return out


def contract_body(ctx, cfg) -> dict:
    is_nontrivial, reason = nontrivial(ctx, cfg)
    sources = ledger.source_paths(ctx, cfg)
    ledger_rels = set(paths.rel(p, ctx.workspace) for p in ledger.paths(ctx))
    touched = [os.path.abspath(p) for p in ledger.contracts_touched(ctx)]
    try:
        loaded = contracts.load_all(ctx.workspace, cfg)
    except OSError:
        loaded = []
    entries: list = []
    covered: set = set()
    errors: list = []
    seen: set = set()
    for contract in loaded:
        absolute = os.path.abspath(contract.path)
        code = _rels(contract.code)
        was_touched = absolute in touched or os.path.realpath(absolute) in [os.path.realpath(t) for t in touched]
        if not was_touched and not (set(code) & set(sources)):
            continue
        seen.add(os.path.realpath(absolute))
        checked = contracts.validate(contract, ctx.workspace, True)
        slug = _slug(checked)
        covered |= set(code)
        errors += ["%s: %s" % (slug, e) for e in checked.errors]
        entries.append({"slug": slug, "path": paths.rel(absolute, ctx.workspace),
                        "fingerprint": contracts.fingerprint(checked), "valid": contracts.is_valid(checked),
                        "errors": [e for e in checked.errors if CODE.match(e)],
                        "warnings": [w for w in checked.warnings if CODE.match(w)], "code": code,
                        "tests": _rels(checked.tests), "seams": contracts.seam_counts(checked),
                        "not_applicable": [s for s in contracts.not_applicable(checked) if s != "Unit"],
                        "code_in_ledger": [c for c in code if c in ledger_rels], "touched_this_session": was_touched})
    for path in touched:
        if os.path.realpath(path) in seen or os.path.exists(path):
            continue
        relative = paths.rel(path, ctx.workspace)
        if relative.startswith("/"):
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", Path(path).stem.lower()).strip("-") or "contract"
        entries.append({"slug": slug, "path": relative, "fingerprint": "<deleted>", "valid": False, "errors": [],
                        "warnings": ["W000: contract file deleted"], "code": [], "tests": [],
                        "seams": {"Unit": 0, "Integration": 0, "Functional": 0, "Journey": 0},
                        "not_applicable": [], "code_in_ledger": [], "touched_this_session": True})
    uncovered = [s for s in sources if s not in covered] if is_nontrivial else []
    return {"nontrivial": bool(is_nontrivial), "reason": one_line(reason), "contracts": entries,
            "uncovered_paths": uncovered, "errors": errors}


def _approval_rows(raw) -> list:
    if isinstance(raw, list):
        rows = [r for r in raw if isinstance(r, dict)]
    elif isinstance(raw, dict) and isinstance(raw.get("approvals"), list):
        rows = [r for r in raw["approvals"] if isinstance(r, dict)]
    elif isinstance(raw, dict):
        rows = [raw]
    else:
        rows = []
    expanded: list = []
    for row in rows:
        per_slug = row.get("per_slug")
        if isinstance(per_slug, dict) and per_slug:
            for slug, fingerprint in sorted(per_slug.items()):
                expanded.append(dict(row, slug=slug, fingerprint=fingerprint))
        else:
            expanded.append(row)
    return expanded


def approvals(ctx, reported: Optional[list] = None) -> list:
    directory = state.session_dir(ctx)
    proposal = state.read_json(directory / CONTRACT_PROPOSAL, {}) or {}
    newest = proposal.get("proposal_id") if isinstance(proposal, dict) else None
    source = reported if isinstance(reported, list) else state.read_json(directory / CONTRACT_APPROVAL, None)
    out: list = []
    for row in _approval_rows(source):
        fingerprint = row.get("fingerprint")
        proposal_id = row.get("proposal_id")
        quote = str(row.get("quote") or "")
        if not (isinstance(fingerprint, str) and (SHA.match(fingerprint) or fingerprint == "<deleted>")):
            continue
        if not (isinstance(proposal_id, str) and PROPOSAL.match(proposal_id)) or not quote or not row.get("turn_uuid"):
            continue
        slug = row.get("slug") if isinstance(row.get("slug"), str) and SLUG.match(row.get("slug")) else "combined"
        recorded = row.get("recorded_ts") if isinstance(row.get("recorded_ts"), str) and ISO.match(row["recorded_ts"]) \
            else state.iso(row.get("ts_ns") if isinstance(row.get("ts_ns"), int) else None)
        channel = row.get("channel") if row.get("channel") in ("transcript", "ui") else transcript.channel_of()
        turn_ts = row.get("turn_ts") if isinstance(row.get("turn_ts"), str) and row.get("turn_ts") else None
        out.append({"slug": slug, "fingerprint": fingerprint, "proposal_id": proposal_id, "quote": quote[:400],
                    "turn_uuid": str(row.get("turn_uuid")), "turn_ts": turn_ts,
                    "turn_source": str(row.get("turn_source") or "unknown"), "channel": channel,
                    "recorded_ts": recorded,
                    "recorded_by": row.get("recorded_by") if row.get("recorded_by") in ("contract_gate.record", "ui.server")
                    else "contract_gate.record",
                    "superseded": bool(row.get("superseded")) or bool(newest and newest != proposal_id)})
    return out


def data_verified(result: Optional[GateResult]) -> bool:
    return result is None or not isinstance(result.data, dict) or result.data.get("verified") is not False


def overrides(ctx) -> list:
    directory = state.session_dir(ctx)
    out: list = []
    for gate, name in (("contract", CONTRACT_OVERRIDE), ("stop", STOP_OVERRIDE)):
        row = state.read_json(directory / name, None)
        if not isinstance(row, dict):
            continue
        token = row.get("token")
        if not (isinstance(token, str) and TOKEN.match(token)) or not row.get("reason") or not row.get("turn_uuid"):
            continue
        ts_ns = row.get("ts_ns") if isinstance(row.get("ts_ns"), int) and not isinstance(row.get("ts_ns"), bool) else None
        entry = {"gate": gate, "token": token, "reason": one_line(row.get("reason")) or "override",
                 "turn_uuid": str(row.get("turn_uuid")),
                 "ts": row.get("ts") if isinstance(row.get("ts"), str) and ISO.match(row["ts"]) else state.iso(ts_ns),
                 "consumed": bool(row.get("consumed"))}
        if ts_ns is not None:
            entry["ts_ns"] = ts_ns
        out.append(entry)
    return out


def scans(ctx, cfg, scope_inside: list) -> tuple:
    secret_hits: list = []
    pii_hits: list = []
    pii_fail = False
    checked = 0
    pii_globs = cfg.get("redaction.pii_fail_globs", []) or []
    for path in scope_inside:
        if not os.path.isfile(path):
            continue
        relative = paths.rel(path, ctx.workspace)
        if relative.startswith("/") or redaction.is_fixture(relative, cfg):
            continue
        checked += 1
        for hit in redaction.scan_file(path, pii=True):
            row = {"rule": hit.rule, "path": relative, "line": max(1, int(hit.line or 1))}
            if hit.rule in PII_RULES:
                pii_hits.append(row)
                if paths.match_globs(relative, pii_globs):
                    pii_fail = True
            else:
                secret_hits.append(row)
    if checked == 0:
        return {"status": NOT_APPLICABLE, "hits": []}, {"status": NOT_APPLICABLE, "hits": []}
    return ({"status": FAIL if secret_hits else PASS, "hits": secret_hits},
            {"status": FAIL if pii_fail else PASS, "hits": pii_hits})


def apply_scans(results: list, secrets_scan: dict, pii_scan: dict) -> None:
    problems = []
    if secrets_scan["status"] == FAIL:
        problems.append("secret scan: " + ", ".join("%s %s:%d" % (h["rule"], h["path"], h["line"])
                                                    for h in secrets_scan["hits"][:5]))
    if pii_scan["status"] == FAIL:
        problems.append("PII scan: " + ", ".join("%s %s:%d" % (h["rule"], h["path"], h["line"])
                                                 for h in pii_scan["hits"][:5]))
    if not problems:
        return
    for result in results:
        if result.gate == "review":
            if result.status != FAIL:
                result.status = FAIL
                result.required = True
                result.detail = one_line("; ".join(problems))
            for text in problems:
                result.items.append({"check": "scan", "status": FAIL, "detail": text})
            return
    results.append(GateResult("review", FAIL, True, one_line("; ".join(problems)), [], 0))


def apply_contract(results: list, body: dict) -> None:
    problems = []
    if body["uncovered_paths"]:
        problems.append("uncovered_paths: no in-scope contract lists %s" % ", ".join(body["uncovered_paths"][:5]))
    invalid = [c["slug"] for c in body["contracts"] if not c["valid"]]
    if invalid:
        problems.append("invalid contract(s): %s" % ", ".join(invalid[:5]))
    if not problems:
        return
    for result in results:
        if result.gate == "contract":
            if result.status != FAIL:
                result.status = FAIL
                result.required = True
                result.detail = one_line("; ".join(problems))
            return
    results.append(GateResult("contract", FAIL, True, one_line("; ".join(problems)), [], 0))


def envelope(kind: str, ctx, stamp: tuple, files: dict, verified: bool, released: bool, overridden: bool,
             attempt: int) -> dict:
    return {"schema": "omega/%s/1" % kind, "omega_version": OMEGA_VERSION, "ts": stamp[0], "ts_ns": stamp[1],
            "session_id": ctx.session_id or "no-session", "provider": ctx.provider if ctx.provider in ("claude", "codex")
            else "claude", "workspace": ctx.workspace, "run_id": ctx.run_id, "verified": bool(verified),
            "released": bool(released), "overridden": bool(overridden), "attempt": max(0, int(attempt)),
            "files": dict(files), "files_digest": hashing.files_digest(files)}


def build_clearances(ctx, cfg, results: list, files: dict, blocking: list, attempt: int, released: bool,
                     overridden: bool, scope_inside: list, scan_pair: Optional[tuple] = None,
                     contract_data: Optional[dict] = None) -> dict:
    by_gate = {r.gate: r for r in results}
    stamp = state.stamp()
    harness_ok = not any(r.gate == OMEGA_GATE and r.status == FAIL for r in results)
    blocked_gates = {b["gate"] for b in blocking}
    trusted = not released and not overridden
    overall = trusted and not blocking
    contract_ok = trusted and harness_ok and "contract" not in blocked_gates and "contract" in by_gate \
        and data_verified(by_gate.get("contract"))
    review_ok = trusted and harness_ok and "review" not in blocked_gates and "review" in by_gate \
        and data_verified(by_gate.get("review"))
    reported = (by_gate["review"].data or {}).get("approvals") if "review" in by_gate else None
    secrets_scan, pii_scan = scan_pair if scan_pair else scans(ctx, cfg, scope_inside)
    proof = envelope("proof", ctx, stamp, files, overall, released, overridden, attempt)
    proof.update({"results": check_rows(by_gate.get("proof")), "tdd": tdd_pairs(by_gate.get("tdd")),
                  "cost": cost_body(ctx, cfg, by_gate.get("cost")), "ship": ship_body(ctx, by_gate.get("ship")),
                  "blocking": blocking, "unparsed_mutations": ledger.unparsed(ctx)})
    contract = envelope("contract", ctx, stamp, files, contract_ok, released, overridden, attempt)
    contract.update(contract_data if contract_data is not None else contract_body(ctx, cfg))
    if contract["uncovered_paths"] or any(not c["valid"] for c in contract["contracts"]):
        contract["verified"] = False
    review = envelope("review", ctx, stamp, files, review_ok, released, overridden, attempt)
    review.update({"channel": transcript.channel_of(), "approvals": approvals(ctx, reported), "overrides": overrides(ctx),
                   "secrets_scan": secrets_scan, "pii_scan": pii_scan})
    if FAIL in (secrets_scan["status"], pii_scan["status"]):
        review["verified"] = False
    return {"proof": proof, "contract": contract, "review": review}


def write_clearances(ctx, bodies: dict) -> None:
    targets = [Path(ctx.workspace) / ".omega" / "clearances", state.session_dir(ctx) / "clearances"]
    for directory in targets:
        for kind in CLEARANCE_KINDS:
            state.write_json_atomic(directory / ("%s.json" % kind), bodies[kind])


def write_last_stop(ctx, outcome: dict) -> None:
    state.write_json_atomic(state.session_dir(ctx) / LAST_STOP, outcome)


def pending_override(ctx) -> Optional[dict]:
    target = state.session_dir(ctx) / STOP_OVERRIDE
    row = state.read_json(target, None)
    if not isinstance(row, dict) or row.get("consumed"):
        return None
    stored = state.read_override_token(ctx)
    if not stored or row.get("token") != stored:
        return None
    return row


def consume_override(ctx, row: dict) -> None:
    updated = dict(row)
    updated["consumed"] = True
    updated["consumed_ts"] = state.iso()
    state.write_json_atomic(state.session_dir(ctx) / STOP_OVERRIDE, updated)


def _outcome(ctx, action: str, message: str, results: list, attempt: int, verified: bool, released: bool,
             overridden: bool, files: dict, blocking: list, wrote: bool, timed_out: bool = False) -> dict:
    stamp = state.stamp()
    return {"ts": stamp[0], "ts_ns": stamp[1], "session_id": ctx.session_id, "attempt": attempt, "verified": verified,
            "released": released, "overridden": overridden, "results": [r.as_dict() for r in results],
            "files_digest": hashing.files_digest(files) if files is not None else None, "blocking": blocking,
            "message": message, "action": action, "clearances_written": wrote, "timed_out": timed_out}


def release_by_override(ctx, cfg, row: dict) -> dict:
    consume_override(ctx, row)
    inside, _ = split_scope(ctx, scope_of(ctx))
    files = hashing.snapshot(ctx.workspace, inside)
    attempt = state.counter_get(ctx, ATTEMPTS)
    results = [GateResult(OMEGA_GATE, UNVERIFIED, False, "released by human override %s: %s" % (
        row.get("token"), one_line(row.get("reason"))), [], 0)]
    blocking: list = []
    bodies = build_clearances(ctx, cfg, results, files, blocking, attempt, False, True, inside)
    write_clearances(ctx, bodies)
    state.counter_reset(ctx, ATTEMPTS)
    message = "[omega] stop released by human override %s: NOT verified (reason: %s)" % (
        row.get("token"), one_line(row.get("reason")))
    outcome = _outcome(ctx, "allow", message, results, attempt, False, False, True, files, blocking, True)
    write_last_stop(ctx, outcome)
    return outcome


def stop(ctx, gate_fns: Optional[dict] = None, count_attempt: bool = True, honour_override: bool = True) -> dict:
    cfg = ctx.cfg
    max_attempts = max(1, int(cfg.get("stop.max_attempts", 4) or 4))
    if honour_override:
        row = pending_override(ctx)
        if row is not None:
            return release_by_override(ctx, cfg, row)
    notes: list = []
    try:
        reconciliation = gitsnap.reconcile(ctx)
        if reconciliation.note:
            notes.append(reconciliation.note)
    except Exception as exc:
        notes.append("reconcile failed: %s" % exc.__class__.__name__)
    unparsed = ledger.unparsed(ctx)
    scope = scope_of(ctx)
    if not unparsed and not scope:
        message = "[omega] nothing changed in this session; nothing to prove"
        return _outcome(ctx, "allow", message, [], state.counter_get(ctx, ATTEMPTS), False, False, False, None, [],
                        False)
    inside, outside = split_scope(ctx, scope)
    files = hashing.snapshot(ctx.workspace, inside)
    timed_out = False
    if unparsed:
        results = [GateResult(OMEGA_GATE, FAIL, True, one_line("omega.unparsed_mutation: an edit could not be "
                                                                 "attributed to a file: " + "; ".join(unparsed[:3])),
                              [{"check": "unparsed_mutation", "status": FAIL, "detail": r} for r in unparsed], 0)]
    else:
        jobstore.settle(ctx, float(cfg.get("proof.settle_timeout_s", 15) or 0))
        results, timed_out = run_gates(ctx, cfg, scope, gate_fns)
        after = hashing.snapshot(ctx.workspace, inside)
        if after != files:
            changed = sorted(k for k in set(files) | set(after) if files.get(k) != after.get(k))
            results.append(GateResult(OMEGA_GATE, FAIL, True, "files changed while gates ran: %s" % ", ".join(
                changed[:5]), [], 0))
    scan_pair = scans(ctx, cfg, inside)
    apply_scans(results, *scan_pair)
    contract_data = contract_body(ctx, cfg)
    if not unparsed:
        apply_contract(results, contract_data)
    if outside:
        notes.append("outside the workspace (not in clearances): %s" % ", ".join(outside[:3]))
    blocking = [entry for r in results if blocks(r, cfg) for entry in blocker_entries(r)]
    previous = state.counter_get(ctx, ATTEMPTS)
    note_lines = ["  note: %s" % one_line(n) for n in notes]
    if not blocking:
        attempt = previous + 1
        if count_attempt:
            state.counter_reset(ctx, ATTEMPTS)
        bodies = build_clearances(ctx, cfg, results, files, blocking, attempt, False, False, inside, scan_pair,
                                  contract_data)
        write_clearances(ctx, bodies)
        verified = all(bodies[k]["verified"] for k in CLEARANCE_KINDS)
        unverified = [k for k in CLEARANCE_KINDS if not bodies[k]["verified"]]
        if verified:
            head = "[omega] stop verified: every required gate passed (clearances %s)" % (
                bodies["proof"]["files_digest"][:12])
        else:
            head = "[omega] stop allowed, but %s.json is NOT verified (nothing blocks this turn; ship stays closed)" % (
                ", ".join(unverified))
        message = "\n".join([head] + summary_lines(results) + note_lines)
        outcome = _outcome(ctx, "allow", message, results, attempt, verified, False, False, files, blocking, True,
                           timed_out)
        write_last_stop(ctx, outcome)
        return outcome
    attempt = state.counter_incr(ctx, ATTEMPTS) if count_attempt else previous + 1
    if count_attempt and attempt >= max_attempts:
        bodies = build_clearances(ctx, cfg, results, files, blocking, attempt, True, False, inside, scan_pair,
                                  contract_data)
        write_clearances(ctx, bodies)
        state.counter_reset(ctx, ATTEMPTS)
        message = "\n".join(["[omega] stop released after %d blocked attempts: NOT verified." % attempt]
                            + summary_lines(results) + note_lines)
        outcome = _outcome(ctx, "allow", message, results, attempt, False, True, False, files, blocking, True, timed_out)
        write_last_stop(ctx, outcome)
        return outcome
    bodies = build_clearances(ctx, cfg, results, files, blocking, attempt, False, False, inside, scan_pair,
                                  contract_data)
    write_clearances(ctx, bodies)
    message = block_message(ctx, results, attempt, max_attempts)
    if note_lines:
        message += "\n" + "\n".join(note_lines)
    outcome = _outcome(ctx, "block", message, results, attempt, False, False, False, files, blocking, True, timed_out)
    write_last_stop(ctx, outcome)
    return outcome


def decision_of(outcome: dict) -> io_mod.Decision:
    if outcome["action"] == "block":
        return io_mod.Decision("block", reason=outcome["message"])
    return io_mod.Decision("allow", context=outcome["message"])


def _flush_exit(code: int, hard: bool) -> int:
    if hard:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(code)
    return code


def hook_main(provider_arg: Optional[str]) -> int:
    provider = provider_arg or os.environ.get("OMEGA_PROVIDER") or "claude"
    event_name = "Stop"
    try:
        payload = io_mod.read_payload()
        normalized = event.normalize(payload, provider_arg)
        provider = normalized.provider
        event_name = normalized.name or "Stop"
        ctx = state.configure(normalized)
        io_mod.debug("stop: stop_hook_active=%s attempts=%d" % (normalized.stop_hook_active,
                                                               state.counter_get(ctx, ATTEMPTS)))
        outcome = stop(ctx)
        code = io_mod.emit(provider, event_name, decision_of(outcome))
        return _flush_exit(code, bool(outcome.get("timed_out")))
    except Exception as exc:
        return io_mod.fail_closed(provider, event_name, exc, SCRIPT)


def _context(args):
    return state.load_context(getattr(args, "session", None), getattr(args, "workspace", None),
                              getattr(args, "provider", None))


def cmd_status(args) -> int:
    ctx = _context(args)
    outcome = state.read_json(state.session_dir(ctx) / LAST_STOP, None)
    if not isinstance(outcome, dict):
        sys.stderr.write("[omega] no Stop has run for session %s yet\n" % ctx.session_id)
        return 2
    if args.json:
        sys.stdout.write(json.dumps(outcome, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(str(outcome.get("message") or "") + "\n")
    return 0 if outcome.get("verified") else 1


def cmd_override(args) -> int:
    ctx = _context(args)
    stored = state.read_override_token(ctx)
    if not stored:
        sys.stderr.write("[omega] this session has no override token; nothing to match\n")
        return 2
    if not args.reason or not args.reason.strip():
        sys.stderr.write("[omega] --reason is required\n")
        return 1
    if args.token != stored:
        sys.stderr.write("[omega] refused: that is not this session's override token\n")
        return 1
    turn = transcript.quoted_turn(transcript.read_human_turns(ctx), args.token)
    if turn is None:
        sys.stderr.write("[omega] refused: no human turn contains %s — the human must send it in chat\n" % args.token)
        return 1
    ts, ts_ns = state.stamp()
    state.write_json_atomic(state.session_dir(ctx) / STOP_OVERRIDE, {
        "token": args.token, "reason": one_line(args.reason), "turn_uuid": turn.uuid, "ts": ts, "ts_ns": ts_ns,
        "consumed": False})
    sys.stdout.write("[omega] override recorded; the next Stop is released and recorded as NOT verified\n")
    return 0


def cmd_run(args) -> int:
    ctx = _context(args)
    outcome = stop(ctx, count_attempt=False, honour_override=False)
    if args.json:
        sys.stdout.write(json.dumps(outcome, ensure_ascii=False) + "\n")
    else:
        stream = sys.stdout if outcome["action"] == "allow" else sys.stderr
        stream.write(outcome["message"] + "\n")
    if outcome["action"] == "allow" and outcome.get("clearances_written") is False:
        return 0
    return 0 if outcome.get("verified") else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="stop_orchestrator.py",
                                     description="Stop hook: runs every gate, writes clearances, loop guard.")
    parser.add_argument("--provider", choices=("claude", "codex"))
    sub = parser.add_subparsers(dest="command")
    for name in ("status", "override", "run"):
        child = sub.add_parser(name)
        child.add_argument("--session")
        child.add_argument("--workspace")
        child.add_argument("--provider", choices=("claude", "codex"))
        if name in ("status", "run"):
            child.add_argument("--json", action="store_true")
        if name == "override":
            child.add_argument("--token", required=True)
            child.add_argument("--reason", required=True)
    return parser


def main(argv: list) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        return hook_main(args.provider)
    handlers = {"status": cmd_status, "override": cmd_override, "run": cmd_run}
    try:
        return handlers[args.command](args)
    except state.AmbiguousSession as exc:
        sys.stderr.write("[omega] %s\n" % exc)
        return 2
    except Exception as exc:
        sys.stderr.write("[omega] internal error: %s: %s\n" % (exc.__class__.__name__, str(exc)[:200]))
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

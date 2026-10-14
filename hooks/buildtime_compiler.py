from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
from collections import Counter, defaultdict
from typing import Optional

from hooks.lib import OMEGA_VERSION, costledger, state
from hooks.lib import config as config_mod

CALLSITE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,99}$")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
DIGITS_RE = re.compile(r"\d+")
TOKEN_RE = re.compile(r"<N>|<ID>|<EMAIL>|\w+")
MAX_LABELS = 64
MAX_LABEL_CHARS = 64
EXIT_OK, EXIT_REFUSED, EXIT_INSUFFICIENT = 0, 1, 2
STATUSES = ("unknown", "logging", "candidate", "shadow", "promoted", "demoted")

RUNTIME_HELPER = '''from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import random
import time
from pathlib import Path
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parent
LOG_DIR = WORKSPACE / ".omega" / "buildtime"
REGISTRY = ROOT / "registry.json"
CANARY_RATE = __CANARY_RATE__
_MODULES: dict = {}


def _registry() -> dict:
    try:
        data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _entry(callsite: str) -> dict:
    entry = _registry().get(callsite)
    return entry if isinstance(entry, dict) else {}


def status(callsite: str) -> str:
    entry = _entry(callsite)
    if entry.get("status"):
        return str(entry["status"])
    if (LOG_DIR / "calls" / ("%s.jsonl" % callsite)).exists():
        return "logging"
    return "unknown"


def _append(path: Path, row: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(str(path), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\\n")
    except OSError:
        pass


def _stamp() -> tuple:
    ts_ns = time.time_ns()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts_ns / 1e9)), ts_ns


def log_call(callsite: str, x: str, y: str, model: str, meta: Optional[dict] = None, source: str = "llm",
             rule_id: Optional[str] = None) -> None:
    ts, ts_ns = _stamp()
    meta = dict(meta or {})
    _append(LOG_DIR / "calls" / ("%s.jsonl" % callsite), {
        "ts": ts, "ts_ns": ts_ns, "callsite": callsite, "input": x, "output": y, "model": model,
        "prompt_hash": meta.get("prompt_hash"), "source": source, "rule_id": rule_id, "meta": meta})


def _compiled(callsite: str):
    path = ROOT / "compiled" / ("%s.py" % callsite)
    if not path.is_file():
        return None
    key = (str(path), path.stat().st_mtime_ns)
    if key not in _MODULES:
        spec = importlib.util.spec_from_file_location("buildtime_compiled_%s" % abs(hash(key)), str(path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULES[key] = module
    return _MODULES[key]


def _shadow(callsite: str, x: str, rule_out, rule_id, llm_out, phase: str, version) -> None:
    ts, ts_ns = _stamp()
    _append(LOG_DIR / "shadow" / ("%s.jsonl" % callsite), {
        "ts": ts, "ts_ns": ts_ns, "callsite": callsite,
        "input_hash": hashlib.sha256(x.encode("utf-8")).hexdigest(), "rule_out": rule_out, "rule_id": rule_id,
        "llm_out": llm_out, "agree": rule_out is not None and rule_out == llm_out, "phase": phase, "version": version})


def route(callsite: str, x: str, llm: Callable[[str], str], model: str = "", meta: Optional[dict] = None) -> str:
    entry = _entry(callsite)
    current = status(callsite)
    version = entry.get("version")
    if current == "promoted":
        module = _compiled(callsite)
        label, rule_id = module.match(x) if module else (None, None)
        if label is not None and random.random() >= CANARY_RATE:
            log_call(callsite, x, label, model, meta, source="rule", rule_id=rule_id)
            return label
        y = llm(x)
        log_call(callsite, x, y, model, meta, source="canary" if label is not None else "llm")
        if label is not None:
            _shadow(callsite, x, label, rule_id, y, "canary", version)
        return y
    if current == "shadow":
        y = llm(x)
        log_call(callsite, x, y, model, meta)
        module = _compiled(callsite)
        if module is not None:
            label, rule_id = module.match(x)
            _shadow(callsite, x, label, rule_id, y, "shadow", version)
        return y
    y = llm(x)
    log_call(callsite, x, y, model, meta)
    return y
'''

COMPILED_TEMPLATE = '''from __future__ import annotations

import hashlib
import re
from typing import Optional

MANIFEST = __MANIFEST__
LOOKUP = __LOOKUP__
RULES = [(rule_id, label, re.compile(pattern)) for rule_id, label, pattern in __RULES__]
_UUID = re.compile(r"\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b")
_EMAIL = re.compile(r"\\b[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}\\b")
_DIGITS = re.compile(r"\\d+")
_TOKEN = re.compile(r"<N>|<ID>|<EMAIL>|\\w+")


def normalize(x: str) -> str:
    text = str(x or "").casefold()
    text = _UUID.sub("<ID>", text)
    text = _EMAIL.sub("<EMAIL>", text)
    text = _DIGITS.sub("<N>", text)
    return " ".join(text.split())


def tokens(normal: str) -> str:
    return " ".join(_TOKEN.findall(normal))


def match(x: str) -> tuple:
    normal = normalize(x)
    key = hashlib.sha256(normal.encode("utf-8")).hexdigest()
    if key in LOOKUP:
        return LOOKUP[key], "lookup"
    joined = tokens(normal)
    for rule_id, label, pattern in RULES:
        if pattern.search(joined):
            return label, rule_id
    return None, None
'''


def wilson_upper(k: int, n: int, z: float = 1.96) -> float:
    if n <= 0:
        return 1.0
    p = k / float(n)
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4.0 * n * n))
    return (c + m) / d


def wilson_lower(k: int, n: int, z: float = 1.96) -> float:
    if n <= 0:
        return 0.0
    p = k / float(n)
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4.0 * n * n))
    return max(0.0, (c - m) / d)


def normalize(x: str) -> str:
    text = str(x or "").casefold()
    text = UUID_RE.sub("<ID>", text)
    text = EMAIL_RE.sub("<EMAIL>", text)
    text = DIGITS_RE.sub("<N>", text)
    return " ".join(text.split())


def tokens(normal: str) -> list:
    return TOKEN_RE.findall(normal)


def key_of(normal: str) -> str:
    return hashlib.sha256(normal.encode("utf-8")).hexdigest()


class Paths:
    def __init__(self, workspace: str, callsite: str, cfg):
        if not CALLSITE.match(callsite or ""):
            raise ValueError("callsite name must match %s" % CALLSITE.pattern)
        self.workspace = os.path.realpath(workspace)
        self.callsite = callsite
        rel_dir = str(cfg.get("buildtime.dir", "buildtime") or "buildtime")
        self.package = Path(self.workspace) / rel_dir
        self.logs = Path(self.workspace) / ".omega" / "buildtime"
        self.calls = self.logs / "calls" / ("%s.jsonl" % callsite)
        self.shadow = self.logs / "shadow" / ("%s.jsonl" % callsite)
        self.stats = self.logs / ("%s.stats.json" % callsite)
        self.registry = self.package / "registry.json"
        self.compiled = self.package / "compiled" / ("%s.py" % callsite)


def read_registry(p: Paths) -> dict:
    data = state.read_json(p.registry, {}) or {}
    return data if isinstance(data, dict) else {}


def registry_entry(p: Paths) -> dict:
    entry = read_registry(p).get(p.callsite)
    return dict(entry) if isinstance(entry, dict) else {}


def update_registry(p: Paths, **fields) -> dict:
    data = read_registry(p)
    entry = dict(data.get(p.callsite) or {})
    entry.update(fields)
    entry.setdefault("stats_path", os.path.relpath(str(p.stats), p.workspace))
    data[p.callsite] = entry
    state.write_json_atomic(p.registry, data)
    return entry


def init(workspace: str, cfg) -> list:
    root = Path(os.path.realpath(workspace)) / str(cfg.get("buildtime.dir", "buildtime") or "buildtime")
    written: list = []
    helper = root / "__init__.py"
    text = RUNTIME_HELPER.replace("__CANARY_RATE__", repr(float(cfg.get("buildtime.canary.rate", 0.03))))
    if not helper.exists() or helper.read_text(encoding="utf-8") != text:
        root.mkdir(parents=True, exist_ok=True)
        helper.write_text(text, encoding="utf-8")
        written.append(str(helper))
    (root / "compiled").mkdir(parents=True, exist_ok=True)
    registry = root / "registry.json"
    if not registry.exists():
        state.write_json_atomic(registry, {})
        written.append(str(registry))
    return written


def training_rows(p: Paths) -> list:
    rows = [r for r in state.read_jsonl(p.calls) if r.get("source", "llm") in ("llm", "canary")]
    return [r for r in rows if isinstance(r.get("input"), str) and isinstance(r.get("output"), str)]


def closed_label(value: str) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_LABEL_CHARS and "\n" not in value


def mine(workspace: str, callsite: str, cfg) -> dict:
    p = Paths(workspace, callsite, cfg)
    rows = training_rows(p)
    labels = Counter(r["output"] for r in rows)
    groups: dict = defaultdict(Counter)
    for row in rows:
        groups[key_of(normalize(row["input"]))][row["output"]] += 1
    impure = sum(1 for counts in groups.values() if len(counts) > 1)
    reasons: list = []
    if len(labels) > MAX_LABELS:
        reasons.append("%d distinct outputs (max %d)" % (len(labels), MAX_LABELS))
    open_labels = [label for label in labels if not closed_label(label)]
    if open_labels:
        reasons.append("%d output(s) are not short single-line labels" % len(open_labels))
    prompt_hashes = Counter(r.get("prompt_hash") for r in rows if r.get("prompt_hash"))
    return {"callsite": callsite, "n": len(rows), "distinct_inputs": len(groups), "labels": dict(labels),
            "cardinality": len(labels), "inconsistent_inputs": impure, "eligible": not reasons and bool(rows),
            "reasons": reasons, "prompt_hash": prompt_hashes.most_common(1)[0][0] if prompt_hashes else None}


def _feature_pattern(feature: tuple) -> str:
    return r"(?:^| )" + r" ".join(re.escape(t) for t in feature) + r"(?: |$)"


def synthesize(rows: list, cfg) -> tuple:
    min_support = int(cfg.get("buildtime.min_support", 20))
    min_purity = float(cfg.get("buildtime.min_purity", 0.995))
    normals = [normalize(r["input"]) for r in rows]
    outputs = [r["output"] for r in rows]
    groups: dict = defaultdict(Counter)
    for normal, output in zip(normals, outputs):
        groups[key_of(normal)][output] += 1
    lookup: dict = {}
    for key, counts in groups.items():
        label, count = counts.most_common(1)[0]
        total = sum(counts.values())
        if total >= min_support and count / float(total) >= min_purity:
            lookup[key] = label
    remaining = [i for i, normal in enumerate(normals) if key_of(normal) not in lookup]
    features_of: list = []
    for normal in normals:
        toks = tokens(normal)
        feats = {(t,) for t in toks} | {(a, b) for a, b in zip(toks, toks[1:])}
        features_of.append(feats)
    index: dict = defaultdict(set)
    for i, feats in enumerate(features_of):
        for feature in feats:
            index[feature].add(i)
    precision_of: dict = {}
    for feature, members in index.items():
        counts = Counter(outputs[i] for i in members)
        label, count = counts.most_common(1)[0]
        precision_of[feature] = (label, count / float(len(members)), count)
    rules: list = []
    uncovered = set(remaining)
    while uncovered:
        best = None
        for feature, (label, precision, support) in precision_of.items():
            if precision < min_purity or support < min_support:
                continue
            gain = sum(1 for i in index[feature] if i in uncovered and outputs[i] == label)
            if gain == 0:
                continue
            rank = (gain, precision, -len(feature), feature)
            if best is None or rank > best[0]:
                best = (rank, feature, label, precision, support)
        if best is None:
            break
        _, feature, label, precision, support = best
        rules.append({"feature": list(feature), "label": label, "precision": precision, "support": support,
                      "pattern": _feature_pattern(feature)})
        uncovered -= index[feature]
        del precision_of[feature]
    rules.sort(key=lambda r: (-r["precision"], -r["support"], r["pattern"]))
    for number, rule in enumerate(rules, 1):
        rule["rule_id"] = "r%03d" % number
    return lookup, rules


def render_compiled(manifest: dict, lookup: dict, rules: list) -> str:
    rule_tuples = [(r["rule_id"], r["label"], r["pattern"]) for r in rules]
    text = COMPILED_TEMPLATE.replace("__MANIFEST__", repr(manifest))
    text = text.replace("__LOOKUP__", repr(dict(sorted(lookup.items()))))
    return text.replace("__RULES__", repr(rule_tuples))


def load_compiled(path: Path):
    spec = importlib.util.spec_from_file_location("buildtime_check_%s" % abs(hash(str(path))), str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synth(workspace: str, callsite: str, cfg) -> tuple:
    p = Paths(workspace, callsite, cfg)
    report = mine(workspace, callsite, cfg)
    min_support = int(cfg.get("buildtime.min_support", 20))
    if report["n"] < min_support:
        report["result"] = "insufficient data: %d logged call(s), need at least %d" % (report["n"], min_support)
        return EXIT_INSUFFICIENT, report
    if not report["eligible"]:
        report["result"] = "ineligible: " + "; ".join(report["reasons"])
        return EXIT_REFUSED, report
    rows = training_rows(p)
    lookup, rules = synthesize(rows, cfg)
    if not lookup and not rules:
        report["result"] = "insufficient data: no input pattern reaches support %d at purity %s" % (
            min_support, cfg.get("buildtime.min_purity", 0.995))
        return EXIT_INSUFFICIENT, report
    entry = registry_entry(p)
    version = int(entry.get("version") or 0) + 1
    labels = sorted(set(lookup.values()) | {r["label"] for r in rules})
    manifest = {"callsite": callsite, "version": version, "generated_at": state.iso(),
                "prompt_hash": report["prompt_hash"], "labels": labels, "lookup_size": len(lookup),
                "rules": len(rules), "generator": "omega %s" % OMEGA_VERSION}
    source = render_compiled(manifest, lookup, rules)
    compile(source, str(p.compiled), "exec")
    p.compiled.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.compiled.with_name(".%s.tmp-%d" % (p.compiled.name, os.getpid()))
    tmp.write_text(source, encoding="utf-8")
    os.replace(str(tmp), str(p.compiled))
    module = load_compiled(p.compiled)
    answered = [(module.match(r["input"])[0], r["output"]) for r in rows]
    hits = [(a, b) for a, b in answered if a is not None]
    agreement = sum(1 for a, b in hits if a == b)
    update_registry(p, status="candidate", version=version, prompt_hash=report["prompt_hash"], promoted_at=None)
    report.update({"result": "written", "path": str(p.compiled), "version": version, "lookup_size": len(lookup),
                   "rules": len(rules), "training_coverage": round(len(hits) / float(len(rows)), 4) if rows else 0.0,
                   "training_agreement": round(agreement / float(len(hits)), 4) if hits else None})
    return EXIT_OK, report


def shadow(workspace: str, callsite: str, cfg) -> tuple:
    p = Paths(workspace, callsite, cfg)
    if not p.compiled.is_file():
        return EXIT_INSUFFICIENT, {"callsite": callsite, "result": "no compiled artifact; run synth first"}
    entry = update_registry(p, status="shadow")
    return EXIT_OK, {"callsite": callsite, "result": "shadow", "version": entry.get("version"),
                     "shadow_rows": len(state.read_jsonl(p.shadow))}


def _shadow_rows(p: Paths, phase: Optional[str] = None) -> list:
    version = registry_entry(p).get("version")
    rows = state.read_jsonl(p.shadow)
    out = []
    for row in rows:
        if version is not None and row.get("version") not in (None, version):
            continue
        if phase is not None and row.get("phase", "shadow") != phase:
            continue
        out.append(row)
    return out


def _emitted_labels(p: Paths) -> list:
    if not p.compiled.is_file():
        return []
    try:
        module = load_compiled(p.compiled)
    except Exception:
        return []
    labels = set(getattr(module, "LOOKUP", {}).values())
    labels |= {rule[1] for rule in getattr(module, "RULES", [])}
    return sorted(labels)


def stats(workspace: str, callsite: str, cfg, z: Optional[float] = None, phase: str = "shadow") -> dict:
    p = Paths(workspace, callsite, cfg)
    z = float(z if z is not None else cfg.get("buildtime.promote.z", 1.96))
    rows = _shadow_rows(p, phase)
    answered = [r for r in rows if r.get("rule_out") is not None]
    k = sum(1 for r in answered if r.get("rule_out") != r.get("llm_out"))
    n = len(answered)
    labels = Counter(str(r.get("rule_out")) for r in answered)
    days = sorted({str(r.get("ts", ""))[:10] for r in answered if r.get("ts")})
    coverage = n / float(len(rows)) if rows else 0.0
    savings = None
    calls = training_rows(p)
    if calls:
        total = 0.0
        priced = 0
        for row in calls[-500:]:
            try:
                total += costledger.estimate_usd(row.get("model") or "", int(math.ceil(len(row["input"]) / 4.0)),
                                                 int(math.ceil(len(row["output"]) / 4.0)), cfg)
                priced += 1
            except (costledger.UnknownModel, TypeError, ValueError):
                continue
        if priced:
            per_month = float(cfg.get("cost.static.calls_per_month", 10000))
            savings = round(coverage * per_month * (total / priced), 4)
    result = {"callsite": callsite, "n": n, "k": k, "total": len(rows), "coverage": round(coverage, 4),
              "labels": dict(labels), "days": days, "wilson_upper": wilson_upper(k, n, z), "z": z,
              "last_eval_ts": state.iso(), "monthly_savings_usd": savings, "phase": phase,
              "version": registry_entry(p).get("version")}
    state.write_json_atomic(p.stats, result)
    return result


def _prompt_hash_changed(p: Paths) -> Optional[str]:
    recorded = registry_entry(p).get("prompt_hash")
    if not recorded:
        return None
    recent = [r.get("prompt_hash") for r in state.read_jsonl(p.calls)[-50:] if r.get("prompt_hash")]
    if recent and recent[-1] != recorded:
        return recent[-1]
    return None


def promote(workspace: str, callsite: str, cfg, min_n: Optional[int] = None, max_upper: Optional[float] = None,
            z: Optional[float] = None) -> tuple:
    p = Paths(workspace, callsite, cfg)
    min_n = int(min_n if min_n is not None else cfg.get("buildtime.promote.min_n", 1000))
    max_upper = float(max_upper if max_upper is not None else cfg.get("buildtime.promote.max_upper", 0.005))
    min_days = int(cfg.get("buildtime.promote.min_days", 3))
    min_per_label = int(cfg.get("buildtime.promote.min_per_label", 30))
    if not p.compiled.is_file():
        return EXIT_INSUFFICIENT, {"callsite": callsite, "result": "no compiled artifact; run synth and shadow first"}
    report = stats(workspace, callsite, cfg, z)
    report.update({"min_n": min_n, "max_upper": max_upper, "min_days": min_days, "min_per_label": min_per_label})
    changed = _prompt_hash_changed(p)
    if changed:
        update_registry(p, status="shadow")
        report["result"] = "refused: the prompt hash changed since synth (%s); re-run synth" % changed[:12]
        return EXIT_REFUSED, report
    short: list = []
    if report["n"] < min_n:
        short.append("n=%d non-abstained comparisons (need %d)" % (report["n"], min_n))
    if len(report["days"]) < min_days:
        short.append("%d distinct day(s) (need %d)" % (len(report["days"]), min_days))
    thin = [label for label in _emitted_labels(p) if report["labels"].get(label, 0) < min_per_label]
    if thin:
        short.append("label(s) seen fewer than %d times: %s" % (min_per_label, ", ".join(thin[:8])))
    if short:
        report["result"] = "insufficient data: " + "; ".join(short)
        return EXIT_INSUFFICIENT, report
    if report["wilson_upper"] >= max_upper:
        report["result"] = "refused: disagreement upper bound %.5f >= %.5f (k=%d, n=%d)" % (
            report["wilson_upper"], max_upper, report["k"], report["n"])
        return EXIT_REFUSED, report
    entry = update_registry(p, status="promoted", promoted_at=state.iso())
    report["result"] = "promoted version %s: disagreement upper bound %.5f < %.5f" % (
        entry.get("version"), report["wilson_upper"], max_upper)
    return EXIT_OK, report


def demote(workspace: str, callsite: str, cfg, reason: str) -> tuple:
    p = Paths(workspace, callsite, cfg)
    entry = update_registry(p, status="demoted", demoted_at=state.iso(), demote_reason=reason)
    return EXIT_OK, {"callsite": callsite, "result": "demoted", "reason": reason, "version": entry.get("version")}


def canary(workspace: str, callsite: str, cfg) -> tuple:
    p = Paths(workspace, callsite, cfg)
    window = int(cfg.get("buildtime.canary.window", 2000))
    limit = float(cfg.get("buildtime.canary.demote_upper", 0.01))
    z = float(cfg.get("buildtime.promote.z", 1.96))
    entry = registry_entry(p)
    if entry.get("status") != "promoted":
        return EXIT_OK, {"callsite": callsite, "result": "not promoted (status %s); nothing to check" % entry.get(
            "status", "unknown")}
    changed = _prompt_hash_changed(p)
    if changed:
        update_registry(p, status="shadow", demote_reason="prompt hash changed")
        return EXIT_REFUSED, {"callsite": callsite, "result": "prompt hash changed (%s): back to shadow" % changed[:12]}
    rows = [r for r in _shadow_rows(p, "canary") if r.get("rule_out") is not None][-window:]
    n = len(rows)
    k = sum(1 for r in rows if r.get("rule_out") != r.get("llm_out"))
    upper = wilson_upper(k, n, z)
    lower = wilson_lower(k, n, z)
    needed = int(math.ceil(z * z * (1 - limit) / limit))
    report = {"callsite": callsite, "n": n, "k": k, "wilson_upper": upper, "wilson_lower": lower, "window": window,
              "demote_upper": limit, "min_n_for_upper": needed}
    if lower > limit or (n >= needed and upper > limit):
        reason = "canary disagreement upper bound %.5f > %.5f (k=%d, n=%d)" % (upper, limit, k, n)
        demote(workspace, callsite, cfg, reason)
        report["result"] = "demoted: " + reason
        return EXIT_REFUSED, report
    report["result"] = "healthy" if n >= needed else "healthy so far (%d of %d canary comparisons)" % (n, needed)
    return EXIT_OK, report


def _emit(payload: dict, as_json: bool) -> None:
    if as_json:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    else:
        sys.stdout.write("[buildtime] %s: %s\n" % (payload.get("callsite", ""), payload.get("result", "")))
        for key in ("n", "k", "coverage", "wilson_upper", "days", "labels", "monthly_savings_usd"):
            if key in payload:
                sys.stdout.write("  %s: %s\n" % (key, payload[key]))


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="buildtime_compiler.py",
                                     description="Compile bounded LLM call sites into deterministic rules.")
    parser.add_argument("--workspace")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("init").add_argument("--workspace", dest="workspace_sub")
    for name in ("mine", "synth", "shadow", "report", "promote", "demote", "canary"):
        child = sub.add_parser(name)
        child.add_argument("--callsite", required=True)
        child.add_argument("--workspace", dest="workspace_sub")
        child.add_argument("--json", action="store_true")
        if name == "promote":
            child.add_argument("--min-n", type=int)
            child.add_argument("--max-upper", type=float)
            child.add_argument("--z", type=float)
        if name == "demote":
            child.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return 2
    workspace = os.path.realpath(getattr(args, "workspace_sub", None) or args.workspace
                                 or os.environ.get("OMEGA_WORKSPACE") or os.getcwd())
    cfg = config_mod.load(workspace=workspace)
    try:
        if args.command == "init":
            written = init(workspace, cfg)
            sys.stdout.write("[buildtime] init: %s\n" % (", ".join(written) if written else "already initialised"))
            return EXIT_OK
        if args.command == "mine":
            report = mine(workspace, args.callsite, cfg)
            report["result"] = "eligible" if report["eligible"] else "ineligible: " + "; ".join(report["reasons"] or ["no data"])
            _emit(report, args.json)
            return EXIT_OK
        if args.command == "report":
            report = stats(workspace, args.callsite, cfg)
            report["result"] = "k=%d n=%d wilson_upper=%.5f coverage=%.3f" % (
                report["k"], report["n"], report["wilson_upper"], report["coverage"])
            _emit(report, args.json)
            return EXIT_OK
        if args.command == "synth":
            code, report = synth(workspace, args.callsite, cfg)
        elif args.command == "shadow":
            code, report = shadow(workspace, args.callsite, cfg)
        elif args.command == "promote":
            code, report = promote(workspace, args.callsite, cfg, args.min_n, args.max_upper, args.z)
        elif args.command == "demote":
            code, report = demote(workspace, args.callsite, cfg, args.reason)
        else:
            code, report = canary(workspace, args.callsite, cfg)
        _emit(report, args.json)
        return code
    except ValueError as exc:
        sys.stderr.write("[buildtime] %s\n" % exc)
        return EXIT_INSUFFICIENT
    except Exception as exc:
        sys.stderr.write("[buildtime] internal error: %s: %s\n" % (exc.__class__.__name__, str(exc)[:200]))
        return EXIT_INSUFFICIENT


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

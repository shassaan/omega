from __future__ import annotations

import fcntl
import json
import math
import os
import re
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import paths, state

CAP_ENV = {
    "per_call_usd": "OMEGA_BUDGET_PER_CALL_USD",
    "per_session_usd": "OMEGA_BUDGET_PER_SESSION_USD",
    "per_run_usd": "OMEGA_BUDGET_PER_RUN_USD",
    "monthly_usd": "OMEGA_BUDGET_MONTHLY_USD",
}
PASS, FAIL, UNVERIFIED = "PASS", "FAIL", "UNVERIFIED"
_DATE_SUFFIX = re.compile(r"-\d{8}$")
_ONE_MILLION = 1_000_000.0


class UnknownModel(KeyError):
    pass


@dataclass
class Price:
    model: str
    in_usd: float
    out_usd: float
    cache_read: float
    cache_write_5m: float
    cache_write_1h: float
    verified: bool
    source: str


@dataclass
class CostVerdict:
    status: str
    breaches: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    sums: dict = field(default_factory=dict)


def ledger_path(path: Optional[str] = None) -> Path:
    if path:
        return Path(path)
    return paths.state_root() / "cost" / "ledger.jsonl"


def _prices(cfg) -> dict:
    return cfg.get("cost.prices", {}) or {}


def resolve_model(name: str, cfg) -> Optional[str]:
    if not isinstance(name, str) or not name.strip():
        return None
    text = name.strip()
    if text.endswith("[1m]"):
        text = text[:-4]
    text = _DATE_SUFFIX.sub("", text)
    prices = _prices(cfg)
    aliases = cfg.get("cost.model_aliases", {}) or {}
    for candidate in (text, text.lower()):
        if candidate in prices:
            return candidate
        if candidate in aliases and aliases[candidate] in prices:
            return aliases[candidate]
    return None


def _float(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def price(model: str, cfg, on_date: Optional[str] = None) -> Optional[Price]:
    canonical = resolve_model(model, cfg)
    if canonical is None:
        return None
    entry = dict(_prices(cfg)[canonical])
    day = on_date or time.strftime("%Y-%m-%d", time.gmtime())
    effective_to = entry.get("effective_to")
    successor = entry.get("successor")
    if effective_to and isinstance(successor, dict) and day > str(effective_to):
        start = successor.get("effective_from")
        if not start or day >= str(start):
            entry.update({k: v for k, v in successor.items() if k != "effective_from"})
    in_usd = _float(entry.get("in"), 0.0)
    return Price(
        model=canonical,
        in_usd=in_usd,
        out_usd=_float(entry.get("out"), 0.0),
        cache_read=_float(entry.get("cache_read"), in_usd),
        cache_write_5m=_float(entry.get("cache_write_5m"), in_usd * 1.25),
        cache_write_1h=_float(entry.get("cache_write_1h"), in_usd * 2.0),
        verified=bool(entry.get("verified", False)),
        source=str(entry.get("source", "")),
    )


def estimate_tokens(text: str, cfg) -> int:
    content = text or ""
    try:
        import tiktoken
        return len(tiktoken.get_encoding("o200k_base").encode(content))
    except Exception:
        multiplier = _float(cfg.get("cost.safety_multiplier", 1.25), 1.25)
        return int(math.ceil(len(content) / 4.0 * multiplier))


def estimate_usd(model: str, in_tokens: int, out_tokens: int, cfg, cache_read: int = 0,
                 cache_write: int = 0) -> float:
    found = price(model, cfg)
    if found is None:
        raise UnknownModel(model)
    total = (max(0, int(in_tokens)) * found.in_usd
             + max(0, int(out_tokens)) * found.out_usd
             + max(0, int(cache_read)) * found.cache_read
             + max(0, int(cache_write)) * found.cache_write_5m)
    return round(total / _ONE_MILLION, 6)


@contextmanager
def _locked(target: Path):
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(target.name.replace(".jsonl", "") + ".lock")
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _read(target: Path) -> tuple:
    rows: list = []
    corrupt: list = []
    try:
        handle = open(str(target), "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return rows, corrupt
    except OSError:
        return rows, [0]
    with handle:
        for number, line in enumerate(handle, 1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except ValueError:
                corrupt.append(number)
                continue
            if not isinstance(row, dict):
                corrupt.append(number)
                continue
            rows.append(row)
    return rows, corrupt


def read_ledger(cfg=None, path: Optional[str] = None) -> tuple:
    return _read(ledger_path(path))


def append(row: dict, cfg, path: Optional[str] = None) -> None:
    target = ledger_path(path)
    record = dict(row)
    if not record.get("ts") or not record.get("ts_ns"):
        ts, ts_ns = state.stamp()
        record.setdefault("ts", ts)
        record.setdefault("ts_ns", ts_ns)
    record.setdefault("id", str(uuid.uuid4()))
    record.setdefault("price_version", cfg.get("cost.price_version") if cfg is not None else None)
    if record.get("usd") is None and record.get("model") and cfg is not None:
        try:
            record["usd"] = estimate_usd(record["model"], record.get("in", 0) or 0, record.get("out", 0) or 0,
                                         cfg, record.get("cache_read", 0) or 0, record.get("cache_write", 0) or 0)
            found = price(record["model"], cfg)
            record.setdefault("verified_price", bool(found and found.verified))
        except UnknownModel:
            record["usd"] = None
            record.setdefault("verified_price", False)
    line = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    with _locked(target):
        existing, _ = _read(target)
        if any(r.get("id") == record["id"] for r in existing):
            return
        fd = os.open(str(target), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            written = 0
            while written < len(line):
                written += os.write(fd, line[written:])
            os.fsync(fd)
        finally:
            os.close(fd)


def rows(cfg, since_ts: Optional[str] = None, path: Optional[str] = None) -> list:
    found, _ = _read(ledger_path(path))
    if since_ts:
        found = [r for r in found if str(r.get("ts", "")) >= since_ts]
    return found


def _row_usd(row: dict, cfg) -> Optional[float]:
    value = row.get("usd")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    model = row.get("model")
    try:
        return estimate_usd(model, row.get("in", 0) or 0, row.get("out", 0) or 0, cfg,
                            row.get("cache_read", 0) or 0, row.get("cache_write", 0) or 0)
    except (UnknownModel, TypeError, ValueError):
        return None


def current_month() -> str:
    return time.strftime("%Y-%m", time.gmtime())


def sums(cfg, session_id=None, run_id=None, month=None, path: Optional[str] = None) -> dict:
    found, corrupt = _read(ledger_path(path))
    month = month or current_month()
    session_total = 0.0 if session_id else None
    run_total = 0.0 if run_id else None
    month_total = 0.0
    max_call = 0.0
    unknown: list = []
    for row in found:
        model = row.get("model")
        if not (isinstance(model, str) and resolve_model(model, cfg) is not None):
            name = model if isinstance(model, str) else str(model)
            if name not in unknown:
                unknown.append(name)
        usd = _row_usd(row, cfg)
        if usd is None:
            usd = 0.0
        in_month = str(row.get("ts", "")).startswith(month)
        in_session = bool(session_id) and row.get("session_id") == session_id
        in_run = bool(run_id) and row.get("run_id") == run_id
        if in_session:
            session_total += usd
        if in_run:
            run_total += usd
        if in_month:
            month_total += usd
        if in_session or in_run or (not session_id and not run_id and in_month):
            max_call = max(max_call, usd)
    return {
        "session": round(session_total, 6) if session_total is not None else None,
        "run": round(run_total, 6) if run_total is not None else None,
        "month": round(month_total, 6),
        "max_call": round(max_call, 6),
        "unknown_models": unknown,
        "corrupt_lines": len(corrupt),
        "corrupt_line_numbers": corrupt,
        "month_key": month,
    }


def caps(cfg) -> dict:
    configured = cfg.get("cost.caps", {}) or {}
    out: dict = {}
    for key, env_name in CAP_ENV.items():
        value = _float(configured.get(key), 0.0)
        raw = os.environ.get(env_name)
        if raw:
            value = _float(raw, value)
        out[key] = value
    return out


def check(cfg, session_id=None, run_id=None, month=None, allow_unknown=False,
          path: Optional[str] = None, cap_overrides: Optional[dict] = None) -> CostVerdict:
    totals = sums(cfg, session_id=session_id, run_id=run_id, month=month, path=path)
    limits = caps(cfg)
    for key, value in (cap_overrides or {}).items():
        if value is not None:
            limits[key] = float(value)
    totals["caps"] = limits
    warn_ratio = _float(cfg.get("cost.warn_ratio", 0.8), 0.8)
    breaches: list = []
    warnings: list = []
    pairs = (("session", "per_session_usd", "session"), ("run", "per_run_usd", "run"),
             ("month", "monthly_usd", "month"), ("max_call", "per_call_usd", "single call"))
    for total_key, cap_key, label in pairs:
        total = totals.get(total_key)
        cap = limits.get(cap_key)
        if total is None or not cap:
            continue
        if total > cap:
            breaches.append("%s $%.2f exceeds cap $%.2f" % (label, total, cap))
        elif total >= cap * warn_ratio:
            warnings.append("%s at %d%% of cap ($%.2f / $%.2f)" % (label, int(round(total / cap * 100)), total, cap))
    if totals["corrupt_lines"]:
        status = UNVERIFIED
        breaches.append("ledger has %d corrupt line(s): %s" % (
            totals["corrupt_lines"], ", ".join(str(n) for n in totals["corrupt_line_numbers"][:10])))
    elif any(b for b in breaches):
        status = FAIL
    elif totals["unknown_models"] and not allow_unknown:
        status = UNVERIFIED
        warnings.append("unknown model(s) with no price: %s" % ", ".join(totals["unknown_models"]))
    else:
        status = PASS
    return CostVerdict(status=status, breaches=breaches, warnings=warnings, sums=totals)

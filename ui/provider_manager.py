from __future__ import annotations

import base64
import fcntl
import json
import os
import random
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

OMEGA_ROOT = Path(__file__).resolve().parents[1]
if str(OMEGA_ROOT) not in sys.path:
    sys.path.insert(0, str(OMEGA_ROOT))

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from hooks.lib import costledger, paths, redaction, state

PROVIDERS = ("anthropic", "openai", "google")
KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "google": "GEMINI_API_KEY"}
KEY_PATTERNS = {
    "anthropic": re.compile(r"^sk-ant-[A-Za-z0-9_\-]+$"),
    "openai": re.compile(r"^sk-(?!ant-)[A-Za-z0-9_\-]+$"),
    "google": re.compile(r"^AIza[A-Za-z0-9_\-]+$"),
}
KEY_PREFIXES = {
    "anthropic": ("sk-ant-",),
    "openai": ("sk-proj-", "sk-svcacct-", "sk-admin-", "sk-"),
    "google": ("AIza",),
}
MAX_KEY_LENGTH = 512
MIN_KEY_LENGTH = 20
DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5", "openai": "gpt-5.6-sol", "google": "gemini-3.1-pro-preview"}
VERIFY_ENDPOINTS = {
    "anthropic": "https://api.anthropic.com/v1/models",
    "openai": "https://api.openai.com/v1/models",
    "google": "https://generativelanguage.googleapis.com/v1beta/models",
}
BASE_ENV = ("PATH", "HOME", "LANG", "TMPDIR")
DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"
VERIFY_TIMEOUT_S = 10


class KeyRejected(ValueError):
    pass


class NoProvider(LookupError):
    pass


class BudgetExceeded(RuntimeError):
    pass


class Secret(str):
    def __new__(cls, value: str):
        instance = super().__new__(cls, "****")
        instance._value = value
        return instance

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "****"

    def __str__(self) -> str:
        return "****"

    def __format__(self, spec: str) -> str:
        return "****"

    def __reduce__(self):
        raise TypeError("a Secret cannot be serialised")


@dataclass
class Choice:
    provider: str
    model: Optional[str]
    runtime: str
    max_budget_usd: float


def _iso() -> str:
    return state.iso()


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(".%s.tmp-%d-%d" % (path.name, os.getpid(), time.time_ns()))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = 0
        while written < len(data):
            written += os.write(fd, data[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))
    os.chmod(str(path), 0o600)


def _parse_keys(raw: str) -> list:
    keys: list = []
    for item in re.split(r"[\s,]+", raw or ""):
        item = item.strip()
        if not item:
            continue
        try:
            decoded = base64.urlsafe_b64decode(item.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            raise ValueError("a Fernet key is not urlsafe base64")
        if len(decoded) != 32:
            raise ValueError("a Fernet key must decode to 32 bytes")
        keys.append(item.encode("ascii"))
    return keys


class ProviderManager:
    def __init__(self, state_root: Path, cfg, secret: Optional[bytes] = None,
                 urlopen: Optional[Callable] = None):
        self.state_root = Path(state_root)
        self.cfg = cfg
        self.ui_dir = self.state_root / "ui"
        self.ui_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(self.ui_dir), 0o700)
        except OSError:
            pass
        self.keys_path = self.ui_dir / "keys.json"
        self.keyfile_path = self.ui_dir / "keyfile"
        self.lock_path = self.ui_dir / "keys.lock"
        self._urlopen = urlopen or urllib.request.urlopen
        self._from_env = False
        if secret is not None:
            material = [secret if isinstance(secret, bytes) else str(secret).encode("ascii")]
            _parse_keys(b",".join(material).decode("ascii"))
        elif os.environ.get("OMEGA_SECRET"):
            material = _parse_keys(os.environ["OMEGA_SECRET"])
            self._from_env = True
        else:
            material = self._keyfile_keys()
        if not material:
            raise ValueError("no Fernet key available")
        self._keys = list(material)
        self._fernet = MultiFernet([Fernet(k) for k in self._keys])

    def _keyfile_keys(self) -> list:
        if self.keyfile_path.is_file():
            keys = _parse_keys(self.keyfile_path.read_text(encoding="ascii"))
            if keys:
                return keys
        key = Fernet.generate_key()
        _write_private(self.keyfile_path, key + b"\n")
        return [key]

    @property
    def kid(self) -> int:
        return len(self._keys)

    def signing_key(self) -> bytes:
        return self._keys[0]

    def add_key(self) -> int:
        if self._from_env:
            raise PermissionError("keys come from OMEGA_SECRET; rotate them there")
        key = Fernet.generate_key()
        self._keys = [key] + self._keys
        _write_private(self.keyfile_path, b"\n".join(self._keys) + b"\n")
        self._fernet = MultiFernet([Fernet(k) for k in self._keys])
        return self.kid

    @contextmanager
    def _locked(self):
        fd = os.open(str(self.lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _load(self) -> dict:
        try:
            data = json.loads(self.keys_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            raise PermissionError("the key store is unreadable")
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict) -> None:
        _write_private(self.keys_path, json.dumps(data, indent=1, sort_keys=True).encode("utf-8"))

    def validate(self, provider: str, key: str) -> str:
        if provider not in PROVIDERS:
            raise KeyRejected("unknown provider %r" % provider)
        if not isinstance(key, str):
            raise KeyRejected("the key must be a string")
        value = key.strip()
        if len(value) > MAX_KEY_LENGTH:
            raise KeyRejected("the key is longer than %d characters" % MAX_KEY_LENGTH)
        if len(value) < MIN_KEY_LENGTH:
            raise KeyRejected("the key is too short")
        if not KEY_PATTERNS[provider].match(value):
            raise KeyRejected("the key does not look like a %s key" % provider)
        return value

    @staticmethod
    def _prefix(provider: str, value: str) -> str:
        for prefix in KEY_PREFIXES[provider]:
            if value.startswith(prefix):
                return prefix
        return ""

    @staticmethod
    def _masked(provider: str, entry: dict) -> dict:
        return {
            "provider": provider,
            "prefix": entry.get("prefix", ""),
            "last4": entry.get("last4", ""),
            "created_at": entry.get("created_at"),
            "last_used_at": entry.get("last_used_at"),
            "status": entry.get("status", "unverified"),
            "kid": entry.get("kid"),
        }

    def set_key(self, user_id: str, provider: str, key: str) -> dict:
        value = self.validate(provider, key)
        redaction.register_exact([value])
        sealed = json.dumps({"u": user_id, "p": provider, "k": value}, separators=(",", ":")).encode("utf-8")
        token = self._fernet.encrypt(sealed).decode("ascii")
        entry = {
            "token": token,
            "prefix": self._prefix(provider, value),
            "last4": value[-4:],
            "kid": self.kid,
            "created_at": _iso(),
            "last_used_at": None,
            "status": "unverified",
        }
        with self._locked():
            data = self._load()
            data.setdefault(user_id, {})[provider] = entry
            self._save(data)
        return self._masked(provider, entry)

    def _entry(self, user_id: str, provider: str) -> dict:
        entry = self._load().get(user_id, {}).get(provider)
        if not isinstance(entry, dict) or not entry.get("token"):
            raise KeyError(provider)
        return entry

    def has_key(self, user_id: str, provider: str) -> bool:
        try:
            self._entry(user_id, provider)
        except (KeyError, PermissionError):
            return False
        return True

    def get_key(self, user_id: str, provider: str) -> Secret:
        entry = self._entry(user_id, provider)
        try:
            sealed = json.loads(self._fernet.decrypt(entry["token"].encode("ascii")).decode("utf-8"))
        except (InvalidToken, ValueError, UnicodeDecodeError):
            raise PermissionError("the stored %s key cannot be decrypted with the current secret" % provider)
        if not isinstance(sealed, dict) or sealed.get("u") != user_id or sealed.get("p") != provider:
            raise PermissionError("the stored %s key is bound to a different user or provider" % provider)
        value = sealed.get("k")
        if not isinstance(value, str) or not value:
            raise PermissionError("the stored %s key is empty" % provider)
        redaction.register_exact([value])
        return Secret(value)

    def list_keys(self, user_id: str) -> list:
        entries = self._load().get(user_id, {})
        order = list(self.cfg.get("ui.fallback_order", list(PROVIDERS)) or PROVIDERS)
        order += [p for p in PROVIDERS if p not in order]
        return [self._masked(p, entries[p]) for p in order if isinstance(entries.get(p), dict)]

    def delete_key(self, user_id: str, provider: str) -> None:
        with self._locked():
            data = self._load()
            entry = data.get(user_id, {}).get(provider)
            if not isinstance(entry, dict):
                raise KeyError(provider)
            entry["token"] = base64.urlsafe_b64encode(secrets.token_bytes(len(entry.get("token", "")) or 64)).decode()
            entry["last4"] = ""
            self._save(data)
            del data[user_id][provider]
            if not data[user_id]:
                del data[user_id]
            self._save(data)

    def _update(self, user_id: str, provider: str, **fields) -> None:
        with self._locked():
            data = self._load()
            entry = data.get(user_id, {}).get(provider)
            if isinstance(entry, dict):
                entry.update(fields)
                self._save(data)

    def verify_key(self, user_id: str, provider: str) -> dict:
        secret = self.get_key(user_id, provider)
        url = VERIFY_ENDPOINTS[provider]
        if provider == "anthropic":
            headers = {"x-api-key": secret.reveal(), "anthropic-version": "2023-06-01"}
        elif provider == "openai":
            headers = {"Authorization": "Bearer " + secret.reveal()}
        else:
            headers = {"x-goog-api-key": secret.reveal()}
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            response = self._urlopen(request, timeout=VERIFY_TIMEOUT_S)
            try:
                code = getattr(response, "status", None) or response.getcode()
            finally:
                close = getattr(response, "close", None)
                if close:
                    close()
            if 200 <= int(code) < 300:
                status, detail = "verified", "the provider accepted the key"
            else:
                status, detail = "unverified", "unexpected HTTP %s" % code
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                status, detail = "invalid", "the provider rejected the key (HTTP %d)" % exc.code
            else:
                status, detail = "unverified", "the provider answered HTTP %d" % exc.code
        except (urllib.error.URLError, OSError, ValueError) as exc:
            status, detail = "unverified", "could not reach the provider: %s" % exc.__class__.__name__
        self._update(user_id, provider, status=status, verified_at=_iso())
        return {"status": status, "detail": redaction.redact_text(detail)}

    def _roles(self) -> dict:
        return self.cfg.get("cost.roles", {}) or {}

    def default_model(self, provider: str) -> Optional[str]:
        configured = self.cfg.get("ui.default_models", {}) or {}
        return configured.get(provider) or DEFAULT_MODELS.get(provider)

    def choose(self, role: str, provider: Optional[str] = None, model: Optional[str] = None,
               user_id: str = "local") -> Choice:
        roles = self._roles()
        if role not in roles:
            raise NoProvider("unknown role %r" % role)
        role_cfg = roles[role] or {}
        runtimes = self.cfg.get("ui.runtimes", {}) or {}
        order = list(self.cfg.get("ui.fallback_order", list(PROVIDERS)) or PROVIDERS)
        budget = float(role_cfg.get("max_budget_usd") or 0.0)
        if provider is not None:
            if provider not in PROVIDERS:
                raise NoProvider("unknown provider %r" % provider)
            if not runtimes.get(provider):
                raise NoProvider("%s has no runtime in this version (key store only)" % provider)
            if not self.has_key(user_id, provider):
                raise NoProvider("no %s key is stored" % provider)
            candidates = [provider]
        else:
            candidates = []
            for name in [role_cfg.get("provider")] + order:
                if name and name not in candidates:
                    candidates.append(name)
        skipped: list = []
        for name in candidates:
            if not runtimes.get(name):
                skipped.append("%s: no runtime" % name)
                continue
            if not self.has_key(user_id, name):
                skipped.append("%s: no key" % name)
                continue
            if model:
                chosen_model = model
            elif name == role_cfg.get("provider") and role_cfg.get("model"):
                chosen_model = role_cfg.get("model")
            else:
                chosen_model = self.default_model(name)
            return Choice(provider=name, model=chosen_model, runtime=runtimes[name], max_budget_usd=budget)
        raise NoProvider("no provider can run role %r (%s)" % (role, "; ".join(skipped) or "none configured"))

    def env_for(self, user_id: str, choice: Choice, run: dict) -> dict:
        env: dict = {}
        for name in BASE_ENV:
            value = os.environ.get(name)
            if value:
                env[name] = value
        env.setdefault("PATH", DEFAULT_PATH)
        env[KEY_ENV[choice.provider]] = self.get_key(user_id, choice.provider).reveal()
        harness = {
            "OMEGA_RUN_ID": run.get("run_id"),
            "OMEGA_WORKSPACE": run.get("workspace"),
            "OMEGA_STATE_DIR": str(self.state_root),
            "OMEGA_HUMAN_LOG": run.get("human_log"),
            "OMEGA_PROVIDER": choice.runtime,
        }
        for name, value in harness.items():
            if value:
                env[name] = str(value)
        for forbidden in ("OMEGA_SECRET", "OMEGA_UI_TOKEN", "OMEGA_GIT_TOKEN"):
            env.pop(forbidden, None)
        self._update(user_id, choice.provider, last_used_at=_iso())
        return env

    def backoff(self, attempt: int) -> float:
        settings = self.cfg.get("ui.backoff", {}) or {}
        base = float(settings.get("base_s", 2))
        cap = float(settings.get("max_s", 60))
        delay = min(base * (2 ** max(0, int(attempt))), cap)
        return delay + random.uniform(0, min(1.0, base))

    def preflight(self, choice: Choice, prompt: str, run_id: Optional[str] = None,
                  budget_usd: Optional[float] = None) -> dict:
        cfg = self.cfg
        model = choice.model
        if not model:
            raise costledger.UnknownModel("no model chosen for %s" % choice.provider)
        in_tokens = costledger.estimate_tokens(prompt or "", cfg)
        out_tokens = int(cfg.get("cost.static.default_max_tokens", 1024) or 1024)
        est = costledger.estimate_usd(model, in_tokens, out_tokens, cfg)
        verdict = costledger.check(cfg, run_id=run_id or "-", allow_unknown=True)
        if verdict.status == costledger.FAIL:
            raise BudgetExceeded("the cost ledger is already over a cap: %s" % "; ".join(verdict.breaches))
        if verdict.status != costledger.PASS:
            raise BudgetExceeded("the cost ledger cannot be verified: %s" % "; ".join(verdict.breaches or verdict.warnings))
        limits = verdict.sums.get("caps") or costledger.caps(cfg)
        run_total = float(verdict.sums.get("run") or 0.0) if run_id else 0.0
        month_total = float(verdict.sums.get("month") or 0.0)
        per_run = float(limits.get("per_run_usd") or 0.0)
        monthly = float(limits.get("monthly_usd") or 0.0)
        per_call = float(limits.get("per_call_usd") or 0.0)
        if per_call and est > per_call:
            raise BudgetExceeded("estimated $%.4f for the first call exceeds the per-call cap $%.2f" % (est, per_call))
        if per_run and est + run_total > per_run:
            raise BudgetExceeded("estimated $%.4f + run so far $%.4f exceeds the per-run cap $%.2f" % (est, run_total, per_run))
        if monthly and est + month_total > monthly:
            raise BudgetExceeded("estimated $%.4f + month so far $%.4f exceeds the monthly cap $%.2f" % (est, month_total, monthly))
        if budget_usd is not None and est > float(budget_usd):
            raise BudgetExceeded("estimated $%.4f exceeds the requested budget $%.2f" % (est, float(budget_usd)))
        ceilings = [choice.max_budget_usd or float("inf")]
        if per_run:
            ceilings.append(per_run - run_total)
        if monthly:
            ceilings.append(monthly - month_total)
        if budget_usd is not None:
            ceilings.append(float(budget_usd))
        max_budget = min(ceilings)
        if max_budget == float("inf"):
            max_budget = per_run or 1.0
        if max_budget <= 0 or max_budget < est:
            raise BudgetExceeded("no budget left for this run ($%.4f available, $%.4f estimated)" % (max(0.0, max_budget), est))
        return {"est_usd": round(est, 6), "in_tokens": in_tokens, "out_tokens": out_tokens,
                "max_budget_usd": round(max_budget, 4), "run_usd": round(run_total, 6),
                "month_usd": round(month_total, 6), "caps": limits}

    def record_usage(self, run: dict, usage: dict, usd: Optional[float], source: str) -> None:
        row = {
            "id": usage.get("id") or "%s:%s" % (run.get("run_id"), secrets.token_hex(6)),
            "source": source,
            "provider": run.get("provider"),
            "model": run.get("model"),
            "role": run.get("role"),
            "session_id": run.get("session_id"),
            "run_id": run.get("run_id"),
            "workspace_hash": paths.workspace_hash(run["workspace"]) if run.get("workspace") else None,
            "in": int(usage.get("in", 0) or 0),
            "out": int(usage.get("out", 0) or 0),
            "cache_read": int(usage.get("cache_read", 0) or 0),
            "cache_write": int(usage.get("cache_write", 0) or 0),
            "usd": usd,
            "est_usd": usage.get("est_usd"),
        }
        if usd is not None:
            row["verified_price"] = source == "cli_result" and run.get("provider") == "anthropic"
        costledger.append(row, self.cfg)

    def rotate(self) -> int:
        count = 0
        with self._locked():
            data = self._load()
            for user_entries in data.values():
                if not isinstance(user_entries, dict):
                    continue
                for entry in user_entries.values():
                    if not isinstance(entry, dict) or not entry.get("token"):
                        continue
                    entry["token"] = self._fernet.rotate(entry["token"].encode("ascii")).decode("ascii")
                    entry["kid"] = self.kid
                    count += 1
            self._save(data)
        return count

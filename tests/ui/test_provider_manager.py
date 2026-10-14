from __future__ import annotations

import io
import json
import os
import stat
import urllib.error

import pytest

from cryptography.fernet import Fernet

from hooks.lib import config as config_mod
from hooks.lib import costledger
from tests.conftest import OMEGA_ROOT
from tests.ui.conftest import synthetic_key
from ui.provider_manager import (BudgetExceeded, Choice, KeyRejected, NoProvider, ProviderManager, Secret)


def _cfg(tmp_path, overlay=None):
    if overlay:
        ws = tmp_path / "cfgws"
        (ws / ".omega").mkdir(parents=True, exist_ok=True)
        (ws / ".omega" / "config.json").write_text(json.dumps(overlay), encoding="utf-8")
        return config_mod.load(OMEGA_ROOT, str(ws))
    return config_mod.load(OMEGA_ROOT)


@pytest.fixture
def pm(tmp_state, tmp_path):
    return ProviderManager(tmp_state, _cfg(tmp_path))


def _mode(path):
    return stat.S_IMODE(os.stat(str(path)).st_mode)


def test_key_is_encrypted_at_rest_and_files_are_private(pm, tmp_state):
    key = synthetic_key("anthropic")
    entry = pm.set_key("local", "anthropic", key)
    assert key not in json.dumps(entry)
    assert entry["prefix"] == "sk-ant-" and entry["last4"] == key[-4:] and entry["status"] == "unverified"
    raw = (tmp_state / "ui" / "keys.json").read_text(encoding="utf-8")
    assert key not in raw
    assert key[8:40] not in raw
    stored = json.loads(raw)["local"]["anthropic"]
    assert stored["token"].startswith("gAAAA")
    assert _mode(tmp_state / "ui" / "keys.json") == 0o600
    assert _mode(tmp_state / "ui" / "keyfile") == 0o600
    assert _mode(tmp_state / "ui") == 0o700


def test_secret_never_renders_its_value(pm):
    key = synthetic_key("openai")
    pm.set_key("local", "openai", key)
    secret = pm.get_key("local", "openai")
    assert isinstance(secret, Secret)
    assert str(secret) == "****" and repr(secret) == "****" and "%s" % secret == "****"
    assert "{}".format(secret) == "****" and f"{secret}" == "****"
    assert json.dumps({"k": secret}) == '{"k": "****"}'
    assert secret.reveal() == key


def test_binding_mismatch_is_refused(pm, tmp_state):
    key = synthetic_key("anthropic")
    pm.set_key("local", "anthropic", key)
    pm.set_key("local", "openai", synthetic_key("openai"))
    path = tmp_state / "ui" / "keys.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["local"]["openai"]["token"] = data["local"]["anthropic"]["token"]
    data["intruder"] = {"anthropic": dict(data["local"]["anthropic"])}
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PermissionError):
        pm.get_key("local", "openai")
    with pytest.raises(PermissionError):
        pm.get_key("intruder", "anthropic")
    assert pm.get_key("local", "anthropic").reveal() == key


def test_wrong_secret_cannot_decrypt(tmp_state, tmp_path):
    first = ProviderManager(tmp_state, _cfg(tmp_path), secret=Fernet.generate_key())
    first.set_key("local", "anthropic", synthetic_key("anthropic"))
    second = ProviderManager(tmp_state, _cfg(tmp_path), secret=Fernet.generate_key())
    with pytest.raises(PermissionError):
        second.get_key("local", "anthropic")


def test_harness_secret_env_is_used_instead_of_a_keyfile(tmp_state, tmp_path, monkeypatch):
    secret = Fernet.generate_key().decode()
    monkeypatch.setenv("OMEGA_SECRET", secret)
    manager = ProviderManager(tmp_state, _cfg(tmp_path))
    key = synthetic_key("google")
    manager.set_key("local", "google", key)
    assert not (tmp_state / "ui" / "keyfile").exists()
    assert ProviderManager(tmp_state, _cfg(tmp_path), secret=secret.encode()).get_key("local", "google").reveal() == key
    monkeypatch.setenv("OMEGA_SECRET", "not-a-fernet-key")
    with pytest.raises(ValueError):
        ProviderManager(tmp_state, _cfg(tmp_path))


def test_rotate_reencrypts_with_the_newest_key(pm, tmp_state, tmp_path):
    key = synthetic_key("anthropic")
    pm.set_key("local", "anthropic", key)
    old_material = (tmp_state / "ui" / "keyfile").read_text(encoding="ascii").split()[0].encode()
    assert pm.add_key() == 2
    assert pm.rotate() == 1
    entry = json.loads((tmp_state / "ui" / "keys.json").read_text(encoding="utf-8"))["local"]["anthropic"]
    assert entry["kid"] == 2
    assert pm.get_key("local", "anthropic").reveal() == key
    with pytest.raises(PermissionError):
        ProviderManager(tmp_state, _cfg(tmp_path), secret=old_material).get_key("local", "anthropic")
    assert ProviderManager(tmp_state, _cfg(tmp_path)).get_key("local", "anthropic").reveal() == key


@pytest.mark.parametrize("provider,key", [
    ("anthropic", "sk-proj-abcdefghijklmnop"),
    ("openai", "sk-ant-api03-abcdefghijklmnop"),
    ("google", "sk-abcdefghijklmnopqrst"),
    ("anthropic", "sk-ant-" + "a" * 600),
    ("anthropic", "sk-ant-short"),
    ("anthropic", "sk-ant-api03 with spaces inside"),
    ("mistral", "sk-abcdefghijklmnopqrst"),
])
def test_invalid_keys_are_rejected(pm, provider, key):
    with pytest.raises(KeyRejected):
        pm.set_key("local", provider, key)


def test_delete_overwrites_then_removes(pm, tmp_state):
    pm.set_key("local", "anthropic", synthetic_key("anthropic"))
    pm.delete_key("local", "anthropic")
    assert pm.list_keys("local") == []
    assert not pm.has_key("local", "anthropic")
    with pytest.raises(KeyError):
        pm.delete_key("local", "anthropic")


def test_fallback_order_skips_providers_without_key_or_runtime(pm, tmp_path, tmp_state):
    with pytest.raises(NoProvider):
        pm.choose("implementer")
    pm.set_key("local", "google", synthetic_key("google"))
    with pytest.raises(NoProvider) as excinfo:
        pm.choose("implementer")
    assert "google: no runtime" in str(excinfo.value)
    pm.set_key("local", "openai", synthetic_key("openai"))
    choice = pm.choose("implementer")
    assert (choice.provider, choice.runtime, choice.model) == ("openai", "codex", "gpt-5.6-sol")
    assert choice.max_budget_usd == 10.0
    pm.set_key("local", "anthropic", synthetic_key("anthropic"))
    choice = pm.choose("implementer")
    assert (choice.provider, choice.runtime, choice.model) == ("anthropic", "claude", "claude-opus-5-5")
    assert pm.choose("research").model == "claude-sonnet-5-5"
    assert pm.choose("implementer", provider="openai").provider == "openai"
    assert pm.choose("implementer", model="claude-haiku-5-5").model == "claude-haiku-5-5"
    with pytest.raises(NoProvider):
        pm.choose("implementer", provider="google")
    with pytest.raises(NoProvider):
        pm.choose("janitor")


def test_fallback_order_comes_from_config(tmp_state, tmp_path):
    overlay = {"ui": {"fallback_order": ["openai", "anthropic", "google"]},
               "cost": {"roles": {"implementer": {"provider": "google", "model": "gemini-3.8-flash", "max_budget_usd": 1.0}}}}
    manager = ProviderManager(tmp_state, _cfg(tmp_path, overlay))
    manager.set_key("local", "anthropic", synthetic_key("anthropic"))
    manager.set_key("local", "openai", synthetic_key("openai"))
    manager.set_key("local", "google", synthetic_key("google"))
    choice = manager.choose("implementer")
    assert choice.provider == "openai"
    assert [k["provider"] for k in manager.list_keys("local")] == ["openai", "anthropic", "google"]


def test_env_for_holds_exactly_one_key_and_no_operator_secrets(pm, tmp_state, monkeypatch):
    monkeypatch.setenv("OMEGA_SECRET", Fernet.generate_key().decode())
    monkeypatch.setenv("OMEGA_UI_TOKEN", "operator-token-value")
    monkeypatch.setenv("OMEGA_GIT_TOKEN", "git-token-value")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-from-the-server-environment")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret-from-the-server")
    key = synthetic_key("anthropic")
    pm.set_key("local", "anthropic", key)
    pm.set_key("local", "openai", synthetic_key("openai"))
    choice = pm.choose("implementer")
    run = {"run_id": "run-20261013000000-abcd", "workspace": "/tmp/ws", "human_log": "/tmp/h.jsonl"}
    env = pm.env_for("local", choice, run)
    key_vars = [name for name in env if name.endswith("_API_KEY") or name.endswith("_KEY")]
    assert key_vars == ["ANTHROPIC_API_KEY"]
    assert env["ANTHROPIC_API_KEY"] == key
    for forbidden in ("OMEGA_SECRET", "OMEGA_UI_TOKEN", "OMEGA_GIT_TOKEN", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY"):
        assert forbidden not in env
    assert env["OMEGA_RUN_ID"] == run["run_id"]
    assert env["OMEGA_HUMAN_LOG"] == "/tmp/h.jsonl"
    assert env["OMEGA_STATE_DIR"] == str(tmp_state)
    assert env["OMEGA_PROVIDER"] == "claude"
    assert set(env) <= {"PATH", "HOME", "LANG", "TMPDIR", "ANTHROPIC_API_KEY", "OMEGA_RUN_ID", "OMEGA_WORKSPACE",
                        "OMEGA_STATE_DIR", "OMEGA_HUMAN_LOG", "OMEGA_PROVIDER"}
    assert pm.list_keys("local")[0]["last_used_at"]


def test_backoff_is_exponential_capped_and_jittered(pm):
    assert 2.0 <= pm.backoff(0) <= 3.0
    assert 8.0 <= pm.backoff(2) <= 9.0
    assert 60.0 <= pm.backoff(12) <= 61.0


class _Response:
    def __init__(self, status):
        self.status = status

    def getcode(self):
        return self.status

    def close(self):
        pass


def test_verify_key_without_network(tmp_state, tmp_path):
    seen = []

    def opener(request, timeout):
        seen.append(request)
        mode = opener.mode
        if mode == "ok":
            return _Response(200)
        if mode == "denied":
            raise urllib.error.HTTPError(request.full_url, 401, "no", {}, io.BytesIO(b""))
        raise urllib.error.URLError("offline")

    manager = ProviderManager(tmp_state, _cfg(tmp_path), urlopen=opener)
    key = synthetic_key("anthropic")
    manager.set_key("local", "anthropic", key)
    opener.mode = "ok"
    assert manager.verify_key("local", "anthropic")["status"] == "verified"
    assert seen[-1].get_header("X-api-key") == key
    assert seen[-1].full_url == "https://api.anthropic.com/v1/models"
    opener.mode = "denied"
    result = manager.verify_key("local", "anthropic")
    assert result["status"] == "invalid" and key not in result["detail"]
    opener.mode = "offline"
    assert manager.verify_key("local", "anthropic")["status"] == "unverified"
    assert manager.has_key("local", "anthropic")
    manager.set_key("local", "openai", synthetic_key("openai"))
    opener.mode = "ok"
    manager.verify_key("local", "openai")
    assert seen[-1].get_header("Authorization").startswith("Bearer sk-proj-")


def test_preflight_estimates_and_caps_the_budget(pm, monkeypatch):
    pm.set_key("local", "anthropic", synthetic_key("anthropic"))
    choice = pm.choose("implementer")
    plan = pm.preflight(choice, "write a test", run_id="run-20261013000000-aaaa")
    assert plan["est_usd"] > 0
    assert plan["max_budget_usd"] == 5.0
    assert pm.preflight(choice, "x" * 40, budget_usd=0.5)["max_budget_usd"] == 0.5
    monkeypatch.setenv("OMEGA_BUDGET_PER_RUN_USD", "0.0001")
    with pytest.raises(BudgetExceeded):
        pm.preflight(choice, "write a test", run_id="run-20261013000000-bbbb")


def test_preflight_refuses_unknown_models_and_spent_months(pm, tmp_state):
    with pytest.raises(costledger.UnknownModel):
        pm.preflight(Choice("anthropic", "claude-mystery-9", "claude", 1.0), "hello")
    costledger.append({"id": "big", "model": "claude-opus-5-5", "in": 30_000_000, "out": 0, "session_id": "s"}, pm.cfg)
    with pytest.raises(BudgetExceeded) as excinfo:
        pm.preflight(Choice("anthropic", "claude-opus-5-5", "claude", 10.0), "hello")
    assert "over a cap" in str(excinfo.value)


def test_preflight_fails_closed_on_a_corrupt_ledger(pm, tmp_state):
    ledger = costledger.ledger_path()
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text("{not json\n", encoding="utf-8")
    with pytest.raises(BudgetExceeded) as excinfo:
        pm.preflight(Choice("anthropic", "claude-opus-5-5", "claude", 10.0), "hello")
    assert "cannot be verified" in str(excinfo.value)


def test_record_usage_appends_a_cli_result_row(pm, workspace):
    run = {"run_id": "run-20261013000000-cccc", "provider": "openai", "model": "gpt-5.6-sol", "role": "implementer",
           "session_id": "thread-1", "workspace": str(workspace)}
    pm.record_usage(run, {"id": "run-x:1", "in": 1000, "out": 100}, None, "cli_result")
    rows = costledger.rows(pm.cfg)
    assert rows[-1]["source"] == "cli_result" and rows[-1]["run_id"] == run["run_id"]
    assert rows[-1]["usd"] > 0 and rows[-1]["verified_price"] is False
    pm.record_usage(run, {"id": "run-x:1", "in": 1000, "out": 100}, None, "cli_result")
    assert len(costledger.rows(pm.cfg)) == 1

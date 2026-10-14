from __future__ import annotations

import json

from hooks.lib import config


def test_defaults_are_identical_to_the_shipped_file(harness_root):
    shipped = json.loads((harness_root / "omega.config.json").read_text(encoding="utf-8"))
    assert config.DEFAULTS == shipped


def test_load_reads_shipped_file_and_reports_sources(harness_root):
    cfg = config.load(harness_root)
    assert cfg.get("tdd.mode") == "strict"
    assert cfg.get("stop.max_attempts") == 4
    assert cfg.sources[:2] == ["defaults", str(harness_root / "omega.config.json")]


def test_get_returns_default_for_missing_and_copies_values(harness_root):
    cfg = config.load(harness_root)
    assert cfg.get("nope.missing", "x") == "x"
    assert cfg.get("tdd.mode.too.deep") is None
    globs = cfg.get("tdd.test_globs")
    globs.append("mutated")
    assert "mutated" not in cfg.get("tdd.test_globs")
    data = cfg.as_dict()
    data["tdd"]["mode"] = "changed"
    assert cfg.get("tdd.mode") == "strict"


def test_workspace_override_deep_merges_dicts_and_replaces_lists(harness_root, tmp_path):
    (tmp_path / ".omega").mkdir()
    (tmp_path / ".omega" / "config.json").write_text(json.dumps({
        "tdd": {"mode": "red-or-green", "source_exts": [".py"]},
        "cost": {"caps": {"monthly_usd": 7.5}},
    }))
    cfg = config.load(harness_root, str(tmp_path))
    assert cfg.get("tdd.mode") == "red-or-green"
    assert cfg.get("tdd.source_exts") == [".py"]
    assert cfg.get("tdd.debounce_s") == 0.8
    assert cfg.get("cost.caps.monthly_usd") == 7.5
    assert cfg.get("cost.caps.per_call_usd") == 0.5


def test_invalid_workspace_override_is_ignored_and_reported(harness_root, tmp_path):
    (tmp_path / ".omega").mkdir()
    (tmp_path / ".omega" / "config.json").write_text("{not json")
    cfg = config.load(harness_root, str(tmp_path))
    assert cfg.get("tdd.mode") == "strict"
    assert cfg.errors and "unreadable" in cfg.errors[0]
    (tmp_path / ".omega" / "config.json").write_text("[1, 2]")
    assert "not a JSON object" in config.load(harness_root, str(tmp_path)).errors[0]


def test_env_overrides_win_over_files(harness_root, tmp_path, monkeypatch):
    (tmp_path / ".omega").mkdir()
    (tmp_path / ".omega" / "config.json").write_text(json.dumps({"tdd": {"mode": "red-or-green"}}))
    monkeypatch.setenv("OMEGA_TDD_MODE", "strict")
    monkeypatch.setenv("OMEGA_BUDGET_PER_CALL_USD", "0.25")
    monkeypatch.setenv("OMEGA_BUDGET_MONTHLY_USD", "not-a-number")
    cfg = config.load(harness_root, str(tmp_path))
    assert cfg.get("tdd.mode") == "strict"
    assert cfg.get("cost.caps.per_call_usd") == 0.25
    assert cfg.get("cost.caps.monthly_usd") == 100.0
    assert "env" in cfg.sources


def test_missing_shipped_file_falls_back_to_defaults(tmp_path):
    cfg = config.load(tmp_path)
    assert cfg.get("tdd.mode") == "strict"
    assert cfg.sources[0] == "defaults"
    assert not any(src.endswith("omega.config.json") for src in cfg.sources)


def test_env_names_cover_the_spec():
    expected = {"OMEGA_STATE_DIR", "OMEGA_WORKSPACE", "OMEGA_PROVIDER", "OMEGA_SESSION_ID",
                "OMEGA_RUN_ID", "OMEGA_DEBUG", "OMEGA_DEV", "OMEGA_HUMAN_LOG", "OMEGA_SECRET",
                "OMEGA_UI_TOKEN", "OMEGA_GIT_TOKEN", "OMEGA_TDD_MODE", "OMEGA_BUDGET_PER_CALL_USD",
                "OMEGA_BUDGET_PER_SESSION_USD", "OMEGA_BUDGET_PER_RUN_USD", "OMEGA_BUDGET_MONTHLY_USD",
                "OMEGA_ALLOW_UNHOOKED"}
    assert set(config.ENV_NAMES) == expected

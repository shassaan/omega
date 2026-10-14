from __future__ import annotations

import importlib.util
import json
import random
from pathlib import Path

import pytest

from hooks import buildtime_compiler as bt
from hooks.lib import config as config_mod
from tests.gates.conftest import write_ws_config

LABELS = {"billing": ["refund my invoice {n}", "charged twice on order {n}", "billing question about invoice {n}"],
          "shipping": ["where is my parcel {n}", "tracking number {n} not moving", "parcel {n} delayed"],
          "account": ["reset my password please", "cannot login to account {n}", "change my account email"]}


def calls_dir(ws: Path) -> Path:
    return ws / ".omega" / "buildtime"


def write_jsonl(path: Path, rows: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(path), "a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


def log_training(ws: Path, callsite: str, per_template: int = 30, prompt_hash: str = "p1") -> None:
    rows = []
    for label, templates in LABELS.items():
        for template in templates:
            for i in range(per_template):
                rows.append({"ts": "2026-10-01T00:00:00Z", "ts_ns": 1, "callsite": callsite,
                             "input": template.format(n=1000 + i), "output": label, "model": "claude-haiku-5-5",
                             "prompt_hash": prompt_hash, "source": "llm", "rule_id": None, "meta": {}})
    write_jsonl(calls_dir(ws) / "calls" / ("%s.jsonl" % callsite), rows)


def shadow_rows(ws: Path, callsite: str, n: int, disagree: int, days=("2026-10-01", "2026-10-02", "2026-10-03"),
                version=1, phase="shadow", abstain: int = 0) -> None:
    labels = list(LABELS)
    rows = []
    for i in range(n):
        label = labels[i % len(labels)]
        llm = label if i >= disagree else "other"
        rows.append({"ts": "%sT10:00:00Z" % days[i % len(days)], "ts_ns": i, "callsite": callsite,
                     "input_hash": "h%d" % i, "rule_out": label, "rule_id": "r001", "llm_out": llm,
                     "agree": llm == label, "phase": phase, "version": version})
    for i in range(abstain):
        rows.append({"ts": "2026-10-01T10:00:00Z", "ts_ns": i, "callsite": callsite, "input_hash": "a%d" % i,
                     "rule_out": None, "rule_id": None, "llm_out": "billing", "agree": False, "phase": phase,
                     "version": version})
    write_jsonl(calls_dir(ws) / "shadow" / ("%s.jsonl" % callsite), rows)


@pytest.fixture
def cfg(workspace):
    return config_mod.load(workspace=str(workspace))


def test_wilson_upper_matches_research_table():
    assert bt.wilson_upper(0, 765) < 0.005 <= bt.wilson_upper(0, 764)
    assert bt.wilson_upper(1, 1130) < 0.005 <= bt.wilson_upper(1, 1120)
    assert bt.wilson_upper(0, 0) == 1.0
    assert bt.wilson_upper(0, 1321, 2.576) < 0.005


def test_normalize():
    text = "Order 123 for Bob@Mail.com id 3f2b1c4e-1111-2222-3333-444455556666  now"
    assert bt.normalize(text) == "order <N> for <EMAIL> id <ID> now"


def test_mine_and_synth_compile_rules(workspace, cfg):
    log_training(workspace, "triage")
    report = bt.mine(str(workspace), "triage", cfg)
    assert report["eligible"] and report["cardinality"] == 3 and report["n"] == 270
    code, result = bt.synth(str(workspace), "triage", cfg)
    assert code == 0, result
    compiled = workspace / "buildtime" / "compiled" / "triage.py"
    module = bt.load_compiled(compiled)
    assert module.MANIFEST["callsite"] == "triage" and module.MANIFEST["version"] == 1
    assert module.match("Refund my invoice 77")[0] == "billing"
    assert module.match("where is my parcel 5")[0] == "shipping"
    assert module.match("completely novel request about llamas") == (None, None)
    assert result["training_agreement"] == 1.0
    assert "#" not in compiled.read_text(encoding="utf-8").split("MANIFEST")[0]
    registry = json.loads((workspace / "buildtime" / "registry.json").read_text(encoding="utf-8"))
    assert registry["triage"]["status"] == "candidate"


def test_synth_refuses_ineligible_and_insufficient(workspace, cfg):
    code, result = bt.synth(str(workspace), "empty", cfg)
    assert code == 2
    rows = [{"input": "q%d" % i, "output": "label-%d" % i, "source": "llm"} for i in range(80)]
    write_jsonl(calls_dir(workspace) / "calls" / "wide.jsonl", rows)
    code, result = bt.synth(str(workspace), "wide", cfg)
    assert code == 1 and "distinct outputs" in result["result"]
    prose = [{"input": "q%d" % i, "output": "a long\nfree form answer", "source": "llm"} for i in range(30)]
    write_jsonl(calls_dir(workspace) / "calls" / "prose.jsonl", prose)
    code, result = bt.synth(str(workspace), "prose", cfg)
    assert code == 1


def prepare_shadow(workspace, cfg, callsite="triage"):
    log_training(workspace, callsite)
    assert bt.synth(str(workspace), callsite, cfg)[0] == 0
    assert bt.shadow(str(workspace), callsite, cfg)[0] == 0


def test_promote_only_under_half_percent_with_sufficient_sample(workspace, cfg):
    prepare_shadow(workspace, cfg)
    shadow_rows(workspace, "triage", 1200, 0, abstain=300)
    code, report = bt.promote(str(workspace), "triage", cfg)
    assert code == 0, report["result"]
    assert report["wilson_upper"] < 0.005 and report["coverage"] == pytest.approx(0.8)
    registry = json.loads((workspace / "buildtime" / "registry.json").read_text(encoding="utf-8"))
    assert registry["triage"]["status"] == "promoted"
    stats = json.loads((workspace / ".omega" / "buildtime" / "triage.stats.json").read_text(encoding="utf-8"))
    assert stats["n"] == 1200 and stats["k"] == 0


def test_promote_refuses_high_disagreement(workspace, cfg):
    prepare_shadow(workspace, cfg)
    shadow_rows(workspace, "triage", 1200, 5)
    code, report = bt.promote(str(workspace), "triage", cfg)
    assert code == 1 and report["wilson_upper"] >= 0.005
    assert "refused" in report["result"]


@pytest.mark.parametrize("n,days,expect", [(500, ("2026-10-01", "2026-10-02", "2026-10-03"), "n=500"),
                                           (1200, ("2026-10-01", "2026-10-02"), "2 distinct day")])
def test_promote_insufficient_sample(workspace, cfg, n, days, expect):
    prepare_shadow(workspace, cfg)
    shadow_rows(workspace, "triage", n, 0, days=days)
    code, report = bt.promote(str(workspace), "triage", cfg)
    assert code == 2 and expect in report["result"]


def test_promote_requires_every_label(workspace, cfg):
    prepare_shadow(workspace, cfg)
    rows = []
    for i in range(1200):
        label = "billing" if i % 100 else "account"
        rows.append({"ts": "2026-10-0%dT00:00:00Z" % (1 + i % 3), "rule_out": label, "llm_out": label,
                     "phase": "shadow", "version": 1})
    write_jsonl(calls_dir(workspace) / "shadow" / "triage.jsonl", rows)
    code, report = bt.promote(str(workspace), "triage", cfg)
    assert code == 2 and "shipping" in report["result"]


def test_prompt_hash_change_invalidates(workspace, cfg):
    prepare_shadow(workspace, cfg)
    shadow_rows(workspace, "triage", 1200, 0)
    assert bt.promote(str(workspace), "triage", cfg)[0] == 0
    write_jsonl(calls_dir(workspace) / "calls" / "triage.jsonl",
                [{"input": "x", "output": "billing", "prompt_hash": "p2", "source": "llm"}])
    code, report = bt.canary(str(workspace), "triage", cfg)
    assert code == 1 and "prompt hash changed" in report["result"]
    registry = json.loads((workspace / "buildtime" / "registry.json").read_text(encoding="utf-8"))
    assert registry["triage"]["status"] == "shadow"


def test_canary_demotes_on_disagreement(workspace, cfg):
    prepare_shadow(workspace, cfg)
    shadow_rows(workspace, "triage", 1200, 0)
    assert bt.promote(str(workspace), "triage", cfg)[0] == 0
    shadow_rows(workspace, "triage", 50, 0, phase="canary")
    code, report = bt.canary(str(workspace), "triage", cfg)
    assert code == 0 and "healthy so far" in report["result"]
    shadow_rows(workspace, "triage", 60, 20, phase="canary")
    code, report = bt.canary(str(workspace), "triage", cfg)
    assert code == 1 and report["result"].startswith("demoted")
    registry = json.loads((workspace / "buildtime" / "registry.json").read_text(encoding="utf-8"))
    assert registry["triage"]["status"] == "demoted"


def load_runtime(workspace: Path):
    spec = importlib.util.spec_from_file_location("ws_buildtime_%d" % random.randint(0, 10 ** 9),
                                                  str(workspace / "buildtime" / "__init__.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runtime_route_uses_rules_and_falls_back_on_unmatched(workspace):
    write_ws_config(workspace, {"buildtime": {"canary": {"rate": 0.0}}})
    cfg = config_mod.load(workspace=str(workspace))
    bt.init(str(workspace), cfg)
    prepare_shadow(workspace, cfg)
    runtime = load_runtime(workspace)
    calls = []

    def llm(x):
        calls.append(x)
        return "billing"
    assert runtime.status("triage") == "shadow"
    assert runtime.route("triage", "refund my invoice 9", llm) == "billing"
    assert len(calls) == 1
    shadow_file = calls_dir(workspace) / "shadow" / "triage.jsonl"
    assert json.loads(shadow_file.read_text(encoding="utf-8").splitlines()[-1])["agree"] is True
    shadow_rows(workspace, "triage", 1200, 0)
    assert bt.promote(str(workspace), "triage", cfg)[0] == 0
    calls.clear()
    assert runtime.route("triage", "where is my parcel 42", llm) == "shipping"
    assert calls == []
    assert runtime.route("triage", "an unseen question about llamas", llm) == "billing"
    assert calls == ["an unseen question about llamas"]
    last = json.loads((calls_dir(workspace) / "calls" / "triage.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert last["source"] == "llm"
    assert runtime.status("never-seen") == "unknown"


def test_cli_exit_codes(workspace, capsys):
    ws = str(workspace)
    assert bt.main(["init", "--workspace", ws]) == 0
    assert bt.main(["synth", "--callsite", "triage", "--workspace", ws]) == 2
    log_training(workspace, "triage")
    assert bt.main(["synth", "--callsite", "triage", "--workspace", ws]) == 0
    assert bt.main(["shadow", "--callsite", "triage", "--workspace", ws]) == 0
    assert bt.main(["promote", "--callsite", "triage", "--workspace", ws]) == 2
    shadow_rows(workspace, "triage", 1200, 0)
    capsys.readouterr()
    assert bt.main(["report", "--callsite", "triage", "--workspace", ws, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["n"] == 1200
    assert bt.main(["promote", "--callsite", "triage", "--workspace", ws, "--max-upper", "0.001"]) == 1
    assert bt.main(["promote", "--callsite", "triage", "--workspace", ws]) == 0
    assert bt.main(["demote", "--callsite", "triage", "--workspace", ws, "--reason", "manual"]) == 0
    assert bt.main(["synth", "--callsite", "../escape", "--workspace", ws]) == 2

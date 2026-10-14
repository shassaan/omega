from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import OMEGA_ROOT

from hooks.lib import config as config_mod
from hooks.lib import ledger
from hooks.stop_proof import GateResult

GATES = ("proof", "tdd", "contract", "review", "cost", "ship")


def load_script(rel: str, name: str):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, str(OMEGA_ROOT / rel))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def orchestrator():
    return load_script("bin/stop_orchestrator.py", "harness_stop_orchestrator")


@pytest.fixture(scope="session")
def auto_ship():
    return load_script("scripts/auto_ship.py", "harness_auto_ship")


@pytest.fixture(scope="session")
def gauntlet():
    return load_script("scripts/create_gauntlet.py", "harness_create_gauntlet")


def write_ws_config(workspace: Path, overlay: dict) -> None:
    target = Path(workspace) / ".omega" / "config.json"
    current = json.loads(target.read_text(encoding="utf-8")) if target.is_file() else {}
    merged = config_mod.deep_merge(current, overlay)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(merged), encoding="utf-8")


def reload_cfg(ctx) -> None:
    ctx.cfg = config_mod.load(ctx.harness_root, ctx.workspace)


def touch(ctx, rel: str, text: str, kind: str = "modified") -> Path:
    path = Path(ctx.workspace) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    ledger.append(ctx, str(path), kind, "Edit", "toolu_test")
    return path


def empty_ship(workspace: str, status: str = "PASS") -> dict:
    return {"schema": "omega/ship/1", "ts": "2026-10-13T10:00:00Z", "workspace": workspace, "mode": "fast",
            "strict": False, "status": status,
            "tiers": {t: {"status": "NOT_APPLICABLE", "applicable": False, "detected": [], "checks": []}
                      for t in ("infra", "database", "application", "analytics", "observability")}}


def stub(gate: str, status: str = "PASS", detail: str = "", items=None, data=None, sleep: float = 0.0,
         raises: Exception = None):
    def run(ctx, cfg, scope, deps):
        if sleep:
            import time
            time.sleep(sleep)
        if raises is not None:
            raise raises
        payload = data
        if gate == "ship" and payload is None:
            payload = {"ship": empty_ship(ctx.workspace)}
        return GateResult(gate, status, True, detail or "stub %s %s" % (gate, status), list(items or []), 1,
                          dict(payload or {}))
    return run


def stub_gates(**overrides) -> dict:
    gates = {g: stub(g) for g in GATES}
    for gate, value in overrides.items():
        gates[gate] = value if callable(value) else stub(gate, value)
    return gates


def make_executable(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture
def fake_bin(tmp_path, monkeypatch):
    directory = Path(os.path.realpath(str(tmp_path))) / "fakebin"
    directory.mkdir()
    monkeypatch.setenv("PATH", "%s:/usr/bin:/bin" % directory)
    return directory


def git(cwd, *args, check=True):
    return subprocess.run(["git", "-c", "user.email=omega-tests@example.com", "-c", "user.name=Harness Tests",
                           "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"] + list(args),
                          cwd=str(cwd), check=check, capture_output=True, text=True)


def schema(kind: str) -> dict:
    return json.loads((OMEGA_ROOT / "schemas" / ("%s.schema.json" % kind)).read_text(encoding="utf-8"))


def assert_valid(kind: str, instance: dict) -> None:
    try:
        import jsonschema
    except ImportError:
        return
    jsonschema.validate(instance, schema(kind), cls=jsonschema.Draft202012Validator)

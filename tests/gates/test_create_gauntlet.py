from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from hooks.lib import config as config_mod
from tests.conftest import OMEGA_ROOT

JOBS = ("lint", "tests", "security", "infra", "migrations", "ship-readiness", "cost", "mutation", "verdict")
TIMEOUTS = (10, 15, 10, 10, 10, 15, 5, 30, 2)


def write(root: Path, rel: str, text: str = "") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def app(tmp_path):
    root = Path(os.path.realpath(str(tmp_path))) / "app"
    write(root, "pyproject.toml", "[project]\nname='app'\n")
    write(root, "requirements.txt", "fastapi\n")
    write(root, "package.json", '{"devDependencies": {"vitest": "1"}}')
    write(root, "package-lock.json", "{}")
    write(root, "tsconfig.json", "{}")
    write(root, "eslint.config.js", "export default []\n")
    write(root, "infra/main.tf", "")
    write(root, "migrations/0001.sql", "CREATE TABLE t (id int);\n")
    return root


def parse(text: str) -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(text)


def test_render_is_parseable_and_complete(gauntlet, app):
    cfg = config_mod.load(workspace=str(app))
    workflow, toml, info = gauntlet.render(str(app), cfg, omega_repo="acme/harness@v1.2.3")
    assert "#" not in "".join(line.split('"')[0] for line in workflow.splitlines())
    doc = parse(workflow)
    assert doc["name"] == "gauntlet"
    assert doc["on"] == {"pull_request": {}, "push": {"branches": ["main"]}}
    assert doc["permissions"] == {"contents": "read"}
    assert doc["concurrency"]["cancel-in-progress"] is True
    assert tuple(doc["jobs"]) == JOBS
    for name, minutes in zip(JOBS, TIMEOUTS):
        assert doc["jobs"][name]["timeout-minutes"] == minutes
        assert doc["jobs"][name]["runs-on"] == "ubuntu-latest"
    assert doc["jobs"]["verdict"]["needs"] == list(JOBS[:-1]) and doc["jobs"]["verdict"]["if"] == "always()"
    assert doc["jobs"]["mutation"]["needs"] == ["lint", "tests"]
    assert doc["jobs"]["mutation"]["if"] == "github.event_name == 'pull_request'"
    uses = [s["uses"] for job in doc["jobs"].values() for s in job["steps"] if "uses" in s]
    assert "actions/checkout@v4" in uses and "gitleaks/gitleaks-action@v2" in uses
    assert all("@" in u for u in uses)
    harness = [s for s in doc["jobs"]["ship-readiness"]["steps"] if s.get("with", {}).get("path") == ".omega-ci"]
    assert harness[0]["with"]["repository"] == "acme/harness" and harness[0]["with"]["ref"] == "v1.2.3"
    runs = "\n".join(s.get("run", "") for job in doc["jobs"].values() for s in job["steps"])
    assert "ship_readiness.py run --workspace \"$GITHUB_WORKSPACE\" --mode full --strict --json" in runs
    assert "ship_readiness.py migration-lint" in runs and "origin/${{ github.base_ref" in runs
    assert "tokentoll_gate.py scan --path ." in runs and "--min-score 0.6" in runs
    assert "npx vitest run" in runs and "npx eslint . --max-warnings 0" in runs and "terraform fmt -check" in runs
    assert "pip-audit -r requirements.txt" in runs and "npm audit --audit-level=high" in runs
    assert "npx stryker run --incremental" in runs
    assert "'''^tests/fixtures/.*$'''" in toml or "tests/fixtures" in toml
    assert info["stack"]["terraform"] is True


def test_missing_harness_repo_fails_first_step(gauntlet, app, monkeypatch):
    monkeypatch.setattr(gauntlet, "resolve_harness_repo", lambda value, cfg: None)
    workflow, _, _ = gauntlet.render(str(app), config_mod.load(workspace=str(app)))
    doc = parse(workflow)
    steps = doc["jobs"]["ship-readiness"]["steps"]
    assert any(s.get("run") == 'echo "set gauntlet.omega_repo" && exit 1' for s in steps)


def test_cli_writes_refuses_overwrite_and_forces(gauntlet, app, capsys):
    target = app / ".github" / "workflows" / "gauntlet.yml"
    assert gauntlet.main(["--workspace", str(app), "--omega-repo", "acme/harness@main", "--dry-run"]) == 0
    assert not target.exists()
    assert gauntlet.main(["--workspace", str(app), "--omega-repo", "acme/harness@main"]) == 0
    assert target.is_file() and (app / ".gitleaks.toml").is_file()
    parse(target.read_text(encoding="utf-8"))
    target.write_text("hand edited\n", encoding="utf-8")
    assert gauntlet.main(["--workspace", str(app), "--omega-repo", "acme/harness@main"]) == 1
    assert target.read_text(encoding="utf-8") == "hand edited\n"
    assert gauntlet.main(["--workspace", str(app), "--omega-repo", "acme/harness@main", "--force",
                          "--python", "3.11"]) == 0
    doc = parse(target.read_text(encoding="utf-8"))
    pythons = [s["with"]["python-version"] for s in doc["jobs"]["tests"]["steps"]
               if s.get("uses", "").startswith("actions/setup-python")]
    assert pythons == ["3.11"]


def test_minimal_workspace_still_valid(gauntlet, tmp_path):
    root = Path(os.path.realpath(str(tmp_path))) / "empty"
    root.mkdir()
    workflow, _, _ = gauntlet.render(str(root), config_mod.load(workspace=str(root)), omega_repo="a/b")
    doc = parse(workflow)
    for job in doc["jobs"].values():
        assert job["steps"], job


def test_structural_check_without_yaml(gauntlet, app):
    workflow, _, _ = gauntlet.render(str(app), config_mod.load(workspace=str(app)), omega_repo="a/b@c")
    jobs_block = workflow.split('\n"jobs":\n', 1)[1]
    keys = re.findall(r'^  "([a-z-]+)":$', jobs_block, flags=re.M)
    assert tuple(keys) == JOBS
    assert all(not line.endswith(" ") for line in workflow.splitlines())


def test_check_all_script_is_valid_bash():
    result = subprocess.run(["bash", "-n", str(OMEGA_ROOT / "scripts" / "check-all.sh")], capture_output=True)
    assert result.returncode == 0, result.stderr
    text = (OMEGA_ROOT / "scripts" / "check-all.sh").read_text(encoding="utf-8")
    assert "set -euo pipefail" in text

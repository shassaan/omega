from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import json
import os
import re
import subprocess
from typing import Optional

from hooks import ship_readiness
from hooks.lib import config as config_mod
from hooks.lib import paths, testmap

JOB_TIMEOUTS = {"lint": 10, "tests": 15, "security": 10, "infra": 10, "migrations": 10, "ship-readiness": 15,
                "cost": 5, "mutation": 30, "verdict": 2}
JOB_ORDER = ("lint", "tests", "security", "infra", "migrations", "ship-readiness", "cost", "mutation", "verdict")
OMEGA_DIR = ".omega-ci"
ESLINT_CONFIGS = ("eslint.config.js", "eslint.config.mjs", ".eslintrc.json", ".eslintrc.cjs", ".eslintrc.js")
OWNER_REPO = re.compile(r"(?:^|[/:])([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$")


def q(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def emit(node, indent: int = 0) -> list:
    pad = " " * indent
    lines: list = []
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, (dict, list)) and value:
                lines.append("%s%s:" % (pad, q(key)))
                lines.extend(emit(value, indent + 2))
            elif isinstance(value, dict):
                lines.append("%s%s: {}" % (pad, q(key)))
            elif isinstance(value, list):
                lines.append("%s%s: []" % (pad, q(key)))
            else:
                lines.append("%s%s: %s" % (pad, q(key), q(value)))
    elif isinstance(node, list):
        for value in node:
            if isinstance(value, dict) and value:
                child = emit(value, indent + 2)
                lines.append("%s- %s" % (pad, child[0].lstrip()))
                lines.extend(child[1:])
            elif isinstance(value, list):
                lines.append("%s- %s" % (pad, json.dumps(value)))
            else:
                lines.append("%s- %s" % (pad, q(value)))
    return lines


def to_yaml(document: dict) -> str:
    return "\n".join(emit(document)) + "\n"


def resolve_harness_repo(cli_value: Optional[str], cfg) -> Optional[tuple]:
    value = cli_value or cfg.get("gauntlet.omega_repo") or cfg.get("ship.omega_repo")
    if value:
        repo, _, ref = str(value).partition("@")
        return repo, ref or "main"
    root = str(paths.harness_root())
    try:
        url = subprocess.run(["git", "-C", root, "remote", "get-url", "origin"], capture_output=True, timeout=30)
        head = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if url.returncode != 0:
        return None
    match = OWNER_REPO.search(url.stdout.decode("utf-8", "replace").strip())
    if not match:
        return None
    ref = head.stdout.decode().strip() if head.returncode == 0 and head.stdout.strip() else "main"
    return "%s/%s" % (match.group(1), match.group(2)), ref


def stack(workspace: str, cfg) -> dict:
    files = ship_readiness.list_files(workspace, cfg)
    found = ship_readiness.detect(workspace, cfg, files)
    has = lambda rel: os.path.exists(os.path.join(workspace, rel))
    python = any(has(f) for f in ("pyproject.toml", "requirements.txt", "setup.cfg"))
    node = has("package.json")
    return {
        "python": python, "node": node, "tsc": node and has("tsconfig.json"),
        "eslint": node and any(has(f) for f in ESLINT_CONFIGS),
        "js_runner": testmap.js_runner(workspace) if node else None,
        "requirements": has("requirements.txt"), "requirements_dev": has("requirements-dev.txt"),
        "lockfile": has("package-lock.json"), "terraform": any(f.endswith(".tf") for f in files),
        "docker": any(os.path.basename(f) == "Dockerfile" for f in files),
        "database": bool(found["database"]), "tiers": {k: bool(v) for k, v in found.items()},
    }


def render(workspace: str, cfg=None, omega_repo: Optional[str] = None, python: Optional[str] = None,
           node: Optional[str] = None) -> tuple:
    workspace = os.path.realpath(workspace)
    cfg = cfg if cfg is not None else config_mod.load(workspace=workspace)
    pins = cfg.get("gauntlet.action_pins", {}) or {}
    python = str(python or cfg.get("gauntlet.python", "3.12"))
    node = str(node or cfg.get("gauntlet.node", "22"))
    detected = stack(workspace, cfg)
    resolved = resolve_harness_repo(omega_repo, cfg)
    min_score = cfg.get("ship_readiness.mutation.min_score", 0.6)

    def uses(action: str, **with_args) -> dict:
        step = {"uses": "%s@%s" % (action, pins.get(action, "v4"))}
        if with_args:
            step["with"] = with_args
        return step

    checkout = uses("actions/checkout")
    checkout_full = uses("actions/checkout", **{"fetch-depth": 0})
    setup_python = uses("actions/setup-python", **{"python-version": python})
    setup_node = uses("actions/setup-node", **{"node-version": node})
    if resolved:
        harness_steps = [uses("actions/checkout", repository=resolved[0], path=OMEGA_DIR, ref=resolved[1])]
    else:
        harness_steps = [{"name": "harness repository", "run": "echo \"set gauntlet.omega_repo\" && exit 1"}]
    harness_py = "python %s" % OMEGA_DIR
    python_install = {"run": "python -m pip install --upgrade pip && " + (
        "pip install -r requirements-dev.txt" if detected["requirements_dev"] else
        "pip install -r requirements.txt pytest" if detected["requirements"] else
        "pip install -e . pytest || pip install pytest")}

    def job(name: str, steps: list, needs: Optional[list] = None, condition: Optional[str] = None) -> dict:
        body: dict = {}
        if needs:
            body["needs"] = needs
        if condition:
            body["if"] = condition
        body["runs-on"] = "ubuntu-latest"
        body["timeout-minutes"] = JOB_TIMEOUTS[name]
        body["steps"] = steps
        return body

    lint = [checkout]
    if detected["python"]:
        lint += [setup_python, {"run": "pip install ruff"}, {"run": "ruff check . && ruff format --check ."}]
    if detected["node"]:
        lint += [setup_node, {"run": "npm ci"}]
        if detected["eslint"]:
            lint.append({"run": "npx eslint . --max-warnings 0"})
        if detected["tsc"]:
            lint.append({"run": "npx tsc --noEmit"})
    if len(lint) == 1:
        lint.append({"run": "echo \"no python or node stack detected\""})
    tests = [checkout]
    if detected["python"]:
        tests += [setup_python, python_install, {"run": "python -m pytest -q -p no:cacheprovider"}]
    if detected["node"]:
        tests += [setup_node, {"run": "npm ci"}]
        if detected["js_runner"] == "vitest":
            tests.append({"run": "npx vitest run"})
        elif detected["js_runner"] == "jest":
            tests.append({"run": "npx jest --ci"})
    if len(tests) == 1:
        tests.append({"run": "echo \"no test runner detected\""})
    security = [checkout_full, uses("gitleaks/gitleaks-action", **{}), setup_python]
    security[1]["env"] = {"GITHUB_TOKEN": "${{ secrets.GITHUB_TOKEN }}"}
    if detected["terraform"] or detected["docker"]:
        security.append({"run": "pip install checkov && checkov -d . --framework terraform,dockerfile,github_actions "
                                "--quiet --compact"})
    if detected["requirements"]:
        security.append({"run": "pip install pip-audit && pip-audit -r requirements.txt"})
    if detected["node"] and detected["lockfile"]:
        security += [setup_node, {"run": "npm audit --audit-level=high"}]
    infra = [checkout]
    if detected["terraform"]:
        infra += [{"uses": "hashicorp/setup-terraform@%s" % pins.get("hashicorp/setup-terraform", "v3")},
                  {"run": "terraform fmt -check -recursive"},
                  {"run": "terraform init -backend=false -input=false -no-color && terraform validate -no-color"}]
    else:
        infra.append({"run": "echo \"no terraform detected\""})
    migrations = [checkout_full, setup_python] + harness_steps + [
        {"run": "%s/hooks/ship_readiness.py migration-lint --workspace \"$GITHUB_WORKSPACE\" --base-ref "
                "\"origin/${{ github.base_ref || 'main' }}\"" % harness_py}]
    readiness = [checkout_full, setup_python] + harness_steps + [
        {"run": "%s/hooks/ship_readiness.py run --workspace \"$GITHUB_WORKSPACE\" --mode full --strict --json"
                % harness_py}]
    cost = [checkout, setup_python] + harness_steps + [
        {"run": "%s/hooks/tokentoll_gate.py scan --path ." % harness_py},
        {"run": "if [ -f %s/ledger.jsonl ]; then %s/hooks/tokentoll_gate.py check --ledger %s/ledger.jsonl; "
                "else echo \"no committed ledger; scan only\"; fi" % (OMEGA_DIR, harness_py, OMEGA_DIR)}]
    mutation = [checkout_full, setup_python]
    if detected["python"]:
        mutation += [python_install, {"run": "pip install mutmut==%s" % cfg.get(
            "ship_readiness.mutation.mutmut_version", "3.3.1")}]
    mutation += harness_steps + [
        {"run": "%s/hooks/ship_readiness.py mutation --workspace \"$GITHUB_WORKSPACE\" --base-ref "
                "\"origin/${{ github.base_ref }}\" --min-score %s" % (harness_py, min_score)}]
    if detected["node"]:
        mutation += [setup_node, {"run": "npm ci"},
                     uses("actions/cache", path="reports/stryker-incremental.json",
                          key="stryker-${{ github.base_ref }}"),
                     {"run": "npx stryker run --incremental"}]
    mutation.append(dict(uses("actions/upload-artifact", name="mutation-reports", path="reports/"),
                         **{"if": "always()"}))
    others = [name for name in JOB_ORDER if name != "verdict"]
    verdict = [{"run": "test \"${{ contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled') }}\" "
                       "!= \"true\""}]
    jobs = {"lint": job("lint", lint), "tests": job("tests", tests), "security": job("security", security),
            "infra": job("infra", infra), "migrations": job("migrations", migrations),
            "ship-readiness": job("ship-readiness", readiness), "cost": job("cost", cost),
            "mutation": job("mutation", mutation, ["lint", "tests"], "github.event_name == 'pull_request'"),
            "verdict": job("verdict", verdict, others, "always()")}
    document = {"name": "gauntlet", "on": {"pull_request": {}, "push": {"branches": [cfg.get("ship.base", "main")]}},
                "permissions": {"contents": "read"},
                "concurrency": {"group": "gauntlet-${{ github.ref }}", "cancel-in-progress": True}, "jobs": jobs}
    workflow = to_yaml(document)
    globs = cfg.get("redaction.fixture_globs", []) or []
    regexes = [glob_regex(g) for g in globs]
    toml = "title = \"omega\"\n\n[extend]\nuseDefault = true\n\n[allowlist]\n" \
           "description = \"fixture paths hold synthetic secrets\"\npaths = [\n%s]\n" % "".join(
               "  '''%s''',\n" % r for r in regexes)
    return workflow, toml, {"stack": detected, "omega_repo": resolved}


def glob_regex(pattern: str) -> str:
    out = ""
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            out += "(?:.*/)?"
            index += 3
        elif pattern.startswith("**", index):
            out += ".*"
            index += 2
        elif pattern[index] == "*":
            out += "[^/]*"
            index += 1
        elif pattern[index] == "?":
            out += "[^/]"
            index += 1
        else:
            out += re.escape(pattern[index])
            index += 1
    return "^" + out + "$"


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="create_gauntlet.py", description="Generate the CI gauntlet workflow.")
    parser.add_argument("--workspace")
    parser.add_argument("--omega-repo")
    parser.add_argument("--python")
    parser.add_argument("--node")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    workspace = os.path.realpath(args.workspace or os.environ.get("OMEGA_WORKSPACE") or os.getcwd())
    if not os.path.isdir(workspace):
        sys.stderr.write("[gauntlet] %s is not a directory\n" % workspace)
        return 2
    try:
        cfg = config_mod.load(workspace=workspace)
        workflow, toml, info = render(workspace, cfg, args.omega_repo, args.python, args.node)
    except Exception as exc:
        sys.stderr.write("[gauntlet] internal error: %s: %s\n" % (exc.__class__.__name__, str(exc)[:200]))
        return 2
    target = Path(workspace) / ".github" / "workflows" / "gauntlet.yml"
    leaks = Path(workspace) / ".gitleaks.toml"
    if args.dry_run:
        sys.stdout.write(workflow)
        sys.stderr.write("[gauntlet] dry run: would write %s and %s\n" % (target, leaks))
        return 0
    refused = [str(p) for p in (target, leaks) if p.exists() and not args.force]
    if refused:
        sys.stderr.write("[gauntlet] refusing to overwrite %s (pass --force)\n" % ", ".join(refused))
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(workflow, encoding="utf-8")
    leaks.write_text(toml, encoding="utf-8")
    if not info["omega_repo"]:
        sys.stderr.write("[gauntlet] warning: no harness repository known; the workflow fails until "
                         "gauntlet.omega_repo is set\n")
    sys.stdout.write("[gauntlet] wrote %s and %s\n" % (target, leaks))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

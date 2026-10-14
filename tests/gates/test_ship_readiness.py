from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from hooks import ship_readiness as sr
from hooks.lib import config as config_mod
from tests.gates.conftest import git, make_executable, schema


def write(root: Path, rel: str, text: str = "") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def ws(tmp_path, fake_bin):
    root = Path(os.path.realpath(str(tmp_path))) / "app"
    root.mkdir()
    return root


def cfg_for(root: Path):
    return config_mod.load(workspace=str(root))


def run(root: Path, **kwargs) -> dict:
    result = sr.run(str(root), cfg_for(root), **kwargs)
    validate_ship(result)
    return result


def validate_ship(result: dict) -> None:
    try:
        import jsonschema
    except ImportError:
        return
    proof = schema("proof")
    ship_schema = dict(proof["$defs"]["ship"])
    ship_schema["$defs"] = proof["$defs"]
    jsonschema.validate(result, ship_schema, cls=jsonschema.Draft202012Validator)


def checks(result: dict, tier: str) -> dict:
    return {c["id"]: c for c in result["tiers"][tier]["checks"]}


def test_empty_workspace_all_not_applicable(ws):
    result = run(ws)
    assert result["status"] == "PASS"
    assert all(t["status"] == "NOT_APPLICABLE" and not t["applicable"] for t in result["tiers"].values())


def test_dockerfile_latest_fails_infra_and_missing_hadolint_is_unverified(ws):
    write(ws, "Dockerfile", "FROM python:latest\nADD https://example.org/x.tgz /x\n")
    result = run(ws)
    infra = checks(result, "infra")
    assert infra["dockerfile_rules:Dockerfile"]["status"] == "FAIL"
    assert "latest tag" in infra["dockerfile_rules:Dockerfile"]["detail"]
    assert infra["hadolint:Dockerfile"]["status"] == "UNVERIFIED"
    assert infra["hadolint:Dockerfile"]["hint"] == "brew install hadolint"
    assert result["tiers"]["infra"]["status"] == "FAIL" and result["status"] == "FAIL"


def test_dockerfile_pinned_with_fake_hadolint_passes(ws, fake_bin):
    make_executable(fake_bin / "hadolint", "#!/bin/sh\necho '[]'\nexit 0\n")
    write(ws, "Dockerfile", "FROM python:3.12-slim AS base\nFROM base\nCOPY . /app\n")
    result = run(ws)
    assert result["tiers"]["infra"]["status"] == "PASS"


def test_terraform_missing_is_unverified_with_hint_and_strict_fails(ws):
    write(ws, "infra/main.tf", 'resource "null_resource" "x" {}\n')
    result = run(ws)
    tf = checks(result, "infra")["terraform_fmt"]
    assert tf["status"] == "UNVERIFIED" and tf["hint"] == "brew install terraform"
    assert result["tiers"]["infra"]["status"] == "UNVERIFIED"
    assert result["status"] == "PASS"
    strict = run(ws, strict=True)
    assert strict["status"] == "UNVERIFIED"
    assert sr.main(["run", "--workspace", str(ws), "--strict"]) == 1
    assert sr.main(["run", "--workspace", str(ws)]) == 0


def test_terraform_fmt_rc3_fails(ws, fake_bin):
    make_executable(fake_bin / "terraform", "#!/bin/sh\necho main.tf\nexit 3\n")
    write(ws, "main.tf", "x = 1\n")
    result = run(ws)
    assert checks(result, "infra")["terraform_fmt"]["status"] == "FAIL"


def test_migration_drop_column_fails_and_waiver_passes(ws):
    path = write(ws, "migrations/0002_drop.sql", "-- drop old column\nALTER TABLE users DROP COLUMN legacy;\n")
    result = run(ws)
    rules = checks(result, "database")["migration_rules"]
    assert rules["status"] == "FAIL" and "drop-column migrations/0002_drop.sql:2" in rules["detail"]
    path.write_text("-- omega:allow destructive (column unused since v3)\nALTER TABLE users DROP COLUMN legacy;\n",
                    encoding="utf-8")
    assert run(ws)["tiers"]["database"]["status"] == "PASS"


def test_migration_comment_and_medium_rules(ws):
    write(ws, "migrations/0003.sql", "-- DROP TABLE users;\n/* TRUNCATE x; */\nCREATE INDEX idx ON t(c);\n")
    rules = checks(run(ws), "database")["migration_rules"]
    assert rules["status"] == "PASS" and "index-nonconcurrent" in rules["detail"]


def test_alembic_python_migration(ws):
    write(ws, "alembic/versions/0004_x.py", "def upgrade():\n    op.drop_table('users')\n")
    rules = sr.migration_rules(str(ws), None, cfg_for(ws))
    assert rules.status == "FAIL" and "drop-table" in rules.detail


def test_migration_rules_only_scan_lines_added_since_base(ws):
    git(ws, "init", "-q")
    write(ws, "migrations/0001.sql", "-- omega:allow destructive (initial)\nDROP TABLE old;\n")
    git(ws, "add", "-A")
    git(ws, "commit", "-q", "-m", "base")
    write(ws, "migrations/0001.sql", "-- omega:allow destructive (initial)\nDROP TABLE old;\nCREATE TABLE t (id int);\n")
    write(ws, "migrations/0002.sql", "ALTER TABLE t RENAME COLUMN id TO key;\n")
    check = sr.migration_rules(str(ws), "HEAD", cfg_for(ws))
    assert check.status == "FAIL" and "rename-column migrations/0002.sql:1" in check.detail
    assert "drop-table" not in check.detail.split("waived")[0]
    missing = sr.migration_rules(str(ws), "no-such-ref", cfg_for(ws))
    assert missing.status == "UNVERIFIED"


def test_alembic_heads_missing_module_is_unverified(ws):
    write(ws, "alembic.ini", "[alembic]\nscript_location = alembic\n")
    heads = checks(run(ws), "database")["alembic_heads"]
    assert heads["status"] == "UNVERIFIED"


def test_application_route_without_test_and_env_example(ws):
    make_executable(ws / ".venv" / "bin" / "python", "#!/bin/sh\necho \"$1 $2: No module named $2\" >&2\nexit 1\n")
    write(ws, "pyproject.toml", "[project]\nname='x'\n")
    write(ws, "app/routes.py", "from fastapi import APIRouter\nimport os\nrouter = APIRouter()\n"
                               "KEY = os.environ['SERVICE_URL']\n@router.get('/x')\ndef x():\n    return 1\n")
    result = run(ws)
    app = checks(result, "application")
    assert app["route_tests"]["status"] == "FAIL" and "app/routes.py" in app["route_tests"]["detail"]
    assert app["env_example"]["status"] == "FAIL"
    assert app["ruff_check"]["status"] == "UNVERIFIED"
    write(ws, "tests/test_routes.py", "def test_x():\n    assert True\n")
    write(ws, ".env.example", "SERVICE_URL=\n")
    again = checks(run(ws), "application")
    assert again["route_tests"]["status"] == "PASS"
    assert again["env_example"]["status"] == "PASS"


def test_application_results_are_consumed(ws):
    write(ws, "pyproject.toml", "[project]\nname='x'\n")
    results = [{"check": "pytest", "status": "FAIL", "required": True, "detail": "exit 1", "rc": 1,
                "duration_ms": 3, "argv": ["pytest"]}]
    result = run(ws, application_results=results)
    app = checks(result, "application")
    assert "ruff_check" not in app and app["pytest"]["status"] == "FAIL"
    assert result["tiers"]["application"]["status"] == "FAIL"


def test_node_checks_need_node_modules(ws, fake_bin):
    make_executable(fake_bin / "npx", "#!/bin/sh\nexit 0\n")
    write(ws, "package.json", '{"name": "x"}')
    write(ws, "tsconfig.json", "{}")
    tsc = checks(run(ws), "application")["tsc"]
    assert tsc["status"] == "UNVERIFIED" and "node_modules missing" in tsc["detail"]
    (ws / "node_modules").mkdir()
    assert checks(run(ws), "application")["tsc"]["status"] == "PASS"


def test_analytics_tier(ws):
    write(ws, "dbt_project.yml", "name: shop\nprofile: shop\n")
    write(ws, "models/staging/stg_orders.sql", "select id from {{ source('raw', 'orders') }}\n")
    write(ws, "models/gold/fct_orders.sql", "select * from raw.orders\n")
    write(ws, "models/staging/schema.yml", "version: 2\nmodels:\n  - name: stg_orders\n"
                                           "    description: staged orders\n    columns:\n      - name: id\n"
                                           "        tests:\n          - unique\n")
    result = run(ws)
    analytics = checks(result, "analytics")
    assert analytics["dbt_models"]["status"] == "FAIL"
    assert "models/gold/fct_orders.sql: no schema.yml entry" in analytics["dbt_models"]["detail"]
    assert analytics["gold_no_select_star"]["status"] == "FAIL"
    write(ws, "models/gold/fct_orders.sql", "select id, total from {{ ref('stg_orders') }}\n")
    write(ws, "models/gold/schema.yml", "models:\n  - name: fct_orders\n    description: orders fact\n"
                                        "    tests:\n      - dbt_utils.recency\n")
    assert run(ws)["tiers"]["analytics"]["status"] == "PASS"


def test_observability_tier(ws):
    write(ws, "requirements.txt", "anthropic\n")
    write(ws, ".env.example", "ANTHROPIC_API_KEY=\n")
    write(ws, "svc/llm.py", "import os\nimport anthropic\nclient = anthropic.Anthropic()\n\n"
                            "def ask(q):\n    return client.messages.create(model='claude-haiku-5-5', max_tokens=10,"
                            " messages=[{'role': 'user', 'content': os.getenv('PROMPT_PREFIX') + q}])\n")
    result = run(ws)
    obs = checks(result, "observability")
    assert obs["tracing_dependency"]["status"] == "FAIL"
    assert obs["tracing_coverage"]["status"] == "FAIL" and "svc/llm.py:6" in obs["tracing_coverage"]["detail"]
    assert obs["env_vars_documented"]["status"] == "FAIL" and "PROMPT_PREFIX" in obs["env_vars_documented"]["detail"]
    assert obs["tokentoll_scan"]["status"] == "PASS"
    write(ws, "requirements.txt", "anthropic\nbraintrust\n")
    write(ws, ".env.example", "ANTHROPIC_API_KEY=\nPROMPT_PREFIX=\n")
    write(ws, "svc/llm.py", "import os\nimport anthropic\nfrom braintrust import init_logger, wrap_anthropic\n"
                            "init_logger(project='x')\nclient = wrap_anthropic(anthropic.Anthropic())\n\n"
                            "def ask(q):\n    return client.messages.create(model='claude-haiku-5-5', max_tokens=10,"
                            " messages=[{'role': 'user', 'content': os.getenv('PROMPT_PREFIX') + q}])\n")
    assert run(ws)["tiers"]["observability"]["status"] == "PASS"


def test_key_literal_in_source_fails_observability(ws):
    write(ws, ".env.example", "X=\n")
    write(ws, "svc/keys.py", "KEY = 'AKIA" + "Q" * 16 + "'\n")
    obs = checks(run(ws), "observability")
    assert obs["no_key_literals"]["status"] == "FAIL"
    assert "AKIA" not in obs["no_key_literals"]["detail"]


def test_full_mode_live_checks_skip_without_keys(ws, monkeypatch):
    monkeypatch.delenv("BRAINTRUST_API_KEY", raising=False)
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    write(ws, ".env.example", "X=\n")
    obs = checks(run(ws, mode="full"), "observability")
    assert obs["live_braintrust"]["status"] == "UNVERIFIED"
    assert obs["live_braintrust"]["detail"] == "skipped: no BRAINTRUST_API_KEY"
    assert obs["live_braintrust"]["required"] is False


def test_cli_json_out(ws, capsys, tmp_path):
    write(ws, "migrations/0002.sql", "DROP TABLE x;\n")
    out = tmp_path / "ship.json"
    code = sr.main(["run", "--workspace", str(ws), "--json", "--out", str(out)])
    assert code == 1
    body = json.loads(capsys.readouterr().out)
    assert body["status"] == "FAIL" and json.loads(out.read_text())["status"] == "FAIL"
    assert sr.main(["migration-lint", "--workspace", str(ws)]) == 1


PINNED_RESULTS = """
    src.calc.x_add__mutmut_1: killed
    src.calc.x_add__mutmut_2: survived
    src.calc.x_add__mutmut_3: killed
    src.calc.x_sub__mutmut_1: timeout
    src.calc.x_sub__mutmut_2: no tests
    src.calc.x_sub__mutmut_3: skipped
    src.calc.x_mul__mutmut_1: suspicious
    src.calc.x_mul__mutmut_2: killed
"""


def test_mutmut_results_parser_against_pinned_output():
    counts = sr.parse_mutmut_results(PINNED_RESULTS)
    assert counts == {"killed": 3, "survived": 1, "timeout": 1, "no tests": 1, "skipped": 1, "suspicious": 1}
    assert sr.mutmut_score(counts) == pytest.approx(3 / 6)
    assert sr.mutmut_score({"no tests": 4}) is None


def test_stryker_score_counts_nocoverage_as_survived():
    report = {"files": {"a.ts": {"mutants": [{"status": "Killed"}, {"status": "Timeout"}, {"status": "Survived"},
                                            {"status": "NoCoverage"}, {"status": "Ignored"}]}}}
    assert sr.stryker_score(report) == pytest.approx(0.5)


def test_mutation_never_passes_when_it_cannot_run(ws):
    git(ws, "init", "-q")
    write(ws, "src/calc.py", "def add(a, b):\n    return a + b\n")
    git(ws, "add", "-A")
    git(ws, "commit", "-q", "-m", "base")
    nothing = sr.mutation(str(ws), "HEAD", 0.6, cfg_for(ws))
    assert nothing.status == "NOT_APPLICABLE"
    write(ws, "src/calc.py", "def add(a, b):\n    return a + b + 0\n")
    check = sr.mutation(str(ws), "HEAD", 0.6, cfg_for(ws))
    if sys.version_info < (3, 10):
        assert check.status == "UNVERIFIED" and "needs Python 3.10" in check.detail
    else:
        assert check.status in ("UNVERIFIED", "PASS", "FAIL")
    assert sr.mutation(str(ws), "no-such-ref", 0.6, cfg_for(ws)).status == "UNVERIFIED"
    assert sr.main(["mutation", "--workspace", str(ws), "--base-ref", "no-such-ref"]) == 2

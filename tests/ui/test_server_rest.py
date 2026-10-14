from __future__ import annotations

import ast
import io
import json
import tokenize
from pathlib import Path

from hooks.lib import costledger, hashing
from tests.conftest import OMEGA_ROOT
from tests.ui.conftest import TOKEN, all_text_under, synthetic_key

UI_DIR = OMEGA_ROOT / "ui"


def test_every_api_call_requires_the_bearer_token(ui):
    for method, path in (("get", "/api/health"), ("get", "/api/keys"), ("get", "/api/projects"),
                         ("get", "/api/runs"), ("get", "/api/cost/report"), ("put", "/api/keys/anthropic"),
                         ("post", "/api/runs"), ("post", "/api/runs/run-20261013000000-abcd/approvals")):
        for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}):
            response = getattr(ui.client, method)(path, headers=headers)
            assert response.status_code == 401, (method, path, headers)
            assert response.json()["error"]["code"] == "unauthorized"
            assert response.headers["cache-control"] == "no-store"


def test_health_reports_runtimes_and_hook_status(ui):
    body = ui.get("/api/health").json()
    assert body["ok"] is True and body["version"] == "0.1.0"
    assert body["runtimes"] == {"claude": None, "codex": None}
    assert body["hooks_verified"] == {"claude": False, "codex": False}


def test_put_key_returns_only_a_masked_entry(ui, tmp_state):
    key = synthetic_key("anthropic")
    response = ui.put("/api/keys/anthropic", {"key": key})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    entry = response.json()
    assert entry == {"provider": "anthropic", "prefix": "sk-ant-", "last4": key[-4:], "created_at": entry["created_at"],
                     "last_used_at": None, "status": "unverified", "kid": 1}
    listed = ui.get("/api/keys")
    assert listed.json() == [entry]
    for text in (response.text, listed.text, ui.get("/api/health").text):
        assert key not in text and key[:-4] not in text
    log_text = (tmp_state / "ui" / "server.log").read_text(encoding="utf-8")
    assert "****" in log_text and key not in log_text
    assert key not in all_text_under(tmp_state)


def test_bad_keys_get_a_400_with_the_error_shape(ui):
    response = ui.put("/api/keys/anthropic", {"key": "sk-proj-not-an-anthropic-key-at-all"})
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "invalid_key" and "sk-proj" not in error["message"]
    assert ui.put("/api/keys/anthropic", {"key": "sk-ant-" + "a" * 600}).status_code == 400
    assert ui.put("/api/keys/anthropic", {}).status_code == 400
    assert ui.put("/api/keys/mistral", {"key": "sk-whatever-1234567890123"}).status_code == 404
    bad_json = ui.client.put("/api/keys/anthropic", headers=dict(ui.headers, **{"Content-Type": "application/json"}),
                             content=b"{nope")
    assert bad_json.status_code == 400 and bad_json.json()["error"]["code"] == "bad_json"


def test_delete_key(ui):
    ui.add_key("openai")
    assert ui.delete("/api/keys/openai").status_code == 204
    assert ui.get("/api/keys").json() == []
    assert ui.delete("/api/keys/openai").status_code == 404


def test_verify_key_endpoint_never_deletes(ui):
    ui.add_key("anthropic")

    def offline(request, timeout):
        raise OSError("no network in tests")

    ui.ui.manager._urlopen = offline
    response = ui.post("/api/keys/anthropic/verify")
    assert response.json()["status"] == "unverified"
    assert ui.get("/api/keys").json()[0]["provider"] == "anthropic"
    assert ui.post("/api/keys/google/verify").status_code == 404


def test_projects_install_adapters_and_validate_paths(ui, workspace, tmp_path):
    project = ui.add_project()
    assert project["path"] == str(workspace) and project["installed"] is True
    assert project["contracts"] == [] and set(project["clearances"]) == {"proof", "contract", "review", "last_stop"}
    call = ui.cli.calls[-1]
    assert call["script"] == "scripts/install_workspace.py" and call["args"] == [str(workspace), "--provider", "both"]
    assert ui.post("/api/projects", {"name": "dup", "path": str(workspace)}).status_code == 409
    assert ui.post("/api/projects", {"name": "rel", "path": "relative/path"}).status_code == 400
    assert ui.post("/api/projects", {"name": "gone", "path": str(tmp_path / "missing")}).status_code == 400
    assert ui.post("/api/projects", {"path": str(tmp_path)}).status_code == 400
    assert ui.get("/api/projects").json()[0]["id"] == project["id"]
    assert ui.get("/api/projects/prj-00000000").status_code == 404
    assert ui.get("/api/projects/../../etc").status_code == 404


def test_project_without_installer_is_still_recorded(ui, tmp_path):
    ui.cli.unavailable.add("scripts/install_workspace.py")
    other = tmp_path / "other"
    other.mkdir()
    project = ui.add_project(path=other, name="other")
    assert project["installed"] is False and "not installed" in project["install_detail"]


def test_project_lists_contracts(ui, workspace):
    (workspace / "docs" / "contracts" / "user-signup.md").write_text(
        "# Contract: User signup\n\nslug: user-signup\ncode: src/signup.py\ntests: tests/test_signup.py\nowed: none\n"
        "assumptions: none\n\n## Unit\n\n### Scenario: valid email\n- Given a new email\n- When they sign up\n"
        "- Then an account exists\n\n## Integration\n\n_Not applicable: no external system_\n\n## Functional\n\n"
        "### Scenario: duplicate\n- Given an existing user\n- When they sign up again\n- Then it is refused\n\n"
        "## Journey\n\n_Not applicable: api only_\n", encoding="utf-8")
    project = ui.add_project()
    detail = ui.get("/api/projects/%s" % project["id"]).json()
    row = detail["contracts"][0]
    assert row["slug"] == "user-signup" and row["valid"] is True
    assert row["seams"] == {"Unit": 1, "Integration": 0, "Functional": 1, "Journey": 0}
    assert row["not_applicable"] == ["Integration", "Journey"]


def _clearance(workspace: Path, files: dict, verified=True) -> dict:
    return {"schema": "omega/proof/1", "omega_version": "0.1.0", "ts": "2026-10-13T10:00:00Z", "ts_ns": 1,
            "session_id": "sess-clear", "provider": "claude", "workspace": str(workspace), "run_id": None,
            "verified": verified, "released": False, "overridden": False, "attempt": 1, "files": files,
            "files_digest": hashing.files_digest(files)}


def test_clearances_report_fresh_then_stale(ui, workspace):
    source = workspace / "src" / "calc.py"
    source.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    files = hashing.snapshot(str(workspace), ["src/calc.py"])
    target = workspace / ".omega" / "clearances"
    target.mkdir(parents=True)
    for name in ("proof", "contract", "review"):
        (target / ("%s.json" % name)).write_text(json.dumps(_clearance(workspace, files)), encoding="utf-8")
    project = ui.add_project()
    view = ui.get("/api/projects/%s/clearances" % project["id"]).json()
    assert view["proof"]["fresh"] is True and view["proof"]["verified"] is True
    assert view["review"]["files_digest"] == hashing.files_digest(files)
    source.write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    view = ui.get("/api/projects/%s/clearances" % project["id"]).json()
    assert view["proof"]["fresh"] is False and "src/calc.py" in view["proof"]["reason"]
    assert view["last_stop"] is None


def test_cost_report_falls_back_to_the_ledger(ui):
    costledger.append({"id": "row-1", "model": "claude-sonnet-5-5", "in": 1000, "out": 100, "run_id": "run-20261013000000-dddd"}, ui.ui.cfg)
    report = ui.get("/api/cost/report", params={"run_id": "run-20261013000000-dddd"}).json()
    assert report["status"] == "PASS" and report["sums"]["run"] > 0 and report["caps"]["per_run_usd"] == 5.0
    assert "tokentoll" not in report
    ui.cli.unavailable.discard("hooks/tokentoll_gate.py")
    ui.cli.results["hooks/tokentoll_gate.py"] = (0, json.dumps({"status": "PASS", "month_usd": 0.1}), "")
    report = ui.get("/api/cost/report").json()
    assert report["tokentoll"]["status"] == "PASS"
    assert ui.cli.calls[-1]["args"] == ["report", "--json"]
    assert ui.get("/api/cost/report", params={"month": "October"}).status_code == 400
    assert ui.get("/api/cost/report", params={"run_id": "../x"}).status_code == 400


def test_static_dashboard_is_served_without_auth_and_never_uses_innerhtml(ui):
    page = ui.client.get("/")
    assert page.status_code == 200 and "Omega Control" in page.text
    assert "default-src 'self'" in page.headers["content-security-policy"]
    script = ui.client.get("/static/app.js")
    assert script.status_code == 200
    assert "innerHTML" not in script.text and "outerHTML" not in script.text and "insertAdjacentHTML" not in script.text
    assert "eval(" not in script.text and "document.write" not in script.text
    assert ui.client.get("/static/styles.css").status_code == 200
    for name in ("index.html", "app.js", "styles.css"):
        text = (UI_DIR / "static" / name).read_text(encoding="utf-8")
        assert "<!--" not in text and "/*" not in text
        assert "http://" not in text.replace("http://www.w3.org", "") and "https://" not in text


def test_ui_python_is_comment_free():
    for name in ("server.py", "provider_manager.py"):
        source = (UI_DIR / name).read_text(encoding="utf-8")
        comments = [tok for tok in tokenize.generate_tokens(io.StringIO(source).readline) if tok.type == tokenize.COMMENT]
        assert comments == [], name
        tree = ast.parse(source)
        for node in [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]:
            assert ast.get_docstring(node) is None, (name, getattr(node, "name", "module"))

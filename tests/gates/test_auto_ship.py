from __future__ import annotations

import http.server
import json
import os
import subprocess
import threading
from pathlib import Path

import pytest

from tests.gates.conftest import assert_valid, git, make_executable, reload_cfg, stub_gates, touch, write_ws_config

SECRET = "sk-ant-api03-" + ("Ab1_" * 23) + "Z" + "AA"


@pytest.fixture
def repo(workspace, tmp_path, fake_bin):
    remote = Path(os.path.realpath(str(tmp_path))) / "remotes" / "acme" / "app.git"
    remote.parent.mkdir(parents=True)
    git(remote.parent, "init", "-q", "--bare", str(remote))
    git(workspace, "config", "user.email", "omega-tests@example.com")
    git(workspace, "config", "user.name", "Harness Tests")
    keys = Path(os.path.realpath(str(tmp_path))) / "signing"
    keys.mkdir()
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(keys / "human")], check=True,
                   capture_output=True)
    pub = keys / "human.pub"
    (keys / "allowed_signers").write_text("omega-tests@example.com %s\n" % " ".join(pub.read_text().split()[:2]))
    git(workspace, "config", "gpg.format", "ssh")
    git(workspace, "config", "user.signingkey", str(pub))
    git(workspace, "config", "commit.gpgsign", "true")
    git(workspace, "config", "gpg.ssh.allowedSignersFile", str(keys / "allowed_signers"))
    git(workspace, "remote", "add", "origin", str(remote))
    git(workspace, "push", "-q", "origin", "main")
    write_ws_config(workspace, {"proof": {"settle_timeout_s": 0}})
    return remote


@pytest.fixture
def cleared(repo, workspace, make_session, orchestrator):
    ctx = make_session()
    reload_cfg(ctx)
    touch(ctx, "src/calc.py", "def add(a, b):\n    return a + b\n")
    outcome = orchestrator.stop(ctx, stub_gates())
    assert outcome["verified"], outcome["message"]
    return ctx


def fake_gh(fake_bin: Path) -> Path:
    log = fake_bin / "gh.log"
    make_executable(fake_bin / "gh", "#!/bin/sh\nprintf '%%s\\n' \"$@\" >> '%s'\n"
                                     "echo https://github.com/acme/app/pull/7\nexit 0\n" % log)
    return log


def test_plan_ok_with_fresh_clearances(auto_ship, cleared, workspace):
    plan = auto_ship.plan(str(workspace))
    assert plan["blockers"] == [] and plan["ok"] is True
    assert plan["files"] == ["src/calc.py"]
    assert plan["branch"].startswith("omega/change-")
    assert plan["title"] == "omega: change"
    assert (plan["owner"], plan["repo"]) == ("acme", "app")
    assert "## Clearances" in plan["pr_body"] and "Generated with Omega" in plan["pr_body"]
    assert "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" in plan["commit_body"]
    assert git(workspace, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "main"


def test_refuses_stale_clearance(auto_ship, cleared, workspace):
    (workspace / "src" / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    plan = auto_ship.plan(str(workspace))
    assert not plan["ok"]
    assert any(b.startswith("clearance stale: src/calc.py changed") for b in plan["blockers"])


def test_refuses_missing_clearances(auto_ship, repo, workspace):
    (workspace / "src" / "calc.py").write_text("x = 1\n", encoding="utf-8")
    plan = auto_ship.plan(str(workspace))
    assert sum(1 for b in plan["blockers"] if b.startswith("clearance missing")) == 3


def test_refuses_released_clearance(auto_ship, repo, workspace, make_session, orchestrator):
    ctx = make_session()
    reload_cfg(ctx)
    touch(ctx, "src/calc.py", "x = 1\n")
    for _ in range(4):
        orchestrator.stop(ctx, stub_gates(proof="FAIL"))
    plan = auto_ship.plan(str(workspace))
    assert any("released by the loop guard" in b for b in plan["blockers"])


def test_refuses_secret_in_diff(auto_ship, repo, workspace, make_session, orchestrator, capsys):
    ctx = make_session()
    reload_cfg(ctx)
    touch(ctx, "tests/x.py", "def test_x():\n    pass\nKEY = '%s'\n" % SECRET)
    orchestrator.stop(ctx, stub_gates())
    plan = auto_ship.plan(str(workspace))
    assert "secret anthropic-key tests/x.py:3" in plan["blockers"]
    code = auto_ship.main(["--workspace", str(workspace), "--dry-run"])
    out = capsys.readouterr().out
    assert code == 1 and "BLOCKER: secret anthropic-key tests/x.py:3" in out
    assert SECRET not in out


def test_refuses_uncleared_and_excluded_paths(auto_ship, repo, workspace, make_session, orchestrator):
    ctx = make_session()
    reload_cfg(ctx)
    touch(ctx, "src/calc.py", "x = 1\n")
    touch(ctx, "config/.env.local", "MODE=dev\n")
    orchestrator.stop(ctx, stub_gates())
    (workspace / "src" / "sneaky.py").write_text("y = 2\n", encoding="utf-8")
    plan = auto_ship.plan(str(workspace))
    assert "uncleared change: src/sneaky.py is dirty but not covered by the clearances" in plan["blockers"]
    assert any(b.startswith("excluded path would be committed: config/.env.local") for b in plan["blockers"])


def test_refuses_without_git(auto_ship, tmp_path):
    plan = auto_ship.plan(str(tmp_path))
    assert plan["blockers"][0].startswith("not a git work tree")


def test_yes_branches_commits_pushes_and_opens_pr(auto_ship, cleared, workspace, repo, fake_bin):
    log = fake_gh(fake_bin)
    code, result = auto_ship.ship(str(workspace))
    assert code == 0, result["blockers"]
    branch = result["branch"]
    assert git(repo, "rev-parse", "--verify", "refs/heads/%s" % branch, check=False).returncode == 0
    message = git(workspace, "log", "-1", "--format=%B").stdout
    assert message.startswith("omega: change")
    assert "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" in message
    assert git(workspace, "show", "--name-only", "--format=", "HEAD").stdout.split() == ["src/calc.py"]
    args = log.read_text(encoding="utf-8").splitlines()
    assert args[:2] == ["pr", "create"] and "--draft" in args
    assert args[args.index("--base") + 1] == "main" and args[args.index("--head") + 1] == branch
    records = list((workspace / ".omega" / "ship").glob("*.json"))
    record = json.loads(records[0].read_text(encoding="utf-8"))
    assert record["pr_number"] == 7 and record["files"] == ["src/calc.py"]
    assert git(repo, "rev-parse", "main").stdout.strip() != record["commit"]


def test_yes_without_gh_or_token_reports_unopened_pr(auto_ship, cleared, workspace, repo, capsys):
    code = auto_ship.main(["--workspace", str(workspace), "--yes"])
    out = capsys.readouterr().out
    assert code == 1
    assert "pushed omega/change-" in out and "no gh CLI and no OMEGA_GIT_TOKEN" in out


class _Handler(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        _Handler.seen.append({"path": self.path, "auth": self.headers.get("Authorization"),
                              "version": self.headers.get("X-GitHub-Api-Version"), "body": body})
        data = json.dumps({"html_url": "https://github.com/acme/app/pull/9", "number": 9}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def test_rest_fallback_when_no_gh(auto_ship, cleared, workspace, repo, monkeypatch):
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("no_proxy", "127.0.0.1")
        monkeypatch.setenv("OMEGA_GITHUB_API", "http://127.0.0.1:%d" % server.server_address[1])
        monkeypatch.setenv("OMEGA_GIT_TOKEN", "test-token-for-a-local-stub")
        code, result = auto_ship.ship(str(workspace))
    finally:
        server.shutdown()
    assert code == 0, result
    assert result["pr_url"].endswith("/pull/9")
    request = _Handler.seen[-1]
    assert request["path"] == "/repos/acme/app/pulls"
    assert request["auth"] == "Bearer test-token-for-a-local-stub"
    assert request["version"] == "2022-11-28"
    assert request["body"]["draft"] is True and request["body"]["head"] == result["branch"]


def test_cli_dry_run_json(auto_ship, cleared, workspace, capsys):
    code = auto_ship.main(["--workspace", str(workspace), "--json"])
    body = json.loads(capsys.readouterr().out)
    assert code == 0 and body["ok"] is True and body["files"] == ["src/calc.py"]
    assert git(workspace, "branch", "--list", "omega/*").stdout.strip() == ""


def test_schema_validator_agrees_with_jsonschema(auto_ship, cleared, workspace):
    for kind in ("proof", "contract", "review"):
        body = json.loads((workspace / ".omega" / "clearances" / ("%s.json" % kind)).read_text(encoding="utf-8"))
        assert auto_ship.schema_errors(body, auto_ship.load_schema(kind)) == []
        assert_valid(kind, body)
        broken = dict(body, verified="yes")
        assert auto_ship.schema_errors(broken, auto_ship.load_schema(kind))


@pytest.mark.parametrize("url,expected", [("https://github.com/acme/app.git", ("acme", "app")),
                                          ("git@github.com:acme/app.git", ("acme", "app")),
                                          ("ssh://git@github.com/acme/app", ("acme", "app")),
                                          ("/tmp/remotes/acme/app.git", ("acme", "app")),
                                          ("", None)])
def test_parse_remote(auto_ship, url, expected):
    assert auto_ship.parse_remote(url) == expected


def test_plan_refuses_when_signing_is_off(auto_ship, cleared, workspace):
    git(workspace, "config", "commit.gpgsign", "false")
    plan = auto_ship.plan(str(workspace))
    assert any(b.startswith("signing: commit.gpgsign is not true") for b in plan["blockers"])


def test_yes_pushes_a_signed_commit(auto_ship, cleared, workspace, repo, fake_bin):
    fake_gh(fake_bin)
    code, result = auto_ship.ship(str(workspace))
    assert code == 0, result["blockers"]
    assert git(workspace, "log", "-1", "--format=%G? %ae", result["commit"]).stdout.strip() == \
        "G omega-tests@example.com"

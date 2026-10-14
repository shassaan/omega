from __future__ import annotations

import json

import pytest

from hooks.lib import state
from tests.guards.support import PROVIDERS, START, session_dir

CAP = 12000


def _context(proc, provider):
    assert proc.returncode == 0, proc.stderr
    if provider == "claude":
        return proc.stdout
    data = json.loads(proc.stdout)
    output = data["hookSpecificOutput"]
    assert output["hookEventName"] == "SessionStart"
    return output["additionalContext"]


@pytest.mark.parametrize("provider", PROVIDERS)
def test_context_within_cap_and_complete(provider, workspace, run_hook, claude_payload, codex_payload, harness_root):
    make = claude_payload if provider == "claude" else codex_payload
    payload = make("SessionStart")
    text = _context(run_hook(START, payload, provider), provider)
    assert len(text.encode("utf-8")) <= CAP
    assert text.startswith("[omega] Omega 0.1.0 · provider %s · workspace %s · session %s."
                           % (provider, workspace, payload["session_id"]))
    assert "contract-first" in text and "observed-red TDD" in text and "Shell writes into the workspace are refused" in text
    assert str(harness_root / "bin" / "launch.sh") in text
    for command in ("hooks/contract_gate.py propose", "hooks/contract_gate.py record", "hooks/tdd_gate.py run",
                    "bin/stop_orchestrator.py status", "scripts/auto_ship.py --dry-run"):
        assert command in text
    assert "Workspace facts:" in text and "contracts: none yet" in text
    assert "mental-models/architecture.md" in text
    framing = text.split("\n\n")[0]
    assert len(framing.encode("utf-8")) <= 600


@pytest.mark.parametrize("provider", PROVIDERS)
def test_context_cap_enforced_with_large_inject(provider, workspace, run_hook, claude_payload, codex_payload):
    config = workspace / ".omega" / "config.json"
    data = json.loads(config.read_text())
    data["session_start"] = {"context_cap_bytes": 12000, "inject": ["mental-models/architecture.md",
                                                                   "mental-models/database_rules.md",
                                                                   "mental-models/provider_contracts.md",
                                                                   "docs/ARCHITECTURE.md"]}
    config.write_text(json.dumps(data))
    make = claude_payload if provider == "claude" else codex_payload
    text = _context(run_hook(START, make("SessionStart"), provider), provider)
    assert len(text.encode("utf-8")) <= CAP
    assert "docs/ARCHITECTURE.md did not fit in the session context; read it with the Read tool" in text


def test_side_effects_baseline_token_and_exclude(workspace, run_hook, claude_payload):
    payload = claude_payload("SessionStart")
    run_hook(START, payload, "claude")
    directory = session_dir(workspace, "claude", payload["session_id"])
    assert (directory / "baseline.json").is_file()
    token = (directory / "override_token").read_text().strip()
    assert token.startswith("hs-") and len(token) == 9
    exclude = (workspace / ".git" / "info" / "exclude").read_text()
    assert ".omega/" in exclude.splitlines()
    run_hook(START, payload, "claude")
    assert (directory / "override_token").read_text().strip() == token
    assert (workspace / ".git" / "info" / "exclude").read_text().count(".omega/") == 1
    context = json.loads((directory / "context.json").read_text())
    assert context["workspace"] == str(workspace) and context["provider"] == "claude"


def test_compact_source_skips_inject_and_baseline(workspace, run_hook, claude_payload):
    payload = claude_payload("SessionStart", source="compact", session_id="compact-sess")
    text = _context(run_hook(START, payload, "claude"), "claude")
    assert "--- mental-models/architecture.md ---" not in text
    assert not (session_dir(workspace, "claude", "compact-sess") / "baseline.json").exists()


def test_facts_report_pending_request_reds_and_dev_warning(workspace, run_hook, claude_payload, session):
    directory = state.session_dir(session)
    state.write_json_atomic(directory / "contract_request.json", {"fingerprint": "abcdef0123456789", "consumed": False})
    state.append_jsonl(directory / "red.jsonl", {"ts_ns": 1, "test_files": {"tests/test_calc.py": "x"}})
    state.write_json_atomic(directory / "last_stop.json", {"verified": False, "released": False, "attempt": 2})
    (workspace / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    text = _context(run_hook(START, claude_payload("SessionStart"), "claude", env={"OMEGA_DEV": "1"}), "claude")
    assert "pending sign-off" in text and "open reds without green: tests/test_calc.py" in text
    assert "last Stop: blocked (attempt 2)" in text
    assert "OMEGA_DEV=1 lifts harness protection" in text
    assert "stacks: infra" in text


@pytest.mark.parametrize("provider", PROVIDERS)
def test_garbage_stdin_never_blocks(provider, workspace, run_hook):
    proc = run_hook(START, "not json", provider)
    assert proc.returncode == 0
    text = proc.stdout if provider == "claude" else json.loads(proc.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "session start failed" in text


def test_records_observed_session_start(workspace, tmp_state, run_hook, codex_payload):
    run_hook(START, codex_payload("SessionStart"), "codex")
    assert "SessionStart" in json.loads((tmp_state / "observed" / "codex.json").read_text())

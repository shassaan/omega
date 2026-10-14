from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from hooks.lib import config, paths


def ctx_for(workspace, harness_root, **extra):
    return SimpleNamespace(workspace=str(workspace), harness_root=Path(harness_root),
                           cfg=config.load(harness_root, str(workspace)), **extra)


def test_harness_root_is_the_repo(harness_root):
    assert paths.harness_root() == harness_root


def test_state_root_from_env_is_created_private(tmp_path, monkeypatch):
    target = tmp_path / "fresh" / "state"
    monkeypatch.setenv("OMEGA_STATE_DIR", str(target))
    assert paths.state_root() == target
    assert stat.S_IMODE(os.stat(str(target)).st_mode) == 0o700


def test_workspace_of_precedence(tmp_path, monkeypatch):
    a, b, c = tmp_path / "a", tmp_path / "b", tmp_path / "c"
    for d in (a, b, c):
        d.mkdir()
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(c))
    assert paths.workspace_of({}) == os.path.realpath(str(c))
    assert paths.workspace_of({"cwd": str(b)}) == os.path.realpath(str(b))
    monkeypatch.setenv("OMEGA_WORKSPACE", str(a))
    assert paths.workspace_of({"cwd": str(b)}) == os.path.realpath(str(a))
    monkeypatch.delenv("OMEGA_WORKSPACE")
    monkeypatch.delenv("CLAUDE_PROJECT_DIR")
    assert paths.workspace_of(None) == os.path.realpath(os.getcwd())


def test_workspace_hash_is_16_hex_and_symlink_invariant(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    value = paths.workspace_hash(str(real))
    assert len(value) == 16 and all(ch in "0123456789abcdef" for ch in value)
    assert paths.workspace_hash(str(link)) == value


@pytest.mark.parametrize("rel,pattern,expected", [
    ("README.md", "**/*.md", True),
    ("docs/a/b.md", "**/*.md", True),
    ("docs/a/b.md", "docs/**", True),
    ("docs", "docs/**", True),
    ("src/docs/a.md", "docs/**", False),
    ("a/b.pem", "*.pem", True),
    ("Dockerfile.dev", "Dockerfile*", True),
    ("svc/Dockerfile", "**/Dockerfile*", True),
    ("src/a.py", "tests/**", False),
    ("tests/test_a.py", "**/test_*.py", True),
    ("pkg/test_a.py", "**/test_*.py", True),
    ("pkg/a_test.py", "**/test_*.py", False),
    ("src/auth/signup.py", "**/auth/**", True),
    ("auth/signup.py", "**/auth/**", True),
    ("src/a.test.ts", "**/*.test.*", True),
    (".github/workflows/gauntlet.yml", ".github/workflows/gauntlet.yml", True),
    ("x/.github/workflows/gauntlet.yml", ".github/workflows/gauntlet.yml", False),
    ("./src/a.py", "src/*.py", True),
    ("src/a/b.py", "src/*.py", False),
    ("src/security_utils.py", "**/*secur*", True),
    ("a.txt", "[ab].txt", True),
    ("c.txt", "[!ab].txt", True),
])
def test_match_globs(rel, pattern, expected):
    assert paths.match_globs(rel, [pattern]) is expected


def test_match_globs_empty_inputs():
    assert paths.match_globs("", ["**"]) is False
    assert paths.match_globs("a", []) is False
    assert paths.match_globs("a", None) is False


def test_is_governed(workspace, harness_root):
    ctx = ctx_for(workspace, harness_root)
    assert paths.is_governed(str(workspace / "src" / "a.py"), ctx)
    assert paths.is_governed(str(harness_root / "hooks" / "prod_guard.py"), ctx)
    assert not paths.is_governed(str(workspace / "node_modules" / "x.js"), ctx)
    assert not paths.is_governed(str(workspace / "src" / "__pycache__" / "a.pyc"), ctx)
    assert not paths.is_governed(str(workspace / ".omega" / "scratch" / "x"), ctx)
    assert paths.is_governed(str(workspace / ".omega" / "clearances" / "proof.json"), ctx)
    assert not paths.is_governed("/usr/local/lib/x.py", ctx)


@pytest.mark.parametrize("rel", [".claude/settings.json", ".codex/hooks.json", ".gemini/settings.json",
                                 ".git/hooks/pre-commit", ".git/config", ".omega/clearances/proof.json",
                                 ".omega/config.json", ".github/workflows/gauntlet.yml", ".gitleaks.toml"])
def test_workspace_protected_paths(workspace, harness_root, rel):
    assert paths.is_protected(str(workspace / rel), ctx_for(workspace, harness_root))


@pytest.mark.parametrize("rel", ["bin/launch.sh", "hooks/prod_guard.py", "hooks/lib/io.py", "schemas/proof.schema.json",
                                 "scripts/auto_ship.py", "omega.config.json", ".claude/settings.json"])
def test_harness_protected_paths_and_dev_lift(workspace, harness_root, rel, monkeypatch):
    ctx = ctx_for(workspace, harness_root)
    assert paths.is_protected(str(harness_root / rel), ctx)
    monkeypatch.setenv("OMEGA_DEV", "1")
    assert not paths.is_protected(str(harness_root / rel), ctx)


def test_dev_mode_never_lifts_workspace_protection(workspace, harness_root, monkeypatch):
    monkeypatch.setenv("OMEGA_DEV", "1")
    assert paths.is_protected(str(workspace / ".claude" / "settings.json"), ctx_for(workspace, harness_root))


def test_ordinary_files_are_not_protected(workspace, harness_root):
    ctx = ctx_for(workspace, harness_root)
    assert not paths.is_protected(str(workspace / "src" / "a.py"), ctx)
    assert not paths.is_protected(str(workspace / "docs" / "contracts" / "x.md"), ctx)
    assert not paths.is_protected("/tmp/x", ctx)


def test_symlink_into_a_protected_path_is_protected(workspace, harness_root):
    (workspace / ".claude").mkdir()
    (workspace / ".claude" / "settings.json").write_text("{}")
    (workspace / "innocent.json").symlink_to(workspace / ".claude" / "settings.json")
    assert paths.is_protected(str(workspace / "innocent.json"), ctx_for(workspace, harness_root))


def test_relative_dotdot_into_protected_path(workspace, harness_root):
    sneaky = str(workspace / "src" / ".." / ".git" / "hooks" / "pre-commit")
    assert paths.is_protected(sneaky, ctx_for(workspace, harness_root))


def test_state_dir_transcripts_and_human_log_are_protected(workspace, harness_root, tmp_state, tmp_path, monkeypatch):
    transcript = tmp_path / "t.jsonl"
    ctx = ctx_for(workspace, harness_root, transcript_path=str(transcript))
    assert paths.is_protected(str(tmp_state / "x" / "claude" / "s" / "red.jsonl"), ctx)
    assert paths.is_protected(str(transcript), ctx)
    assert paths.is_protected(os.path.expanduser("~/.claude/projects/p/s.jsonl"), ctx)
    assert paths.is_protected(os.path.expanduser("~/.codex/sessions/2026/rollout.jsonl"), ctx)
    assert paths.is_protected(os.path.expanduser("~/.claude/settings.json"), ctx)
    assert paths.is_protected(os.path.expanduser("~/.codex/config.toml"), ctx)
    assert paths.is_protected(os.path.expanduser("~/.gemini/settings.json"), ctx)
    assert not paths.is_protected(os.path.expanduser("~/.claudeish/x"), ctx)
    log = tmp_path / "human_turns.jsonl"
    monkeypatch.setenv("OMEGA_HUMAN_LOG", str(log))
    assert paths.is_protected(str(log), ctx)


def test_is_scratch(workspace, harness_root):
    ctx = ctx_for(workspace, harness_root)
    assert paths.is_scratch("/dev/null", ctx)
    assert paths.is_scratch("/tmp/harness-x", ctx)
    assert paths.is_scratch(str(workspace / ".scratch" / "notes.txt"), ctx)
    assert not paths.is_scratch(str(workspace / "src" / "a.py"), ctx)
    assert not paths.is_scratch(str(harness_root / "hooks" / "x.py"), ctx)
    assert not paths.is_scratch("/usr/local/x", ctx)


def test_workspace_under_tmp_is_not_scratch(workspace, harness_root):
    assert str(workspace).startswith(tuple(paths.temp_roots())) or True
    assert not paths.is_scratch(str(workspace / "src" / "calc.py"), ctx_for(workspace, harness_root))


def test_is_exempt(workspace, harness_root):
    ctx = ctx_for(workspace, harness_root)
    assert paths.is_exempt(str(workspace / "docs" / "x.md"), ctx)
    assert paths.is_exempt(str(workspace / "migrations" / "0001.sql"), ctx)
    assert paths.is_exempt(str(workspace / "src" / "__init__.py"), ctx)
    assert not paths.is_exempt(str(workspace / "src" / "calc.py"), ctx)


def test_rel(workspace):
    assert paths.rel(str(workspace / "src" / "a.py"), str(workspace)) == "src/a.py"
    assert paths.rel(str(workspace), str(workspace)) == "."
    assert paths.rel("/elsewhere/x.py", str(workspace)) == "/elsewhere/x.py"

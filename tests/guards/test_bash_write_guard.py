from __future__ import annotations

import pytest

from hooks import bash_write_guard, prod_guard
from tests.guards.support import PRE, PROVIDERS, bash_payload, pre_outcome

REFUSED = [
    "echo x > src/a.py",
    "echo x >> src/a.py",
    "printf 'x' 2> src/a.py",
    "echo x &> src/a.py",
    "echo x >| src/a.py",
    "tee src/a.py",
    "echo x | tee -a src/a.py",
    "sed -i s/a/b/ src/a.py",
    "sed -i '' 's/a/b/' src/a.py",
    "sed -i.bak -e 's/a/b/' src/a.py",
    "perl -pi -e 's/a/b/' src/a.py",
    "python3 -c \"open('src/a.py','w')\"",
    "python3 -c \"from pathlib import Path; Path('src/a.py').write_text('x')\"",
    "node -e \"require('fs').writeFileSync('src/a.js', 'x')\"",
    "bash -c 'cat > src/a.py'",
    "sh -c \"echo x > src/a.py\"",
    "cp /tmp/x src/a.py",
    "cp -t src /tmp/x",
    "install -m 644 /tmp/x src/a.py",
    "ln -s /tmp/x src/a.py",
    "rsync -a /tmp/x/ src/",
    "mv /tmp/x src/a.py",
    "mv src/a.py /tmp/a.py",
    "rm src/a.py",
    "truncate -s 0 src/a.py",
    "touch src/new.py",
    "dd if=/dev/zero of=src/a.py bs=1 count=1",
    "cat <<EOF > src/a.py\nprint(1)\nEOF",
    "cd src && echo x > a.py",
    "python3 - <<'EOF'\nopen('src/a.py', 'w').write('x')\nEOF",
    "echo $(echo x > src/a.py)",
    "find src -name '*.py' -exec rm {} \\;",
    "curl -s -o src/vendor.js http://localhost:3000/vendor.js",
    "tar xzf /tmp/a.tgz",
    "sort -o src/a.py src/a.py",
    "echo x > README.md",
    "patch src/a.py /tmp/fix.diff",
    "echo x > tests/test_a.py",
]

UNPROVEN = [
    "echo x > $DEST",
    "echo x > \"$(pwd)/a.py\"",
    "cd \"$DIR\" && echo x > a.py",
    "ls | xargs rm",
    "find . -name '*.tmp' | xargs -I{} cp {} /tmp/",
    "patch -p1 < /tmp/fix.diff",
    "python3 -c \"import sys; open(sys.argv[1], 'w')\" x",
    "bash /tmp/does-not-exist.sh",
    "echo 'echo hi > src/a.py' | sh",
]

ALLOWED = [
    "echo x > /tmp/x",
    "echo x > /dev/null",
    "echo x 2>&1",
    "echo x > .scratch/x",
    "mkdir -p .scratch && echo x > .scratch/notes.txt",
    "cat src/a.py",
    "grep -rn foo src/",
    "cp src/a.py /tmp/a.py",
    "sed -n 1,5p src/a.py",
    "pytest -q > /tmp/pytest.log 2>&1",
    "python3 -c 'print(1)'",
    "echo x > node_modules/.cache/x",
    "rm -rf node_modules",
    "cd /tmp && echo x > a.txt",
    "tee /dev/stderr < /dev/null",
    "echo '> src/a.py'",
    "cat <<'EOF'\necho x > src/a.py\nEOF",
]


@pytest.mark.parametrize("command", REFUSED, ids=lambda c: c[:40])
def test_governed_shell_writes_refused(command, workspace, run_hook, claude_payload):
    proc = run_hook(PRE, bash_payload(claude_payload, command), "claude")
    blocked, reason = pre_outcome(proc, "claude")
    assert blocked, (command, proc.stdout)
    assert reason.startswith("[bash-write-guard] this command writes into a path the harness governs") or \
        reason.startswith("[prod-guard] blocked"), reason
    if reason.startswith("[bash-write-guard]"):
        assert "Use the Edit or Write tool on" in reason


@pytest.mark.parametrize("command", UNPROVEN, ids=lambda c: c[:40])
def test_unreadable_destinations_are_unproven(command, workspace, run_hook, claude_payload):
    proc = run_hook(PRE, bash_payload(claude_payload, command), "claude")
    blocked, reason = pre_outcome(proc, "claude")
    assert blocked, (command, proc.stdout)
    assert reason.startswith("[bash-write-guard] this command writes somewhere the guard cannot work out") or \
        reason.startswith("[prod-guard] blocked (dynamic."), reason


@pytest.mark.parametrize("command", ALLOWED, ids=lambda c: c[:40])
def test_scratch_and_read_only_commands_allowed(command, workspace, run_hook, claude_payload):
    proc = run_hook(PRE, bash_payload(claude_payload, command), "claude")
    blocked, reason = pre_outcome(proc, "claude")
    assert not blocked, (command, reason)


@pytest.mark.parametrize("provider", PROVIDERS)
def test_v2_table_for_both_providers(provider, workspace, run_hook, claude_payload, codex_payload):
    make = claude_payload if provider == "claude" else codex_payload
    for command in ("echo x > src/a.py", "tee src/a.py", "cp /tmp/x src/a.py"):
        blocked, reason = pre_outcome(run_hook(PRE, bash_payload(make, command), provider), provider)
        assert blocked and reason.startswith("[bash-write-guard]"), (provider, command, reason)
    blocked, reason = pre_outcome(run_hook(PRE, bash_payload(make, "echo x > $DEST"), provider), provider)
    assert blocked and "cannot work out" in reason
    blocked, _ = pre_outcome(run_hook(PRE, bash_payload(make, "echo x > /tmp/x"), provider), provider)
    assert not blocked


def test_protected_paths_refused_with_rule(workspace, run_hook, claude_payload):
    proc = run_hook(PRE, bash_payload(claude_payload, "printf x | tee .codex/hooks.json"), "claude")
    blocked, reason = pre_outcome(proc, "claude")
    assert blocked and "omega.protected_path" in reason


def test_shell_write_into_harness_root_refused(workspace, run_hook, claude_payload, harness_root):
    proc = run_hook(PRE, bash_payload(claude_payload, "echo x >> %s/hooks/prod_guard.py" % harness_root), "claude")
    blocked, reason = pre_outcome(proc, "claude")
    assert blocked and "omega.protected_path" in reason


def test_sensitive_home_paths_refused(workspace, run_hook, claude_payload):
    proc = run_hook(PRE, bash_payload(claude_payload, "echo 'alias ls=rm' >> ~/.zshrc"), "claude")
    blocked, reason = pre_outcome(proc, "claude")
    assert blocked and "system or user configuration path" in reason


def test_one_level_of_script_following(workspace, run_hook, claude_payload):
    (workspace / ".scratch").mkdir()
    (workspace / ".scratch" / "gen.sh").write_text("echo x > src/generated.py\n", encoding="utf-8")
    proc = run_hook(PRE, bash_payload(claude_payload, "bash .scratch/gen.sh"), "claude")
    blocked, reason = pre_outcome(proc, "claude")
    assert blocked
    (workspace / ".scratch" / "nested.sh").write_text("bash .scratch/gen.sh\n", encoding="utf-8")
    verdict = bash_write_guard.judge("bash .scratch/nested.sh", prod_guard.guard_context(str(workspace)))
    assert verdict.rule == bash_write_guard.UNPROVEN and "only one level" in verdict.reason


def test_destinations_api(workspace):
    targets, opaque = bash_write_guard.destinations("cp a b && echo x > /tmp/y", str(workspace))
    assert targets == [str(workspace / "b"), "/tmp/y"] and opaque is False
    targets, opaque = bash_write_guard.destinations("echo x > $OUT", str(workspace))
    assert targets == [] and opaque is True


def test_judge_rules(workspace):
    ctx = prod_guard.guard_context(str(workspace))
    assert bash_write_guard.judge("echo x > src/a.py", ctx).rule == bash_write_guard.REFUSE
    assert bash_write_guard.judge("echo x > $X", ctx).rule == bash_write_guard.UNPROVEN
    assert bash_write_guard.judge("echo x > /tmp/x", ctx).rule == bash_write_guard.ALLOW
    assert bash_write_guard.judge("echo x > .git/config", ctx).rule == bash_write_guard.PROTECTED


def test_dry_run_cli_exit_codes(workspace, harness_root):
    import subprocess
    import sys
    script = str(harness_root / "hooks" / "bash_write_guard.py")
    refused = subprocess.run([sys.executable, script, "--command", "echo x > src/a.py", "--workspace", str(workspace)],
                             capture_output=True, text=True)
    assert refused.returncode == 1 and refused.stdout.startswith("[bash-write-guard]")
    allowed = subprocess.run([sys.executable, script, "--command", "echo x > /tmp/x", "--workspace", str(workspace)],
                             capture_output=True, text=True)
    assert allowed.returncode == 0


def test_case_arm_writer_refused(workspace):
    ctx = prod_guard.guard_context(str(workspace))
    assert bash_write_guard.judge("case x in x) rm src/a.py;; esac", ctx).rule == bash_write_guard.REFUSE

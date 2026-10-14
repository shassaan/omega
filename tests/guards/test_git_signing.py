from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from hooks.lib import config as config_mod
from hooks.lib import git_signing
from tests.guards.support import PRE, bash_payload, pre_outcome

HUMAN = "human@example.com"


def git(cwd, *args, check=True):
    return subprocess.run(["git"] + list(args), cwd=str(cwd), check=check, capture_output=True, text=True)


def make_key(directory: Path, name: str) -> Path:
    key = directory / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)], check=True,
                   capture_output=True)
    return Path(str(key) + ".pub")


def configure_signing(repo: Path, pub: Path, signers: Path, email: str = HUMAN) -> None:
    git(repo, "config", "user.email", email)
    git(repo, "config", "user.name", "Human")
    git(repo, "config", "gpg.format", "ssh")
    git(repo, "config", "user.signingkey", str(pub))
    git(repo, "config", "commit.gpgsign", "true")
    git(repo, "config", "gpg.ssh.allowedSignersFile", str(signers))


@pytest.fixture
def signed(workspace, tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir()
    pub = make_key(keys, "human")
    other = make_key(keys, "intruder")
    signers = keys / "allowed_signers"
    signers.write_text("%s %s\n%s %s\n" % (HUMAN, pub.read_text().strip(), HUMAN, other.read_text().strip()))
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", str(remote))
    git(workspace, "remote", "add", "origin", str(remote))
    git(workspace, "push", "-q", "origin", "main")
    configure_signing(workspace, pub, signers)
    return {"ws": workspace, "pub": pub, "other": other, "signers": signers, "remote": remote, "tmp": tmp_path}


def commit_file(ws: Path, name: str, *extra: str) -> None:
    (ws / name).write_text(name + "\n")
    git(ws, "add", name)
    git(ws, *extra, "commit", "-q", "-m", "add %s" % name)


def judge(run_hook, claude_payload, command):
    proc = run_hook(PRE, bash_payload(claude_payload, command), "claude")
    return pre_outcome(proc, "claude")


def assert_rule(run_hook, claude_payload, command, rule):
    blocked, reason = judge(run_hook, claude_payload, command)
    assert blocked, command
    assert reason.startswith("[prod-guard] blocked (%s)" % rule), reason
    return reason


def test_commit_allowed_when_signing_is_configured(signed, run_hook, claude_payload):
    assert judge(run_hook, claude_payload, "git commit -m 'add feature'") == (False, "")
    assert judge(run_hook, claude_payload, "git commit --amend --no-edit -S")[0] is False


def test_push_of_signed_commits_allowed(signed, run_hook, claude_payload):
    commit_file(signed["ws"], "a.txt")
    assert git(signed["ws"], "log", "-1", "--format=%G?").stdout.strip() == "G"
    assert judge(run_hook, claude_payload, "git push origin main")[0] is False
    assert judge(run_hook, claude_payload, "git push -u origin HEAD:feature/x")[0] is False


def test_push_of_unsigned_commit_blocked(signed, run_hook, claude_payload):
    commit_file(signed["ws"], "a.txt", "-c", "commit.gpgsign=false")
    reason = assert_rule(run_hook, claude_payload, "git push origin main", "git.unsigned_push")
    assert "has no signature" in reason


def test_push_of_commit_signed_by_other_key_blocked(signed, run_hook, claude_payload):
    commit_file(signed["ws"], "a.txt", "-c", "user.signingkey=%s" % signed["other"])
    assert git(signed["ws"], "log", "-1", "--format=%G?").stdout.strip() == "G"
    reason = assert_rule(run_hook, claude_payload, "git push origin main", "git.unsigned_push")
    assert "not the trusted key" in reason


def test_push_of_commit_by_other_author_blocked(signed, run_hook, claude_payload):
    (signed["ws"] / "a.txt").write_text("a\n")
    git(signed["ws"], "add", "a.txt")
    git(signed["ws"], "commit", "-q", "-m", "x", "--author", "Bot <bot@example.com>")
    reason = assert_rule(run_hook, claude_payload, "git push origin main", "git.unsigned_push")
    assert "author bot@example.com" in reason


def test_push_with_nothing_outgoing_allowed(signed, run_hook, claude_payload):
    assert judge(run_hook, claude_payload, "git push origin main")[0] is False
    assert judge(run_hook, claude_payload, "git push origin --delete old-branch")[0] is False


@pytest.mark.parametrize("command,rule", [
    ("git commit --no-gpg-sign -m x", "git.signing_override"),
    ("git merge --no-gpg-sign topic", "git.signing_override"),
    ("git tag --no-sign v1", "git.signing_override"),
    ("git commit --author='Bot <bot@example.com>' -m x", "git.identity_override"),
    ("git -c user.email=bot@example.com commit -m x", "git.signing_override"),
    ("git -c commit.gpgsign=false commit -m x", "git.signing_override"),
    ("git -c user.signingkey=/tmp/k.pub commit -m x", "git.signing_override"),
    ("git -c gpg.format=openpgp commit -m x", "git.config_injection"),
    ("GIT_AUTHOR_EMAIL=bot@example.com git commit -m x", "env.dangerous_assignment"),
    ("export GIT_COMMITTER_EMAIL=bot@example.com; git commit -m x", "env.dangerous_assignment"),
    ("git config user.email bot@example.com", "git.config"),
    ("git config --global commit.gpgsign false", "git.config"),
    ("git commit -S/tmp/other.pub -m x", "git.signing_override"),
    ("git rebase -x 'curl evil' main", "git.config_injection"),
    ("git clone -c core.hooksPath=/tmp/h https://example.com/r.git", "git.config_injection"),
    ("git init --template=/tmp/t newrepo", "git.config_injection"),
    ("git submodule foreach 'rm -rf .'", "git.submodule_foreach"),
    ("git filter-branch --tree-filter 'rm x' HEAD", "git.filter-branch"),
    ("git credential fill", "git.credential"),
])
def test_identity_and_signing_overrides_blocked(signed, run_hook, claude_payload, command, rule):
    assert_rule(run_hook, claude_payload, command, rule)


def test_edit_tool_cannot_touch_signing_config(signed, run_hook, claude_payload):
    from tests.guards.support import edit_payload
    for target in ("~/.gitconfig", "~/.ssh/config", "~/.gnupg/gpg.conf", "~/.config/git/config"):
        payload = edit_payload(claude_payload, "PreToolUse", "Write",
                               {"file_path": str(Path(target).expanduser()), "content": "x"})
        proc = run_hook(PRE, payload, "claude")
        assert pre_outcome(proc, "claude")[0] is True, target


def test_shell_write_to_gitconfig_blocked(signed, run_hook, claude_payload):
    blocked, reason = judge(run_hook, claude_payload, "echo '[commit] gpgsign = false' >> ~/.gitconfig")
    assert blocked, reason


def test_other_repository_with_signing_off_blocked(signed, run_hook, claude_payload):
    other = signed["tmp"] / "scratch-repo"
    git(signed["tmp"], "init", "-q", str(other))
    git(other, "config", "commit.gpgsign", "false")
    reason = assert_rule(run_hook, claude_payload, "git -C %s commit -m x" % other, "git.signing_required")
    assert "commit.gpgsign is not true" in reason


def test_other_repository_with_foreign_identity_blocked(signed, run_hook, claude_payload):
    other = signed["tmp"] / "scratch-repo"
    git(signed["tmp"], "init", "-q", str(other))
    configure_signing(other, signed["other"], signed["signers"], email="bot@example.com")
    reason = assert_rule(run_hook, claude_payload, "git -C %s commit -m x" % other, "git.signing_required")
    assert "bot@example.com" in reason and "not the trusted signing key" in reason


def test_pinned_identity_overrides_repository_config(signed, run_hook, claude_payload):
    config = signed["ws"] / ".omega" / "config.json"
    data = json.loads(config.read_text())
    data["git"] = {"identity": {"email": "personal@example.com"}}
    config.write_text(json.dumps(data))
    reason = assert_rule(run_hook, claude_payload, "git commit -m x", "git.signing_required")
    assert "personal@example.com" in reason


def test_unsigned_tag_blocked_and_signed_tag_allowed(signed, run_hook, claude_payload):
    assert_rule(run_hook, claude_payload, "git tag v1", "git.unsigned_tag")
    assert judge(run_hook, claude_payload, "git tag -s v1 -m 'release'")[0] is False
    assert judge(run_hook, claude_payload, "git tag -l")[0] is False
    assert judge(run_hook, claude_payload, "git tag -d v1")[0] is False
    git(signed["ws"], "config", "tag.gpgsign", "true")
    assert judge(run_hook, claude_payload, "git tag v2 -m x")[0] is False


def test_require_signed_false_allows_unsigned_commits(workspace, run_hook, claude_payload):
    config = workspace / ".omega" / "config.json"
    data = json.loads(config.read_text())
    data["git"] = {"require_signed": False}
    config.write_text(json.dumps(data))
    assert judge(run_hook, claude_payload, "git commit -m x")[0] is False
    assert judge(run_hook, claude_payload, "git push origin main")[0] is False


def test_unsigned_workspace_blocks_commit_and_push(workspace, run_hook, claude_payload):
    for command in ("git commit -m x", "git push origin main", "git merge topic", "git cherry-pick abc", "git pull"):
        reason = assert_rule(run_hook, claude_payload, command, "git.signing_required")
        assert "no trusted signing key" in reason


@pytest.mark.parametrize("rest,refs", [
    (["origin", "main"], ["main"]),
    (["origin"], ["HEAD"]),
    ([], ["HEAD"]),
    (["-u", "origin", "HEAD:feature"], ["HEAD"]),
    (["origin", "+main:main", "dev"], ["main", "dev"]),
    (["--all", "origin"], ["--branches"]),
    (["--tags", "origin"], ["--tags"]),
    (["origin", ":gone"], []),
    (["--delete", "origin", "x"], []),
    (["origin", "refs/heads/*:refs/heads/*"], ["--branches"]),
])
def test_push_refs(rest, refs):
    assert git_signing.push_refs(rest) == refs


def test_same_key_normalisation(tmp_path):
    pub = make_key(tmp_path, "k")
    material = " ".join(pub.read_text().split()[:2])
    assert git_signing.same_key(str(pub), "key::" + material, "ssh")
    assert git_signing.same_key(str(pub)[:-4], str(pub), "ssh")
    assert git_signing.ssh_fingerprint(str(pub)).startswith("SHA256:")
    assert git_signing.same_key("0x04C09F7D0BF69138!", "0BF69138", "openpgp")
    assert not git_signing.same_key("AAAA1111", "BBBB2222", "openpgp")


def test_location_follows_dash_c(tmp_path):
    argv = ["git", "-C", "sub", "--git-dir=.git", "commit", "-m", "x"]
    assert git_signing.location_of(argv, 2, str(tmp_path)) == ["-C", str(tmp_path), "-C", "sub", "--git-dir=.git"]


def test_policy_reads_pins(workspace):
    cfg = config_mod.Config({"git": {"identity": {"email": "p@example.com", "signing_key": "~/.ssh/k.pub",
                                                  "format": "ssh"}}}, [], [])
    pol = git_signing.policy(cfg, str(workspace))
    assert (pol.trusted.email, pol.trusted.key, pol.trusted.fmt) == ("p@example.com", "~/.ssh/k.pub", "ssh")
    assert pol.require_signed is True and pol.accept == ("G", "U")


def test_describe_names_the_target_repository(tmp_path):
    assert git_signing.describe(["-C", str(tmp_path), "-C", "sub"]) == str(tmp_path / "sub")
    assert git_signing.describe(["-C", str(tmp_path), "-C", "/abs/repo"]) == "/abs/repo"


def test_push_from_repository_without_commits_is_not_an_error(tmp_path, workspace, run_hook, claude_payload):
    empty = tmp_path / "empty-repo"
    git(tmp_path, "init", "-q", str(empty))
    pol = git_signing.Policy(True, git_signing.Identity(True, "ssh", "k", "h@example.com", "h", False), ("G",), 10)
    assert git_signing.outgoing_problems(["-C", str(empty)], ["HEAD"], pol) == []

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from hooks.lib import shell

CORPUS = json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "shell" / "corpus.json").read_text())
READ_ONLY_GIT = {"status", "diff", "log", "show", "blame", "rev-parse", "ls-files", "fetch", "describe", "grep"}
SQL_BAD = re.compile(r"\b(drop|truncate|delete\s+from|alter|grant)\b", re.I)
INTERP_BAD = re.compile(r"os\.(system|popen)|subprocess|child_process|execSync", re.I)
SENSITIVE_RM = {"/", "/*", "~", "~/", "$HOME/", "$HOME", "*", "."}


def dangerous(argv):
    name = argv[0]
    words = [a for a in argv[1:] if not a.startswith("-")]
    if name == "git":
        sub, rest, configs = shell.git_subcommand(argv)
        if any(re.match(r"(alias\.|core\.(sshcommand|pager|editor|hookspath|fsmonitor)|credential\.|include)", c, re.I)
               for c in configs):
            return True
        if sub == "branch":
            return any(r in ("-d", "-D", "-m", "-M", "--delete") for r in rest) or bool([r for r in rest if not r.startswith("-")])
        if sub == "stash":
            return (rest[:1] or ["push"])[0] not in ("list", "show")
        return sub not in READ_ONLY_GIT
    if name in ("terraform", "tofu"):
        return bool(words) and words[0] in ("apply", "destroy", "import", "state", "taint")
    if name == "kubectl":
        return bool(words) and words[0] in ("delete", "apply", "patch", "exec")
    if name == "docker":
        return "prune" in words or (bool(words) and words[0] in ("system", "rm", "push", "run", "exec"))
    if name in ("psql", "sqlite3", "mysql"):
        return bool(SQL_BAD.search(" ".join(argv[1:])))
    if name in ("npx", "prisma"):
        return "migrate" in words and "reset" in words
    if name == "alembic":
        return bool(words) and words[0] in ("downgrade", "stamp")
    if name in ("rm", "unlink", "rmdir"):
        return any(w in SENSITIVE_RM for w in words)
    if name == "gh":
        return words[:2] in (["pr", "merge"], ["repo", "delete"])
    return False


def exposed(command):
    result = shell.walk(command)
    if result.dynamic:
        return True
    if any(INTERP_BAD.search(code) for _, code in result.code):
        return True
    return any(dangerous(entry["argv"]) for entry in result.commands)


@pytest.mark.parametrize("command", CORPUS["deny"] + CORPUS["extra_deny"])
def test_corpus_deny_is_exposed(command):
    assert exposed(command), shell.walk(command)


@pytest.mark.parametrize("command", CORPUS["allow"] + CORPUS["extra_allow"])
def test_corpus_allow_is_not_exposed(command):
    result = shell.walk(command)
    assert not exposed(command), result
    assert result.commands


def test_corpus_sizes_match_research():
    assert len(CORPUS["deny"]) == 49
    assert len(CORPUS["allow"]) == 22
    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "shell"
    assert len((fixtures / "deny.txt").read_text().splitlines()) == 47


@pytest.mark.parametrize("command,expected", [
    ("a; b && c || d | e & f", ["a", "b", "c", "d", "e", "f"]),
    ("a\nb", ["a", "b"]),
    ("echo 'a; b' \"c | d\"", ["echo 'a; b' \"c | d\""]),
    ("echo $(a; b) `c; d`", ["echo $(a; b) `c; d`"]),
    ("cmd 2>&1 >&2 &>out >|clobber", ["cmd 2>&1 >&2 &>out >|clobber"]),
    ("git \\\n push", ["git  push"]),
    ("ls # comment ; rm -rf /", ["ls"]),
    ("echo a#b", ["echo a#b"]),
    ("diff <(a; b) >(c)", ["diff <(a; b) >(c)"]),
    ("a |& b", ["a", "b"]),
    ("", []),
])
def test_split_commands(command, expected):
    assert shell.split_commands(command) == expected


def test_tokens_posix_and_failure():
    assert shell.tokens("g''it \"pu\"sh 'a b'") == ["git", "push", "a b"]
    with pytest.raises(ValueError):
        shell.tokens("echo 'unbalanced")


@pytest.mark.parametrize("command,expected", [
    ("echo $(git push)", ["git push"]),
    ("echo `git push`", ["git push"]),
    ("echo \"$(git push)\"", ["git push"]),
    ("echo '$(git push)'", []),
    ("echo $(echo $(git push))", ["echo $(git push)"]),
    ("diff <(ls a) >(tee b)", ["ls a", "tee b"]),
    ("echo $((1 + $(git push)))", ["git push"]),
    ("echo \\$(git push)", []),
    ("echo $(a \")\" b)", ["a \")\" b"]),
])
def test_substitutions(command, expected):
    assert shell.substitutions(command) == expected


def test_heredocs_and_strip():
    command = "cat <<EOF > out.txt\nline1\nline2\nEOF\necho after"
    assert shell.heredocs(command) == [("cat   > out.txt", "line1\nline2")]
    assert "line1" not in shell.strip_heredocs(command) and "echo after" in shell.strip_heredocs(command)
    assert shell.heredocs("bash <<'X'\ngit push\nX") == [("bash", "git push")]
    assert shell.heredocs("sh <<-EOF\n\tgit push\n\tEOF\nls") == [("sh", "git push")]
    assert shell.heredocs("python3 - <<\"PY\"\nimport os\nPY") == [("python3 -", "import os")]
    assert shell.heredocs("cat <<<'here string'") == []
    assert shell.heredocs("echo \"<<EOF\"\ngit push\nEOF") == []
    assert shell.heredocs("cat <<A <<B\na\nA\nb\nB") == [("cat", "a"), ("cat", "b")]
    assert shell.heredocs("cat <<EOF\nno terminator") == [("cat", "no terminator")]


def test_mask_expansions():
    assert shell.mask_expansions("echo $(rm -rf /) > out") == "echo $SUBST > out"
    assert shell.mask_expansions("[[ $a > $b ]] && x") == " _test_  && x"
    assert shell.mask_expansions("(( n > 0 )) && y") == " _arith_  && y"
    assert shell.mask_expansions("echo '$(literal)'") == "echo '$(literal)'"
    assert shell.mask_expansions("echo `date`") == "echo $SUBST"


@pytest.mark.parametrize("segment,targets,opaque", [
    ("echo x > src/a.py", ["src/a.py"], False),
    ("echo x >> 'a b.txt'", ["a b.txt"], False),
    ("echo x>src/a.py", ["src/a.py"], False),
    ("cmd 2> err.log", ["err.log"], False),
    ("cmd &> all.log", ["all.log"], False),
    ("cmd &>> all.log", ["all.log"], False),
    ("cmd >| clobber", ["clobber"], False),
    ("cmd 2>&1", [], False),
    ("cmd >&2", [], False),
    ("cmd 2>&-", [], False),
    ("cmd >& file.txt", ["file.txt"], False),
    ("cmd > \"$DEST\"", [], True),
    ("cmd > $(pick)", [], True),
    ("cmd > '$LITERAL'", ["$LITERAL"], False),
    ("cmd > *.py", [], True),
    ("cmd >", [], True),
    ("cmd < input.txt", [], False),
    ("cat <<EOF > out\nbody > ignored\nEOF", ["out"], False),
    ("[[ $a > $b ]]", [], False),
    ("echo '>' quoted", [], False),
    ("cmd 1<>rw.txt", ["rw.txt"], False),
])
def test_redirect_targets(segment, targets, opaque):
    assert shell.redirect_targets(segment) == (targets, opaque)


def test_argv_of_removes_redirects_and_unquotes():
    assert shell.argv_of("FOO=1 cmd 'a b' >out 2>&1 <in --flag") == ["FOO=1", "cmd", "a b", "--flag"]
    assert shell.argv_of("echo \"<<EOF\"") == ["echo", "<<EOF"]
    with pytest.raises(ValueError):
        shell.argv_of("echo \"open")


def test_strip_redirect_tokens():
    assert shell.strip_redirect_tokens(["echo", "x", ">", "out", "2>&1", ">>log", "y"]) == ["echo", "x", "y"]


def test_leading_assignments():
    assert shell.leading_assignments(["A=1", "B+=2", "cmd", "C=3"]) == (["A=1", "B+=2"], ["cmd", "C=3"])
    assert shell.leading_assignments([]) == ([], [])


@pytest.mark.parametrize("argv,inner", [
    (["sudo", "-u", "root", "git", "push"], ["git", "push"]),
    (["env", "FOO=1", "-u", "BAR", "git", "push"], ["git", "push"]),
    (["/usr/bin/env", "git", "push"], ["git", "push"]),
    (["env", "-S", "git push"], ["git", "push"]),
    (["env", "--split-string=git push"], ["git", "push"]),
    (["nohup", "nice", "-n", "5", "timeout", "-s", "KILL", "10", "git", "push"], ["git", "push"]),
    (["timeout", "5s", "git", "push"], ["git", "push"]),
    (["xargs", "-I", "{}", "-n", "1", "git", "push"], ["git", "push"]),
    (["command", "git", "push"], ["git", "push"]),
    (["command", "-v", "git"], []),
    (["builtin", "eval", "x"], ["eval", "x"]),
    (["exec", "-a", "name", "git", "push"], ["git", "push"]),
    (["chroot", "/jail", "git", "push"], ["git", "push"]),
    (["busybox", "sh", "-c", "x"], ["sh", "-c", "x"]),
    (["stdbuf", "-oL", "git", "push"], ["git", "push"]),
    (["watch", "-n", "1", "git", "push"], ["git", "push"]),
    (["uv", "run", "--frozen", "git", "push"], ["git", "push"]),
    (["poetry", "run", "git", "push"], ["git", "push"]),
    (["sudo"], []),
    (["env"], []),
    (["git", "status"], ["git", "status"]),
])
def test_unwrap(argv, inner):
    assert shell.unwrap(argv) == inner


def test_unwrap_keeps_assignments_for_inspection():
    inner, assignments = shell.unwrap_with_assignments(["PATH=/evil", "env", "LD_PRELOAD=x.so", "git", "push"])
    assert inner == ["git", "push"] and assignments == ["PATH=/evil", "LD_PRELOAD=x.so"]


@pytest.mark.parametrize("argv,expected", [
    (["git", "push"], ("push", [], [])),
    (["git", "-C", "/tmp/x", "push", "origin"], ("push", ["origin"], [])),
    (["git", "-c", "alias.x=push", "x"], ("x", [], ["alias.x=push"])),
    (["git", "--git-dir=.git", "--work-tree", "/w", "commit", "-m", "x"], ("commit", ["-m", "x"], [])),
    (["git", "--no-pager", "-P", "log"], ("log", [], [])),
    (["git", "--config-env=core.sshCommand=EVIL", "fetch"], ("fetch", [], ["core.sshCommand=EVIL"])),
    (["git", "--version"], ("version", [], [])),
    (["git"], ("", [], [])),
])
def test_git_subcommand(argv, expected):
    assert shell.git_subcommand(argv) == expected


@pytest.mark.parametrize("tok,expected", [("$x", True), ("`x`", True), ("*.py", True), ("a?", True), ("[ab]", True),
                                          ("{a,b}", True), ("", True), ("git", False), ("/usr/bin/git", False)])
def test_is_opaque(tok, expected):
    assert shell.is_opaque(tok) is expected


def test_basename():
    assert shell.basename("/usr/bin/git") == "git" and shell.basename("./git") == "git" and shell.basename("") == ""


def test_walk_limits():
    assert any(d.startswith("too_long") for d in shell.walk("a" * 20001).dynamic)
    nested = "git push"
    for _ in range(8):
        nested = "bash -c %s" % __import__("shlex").quote(nested)
    assert any(d.startswith("nesting") for d in shell.walk(nested).dynamic)
    assert "parse_failure: unbalanced quotes" in shell.walk("echo 'oops").dynamic


def test_walk_reports_interpreter_code_and_heredoc_code():
    result = shell.walk("python3 -c 'import shutil; shutil.rmtree(\"/\")'")
    assert result.code == [("python3", 'import shutil; shutil.rmtree("/")')]
    result = shell.walk("python3 - <<EOF\nimport os\nos.system('git push')\nEOF")
    assert result.code and "os.system" in result.code[0][1]
    assert shell.walk("node -e 'require(\"child_process\")'").code[0][0] == "node"

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

GIT_TIMEOUT_S = 15
FIELD = "\x1f"
LOG_FORMAT = FIELD.join(("%H", "%G?", "%GF", "%GP", "%GK", "%GS", "%ae", "%ce"))
TRUTHY = ("true", "yes", "on", "1")
DEFAULT_ACCEPT = ("G", "U")
DEFAULT_MAX_OUTGOING = 2000
STATUS_TEXT = {
    "N": "has no signature",
    "B": "has a bad signature",
    "E": "has a signature that cannot be checked",
    "X": "has a good signature that has expired",
    "Y": "has a good signature made by an expired key",
    "R": "has a good signature made by a revoked key",
    "U": "has a good signature of unknown validity",
}
COMMIT_MAKERS = frozenset(("commit", "merge", "rebase", "cherry-pick", "revert", "am", "pull", "commit-tree"))
SIGNING_CONFIG = re.compile(r"^(user\.|author\.|committer\.|commit\.gpgsign|tag\.gpgsign|tag\.forcesignannotated"
                            r"|push\.gpgsign|gpg\.)", re.I)
LOCATION_VALUED = ("-C", "--git-dir", "--work-tree", "--namespace")


@dataclass
class Identity:
    enabled: bool
    fmt: str
    key: str
    email: str
    name: str
    tag_sign: bool


@dataclass
class Policy:
    require_signed: bool
    trusted: Identity
    accept: tuple
    max_outgoing: int


def _run(args: list, env: Optional[dict]) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(["git"] + args, capture_output=True, timeout=GIT_TIMEOUT_S, env=env,
                              stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def _text(data: bytes) -> str:
    return data.decode("utf-8", "replace").strip()


def _get(location: list, key: str, env: Optional[dict]) -> str:
    proc = _run(location + ["config", "--get", key], env)
    if proc is None or proc.returncode != 0:
        return ""
    return _text(proc.stdout)


def read_identity(location: list, env: Optional[dict] = None) -> Identity:
    return Identity(
        enabled=_get(location, "commit.gpgsign", env).lower() in TRUTHY,
        fmt=(_get(location, "gpg.format", env) or "openpgp").lower(),
        key=_get(location, "user.signingkey", env),
        email=_get(location, "user.email", env),
        name=_get(location, "user.name", env),
        tag_sign=_get(location, "tag.gpgsign", env).lower() in TRUTHY,
    )


def policy(cfg, workspace: str, env: Optional[dict] = None) -> Policy:
    getter = getattr(cfg, "get", None)

    def setting(dotted: str, default):
        if getter is None:
            return default
        value = getter(dotted, default)
        return default if value is None else value

    base = read_identity(["-C", workspace], env)
    pinned = setting("git.identity", {}) or {}
    trusted = Identity(
        enabled=base.enabled,
        fmt=str(pinned.get("format") or base.fmt).lower(),
        key=str(pinned.get("signing_key") or base.key),
        email=str(pinned.get("email") or base.email),
        name=str(pinned.get("name") or base.name),
        tag_sign=base.tag_sign,
    )
    accept = tuple(str(s) for s in (setting("git.accept_signature_status", list(DEFAULT_ACCEPT)) or DEFAULT_ACCEPT))
    return Policy(require_signed=bool(setting("git.require_signed", True)), trusted=trusted, accept=accept,
                  max_outgoing=int(setting("git.max_outgoing", DEFAULT_MAX_OUTGOING)))


def _ssh_material(key: str) -> str:
    raw = key[len("key::"):] if key.startswith("key::") else ""
    if not raw:
        path = os.path.expanduser(key)
        if not path.endswith(".pub") and os.path.isfile(path + ".pub"):
            path = path + ".pub"
        try:
            with open(path, "r", encoding="utf-8") as handle:
                raw = handle.read()
        except OSError:
            return key.strip()
    parts = raw.split()
    return " ".join(parts[:2]) if len(parts) >= 2 else raw.strip()


def normalise_key(key: str, fmt: str) -> str:
    text = (key or "").strip()
    if not text:
        return ""
    if fmt == "ssh":
        return _ssh_material(text)
    text = text.rstrip("!")
    if text.lower().startswith("0x"):
        text = text[2:]
    return text.replace(" ", "").upper()


def ssh_fingerprint(key: str) -> str:
    material = _ssh_material(key)
    if not material:
        return ""
    handle = tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False)
    try:
        handle.write(material + "\n")
        handle.close()
        proc = subprocess.run(["ssh-keygen", "-l", "-E", "sha256", "-f", handle.name], capture_output=True,
                              timeout=GIT_TIMEOUT_S, stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
    if proc.returncode != 0:
        return ""
    words = _text(proc.stdout).split()
    return words[1] if len(words) > 1 else ""


def same_key(left: str, right: str, fmt: str) -> bool:
    a = normalise_key(left, fmt)
    b = normalise_key(right, fmt)
    if not a or not b:
        return False
    if fmt == "ssh":
        return a == b
    return a == b or a.endswith(b) or b.endswith(a)


def config_problems(location: list, pol: Policy, env: Optional[dict] = None) -> list:
    if not pol.require_signed:
        return []
    trusted = pol.trusted
    problems: list = []
    if not trusted.email:
        problems.append("no trusted committer email: set user.email in the workspace repository or git.identity.email "
                        "in .omega/config.json")
    if not trusted.key:
        problems.append("no trusted signing key: set user.signingkey in the workspace repository or "
                        "git.identity.signing_key in .omega/config.json")
    if problems:
        return problems
    actual = read_identity(location, env)
    where = describe(location)
    if not actual.enabled:
        problems.append("commit.gpgsign is not true in %s, so commits would be unsigned" % where)
    if actual.email.lower() != trusted.email.lower():
        problems.append("user.email in %s is %r, but commits must be made as %r" % (where, actual.email or "",
                                                                                     trusted.email))
    if actual.fmt != trusted.fmt:
        problems.append("gpg.format in %s is %s, but the trusted signing key is %s" % (where, actual.fmt,
                                                                                     trusted.fmt))
    elif not same_key(actual.key, trusted.key, trusted.fmt):
        problems.append("user.signingkey in %s is not the trusted signing key" % where)
    return problems


def describe(location: list) -> str:
    path = ""
    index = 0
    while index < len(location):
        if location[index] == "-C" and index + 1 < len(location):
            path = os.path.join(path, location[index + 1]) if path else location[index + 1]
            index += 2
            continue
        index += 1
    return os.path.normpath(path) if path else "this repository"


def flag_problems(sub: str, rest: list, pol: Policy) -> list:
    if not pol.require_signed:
        return []
    problems: list = []
    trusted = pol.trusted
    for index, token in enumerate(rest):
        if token == "--":
            break
        if token in ("--no-gpg-sign", "--no-sign"):
            problems.append("git %s %s turns signing off" % (sub, token))
        elif token == "--author" or token.startswith("--author="):
            problems.append("git %s --author commits as someone other than %s" % (sub, trusted.email))
        elif token.startswith("--gpg-sign=") or (token.startswith("-S") and len(token) > 2 and not token.startswith("--")):
            value = token.split("=", 1)[1] if "=" in token else token[2:]
            if not same_key(value, trusted.key, trusted.fmt):
                problems.append("git %s %s signs with a key other than the trusted signing key" % (sub, token))
        elif sub == "tag" and token in ("-u", "--local-user") and index + 1 < len(rest):
            if not same_key(rest[index + 1], trusted.key, trusted.fmt):
                problems.append("git tag %s signs with a key other than the trusted signing key" % token)
        elif sub == "tag" and token.startswith("--local-user="):
            if not same_key(token.split("=", 1)[1], trusted.key, trusted.fmt):
                problems.append("git tag --local-user signs with a key other than the trusted signing key")
    return problems


def tag_creates(rest: list) -> bool:
    readers = {"-l", "--list", "-d", "--delete", "-v", "--verify", "-n", "--contains", "--no-contains",
               "--points-at", "--merged", "--no-merged", "--column", "--sort", "--format"}
    if any(t in readers or t.split("=", 1)[0] in readers for t in rest):
        return False
    return any(not t.startswith("-") for t in rest)


def tag_signed(rest: list, location: list, env: Optional[dict]) -> bool:
    if any(t in ("-s", "--sign", "-u", "--local-user") or t.startswith("--local-user=") for t in rest):
        return True
    return read_identity(location, env).tag_sign


PUSH_VALUED = {"--repo", "-o", "--push-option", "--receive-pack", "--exec", "--signed", "--force-with-lease"}


def push_refs(rest: list) -> list:
    positional: list = []
    refs: list = []
    skip = False
    for token in rest:
        if skip:
            skip = False
            continue
        if token in PUSH_VALUED and token not in ("--signed", "--force-with-lease"):
            skip = True
            continue
        if token in ("-d", "--delete", "--prune"):
            return []
        if token in ("--all", "--branches"):
            refs.append("--branches")
            continue
        if token == "--mirror":
            refs.append("--all")
            continue
        if token in ("--tags",):
            refs.append("--tags")
            continue
        if token.startswith("-"):
            continue
        positional.append(token)
    for spec in positional[1:]:
        source = spec.lstrip("+").split(":", 1)[0]
        if not source:
            continue
        if "*" in source:
            refs.append("--branches")
            continue
        refs.append(source)
    if not refs and not positional[1:]:
        refs.append("HEAD")
    return refs


def outgoing_problems(location: list, refs: list, pol: Policy, env: Optional[dict] = None) -> list:
    if not pol.require_signed or not refs:
        return []
    proc = _run(location + ["log", "--format=" + LOG_FORMAT, "-n", str(pol.max_outgoing + 1)] + refs +
                ["--not", "--remotes", "--"], env)
    if proc is None:
        return ["could not list the commits this push would publish"]
    if proc.returncode != 0:
        stderr = _text(proc.stderr)
        if "does not have any commits" in stderr or "unknown revision" in stderr or "bad revision" in stderr:
            return []
        detail = stderr.splitlines()[:1] or ["unknown error"]
        return ["could not list the commits this push would publish: %s" % detail[0][:200]]
    rows = [line.split(FIELD) for line in _text(proc.stdout).splitlines() if line.strip()]
    if len(rows) > pol.max_outgoing:
        return ["this push would publish more than %d commits; the guard cannot verify that many" % pol.max_outgoing]
    trusted = pol.trusted
    expected_fpr = ssh_fingerprint(trusted.key) if trusted.fmt == "ssh" else ""
    problems: list = []
    for row in rows:
        row = (row + [""] * 8)[:8]
        sha, status, fpr, primary, keyid, signer, author, committer = row
        short = sha[:10]
        if status not in pol.accept:
            hint = ""
            if status in ("N", "E") and trusted.fmt == "ssh":
                hint = " (SSH signatures need gpg.ssh.allowedSignersFile to be verified)"
            problems.append("commit %s %s%s" % (short, STATUS_TEXT.get(status, "has signature status %s" % status),
                                                hint))
            continue
        if trusted.fmt == "ssh":
            if expected_fpr and fpr and fpr != expected_fpr:
                problems.append("commit %s is signed with SSH key %s, not the trusted key" % (short, fpr))
        else:
            wanted = normalise_key(trusted.key, trusted.fmt)
            candidates = [c.upper() for c in (fpr, primary, keyid) if c]
            matched = any(c.endswith(wanted) or wanted.endswith(c) for c in candidates) or \
                ("@" in trusted.key and trusted.key.lower() in signer.lower())
            if not matched:
                problems.append("commit %s is signed with key %s, not the trusted key" % (short, keyid or fpr))
        for role, email in (("author", author), ("committer", committer)):
            if email.lower() != trusted.email.lower():
                problems.append("commit %s has %s %s, not %s" % (short, role, email, trusted.email))
    return problems


def location_of(argv: list, rest_length: int, cwd: str) -> list:
    head = list(argv[1:len(argv) - rest_length - 1]) if rest_length < len(argv) else []
    location = ["-C", cwd]
    index = 0
    while index < len(head):
        token = head[index]
        if token in LOCATION_VALUED and index + 1 < len(head):
            location += [token, head[index + 1]]
            index += 2
            continue
        for option in LOCATION_VALUED[1:]:
            if token.startswith(option + "="):
                location.append(token)
        if token.startswith("-C") and len(token) > 2:
            location += ["-C", token[2:]]
        index += 1
    return location

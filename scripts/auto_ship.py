from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Optional

from hooks import ship_readiness
from hooks.lib import config as config_mod
from hooks.lib import contracts, costledger, git_signing, hashing, ledger, paths, redaction, state

EXIT_OK, EXIT_BLOCKED, EXIT_INTERNAL, EXIT_NOTHING = 0, 1, 2, 3
GIT_TIMEOUT_S = 120
KINDS = ("proof", "contract", "review")
REMOTE = re.compile(r"(?:^|[/:])([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$")
GITHUB_API = "https://api.github.com"
PII_RULES = tuple(name for name, _ in redaction.PII_RULES)


class ShipError(RuntimeError):
    pass


def schema_errors(instance, schema: dict, root: Optional[dict] = None, where: str = "$") -> list:
    root = root if root is not None else schema
    if "$ref" in schema:
        ref = schema["$ref"]
        node = root
        for part in ref.lstrip("#/").split("/"):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        return schema_errors(instance, node, root, where)
    errors: list = []
    if "const" in schema and instance != schema["const"]:
        errors.append("%s: expected %r" % (where, schema["const"]))
    if "enum" in schema and instance not in schema["enum"]:
        errors.append("%s: %r not in %r" % (where, instance, schema["enum"]))
    if "type" in schema:
        allowed = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(instance, t) for t in allowed):
            return errors + ["%s: expected %s" % (where, "/".join(allowed))]
    if "oneOf" in schema:
        matches = sum(1 for option in schema["oneOf"] if not schema_errors(instance, option, root, where))
        if matches != 1:
            errors.append("%s: matches %d of oneOf" % (where, matches))
    if isinstance(instance, str):
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append("%s: %r does not match %s" % (where, instance[:60], schema["pattern"]))
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append("%s: shorter than %d" % (where, schema["minLength"]))
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append("%s: longer than %d" % (where, schema["maxLength"]))
    if _is_type(instance, "number"):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append("%s: below %s" % (where, schema["minimum"]))
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append("%s: fewer than %d items" % (where, schema["minItems"]))
        if "items" in schema:
            for index, item in enumerate(instance):
                errors += schema_errors(item, schema["items"], root, "%s[%d]" % (where, index))
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append("%s: missing %s" % (where, key))
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if "propertyNames" in schema:
                errors += schema_errors(key, schema["propertyNames"], root, "%s.<key %s>" % (where, key))
            if key in properties:
                errors += schema_errors(value, properties[key], root, "%s.%s" % (where, key))
            elif schema.get("additionalProperties") is False:
                errors.append("%s: unexpected property %s" % (where, key))
            elif isinstance(schema.get("additionalProperties"), dict):
                errors += schema_errors(value, schema["additionalProperties"], root, "%s.%s" % (where, key))
    return errors


def _is_type(value, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "null":
        return value is None
    return False


def load_schema(kind: str) -> dict:
    return json.loads((paths.harness_root() / "schemas" / ("%s.schema.json" % kind)).read_text(encoding="utf-8"))


def git(workspace: str, args: list, env: Optional[dict] = None, check: bool = False) -> subprocess.CompletedProcess:
    proc = subprocess.run(["git", "-C", workspace] + args, check=False, capture_output=True, timeout=GIT_TIMEOUT_S,
                          env=env, stdin=subprocess.DEVNULL)
    if check and proc.returncode != 0:
        raise ShipError("git %s failed: %s" % (" ".join(args[:3]), redaction.redact_text(
            proc.stderr.decode("utf-8", "replace").strip()[-300:])))
    return proc


def _out(proc: subprocess.CompletedProcess) -> str:
    return proc.stdout.decode("utf-8", "replace")


def parse_remote(url: str) -> Optional[tuple]:
    text = (url or "").strip()
    if not text:
        return None
    match = REMOTE.search(text)
    if not match:
        return None
    return match.group(1), match.group(2)


def dirty_paths(workspace: str) -> list:
    proc = git(workspace, ["status", "--porcelain", "-z", "--untracked-files=all"])
    if proc.returncode != 0:
        raise ShipError("git status failed")
    entries = _out(proc).split("\0")
    found: list = []
    index = 0
    while index < len(entries):
        entry = entries[index]
        index += 1
        if len(entry) < 4:
            continue
        code, rel = entry[:2], entry[3:]
        names = [rel]
        if code[0] in "RC" and index < len(entries):
            names.append(entries[index])
            index += 1
        for name in names:
            posix = Path(name).as_posix().rstrip("/")
            if posix not in found:
                found.append(posix)
    return found


def model_display(model: Optional[str]) -> str:
    name = str(model or "").strip()
    if not name:
        return "Claude"
    if not name.startswith("claude-"):
        return name
    parts = name[len("claude-"):].split("-")
    words = [p for p in parts if not p.isdigit()]
    digits = [p for p in parts if p.isdigit() and len(p) < 8]
    return "Claude %s%s" % (" ".join(w.capitalize() for w in words), (" " + ".".join(digits)) if digits else "")


def _ignored(rel: str, cfg) -> bool:
    if rel == ".omega" or rel.startswith(".omega/"):
        return True
    parts = rel.split("/")
    for entry in cfg.get("workspace.ignored_dirs", []) or []:
        wanted = [p for p in str(entry).strip("/").split("/") if p]
        width = len(wanted)
        for start in range(0, len(parts) - width + 1):
            if width and parts[start:start + width] == wanted:
                return True
    return False


def added_lines(workspace: str, rel: str, tracked: bool, cached: bool = False) -> list:
    absolute = os.path.join(workspace, rel)
    if not tracked:
        try:
            text = Path(absolute).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return list(enumerate(text.splitlines(), 1))
    args = ["diff", "--no-color", "--no-ext-diff", "-U0"] + (["--cached"] if cached else ["HEAD"]) + ["--", rel]
    proc = git(workspace, args)
    lines: list = []
    number = 0
    for line in _out(proc).splitlines():
        hunk = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if hunk:
            number = int(hunk.group(1))
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            lines.append((number, line[1:]))
            number += 1
    return lines


def scan_added(workspace: str, files: list, tracked: set, cfg, cached: bool = False) -> tuple:
    secrets: list = []
    pii: list = []
    pii_globs = cfg.get("redaction.pii_fail_globs", []) or []
    for rel in files:
        lines = added_lines(workspace, rel, rel in tracked, cached)
        if not lines:
            continue
        numbers = [n for n, _ in lines]
        text = "\n".join(t for _, t in lines)
        for hit in redaction.strict_secret_hits(text):
            secrets.append("secret %s %s:%d" % (hit.rule, rel, numbers[min(len(numbers), hit.line or 1) - 1]))
        if paths.match_globs(rel, pii_globs) and not redaction.is_fixture(rel, cfg):
            for hit in redaction.scan(text, pii=True):
                if hit.rule in PII_RULES:
                    pii.append("pii %s %s:%d" % (hit.rule, rel, numbers[min(len(numbers), hit.line or 1) - 1]))
    return secrets, pii


def gitleaks_staged(workspace: str) -> Optional[list]:
    binary = shutil.which("gitleaks")
    if not binary:
        return None
    try:
        proc = subprocess.run([binary, "protect", "--staged", "--redact", "--no-banner", "--exit-code", "1"],
                              cwd=workspace, capture_output=True, timeout=GIT_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ["gitleaks could not run: %s" % exc.__class__.__name__]
    if proc.returncode == 0:
        return []
    text = redaction.redact_text((proc.stdout + proc.stderr).decode("utf-8", "replace"))
    return ["gitleaks: %s" % " | ".join(line.strip() for line in text.splitlines() if line.strip())[-300:]]


def _ledger_rel_paths(proof: dict, workspace: str) -> Optional[list]:
    session_id = proof.get("session_id")
    provider = proof.get("provider")
    if not session_id:
        return None
    directory = state.session_path(workspace, provider or "claude", session_id)
    if not directory.is_dir():
        return None
    ctx = state.load_context(session_id, workspace, provider)
    found: list = []
    for item in ledger.paths(ctx) + ledger.contracts_touched(ctx):
        relative = paths.rel(item, workspace)
        if not relative.startswith("/") and relative != "." and relative not in found:
            found.append(relative)
    return found


def check_clearances(workspace: str, cfg) -> tuple:
    blockers: list = []
    loaded: dict = {}
    directory = Path(workspace) / ".omega" / "clearances"
    for kind in KINDS:
        path = directory / ("%s.json" % kind)
        data = state.read_json(path, None)
        if not isinstance(data, dict):
            blockers.append("clearance missing: .omega/clearances/%s.json (let a Stop run to completion)" % kind)
            continue
        problems = schema_errors(data, load_schema(kind))
        if problems:
            blockers.append("clearance invalid: %s.json: %s" % (kind, "; ".join(problems[:3])))
            continue
        loaded[kind] = data
        if data.get("released"):
            blockers.append("clearance %s.json was released by the loop guard (NOT verified)" % kind)
        elif data.get("overridden"):
            blockers.append("clearance %s.json was released by a human override (NOT verified)" % kind)
        elif not data.get("verified"):
            blockers.append("clearance %s.json is not verified (fix the blocking gates and stop again)" % kind)
    if len(loaded) == len(KINDS):
        digests = {loaded[k]["files_digest"] for k in KINDS}
        if len(digests) != 1:
            blockers.append("clearances disagree: files_digest differs between proof, contract and review")
        ledger_rel = _ledger_rel_paths(loaded["proof"], workspace)
        if ledger_rel is None:
            blockers.append("clearance stale: cannot read the change ledger of session %s (state dir %s)" % (
                loaded["proof"].get("session_id"), paths.state_root()))
        else:
            ok, why = hashing.fresh(loaded["proof"], workspace, ledger_rel)
            if not ok:
                blockers.append("clearance stale: %s — stop again so the gates re-run" % why)
    return loaded, blockers


def contract_titles(workspace: str, cfg, entries: list) -> list:
    titles: list = []
    for entry in entries:
        path = os.path.join(workspace, entry.get("path", ""))
        try:
            parsed = contracts.load_file(path, workspace)
            titles.append((entry.get("slug"), parsed.title or entry.get("slug"), entry.get("seams") or {},
                           entry.get("path")))
        except Exception:
            titles.append((entry.get("slug"), entry.get("slug"), entry.get("seams") or {}, entry.get("path")))
    return titles


def pr_body(workspace: str, cfg, loaded: dict, ship_result: Optional[dict], last_stop: Optional[dict],
            titles: list) -> str:
    proof = loaded.get("proof") or {}
    cost = proof.get("cost") or {}
    lines = ["## Summary", ""]
    if titles:
        for slug, title, seams, _ in titles:
            counts = ", ".join("%s %s" % (seam, seams.get(seam, 0)) for seam in ("Unit", "Integration", "Functional",
                                                                                 "Journey"))
            lines.append("- %s (`%s`): %s" % (title, slug, counts))
    else:
        lines.append("- trivial change (no contract required)")
    lines += ["", "## Clearances", "", "files_digest `%s`" % str(proof.get("files_digest", ""))[:12], "",
              "| gate | status | detail |", "|---|---|---|"]
    for result in (last_stop or {}).get("results") or []:
        lines.append("| %s | %s | %s |" % (result.get("gate"), result.get("status"),
                                           str(result.get("detail", "")).replace("|", "/")[:160]))
    lines += ["", "## Ship readiness", "", "| tier | status |", "|---|---|"]
    for tier in ship_readiness.TIERS:
        status = ((ship_result or {}).get("tiers") or {}).get(tier, {}).get("status", "n/a")
        lines.append("| %s | %s |" % (tier, status))
    lines += ["", "## Cost", "", "session %s · month %s" % (_usd(cost.get("session_usd")), _usd(cost.get("month_usd")))]
    lines += ["", "## Contracts", ""]
    lines += ["- [%s](%s)" % (slug, path) for slug, _, _, path in titles] or ["- none"]
    lines += ["", str(cfg.get("ship.pr_footer", "Generated with Omega"))]
    return "\n".join(lines) + "\n"


def _usd(value) -> str:
    return "n/a" if value is None else "$%.2f" % float(value)


def plan(workspace: str, cfg=None, base: Optional[str] = None, slug: Optional[str] = None,
         title: Optional[str] = None, allow_unverified: bool = False, draft: Optional[bool] = None) -> dict:
    workspace = os.path.realpath(workspace)
    cfg = cfg if cfg is not None else config_mod.load(workspace=workspace)
    base = base or str(cfg.get("ship.base", "main"))
    draft = bool(cfg.get("ship.draft", True)) if draft is None else bool(draft)
    blockers: list = []
    result: dict = {"workspace": workspace, "base": base, "draft": draft, "blockers": blockers, "ok": False}
    inside = git(workspace, ["rev-parse", "--is-inside-work-tree"])
    if inside.returncode != 0 or _out(inside).strip() != "true":
        blockers.append("not a git work tree: %s (git init and add an origin remote)" % workspace)
        return result
    origin = _out(git(workspace, ["remote", "get-url", "origin"])).strip()
    owner_repo = parse_remote(origin)
    if not owner_repo:
        blockers.append("origin remote missing or not owner/repo: %r (git remote add origin <url>)" % origin)
    else:
        result["owner"], result["repo"] = owner_repo
    signing = git_signing.policy(cfg, workspace)
    result["signing"] = {"required": signing.require_signed, "email": signing.trusted.email,
                         "format": signing.trusted.fmt}
    for problem in git_signing.config_problems(["-C", workspace], signing):
        blockers.append("signing: %s" % problem)
    loaded, clearance_blockers = check_clearances(workspace, cfg)
    blockers.extend(clearance_blockers)
    contract_c = loaded.get("contract") or {}
    review_c = loaded.get("review") or {}
    proof_c = loaded.get("proof") or {}
    if contract_c.get("nontrivial"):
        approved = {(a.get("slug"), a.get("fingerprint")) for a in review_c.get("approvals") or []
                    if not a.get("superseded")}
        fingerprints = {a.get("fingerprint") for a in review_c.get("approvals") or [] if not a.get("superseded")}
        for entry in contract_c.get("contracts") or []:
            if (entry.get("slug"), entry.get("fingerprint")) not in approved and entry.get("fingerprint") not in fingerprints:
                blockers.append("contract %s has no current human approval (record it after the human agrees)"
                                % entry.get("slug"))
    if proof_c:
        if (proof_c.get("cost") or {}).get("status") != "PASS":
            blockers.append("cost gate was %s in proof.json" % (proof_c.get("cost") or {}).get("status"))
        verdict = costledger.check(cfg, session_id=proof_c.get("session_id"), run_id=proof_c.get("run_id"))
        if verdict.status != "PASS":
            blockers.append("tokentoll check now: %s %s" % (verdict.status, "; ".join(verdict.breaches + verdict.warnings)[:200]))
    ship_result = ship_readiness.run(workspace, cfg, mode="full", strict=not allow_unverified)
    result["ship"] = {"status": ship_result["status"], "summary": ship_readiness.summary(ship_result)}
    if ship_result["status"] != "PASS":
        failing = ["%s/%s %s" % (tier, c["id"], c["status"]) for tier in ship_readiness.TIERS
                   for c in ship_result["tiers"][tier]["checks"] if c["status"] in ("FAIL", "UNVERIFIED")]
        blockers.append("ship readiness %s: %s%s" % (ship_result["status"], ", ".join(failing[:6]),
                                                    "" if allow_unverified else " (--allow-unverified accepts UNVERIFIED)"))
    cleared = dict(proof_c.get("files") or {})
    dirty = dirty_paths(workspace)
    tracked = set(_out(git(workspace, ["ls-files", "-z"])).split("\0")) - {""}
    stage: list = []
    excluded = cfg.get("ship.exclude_globs", []) or []
    for rel in dirty:
        if rel in cleared:
            stage.append(rel)
        elif not _ignored(rel, cfg):
            blockers.append("uncleared change: %s is dirty but not covered by the clearances" % rel)
    for rel in stage:
        if paths.match_globs(rel, excluded):
            blockers.append("excluded path would be committed: %s (matches ship.exclude_globs)" % rel)
    max_files = int(cfg.get("ship.max_files", 200))
    if len(stage) > max_files:
        blockers.append("%d files to commit exceeds ship.max_files %d" % (len(stage), max_files))
    if not stage and not blockers:
        result["nothing_to_commit"] = True
    secrets, pii = scan_added(workspace, stage, tracked, cfg)
    blockers.extend(secrets)
    blockers.extend(pii)
    titles = contract_titles(workspace, cfg, contract_c.get("contracts") or [])
    slug = slug or (titles[0][0] if titles else None) or "change"
    slug = re.sub(r"[^a-z0-9-]+", "-", slug.lower()).strip("-") or "change"
    if not title:
        title = ("%s" % titles[0][1]) if titles and titles[0][1] else "omega: %s" % slug
    branch = "%s%s-%s" % (cfg.get("ship.branch_prefix", "omega/"), slug, time.strftime("%Y%m%d%H%M%S", time.gmtime()))
    protected = cfg.get("ship.protected_branches", []) or []
    if any(fnmatch.fnmatch(branch, pattern) for pattern in protected):
        blockers.append("branch %s matches a protected branch pattern" % branch)
    current = _out(git(workspace, ["rev-parse", "--abbrev-ref", "HEAD"])).strip()
    last_stop = None
    if proof_c.get("session_id"):
        directory = state.session_path(workspace, proof_c.get("provider") or "claude", proof_c["session_id"])
        last_stop = state.read_json(directory / "last_stop.json", None)
        context = state.read_json(directory / "context.json", {}) or {}
    else:
        context = {}
    trailers = [t.replace("{model_display}", model_display(context.get("model"))) for t in
                cfg.get("ship.commit_trailers", []) or []]
    body_lines = ["Contracts: %s" % (", ".join(t[0] for t in titles) if titles else "none"),
                  "clearances: %s" % str(proof_c.get("files_digest", ""))[:12]]
    commit_body = "\n".join(body_lines + ([""] + trailers if trailers else []))
    body = redaction.redact_text(pr_body(workspace, cfg, loaded, ship_result, last_stop, titles))
    if redaction.strict_secret_hits(body):
        blockers.append("PR body still contains a secret after redaction")
    result.update({"branch": branch, "current_branch": current, "files": stage, "title": title, "slug": slug,
                   "commit_body": commit_body, "pr_body": body,
                   "files_digest": proof_c.get("files_digest"), "session_id": proof_c.get("session_id"),
                   "commands": [["git", "fetch", "origin", base], ["git", "switch", "-c", branch, "origin/%s" % base],
                                ["git", "reset", "-q"], ["git", "add", "--"] + stage,
                                ["git", "commit", "-m", title, "-m", "<body>"], ["git", "push", "-u", "origin", branch],
                                ["gh", "pr", "create", "--base", base, "--head", branch, "--title", title,
                                 "--body-file", "<tmp>"] + (["--draft"] if draft else [])]})
    result["ok"] = not blockers
    return result


def git_env() -> dict:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    askpass = paths.harness_root() / "bin" / "git-askpass.sh"
    if env.get("OMEGA_GIT_TOKEN") and askpass.is_file():
        env["GIT_ASKPASS"] = str(askpass)
    return env


def create_pr_rest(owner: str, repo: str, base: str, branch: str, title: str, body: str, draft: bool) -> dict:
    token = os.environ.get("OMEGA_GIT_TOKEN")
    if not token:
        return {"ok": False, "error": "no gh CLI and no OMEGA_GIT_TOKEN: the branch is pushed but no PR was opened"}
    api = os.environ.get("OMEGA_GITHUB_API", GITHUB_API).rstrip("/")
    payload = json.dumps({"title": title, "head": branch, "base": base, "body": body, "draft": bool(draft)}).encode()
    request = urllib.request.Request("%s/repos/%s/%s/pulls" % (api, owner, repo), data=payload, method="POST",
                                     headers={"Authorization": "Bearer %s" % token,
                                              "Accept": "application/vnd.github+json",
                                              "X-GitHub-Api-Version": "2022-11-28",
                                              "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8") or "{}")
            return {"ok": True, "pr_url": data.get("html_url"), "pr_number": data.get("number"), "via": "rest"}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        return {"ok": False, "error": "REST %d: %s" % (exc.code, redaction.redact_text(detail)), "via": "rest"}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"ok": False, "error": "REST request failed: %s" % exc.__class__.__name__, "via": "rest"}


def create_pr(workspace: str, plan_result: dict, env: dict) -> dict:
    title = plan_result["title"]
    body = plan_result["pr_body"]
    base = plan_result["base"]
    branch = plan_result["branch"]
    gh = shutil.which("gh", path=env.get("PATH"))
    if gh:
        handle, body_file = tempfile.mkstemp(prefix="omega-pr-", suffix=".md")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(body)
            argv = [gh, "pr", "create", "--base", base, "--head", branch, "--title", title, "--body-file", body_file]
            if plan_result.get("draft"):
                argv.append("--draft")
            try:
                proc = subprocess.run(argv, cwd=workspace, capture_output=True, timeout=GIT_TIMEOUT_S, env=env,
                                      stdin=subprocess.DEVNULL)
            except (OSError, subprocess.TimeoutExpired) as exc:
                proc = None
                gh_error = exc.__class__.__name__
            if proc is not None and proc.returncode == 0:
                url = _out(proc).strip().splitlines()[-1] if _out(proc).strip() else ""
                number = re.search(r"/pull/(\d+)", url)
                return {"ok": True, "pr_url": url, "pr_number": int(number.group(1)) if number else None, "via": "gh"}
            if proc is not None:
                gh_error = redaction.redact_text(proc.stderr.decode("utf-8", "replace").strip()[-300:])
        finally:
            try:
                os.unlink(body_file)
            except OSError:
                pass
        fallback = create_pr_rest(plan_result.get("owner"), plan_result.get("repo"), base, branch, title, body,
                                  plan_result.get("draft"))
        fallback["gh_error"] = gh_error
        return fallback
    return create_pr_rest(plan_result.get("owner"), plan_result.get("repo"), base, branch, title, body,
                          plan_result.get("draft"))


def ship(workspace: str, cfg=None, base: Optional[str] = None, slug: Optional[str] = None,
         title: Optional[str] = None, allow_unverified: bool = False, draft: Optional[bool] = None) -> tuple:
    workspace = os.path.realpath(workspace)
    cfg = cfg if cfg is not None else config_mod.load(workspace=workspace)
    planned = plan(workspace, cfg, base, slug, title, allow_unverified, draft)
    if not planned["ok"]:
        return EXIT_BLOCKED, planned
    if planned.get("nothing_to_commit"):
        planned["result"] = "nothing to commit"
        return EXIT_NOTHING, planned
    env = git_env()
    base = planned["base"]
    branch = planned["branch"]
    fetched = git(workspace, ["fetch", "origin", base], env)
    if fetched.returncode != 0:
        planned["blockers"].append("git fetch origin %s failed: %s" % (base, redaction.redact_text(
            fetched.stderr.decode("utf-8", "replace").strip()[-200:])))
        return EXIT_BLOCKED, planned
    switched = git(workspace, ["switch", "-c", branch, "origin/%s" % base], env)
    if switched.returncode != 0:
        planned["blockers"].append("git switch -c %s origin/%s failed: %s" % (branch, base, redaction.redact_text(
            switched.stderr.decode("utf-8", "replace").strip()[-200:])))
        return EXIT_BLOCKED, planned
    git(workspace, ["reset", "-q"], env, check=True)
    git(workspace, ["add", "--"] + planned["files"], env, check=True)
    if git(workspace, ["diff", "--cached", "--quiet"], env).returncode == 0:
        planned["result"] = "nothing to commit"
        return EXIT_NOTHING, planned
    tracked_head = set(_out(git(workspace, ["ls-tree", "-r", "--name-only", "-z", "HEAD"])).split("\0")) - {""}
    staged_secrets, staged_pii = scan_added(workspace, planned["files"], tracked_head | set(planned["files"]), cfg,
                                            cached=True)
    leaks = gitleaks_staged(workspace) or []
    if staged_secrets or staged_pii or leaks:
        git(workspace, ["reset", "-q"], env)
        planned["blockers"].extend(staged_secrets + staged_pii + leaks)
        return EXIT_BLOCKED, planned
    committed = git(workspace, ["commit", "-m", planned["title"], "-m", planned["commit_body"]], env)
    if committed.returncode != 0:
        planned["blockers"].append("git commit failed: %s" % redaction.redact_text(
            (committed.stderr + committed.stdout).decode("utf-8", "replace").strip()[-200:]))
        return EXIT_BLOCKED, planned
    commit = _out(git(workspace, ["rev-parse", "HEAD"], env)).strip()
    signing = git_signing.policy(cfg, workspace, env)
    unsigned = git_signing.outgoing_problems(["-C", workspace], ["HEAD"], signing, env)
    if unsigned:
        planned["blockers"].extend("signing: %s" % problem for problem in unsigned)
        planned["commit"] = commit
        return EXIT_BLOCKED, planned
    pushed = git(workspace, ["push", "-u", "origin", branch], env)
    if pushed.returncode != 0:
        planned["blockers"].append("git push failed: %s" % redaction.redact_text(
            pushed.stderr.decode("utf-8", "replace").strip()[-200:]))
        planned["commit"] = commit
        return EXIT_INTERNAL, planned
    pr = create_pr(workspace, planned, env)
    record = {"branch": branch, "commit": commit, "pr_url": pr.get("pr_url"), "pr_number": pr.get("pr_number"),
              "files": planned["files"], "files_digest": planned.get("files_digest"), "pr": pr}
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    state.write_json_atomic(Path(workspace) / ".omega" / "ship" / ("%s.json" % stamp), record)
    planned.update(record)
    if not pr.get("ok"):
        planned["result"] = "pushed %s but the PR was not created: %s" % (branch, pr.get("error"))
        return EXIT_BLOCKED, planned
    planned["result"] = "opened %s" % pr.get("pr_url")
    return EXIT_OK, planned


def _print(result: dict, as_json: bool, dry_run: bool) -> None:
    if as_json:
        sys.stdout.write(json.dumps(result, ensure_ascii=False, default=str) + "\n")
    stream = sys.stderr if as_json else sys.stdout
    for blocker in result.get("blockers") or []:
        stream.write("BLOCKER: %s\n" % blocker)
    if result.get("blockers"):
        return
    if dry_run:
        stream.write("[auto-ship] dry run: would commit %d file(s) on %s and open a %sPR against %s\n" % (
            len(result.get("files") or []), result.get("branch"), "draft " if result.get("draft") else "",
            result.get("base")))
        for rel in result.get("files") or []:
            stream.write("  %s\n" % rel)
        stream.write("[auto-ship] a human runs it for real with --yes\n")
    elif result.get("result"):
        stream.write("[auto-ship] %s\n" % result["result"])


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="auto_ship.py", description="The only git writer: branch, commit, push, PR.")
    parser.add_argument("--workspace")
    parser.add_argument("--base")
    parser.add_argument("--slug")
    parser.add_argument("--title")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--no-draft", action="store_true")
    parser.add_argument("--allow-unverified", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    workspace = os.path.realpath(args.workspace or os.environ.get("OMEGA_WORKSPACE") or os.getcwd())
    draft = False if args.no_draft else None
    dry_run = args.dry_run or not args.yes
    try:
        cfg = config_mod.load(workspace=workspace)
        if dry_run:
            result = plan(workspace, cfg, args.base, args.slug, args.title, args.allow_unverified, draft)
            _print(result, args.json, True)
            if result["blockers"]:
                return EXIT_BLOCKED
            return EXIT_NOTHING if result.get("nothing_to_commit") else EXIT_OK
        code, result = ship(workspace, cfg, args.base, args.slug, args.title, args.allow_unverified, draft)
        _print(result, args.json, False)
        return code
    except (ShipError, subprocess.TimeoutExpired, OSError) as exc:
        sys.stderr.write("[auto-ship] internal error: %s: %s\n" % (exc.__class__.__name__, str(exc)[:200]))
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

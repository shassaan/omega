from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import ast
import configparser
import dataclasses
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Callable, Optional

from hooks.lib import config as config_mod
from hooks.lib import costledger, jobstore, paths, redaction, state, testmap

PASS, FAIL, UNVERIFIED, NOT_APPLICABLE = "PASS", "FAIL", "UNVERIFIED", "NOT_APPLICABLE"
TIERS = ("infra", "database", "application", "analytics", "observability")
SCHEMA = "omega/ship/1"
FAST_TIMEOUT_S = 30
FULL_TIMEOUT_S = 120
MAX_FILES = 20000
MAX_DETECTED = 50
DETAIL_CHARS = 300
CHILD_ENV_DROP = ("OMEGA_SECRET", "OMEGA_UI_TOKEN", "OMEGA_GIT_TOKEN")
HINTS = {
    "terraform": "brew install terraform",
    "hadolint": "brew install hadolint",
    "docker": "install the docker CLI (Docker Desktop or colima)",
    "tflint": "brew install tflint",
    "checkov": "pip install checkov",
    "squawk": "npm install -g squawk-cli",
    "alembic": "pip install alembic into the workspace .venv",
    "ruff": "pip install ruff",
    "npx": "install Node.js 22 (npx ships with npm)",
    "pip-audit": "pip install pip-audit",
    "npm": "install Node.js 22",
    "gitleaks": "brew install gitleaks",
    "dbt": "pip install dbt-core dbt-duckdb",
    "sqlfluff": "pip install sqlfluff",
    "atlas": "curl -sSf https://atlasgo.sh | sh",
    "mutmut": "pip install mutmut==3.3.1 into the workspace .venv",
    "pytest": "pip install pytest into the workspace .venv",
    "prisma": "npm install --save-dev prisma",
}
NETWORK_SIGNATURES = ("getaddrinfo", "ENOTFOUND", "Could not resolve host", "Network is unreachable",
                      "network is unreachable", "Failed to query available provider packages",
                      "Failed to install provider", "no such host", "dial tcp", "ConnectionError",
                      "Name or service not known", "nodename nor servname provided", "EAI_AGAIN")
MIGRATION_RULES = [
    ("drop-column", re.compile(r"\bDROP\s+COLUMN\b|op\.drop_column\(", re.I), "high"),
    ("drop-table", re.compile(r"\bDROP\s+TABLE\b|op\.drop_table\(", re.I), "high"),
    ("truncate", re.compile(r"\bTRUNCATE\b", re.I), "high"),
    ("not-null-no-default", re.compile(r"ADD\s+COLUMN\s+\w+\s+[\w()]+\s+NOT\s+NULL(?!.*\bDEFAULT\b)", re.I), "high"),
    ("alter-not-null", re.compile(r"ALTER\s+COLUMN\s+\w+\s+SET\s+NOT\s+NULL|nullable=False", re.I), "medium"),
    ("rename-column", re.compile(r"RENAME\s+COLUMN|op\.alter_column\([^)]*new_column_name", re.I), "high"),
    ("rename-table", re.compile(r"RENAME\s+TO|op\.rename_table\(", re.I), "high"),
    ("alter-type", re.compile(r"ALTER\s+COLUMN\s+\w+\s+(SET\s+DATA\s+)?TYPE", re.I), "medium"),
    ("index-nonconcurrent", re.compile(r"CREATE\s+(UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY)", re.I), "medium"),
]
DBT_NON_MIGRATION_DIRS = ("models", "macros", "seeds", "snapshots", "analyses", "analysis", "tests", "target",
                          "dbt_packages")
MIGRATION_SEGMENTS = ("migrations", "migrate", "versions")
LLM_CALL = re.compile(r"messages\.create\(|chat\.completions\.create\(|responses\.create\(|generate_content\(|"
                      r"generateContent\(")
LLM_ATTRS = ("create", "generate_content", "generateContent")
TRACING_DEPS = re.compile(r"(?im)^\s*[\"']?(braintrust|langsmith|langchain)\b|[\"'](braintrust|langsmith|langchain)[\"']\s*:")
TRACING_INIT = re.compile(r"init_logger\(|initLogger\(|@traceable|\btraceable\(|wrap_openai|wrap_anthropic|wrapOpenAI|"
                          r"wrapAnthropic|wrapSDK\(|@traced|@braintrust\.traced")
FILE_WRAPPERS = re.compile(r"wrap_openai\(|wrap_anthropic\(|wrapOpenAI\(|wrapAnthropic\(|wrapSDK\(|wrapAISDK")
EXTRA_KEY_LITERALS = [("langsmith-key", re.compile(r"\blsv2_(?:pt|sk)_[A-Za-z0-9]{20,}")),
                      ("braintrust-key", re.compile(r"\bsk-bt-[A-Za-z0-9]{20,}"))]
ENV_REFERENCE = re.compile(r"os\.environ\[\s*[\"']([A-Z][A-Z0-9_]*)[\"']\s*\]|os\.environ\.get\(\s*[\"']([A-Z][A-Z0-9_]*)[\"']|"
                           r"os\.getenv\(\s*[\"']([A-Z][A-Z0-9_]*)[\"']|process\.env\.([A-Z][A-Z0-9_]*)|"
                           r"process\.env\[\s*[\"']([A-Z][A-Z0-9_]*)[\"']\s*\]")
ENV_ANY = re.compile(r"os\.environ\[|os\.environ\.get\(|os\.getenv\(|process\.env\.|process\.env\[")
ROUTE_PY = re.compile(r"@(?:app|router|api|bp|blueprint)\.(?:get|post|put|patch|delete|route|api_route)\(|\bAPIRouter\(")
ROUTE_JS = re.compile(r"\b(?:app|router)\.(?:get|post|put|patch|delete|all|use)\(\s*[\"'`/]")
EXPRESS_IMPORT = re.compile(r"require\(\s*[\"']express[\"']\s*\)|from\s+[\"']express[\"']")
CODE_EXTS = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
LIVE_KEYS = (("BRAINTRUST_API_KEY", "https://api.braintrust.dev/v1/project", "Authorization", "Bearer "),
             ("LANGSMITH_API_KEY", "https://api.smith.langchain.com/api/v1/sessions?limit=1", "x-api-key", ""))
MUTMUT_LINE = re.compile(r"^\s*(\S+?):\s*(killed|survived|timeout|suspicious|no tests|skipped|not checked|segfault|"
                         r"check was interrupted by user|caught by type check)\s*$")
MUTMUT_SCORED = ("killed", "survived", "timeout", "suspicious")
STRYKER_DETECTED = ("Killed", "Timeout")
STRYKER_UNDETECTED = ("Survived", "NoCoverage")


@dataclass
class Check:
    id: str
    status: str
    argv: list
    rc: Optional[int]
    duration_ms: int
    detail: str
    hint: str
    required: bool

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass
class Tier:
    name: str
    status: str
    applicable: bool
    detected: list
    checks: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"status": self.status, "applicable": self.applicable, "detected": list(self.detected),
                "checks": [c.as_dict() if isinstance(c, Check) else c for c in self.checks]}


@dataclass
class Run:
    workspace: str
    cfg: object
    mode: str
    timeout_s: int
    files: list
    base_ref: Optional[str] = None
    env: dict = field(default_factory=dict)


def one_line(text: str, limit: int = DETAIL_CHARS) -> str:
    return redaction.redact_text(" ".join(str(text or "").split())[:limit])


def last_lines(text: str, count: int = 3) -> str:
    kept = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return " | ".join(kept[-count:])


def make_check(cid: str, status: str, detail: str = "", argv: Optional[list] = None, rc: Optional[int] = None,
               started: Optional[float] = None, hint: str = "", required: bool = True) -> Check:
    duration = int((time.monotonic() - started) * 1000) if started is not None else 0
    return Check(id=cid, status=status, argv=[str(a) for a in (argv or [])], rc=rc, duration_ms=max(0, duration),
                 detail=one_line(detail), hint=hint, required=required)


def child_env(extra: Optional[dict] = None) -> dict:
    env = dict(os.environ)
    for name in CHILD_ENV_DROP:
        env.pop(name, None)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    env["CI"] = "1"
    env.update(extra or {})
    return env


def _ignored(rel: str, ignored: list) -> bool:
    parts = rel.split("/")
    for entry in ignored:
        wanted = [p for p in str(entry).strip("/").split("/") if p]
        width = len(wanted)
        if not width:
            continue
        for start in range(0, len(parts) - width + 1):
            if parts[start:start + width] == wanted:
                return True
    return False


def list_files(workspace: str, cfg) -> list:
    ignored = list(cfg.get("workspace.ignored_dirs", []) or []) + [".omega", ".git"]
    found: list = []
    root = os.path.realpath(workspace)
    if not os.path.isdir(root):
        return found
    for directory, dirs, files in os.walk(root):
        rel_dir = os.path.relpath(directory, root)
        rel_dir = "" if rel_dir == "." else Path(rel_dir).as_posix()
        dirs[:] = sorted(d for d in dirs if not _ignored((rel_dir + "/" + d).lstrip("/"), ignored))
        for name in sorted(files):
            found.append((rel_dir + "/" + name).lstrip("/"))
            if len(found) >= MAX_FILES:
                return found
    return found


def detect(workspace: str, cfg, files: Optional[list] = None) -> dict:
    files = files if files is not None else list_files(workspace, cfg)
    tiers_cfg = cfg.get("ship_readiness.tiers", {}) or {}
    out: dict = {}
    for tier in TIERS:
        globs = (tiers_cfg.get(tier) or {}).get("detect", []) or []
        matched = [f for f in files if paths.match_globs(f, globs)]
        out[tier] = matched[:MAX_DETECTED]
    return out


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _which(exe: str, env: dict) -> Optional[str]:
    if os.path.isabs(exe):
        return exe if os.access(exe, os.X_OK) else None
    return shutil.which(exe, path=env.get("PATH", os.defpath))


def tool_check(run: Run, cid: str, argv: list, required: bool = True, hint: Optional[str] = None,
               interpret: Optional[Callable] = None, needs_node: bool = False, env_extra: Optional[dict] = None,
               cwd: Optional[str] = None, network: bool = False, timeout_s: Optional[int] = None) -> Check:
    started = time.monotonic()
    env = child_env(dict(run.env, **(env_extra or {})))
    exe = str(argv[0])
    tool = os.path.basename(exe)
    if len(argv) > 2 and argv[1] == "-m":
        tool = str(argv[2])
    hint = hint if hint is not None else HINTS.get(tool, HINTS.get(os.path.basename(exe), ""))
    if _which(exe, env) is None:
        return make_check(cid, UNVERIFIED, "%s not installed" % exe, argv, None, started, hint, required)
    workdir = cwd or run.workspace
    if needs_node and not os.path.isdir(os.path.join(workdir, "node_modules")):
        return make_check(cid, UNVERIFIED, "node_modules missing (run npm ci)", argv, None, started,
                          "npm ci", required)
    limit = timeout_s or run.timeout_s
    try:
        proc = subprocess.run([str(a) for a in argv], cwd=workdir, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=limit, env=env)
    except FileNotFoundError:
        return make_check(cid, UNVERIFIED, "%s not installed" % exe, argv, None, started, hint, required)
    except subprocess.TimeoutExpired:
        return make_check(cid, UNVERIFIED, "timed out after %ds" % limit, argv, None, started, hint, required)
    except OSError as exc:
        return make_check(cid, UNVERIFIED, "cannot run: %s" % exc.__class__.__name__, argv, None, started, hint,
                          required)
    output = proc.stdout.decode("utf-8", "replace") if isinstance(proc.stdout, bytes) else (proc.stdout or "")
    if proc.returncode != 0 and re.search(r"No module named ['\"]?%s\b" % re.escape(tool), output):
        return make_check(cid, UNVERIFIED, "%s not installed for %s" % (tool, exe), argv, proc.returncode, started,
                          hint, required)
    if interpret is not None:
        status, detail = interpret(proc.returncode, output)
    elif proc.returncode == 0:
        status, detail = PASS, last_lines(output, 1) or "exit 0"
    else:
        status, detail = FAIL, "exit %d — %s" % (proc.returncode, last_lines(output))
    if status == FAIL and network and (any(s in output for s in NETWORK_SIGNATURES)
                                       or jobstore.is_environment_failure(output, run.cfg, workdir)):
        status, detail = UNVERIFIED, "network unavailable: %s" % last_lines(output, 1)
    return make_check(cid, status, detail, argv, proc.returncode, started, hint, required)


def _python(run: Run) -> str:
    return testmap.workspace_python(run.workspace)


def _exists(run: Run, rel: str) -> bool:
    return os.path.exists(os.path.join(run.workspace, rel))


def _has(run: Run, predicate: Callable) -> list:
    return [f for f in run.files if predicate(f)]


def dockerfile_rules(run: Run, rel: str) -> Check:
    started = time.monotonic()
    text = _read(os.path.join(run.workspace, rel))
    problems: list = []
    stages: set = set()
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        match = re.match(r"(?i)^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", stripped)
        if match:
            image = match.group(1)
            if match.group(2):
                stages.add(match.group(2).lower())
            if image.lower() not in stages and "@" not in image and re.search(r":latest$", image, re.I):
                problems.append("%s:%d uses the latest tag (%s)" % (rel, number, image))
        if re.match(r"(?i)^ADD\s+(?:--\S+\s+)*https?://", stripped):
            problems.append("%s:%d ADD fetches a URL (use curl with a checksum)" % (rel, number))
    if problems:
        return make_check("dockerfile_rules:%s" % rel, FAIL, "; ".join(problems), [], None, started)
    return make_check("dockerfile_rules:%s" % rel, PASS, "no latest tag, no ADD http", [], None, started)


def _tf_fmt(rc: int, output: str) -> tuple:
    if rc == 0:
        return PASS, "formatted"
    if rc == 3:
        return FAIL, "unformatted files: %s" % last_lines(output)
    return FAIL, "exit %d — %s" % (rc, last_lines(output))


def _hadolint(rc: int, output: str) -> tuple:
    try:
        findings = json.loads(output or "[]")
    except ValueError:
        findings = None
    if rc == 0:
        return PASS, "no findings"
    if isinstance(findings, list):
        codes = sorted({str(f.get("code")) for f in findings if isinstance(f, dict)})
        return FAIL, "%d finding(s): %s" % (len(findings), ", ".join(codes[:8]))
    return FAIL, "exit %d — %s" % (rc, last_lines(output))


def infra_checks(run: Run, detected: list) -> list:
    jobs: list = []
    tf = [f for f in detected if f.endswith(".tf")]
    dockerfiles = [f for f in run.files if os.path.basename(f) == "Dockerfile" or os.path.basename(f).startswith("Dockerfile.")]
    compose = [f for f in detected if os.path.basename(f) in ("docker-compose.yml", "docker-compose.yaml",
                                                               "compose.yml", "compose.yaml")]
    if tf:
        jobs.append(lambda: tool_check(run, "terraform_fmt", ["terraform", "fmt", "-check", "-recursive"],
                                       interpret=_tf_fmt))
    for rel in dockerfiles[:10]:
        jobs.append(lambda rel=rel: tool_check(run, "hadolint:%s" % rel, ["hadolint", "--format", "json", rel],
                                               interpret=_hadolint))
        jobs.append(lambda rel=rel: dockerfile_rules(run, rel))
    for rel in compose[:5]:
        argv = ["docker", "compose", "-f", rel, "config", "-q"]
        if _exists(run, ".env.example"):
            argv += ["--env-file", ".env.example"]
        jobs.append(lambda argv=argv, rel=rel: tool_check(run, "compose_config:%s" % rel, argv))
    if run.mode == "full":
        if tf:
            jobs.append(lambda: terraform_validate(run))
            jobs.append(lambda: tool_check(run, "tflint", ["tflint", "--recursive"]))
        if tf or dockerfiles:
            jobs.append(lambda: tool_check(run, "checkov", ["checkov", "-d", ".", "--framework",
                                                            "terraform,dockerfile,github_actions", "--quiet",
                                                            "--compact", "-o", "json"]))
    return jobs


def terraform_validate(run: Run) -> Check:
    started = time.monotonic()
    init = tool_check(run, "terraform_validate", ["terraform", "init", "-backend=false", "-input=false", "-no-color"],
                      network=True)
    if init.status != PASS:
        if init.status == UNVERIFIED and "not installed" not in init.detail:
            init.detail = one_line("providers unavailable: " + init.detail)
        return init
    validate = tool_check(run, "terraform_validate", ["terraform", "validate", "-no-color"])
    validate.duration_ms = int((time.monotonic() - started) * 1000)
    return validate


def is_migration_file(rel: str) -> bool:
    if not rel.endswith((".sql", ".py")):
        return False
    parts = rel.split("/")
    if os.path.basename(rel) in ("__init__.py", "env.py"):
        return False
    if rel.endswith(".py"):
        return any(p in MIGRATION_SEGMENTS for p in parts[:-1]) or parts[0] == "alembic"
    if any(p in MIGRATION_SEGMENTS for p in parts[:-1]) or parts[0] in ("alembic", "prisma"):
        return True
    return not any(p in DBT_NON_MIGRATION_DIRS for p in parts[:-1])


def _strip_comments(line: str, python: bool, in_block: bool) -> tuple:
    if python:
        return line.split("#", 1)[0], False
    out = ""
    index = 0
    while index < len(line):
        if in_block:
            end = line.find("*/", index)
            if end == -1:
                return out, True
            index = end + 2
            in_block = False
            continue
        start_block = line.find("/*", index)
        start_dash = line.find("--", index)
        candidates = [p for p in (start_block, start_dash) if p != -1]
        if not candidates:
            out += line[index:]
            break
        first = min(candidates)
        out += line[index:first]
        if first == start_dash:
            break
        in_block = True
        index = first + 2
    return out, in_block


def _git(workspace: str, args: list, timeout: int = 60) -> Optional[str]:
    try:
        proc = subprocess.run(["git", "-C", workspace] + args, capture_output=True, timeout=timeout,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace")


def is_git(workspace: str) -> bool:
    out = _git(workspace, ["rev-parse", "--is-inside-work-tree"])
    return bool(out and out.strip() == "true")


def _diff_added(workspace: str, base_ref: str, rel: str) -> Optional[list]:
    out = _git(workspace, ["diff", "--no-color", "--no-ext-diff", "-U0", base_ref, "--", rel])
    if out is None:
        return None
    added: list = []
    number = 0
    for line in out.splitlines():
        hunk = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if hunk:
            number = int(hunk.group(1))
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append((number, line[1:]))
            number += 1
    return added


def migration_rules(workspace: str, base_ref: Optional[str], cfg, files: Optional[list] = None) -> Check:
    started = time.monotonic()
    cfg = cfg if cfg is not None else config_mod.load(workspace=workspace)
    files = files if files is not None else list_files(workspace, cfg)
    candidates = [f for f in files if is_migration_file(f)]
    if not candidates:
        return make_check("migration_rules", NOT_APPLICABLE, "no migration files", [], None, started)
    waiver = re.compile(r"%s\s*\(\s*[^)\s][^)]*\)" % re.escape(cfg.get("ship_readiness.migration_waiver_comment",
                                                                         "omega:allow destructive")), re.I)
    scoped: dict = {}
    if base_ref:
        if _git(workspace, ["rev-parse", "--verify", "--quiet", base_ref + "^{commit}"]) is None:
            return make_check("migration_rules", UNVERIFIED, "base ref %s not found" % base_ref, [], None, started,
                              "git fetch origin")
        untracked = set((_git(workspace, ["ls-files", "--others", "--exclude-standard"]) or "").splitlines())
        for rel in candidates:
            if rel in untracked:
                scoped[rel] = list(enumerate(_read(os.path.join(workspace, rel)).splitlines(), 1))
                continue
            added = _diff_added(workspace, base_ref, rel)
            if added:
                scoped[rel] = added
    else:
        for rel in candidates:
            scoped[rel] = list(enumerate(_read(os.path.join(workspace, rel)).splitlines(), 1))
    high: list = []
    medium: list = []
    waived: list = []
    for rel, lines in sorted(scoped.items()):
        python = rel.endswith(".py")
        in_block = False
        file_waived = bool(waiver.search(_read(os.path.join(workspace, rel))))
        for number, line in lines:
            code, in_block = _strip_comments(line, python, in_block)
            if not code.strip():
                continue
            for rule_id, pattern, severity in MIGRATION_RULES:
                if pattern.search(code):
                    where = "%s %s:%d" % (rule_id, rel, number)
                    if severity == "high":
                        (waived if file_waived else high).append(where)
                    else:
                        medium.append(where)
    parts = ["%d file(s), %d high, %d medium" % (len(scoped), len(high), len(medium))]
    if high:
        parts.append("(%s)" % ", ".join(high[:6]))
    if medium:
        parts.append("medium: %s" % ", ".join(medium[:4]))
    if waived:
        parts.append("waived: %s" % ", ".join(waived[:4]))
    if not scoped:
        return make_check("migration_rules", PASS, "no migration lines changed since %s" % base_ref, [], None, started)
    status = FAIL if high else PASS
    hint = "" if not high else ("make the change expand/contract, or add '-- %s (<reason>)' to the migration"
                                % cfg.get("ship_readiness.migration_waiver_comment", "omega:allow destructive"))
    return make_check("migration_rules", status, " ".join(parts), [], None, started, hint)


def _alembic_heads(rc: int, output: str) -> tuple:
    if rc != 0:
        return FAIL, "alembic heads failed (exit %d) — %s" % (rc, last_lines(output))
    heads = [line for line in output.splitlines() if "(head)" in line]
    if len(heads) == 1:
        return PASS, "one head: %s" % heads[0].strip()
    return FAIL, "%d heads (expected exactly 1): %s" % (len(heads), last_lines(output))


def database_checks(run: Run, detected: list) -> list:
    jobs: list = [lambda: migration_rules(run.workspace, run.base_ref, run.cfg, run.files)]
    alembic = _exists(run, "alembic.ini")
    if alembic:
        jobs.append(lambda: tool_check(run, "alembic_heads", [_python(run), "-m", "alembic", "heads"],
                                       interpret=_alembic_heads, hint=HINTS["alembic"]))
    if run.mode == "full":
        sql = [f for f in run.files if f.endswith(".sql") and is_migration_file(f)]
        if sql:
            jobs.append(lambda: tool_check(run, "squawk", ["squawk", "--reporter", "json"] + sql[:200]))
        if _exists(run, "prisma/schema.prisma"):
            dummy = {"DATABASE_URL": "postgresql://x:x@localhost/x"}
            jobs.append(lambda: tool_check(run, "prisma_validate", ["npx", "prisma", "validate"], needs_node=True,
                                           env_extra=dummy, hint=HINTS["prisma"]))
            jobs.append(lambda: tool_check(run, "prisma_format", ["npx", "prisma", "format", "--check"],
                                           needs_node=True, env_extra=dummy, hint=HINTS["prisma"]))
        if alembic:
            jobs.append(lambda: tool_check(run, "alembic_sql", [_python(run), "-m", "alembic", "upgrade", "head",
                                                                "--sql"], hint=HINTS["alembic"]))
        if _exists(run, "migrations/atlas.sum"):
            jobs.append(lambda: tool_check(run, "atlas_validate", ["atlas", "migrate", "validate", "--dir",
                                                                   "file://migrations"]))
    return jobs


def _code_files(run: Run) -> list:
    return [f for f in run.files if f.endswith(CODE_EXTS)]


def _non_test_code(run: Run) -> list:
    return [f for f in _code_files(run) if not testmap.is_test(f, run.cfg)]


def env_example_check(run: Run) -> Check:
    started = time.monotonic()
    users = [f for f in _non_test_code(run) if ENV_ANY.search(_read(os.path.join(run.workspace, f)))]
    if not users:
        return make_check("env_example", NOT_APPLICABLE, "no environment variable references", [], None, started)
    if _exists(run, ".env.example"):
        return make_check("env_example", PASS, ".env.example present (%d file(s) read the environment)" % len(users),
                          [], None, started)
    return make_check("env_example", FAIL, ".env.example missing but %s read the environment" % ", ".join(users[:5]),
                      [], None, started, "add .env.example listing every variable name (no real values)")


def route_tests_check(run: Run) -> Check:
    started = time.monotonic()
    routes: list = []
    for rel in _non_test_code(run):
        text = _read(os.path.join(run.workspace, rel))
        if rel.endswith(".py") and ROUTE_PY.search(text):
            routes.append(rel)
        elif not rel.endswith(".py") and ROUTE_JS.search(text) and EXPRESS_IMPORT.search(text):
            routes.append(rel)
    if not routes:
        return make_check("route_tests", NOT_APPLICABLE, "no FastAPI/Express route files", [], None, started)
    ctx = SimpleNamespace(workspace=run.workspace, cfg=run.cfg)
    missing: list = []
    for rel in routes:
        try:
            mapped = testmap.map_test(rel, ctx, run.cfg)
        except Exception:
            mapped = None
        if mapped is None or mapped.existing is None:
            missing.append(rel)
    if missing:
        return make_check("route_tests", FAIL, "route file(s) without a test: %s" % ", ".join(missing[:8]), [], None,
                          started, "write the mapped test file for each route module")
    return make_check("route_tests", PASS, "%d route file(s), each with a test" % len(routes), [], None, started)


def _from_result(item: dict) -> Check:
    status = item.get("status") if item.get("status") in (PASS, FAIL, UNVERIFIED, NOT_APPLICABLE) else UNVERIFIED
    rc = item.get("rc")
    return Check(id=str(item.get("check") or item.get("id") or "check"), status=status,
                 argv=[str(a) for a in item.get("argv") or []], rc=rc if isinstance(rc, int) else None,
                 duration_ms=max(0, int(item.get("duration_ms") or 0)), detail=one_line(item.get("detail", "")),
                 hint="", required=bool(item.get("required", True)))


def _pytest(rc: int, output: str) -> tuple:
    if rc == 0:
        return PASS, last_lines(output, 1)
    if rc == 5:
        return UNVERIFIED, "no tests collected"
    return FAIL, "exit %d — %s" % (rc, last_lines(output))


def application_checks(run: Run, detected: list, application_results: Optional[list],
                       run_mutation: bool) -> list:
    jobs: list = []
    python_stack = any(_exists(run, f) for f in ("pyproject.toml", "requirements.txt", "setup.cfg"))
    js_stack = _exists(run, "package.json")
    if application_results is not None:
        converted = [_from_result(r if isinstance(r, dict) else dataclasses.asdict(r)) for r in application_results]
        jobs.extend([lambda c=c: c for c in converted])
    else:
        if python_stack:
            ruff = ["ruff"] if _which("ruff", child_env(run.env)) else [_python(run), "-m", "ruff"]
            jobs.append(lambda: tool_check(run, "ruff_check", ruff + ["check", "."], hint=HINTS["ruff"]))
            jobs.append(lambda: tool_check(run, "ruff_format", ruff + ["format", "--check", "."], hint=HINTS["ruff"]))
        if js_stack and _exists(run, "tsconfig.json"):
            jobs.append(lambda: tool_check(run, "tsc", ["npx", "tsc", "--noEmit"], needs_node=True))
        eslint_configs = ("eslint.config.js", "eslint.config.mjs", ".eslintrc.json", ".eslintrc.cjs", ".eslintrc.js")
        if js_stack and any(_exists(run, f) for f in eslint_configs):
            jobs.append(lambda: tool_check(run, "eslint", ["npx", "eslint", ".", "--max-warnings", "0"],
                                           needs_node=True))
    jobs.append(lambda: env_example_check(run))
    jobs.append(lambda: route_tests_check(run))
    if run.mode == "full":
        if python_stack and application_results is None:
            jobs.append(lambda: tool_check(run, "pytest", [_python(run), "-m", "pytest", "-q", "-x", "-p",
                                                           "no:cacheprovider"], interpret=_pytest,
                                           hint=HINTS["pytest"]))
        runner = testmap.js_runner(run.workspace) if js_stack else None
        if runner == "vitest" and application_results is None:
            jobs.append(lambda: tool_check(run, "vitest", ["npx", "vitest", "run"], needs_node=True))
        elif runner == "jest" and application_results is None:
            jobs.append(lambda: tool_check(run, "jest", ["npx", "jest", "--ci"], needs_node=True))
        if _exists(run, "requirements.txt"):
            jobs.append(lambda: tool_check(run, "pip_audit", ["pip-audit", "-r", "requirements.txt"], network=True))
        if js_stack and _exists(run, "package-lock.json"):
            jobs.append(lambda: tool_check(run, "npm_audit", ["npm", "audit", "--audit-level=high"], network=True))
        jobs.append(lambda: tool_check(run, "gitleaks", ["gitleaks", "dir", ".", "--no-banner", "--redact",
                                                         "--exit-code", "1"]))
        if run_mutation and run.base_ref:
            jobs.append(lambda: mutation(run.workspace, run.base_ref,
                                         float(run.cfg.get("ship_readiness.mutation.min_score", 0.6)), run.cfg))
    return jobs


def _dbt_roots(run: Run) -> list:
    roots = sorted({os.path.dirname(f) for f in run.files if os.path.basename(f) == "dbt_project.yml"})
    return roots or [""]


def _yaml_model_blocks(text: str) -> dict:
    blocks: dict = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        header = re.match(r"^(\s*)models\s*:\s*$", lines[index])
        if not header:
            index += 1
            continue
        base = len(header.group(1))
        index += 1
        item_indent = None
        current = None
        body: list = []
        while index < len(lines):
            line = lines[index]
            if line.strip() and not line.lstrip().startswith("#"):
                indent = len(line) - len(line.lstrip())
                if indent <= base and not line.lstrip().startswith("- "):
                    break
                if indent <= base and line.lstrip().startswith("- ") and item_indent is None:
                    item_indent = indent
                item = re.match(r"^(\s*)-\s+name\s*:\s*[\"']?([\w.\-]+)[\"']?\s*$", line)
                if item and (item_indent is None or len(item.group(1)) == item_indent):
                    item_indent = len(item.group(1))
                    if current is not None:
                        blocks[current] = body
                    current = item.group(2)
                    body = []
                    index += 1
                    continue
                if item_indent is not None and indent <= item_indent and not line.lstrip().startswith("- "):
                    break
            if current is not None:
                body.append(line)
            index += 1
        if current is not None:
            blocks[current] = body
    return blocks


def _block_ok(body: list) -> tuple:
    indents = [len(l) - len(l.lstrip()) for l in body if l.strip()]
    top = min(indents) if indents else 0
    described = any(re.match(r"^\s{%d}description\s*:\s*\S" % top, l) for l in body)
    tested = False
    for position, line in enumerate(body):
        match = re.match(r"^(\s*)(?:data_)?tests\s*:\s*(.*)$", line)
        if not match:
            continue
        inline = match.group(2).strip()
        if inline and inline not in ("[]", "~", "null"):
            tested = True
            break
        indent = len(match.group(1))
        for following in body[position + 1:]:
            if not following.strip():
                continue
            if len(following) - len(following.lstrip()) > indent or following.lstrip().startswith("- "):
                tested = following.lstrip().startswith("- ")
            break
        if tested:
            break
    return described, tested


def dbt_models_check(run: Run) -> Check:
    started = time.monotonic()
    problems: list = []
    total = 0
    for root in _dbt_roots(run):
        prefix = (root + "/") if root else ""
        models = [f for f in run.files if f.startswith(prefix + "models/") and f.endswith(".sql")]
        schemas = [f for f in run.files if f.startswith(prefix + "models/") and f.endswith((".yml", ".yaml"))]
        blocks: dict = {}
        for rel in schemas:
            blocks.update(_yaml_model_blocks(_read(os.path.join(run.workspace, rel))))
        for rel in models:
            total += 1
            name = os.path.splitext(os.path.basename(rel))[0]
            if name not in blocks:
                problems.append("%s: no schema.yml entry" % rel)
                continue
            described, tested = _block_ok(blocks[name])
            if not described:
                problems.append("%s: no description" % rel)
            if not tested:
                problems.append("%s: no test" % rel)
    if total == 0:
        return make_check("dbt_models", NOT_APPLICABLE, "no models/**/*.sql", [], None, started)
    if problems:
        return make_check("dbt_models", FAIL, "%d problem(s): %s" % (len(problems), "; ".join(problems[:6])), [], None,
                          started, "document and test every model in a schema.yml next to it")
    return make_check("dbt_models", PASS, "%d model(s) documented and tested" % total, [], None, started)


def gold_select_check(run: Run) -> Check:
    started = time.monotonic()
    gold = [f for f in run.files if f.endswith(".sql") and "models/" in ("/" + f)
            and ("/gold/" in "/" + f or "/marts/" in "/" + f or os.path.basename(f).startswith("gold_"))]
    if not gold:
        return make_check("gold_no_select_star", NOT_APPLICABLE, "no gold models", [], None, started)
    pattern = re.compile(r"select\s+\*\s+from\s+[^\n;]*\b(raw|bronze)", re.I)
    bad = [f for f in gold if pattern.search(_read(os.path.join(run.workspace, f)))]
    if bad:
        return make_check("gold_no_select_star", FAIL, "select * from raw/bronze in: %s" % ", ".join(bad[:6]), [],
                          None, started, "select explicit columns from silver/staging models")
    return make_check("gold_no_select_star", PASS, "%d gold model(s) clean" % len(gold), [], None, started)


def policies_check(run: Run) -> Check:
    started = time.monotonic()
    directory = os.path.join(run.workspace, "policies")
    if not os.path.isdir(directory):
        return make_check("access_policies", NOT_APPLICABLE, "no policies/ directory", [], None, started)
    count = len([f for f in run.files if f.startswith("policies/")])
    if count == 0:
        return make_check("access_policies", FAIL, "policies/ exists but holds no policy file", [], None, started)
    return make_check("access_policies", PASS, "%d policy file(s)" % count, [], None, started)


def _dbt_profile_dir(run: Run, root: str) -> str:
    project = _read(os.path.join(run.workspace, root, "dbt_project.yml"))
    match = re.search(r"(?m)^profile\s*:\s*[\"']?([\w\-]+)", project)
    name = match.group(1) if match else "default"
    directory = tempfile.mkdtemp(prefix="omega-dbt-")
    Path(directory, "profiles.yml").write_text(
        "%s:\n  target: stub\n  outputs:\n    stub:\n      type: duckdb\n      path: ':memory:'\n" % name,
        encoding="utf-8")
    return directory


def analytics_checks(run: Run, detected: list) -> list:
    jobs: list = [lambda: dbt_models_check(run), lambda: gold_select_check(run), lambda: policies_check(run)]
    if run.mode == "full":
        for root in _dbt_roots(run):
            if not _exists(run, os.path.join(root, "dbt_project.yml")):
                continue

            def dbt_parse(root=root) -> Check:
                profiles = _dbt_profile_dir(run, root)
                try:
                    return tool_check(run, "dbt_parse%s" % (":" + root if root else ""),
                                      ["dbt", "parse", "--no-partial-parse"], env_extra={"DBT_PROFILES_DIR": profiles},
                                      cwd=os.path.join(run.workspace, root) if root else None, network=True)
                finally:
                    shutil.rmtree(profiles, ignore_errors=True)
            jobs.append(dbt_parse)
        if _which("sqlfluff", child_env(run.env)):
            jobs.append(lambda: tool_check(run, "sqlfluff", ["sqlfluff", "lint", "models/"], required=False))
        else:
            jobs.append(lambda: make_check("sqlfluff", NOT_APPLICABLE, "sqlfluff not installed (optional)",
                                           hint=HINTS["sqlfluff"], required=False))
    return jobs


def _deps_text(run: Run) -> str:
    chunks = []
    for rel in run.files:
        base = os.path.basename(rel)
        if base in ("pyproject.toml", "package.json", "setup.cfg") or (base.startswith("requirements") and base.endswith(".txt")):
            chunks.append(_read(os.path.join(run.workspace, rel)))
    return "\n".join(chunks)


def llm_call_sites(run: Run) -> list:
    sites: list = []
    for rel in _non_test_code(run):
        text = _read(os.path.join(run.workspace, rel))
        if not LLM_CALL.search(text):
            continue
        if rel.endswith(".py"):
            sites.extend(_python_sites(rel, text))
        else:
            for number, line in enumerate(text.splitlines(), 1):
                if LLM_CALL.search(line):
                    sites.append({"path": rel, "line": number, "covered": bool(FILE_WRAPPERS.search(text)
                                                                                or re.search(r"\btraceable\(", text))})
    return sites


def _decorated_traced(node) -> bool:
    for decorator in getattr(node, "decorator_list", []):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
        if "traced" in str(name) or "traceable" in str(name):
            return True
    return False


def _python_sites(rel: str, text: str) -> list:
    wrapped = bool(FILE_WRAPPERS.search(text))
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [{"path": rel, "line": n, "covered": wrapped} for n, line in enumerate(text.splitlines(), 1)
                if LLM_CALL.search(line)]
    sites: list = []

    def visit(node, traced: bool) -> None:
        for child in ast.iter_child_nodes(node):
            inner = traced
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = traced or _decorated_traced(child)
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr in LLM_ATTRS:
                segment = ast.get_source_segment(text, child.func) or ""
                if LLM_CALL.search(segment + "("):
                    sites.append({"path": rel, "line": child.lineno, "covered": wrapped or inner})
            visit(child, inner)
    visit(tree, False)
    return sites


def _env_names(run: Run) -> list:
    names: list = []
    for rel in _non_test_code(run):
        for match in ENV_REFERENCE.finditer(_read(os.path.join(run.workspace, rel))):
            name = next(g for g in match.groups() if g)
            if name not in names:
                names.append(name)
    return names


def _env_example_names(run: Run) -> set:
    names: set = set()
    for line in _read(os.path.join(run.workspace, ".env.example")).splitlines():
        match = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if match:
            names.add(match.group(1))
    return names


def observability_checks(run: Run, detected: list) -> list:
    sites = llm_call_sites(run)
    deps = _deps_text(run)
    has_dep = bool(TRACING_DEPS.search(deps))
    code_text = "\n".join(_read(os.path.join(run.workspace, f)) for f in _non_test_code(run))
    has_init = bool(TRACING_INIT.search(code_text))

    def dependency() -> Check:
        if has_dep:
            return make_check("tracing_dependency", PASS, "braintrust/langsmith declared")
        if sites:
            return make_check("tracing_dependency", FAIL, "%d LLM call site(s) but no braintrust/langsmith dependency"
                              % len(sites), hint="pip install braintrust (or langsmith) and declare it")
        return make_check("tracing_dependency", NOT_APPLICABLE, "no LLM call sites")

    def init() -> Check:
        if not sites:
            return make_check("tracing_init", NOT_APPLICABLE, "no LLM call sites")
        if has_init:
            return make_check("tracing_init", PASS, "tracing initialised")
        return make_check("tracing_init", FAIL, "no init_logger/initLogger/@traceable/wrap_* found",
                          hint="initialise the tracer once at startup")

    def coverage() -> Check:
        if not sites:
            return make_check("tracing_coverage", NOT_APPLICABLE, "no LLM call sites")
        uncovered = ["%s:%d" % (s["path"], s["line"]) for s in sites if not s["covered"]]
        if uncovered:
            return make_check("tracing_coverage", FAIL, "uncovered LLM call site(s): %s" % ", ".join(uncovered[:8]),
                              hint="wrap the client (wrap_openai/wrap_anthropic) or decorate the caller (@traceable)")
        return make_check("tracing_coverage", PASS, "%d call site(s) traced" % len(sites))

    def env_vars() -> Check:
        names = _env_names(run)
        if not names:
            return make_check("env_vars_documented", NOT_APPLICABLE, "no environment variable references")
        if not _exists(run, ".env.example"):
            return make_check("env_vars_documented", FAIL, ".env.example missing; code reads %s" % ", ".join(names[:8]),
                              hint="add .env.example with every variable name")
        documented = _env_example_names(run)
        missing = [n for n in names if n not in documented]
        if missing:
            return make_check("env_vars_documented", FAIL, "not in .env.example: %s" % ", ".join(missing[:10]),
                              hint="list each variable name in .env.example (no real values)")
        return make_check("env_vars_documented", PASS, "%d variable(s) documented" % len(names))

    def key_literals() -> Check:
        hits: list = []
        for rel in _code_files(run) + [f for f in run.files if os.path.basename(f).startswith(".env")]:
            if redaction.is_fixture(rel, run.cfg) or os.path.basename(rel) == ".env":
                continue
            text = _read(os.path.join(run.workspace, rel))
            for hit in redaction.strict_secret_hits(text):
                hits.append("%s %s:%s" % (hit.rule, rel, hit.line))
            for rule, pattern in EXTRA_KEY_LITERALS:
                for match in pattern.finditer(text):
                    if not redaction.is_dummy(match.group(0)):
                        hits.append("%s %s:%d" % (rule, rel, text.count("\n", 0, match.start()) + 1))
        if hits:
            return make_check("no_key_literals", FAIL, "key literal(s): %s" % ", ".join(hits[:8]),
                              hint="move keys to the environment and rotate them")
        return make_check("no_key_literals", PASS, "no key literals")

    def cost_caps() -> Check:
        verdict = costledger.check(run.cfg)
        sums = verdict.sums or {}
        if sums.get("corrupt_lines"):
            return make_check("tokentoll_check", UNVERIFIED, "cost ledger has corrupt lines")
        if verdict.status == FAIL:
            return make_check("tokentoll_check", FAIL, "; ".join(verdict.breaches))
        if sums.get("unknown_models"):
            return make_check("tokentoll_check", UNVERIFIED, "unknown model(s): %s" % ", ".join(sums["unknown_models"]),
                              hint="add the model to cost.prices")
        return make_check("tokentoll_check", PASS, "month $%.2f under caps" % float(sums.get("month") or 0.0))

    def cost_scan() -> Check:
        from hooks import tokentoll_gate
        result = tokentoll_gate.scan(run.workspace, run.cfg)
        if not result["sites"]:
            return make_check("tokentoll_scan", NOT_APPLICABLE, "no LLM call sites")
        if result["status"] == FAIL:
            return make_check("tokentoll_scan", FAIL, "static estimate $%.2f / month exceeds $%.2f" % (
                result["total_monthly_usd"], result["max_monthly_usd"]))
        if result["unknown_models"]:
            return make_check("tokentoll_scan", UNVERIFIED, "unpriced or unresolved model(s): %s" % ", ".join(
                result["unknown_models"]), hint="use a literal model name listed in cost.prices")
        return make_check("tokentoll_scan", PASS, "static estimate $%.2f / month" % result["total_monthly_usd"])

    jobs: list = [dependency, init, coverage, env_vars, key_literals, cost_caps, cost_scan]
    if run.mode == "full":
        for key, url, header, prefix in LIVE_KEYS:
            jobs.append(lambda key=key, url=url, header=header, prefix=prefix: live_check(key, url, header, prefix))
    return jobs


def live_check(key: str, url: str, header: str, prefix: str) -> Check:
    started = time.monotonic()
    cid = "live_%s" % key.split("_")[0].lower()
    value = os.environ.get(key)
    if not value:
        return make_check(cid, UNVERIFIED, "skipped: no %s" % key, [], None, started, required=False)
    request = urllib.request.Request(url, headers={header: prefix + value, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            code = response.getcode()
    except urllib.error.HTTPError as exc:
        return make_check(cid, FAIL, "GET %s returned %d" % (url.split("?")[0], exc.code), [], exc.code, started,
                          required=False)
    except (urllib.error.URLError, OSError) as exc:
        return make_check(cid, UNVERIFIED, "network unavailable: %s" % exc.__class__.__name__, [], None, started,
                          required=False)
    status = PASS if 200 <= code < 300 else FAIL
    return make_check(cid, status, "GET %s returned %d" % (url.split("?")[0], code), [], code, started, required=False)


def _safe(job: Callable, cid: str) -> Check:
    try:
        result = job()
    except Exception as exc:
        return make_check(cid, UNVERIFIED, "check crashed: %s: %s" % (exc.__class__.__name__, exc))
    return result if isinstance(result, Check) else make_check(cid, UNVERIFIED, "check returned no result")


def tier_status(applicable: bool, checks: list) -> str:
    if not applicable:
        return NOT_APPLICABLE
    if any(c.status == FAIL for c in checks):
        return FAIL
    if any(c.status == UNVERIFIED and c.required for c in checks):
        return UNVERIFIED
    return PASS


def overall_status(tiers: dict, strict: bool) -> str:
    statuses = [t["status"] for t in tiers.values()]
    if FAIL in statuses:
        return FAIL
    if UNVERIFIED in statuses and strict:
        return UNVERIFIED
    return PASS


def run(workspace: str, cfg, mode: str = "fast", strict: bool = False, application_results: Optional[list] = None,
        changed: Optional[list] = None, base_ref: Optional[str] = None, run_mutation: bool = False) -> dict:
    workspace = os.path.realpath(workspace)
    cfg = cfg if cfg is not None else config_mod.load(workspace=workspace)
    mode = mode if mode in ("fast", "full") else "fast"
    files = list_files(workspace, cfg)
    found = detect(workspace, cfg, files)
    runner = Run(workspace=workspace, cfg=cfg, mode=mode,
                 timeout_s=FULL_TIMEOUT_S if mode == "full" else FAST_TIMEOUT_S, files=files, base_ref=base_ref)
    builders = {"infra": infra_checks, "database": database_checks,
                "application": lambda r, d: application_checks(r, d, application_results, run_mutation),
                "analytics": analytics_checks, "observability": observability_checks}
    plan: list = []
    for tier in TIERS:
        if not found[tier]:
            continue
        for index, job in enumerate(builders[tier](runner, found[tier])):
            plan.append((tier, index, job))
    results: dict = {tier: [] for tier in TIERS}
    if plan:
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [(tier, index, pool.submit(_safe, job, "%s_%d" % (tier, index))) for tier, index, job in plan]
            for tier, index, future in futures:
                results[tier].append((index, future.result()))
    tiers: dict = {}
    for tier in TIERS:
        checks = [c for _, c in sorted(results[tier], key=lambda pair: pair[0])]
        applicable = bool(found[tier])
        tiers[tier] = Tier(tier, tier_status(applicable, checks), applicable, found[tier], checks).as_dict()
    return {"schema": SCHEMA, "ts": state.iso(), "workspace": workspace, "mode": mode, "strict": bool(strict),
            "status": overall_status(tiers, strict), "tiers": tiers}


def summary(result: dict) -> str:
    parts = []
    for tier in TIERS:
        status = (result.get("tiers") or {}).get(tier, {}).get("status", NOT_APPLICABLE)
        parts.append("%s %s" % (tier, "n/a" if status == NOT_APPLICABLE else status))
    return " · ".join(parts) + " (%s)" % result.get("mode", "fast")


def worst_tier(result: dict) -> str:
    statuses = [t.get("status") for t in (result.get("tiers") or {}).values()]
    if FAIL in statuses:
        return FAIL
    if UNVERIFIED in statuses:
        return UNVERIFIED
    if statuses and all(s == NOT_APPLICABLE for s in statuses):
        return NOT_APPLICABLE
    return PASS


def parse_mutmut_results(text: str) -> dict:
    counts: dict = {}
    for line in (text or "").splitlines():
        match = MUTMUT_LINE.match(line)
        if match:
            counts[match.group(2)] = counts.get(match.group(2), 0) + 1
    return counts


def mutmut_score(counts: dict) -> Optional[float]:
    denominator = sum(counts.get(k, 0) for k in MUTMUT_SCORED)
    if denominator == 0:
        return None
    return counts.get("killed", 0) / float(denominator)


def stryker_score(report: dict) -> Optional[float]:
    detected = undetected = 0
    for entry in (report.get("files") or {}).values():
        for mutant in entry.get("mutants") or []:
            status = mutant.get("status")
            if status in STRYKER_DETECTED:
                detected += 1
            elif status in STRYKER_UNDETECTED:
                undetected += 1
    total = detected + undetected
    return detected / float(total) if total else None


def _changed_sources(workspace: str, base_ref: str, cfg, exts: tuple) -> Optional[list]:
    out = _git(workspace, ["diff", "--name-only", base_ref, "--"])
    if out is None:
        return None
    untracked = _git(workspace, ["ls-files", "--others", "--exclude-standard"]) or ""
    names = [n.strip() for n in (out + "\n" + untracked).splitlines() if n.strip()]
    return [n for n in dict.fromkeys(names) if n.endswith(exts) and testmap.is_source(n, cfg)
            and os.path.isfile(os.path.join(workspace, n))]


def _python_version(python: str) -> Optional[tuple]:
    try:
        proc = subprocess.run([python, "-c", "import sys;print('%d.%d' % sys.version_info[:2])"], capture_output=True,
                              timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    try:
        major, minor = proc.stdout.decode().strip().split(".")
        return int(major), int(minor)
    except ValueError:
        return None


def mutation(workspace: str, base_ref: str, min_score: float, cfg, stryker: bool = False) -> Check:
    started = time.monotonic()
    workspace = os.path.realpath(workspace)
    cfg = cfg if cfg is not None else config_mod.load(workspace=workspace)
    if stryker:
        return _stryker(workspace, base_ref, min_score, cfg, started)
    changed = _changed_sources(workspace, base_ref, cfg, (".py",))
    if changed is None:
        return make_check("mutation", UNVERIFIED, "cannot diff against %s" % base_ref, [], None, started)
    if not changed:
        return make_check("mutation", NOT_APPLICABLE, "nothing to mutate: no changed Python source", [], None, started)
    python = testmap.workspace_python(workspace)
    version = _python_version(python)
    if version is None:
        return make_check("mutation", UNVERIFIED, "cannot run %s" % python, [python], None, started)
    if version < (3, 10):
        return make_check("mutation", UNVERIFIED, "mutmut 3.4+ needs Python 3.10 (found %d.%d)" % version, [python],
                          None, started, HINTS["mutmut"])
    scratch = tempfile.mkdtemp(prefix="omega-mutation-")
    copy = os.path.join(scratch, "ws")
    timeout = int(cfg.get("ship_readiness.mutation.timeout_s", 900))
    try:
        shutil.copytree(workspace, copy, symlinks=True,
                        ignore=shutil.ignore_patterns(".git", ".omega", "node_modules", ".venv", "venv", "mutants",
                                                      "__pycache__", ".mutmut-cache"))
        parser = configparser.ConfigParser()
        setup = os.path.join(copy, "setup.cfg")
        parser.read(setup)
        if not parser.has_section("mutmut"):
            parser.add_section("mutmut")
        parser.set("mutmut", "paths_to_mutate", ",".join(changed))
        parser.set("mutmut", "tests_dir", "tests/")
        with open(setup, "w", encoding="utf-8") as handle:
            parser.write(handle)
        env = child_env()
        argv = [python, "-m", "mutmut", "run"]
        try:
            subprocess.run(argv, cwd=copy, capture_output=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL)
            proc = subprocess.run([python, "-m", "mutmut", "results", "--all", "true"], cwd=copy, capture_output=True,
                                  timeout=300, env=env, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return make_check("mutation", UNVERIFIED, "mutmut timed out after %ds" % timeout, argv, None, started)
        except OSError as exc:
            return make_check("mutation", UNVERIFIED, "could not run mutmut: %s" % exc.__class__.__name__, argv, None,
                              started, HINTS["mutmut"])
        output = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
        if "No module named" in output and "mutmut" in output:
            return make_check("mutation", UNVERIFIED, "mutmut not installed for %s" % python, argv, proc.returncode,
                              started, HINTS["mutmut"])
        counts = parse_mutmut_results(output)
        score = mutmut_score(counts)
        if score is None:
            return make_check("mutation", UNVERIFIED, "could not run: no scored mutants (%s)" % last_lines(output, 1),
                              argv, proc.returncode, started)
        detail = "score %.2f (min %.2f): %s" % (score, min_score, ", ".join("%s %d" % kv for kv in sorted(counts.items())))
        return make_check("mutation", PASS if score >= min_score else FAIL, detail, argv, proc.returncode, started)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _stryker(workspace: str, base_ref: str, min_score: float, cfg, started: float) -> Check:
    changed = _changed_sources(workspace, base_ref, cfg, (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"))
    if changed is None:
        return make_check("mutation", UNVERIFIED, "cannot diff against %s" % base_ref, [], None, started)
    if not changed:
        return make_check("mutation", NOT_APPLICABLE, "nothing to mutate: no changed JS/TS source", [], None, started)
    runner = Run(workspace=workspace, cfg=cfg, mode="full", files=[],
                 timeout_s=int(cfg.get("ship_readiness.mutation.timeout_s", 900)))
    breaking = int(cfg.get("ship_readiness.mutation.stryker_break", 55))
    argv = ["npx", "stryker", "run", "--incremental", "--mutate", ",".join(changed),
            "--thresholds.break", str(breaking)]
    ran = tool_check(runner, "mutation", argv, needs_node=True)
    report_path = os.path.join(workspace, "reports", "mutation", "mutation.json")
    try:
        report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        if ran.status == UNVERIFIED:
            return ran
        return make_check("mutation", UNVERIFIED, "could not run: no reports/mutation/mutation.json", argv, ran.rc,
                          started)
    score = stryker_score(report)
    if score is None:
        return make_check("mutation", UNVERIFIED, "could not run: no scored mutants", argv, ran.rc, started)
    status = PASS if score >= min_score else FAIL
    return make_check("mutation", status, "score %.2f (min %.2f)" % (score, min_score), argv, ran.rc, started)


def _print_human(result: dict) -> None:
    sys.stderr.write("[ship-readiness] %s %s\n" % (result["status"], summary(result)))
    for tier in TIERS:
        for check in result["tiers"][tier]["checks"]:
            sys.stderr.write("  %-13s %-22s %-14s %s%s\n" % (tier, check["id"][:22], check["status"], check["detail"],
                                                             (" [hint: %s]" % check["hint"]) if check["hint"]
                                                             and check["status"] != PASS else ""))


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="ship_readiness.py", description="Five-tier ship readiness checks.")
    sub = parser.add_subparsers(dest="command")
    run_p = sub.add_parser("run")
    run_p.add_argument("--workspace")
    run_p.add_argument("--mode", choices=("fast", "full"), default="fast")
    run_p.add_argument("--strict", action="store_true")
    run_p.add_argument("--base-ref")
    run_p.add_argument("--mutation", action="store_true")
    run_p.add_argument("--json", action="store_true")
    run_p.add_argument("--out")
    mig = sub.add_parser("migration-lint")
    mig.add_argument("--workspace")
    mig.add_argument("--base-ref")
    mig.add_argument("--json", action="store_true")
    mut = sub.add_parser("mutation")
    mut.add_argument("--workspace")
    mut.add_argument("--base-ref", required=True)
    mut.add_argument("--min-score", type=float)
    mut.add_argument("--stryker", action="store_true")
    mut.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return 2
    workspace = os.path.realpath(args.workspace or os.environ.get("OMEGA_WORKSPACE") or os.getcwd())
    try:
        cfg = config_mod.load(workspace=workspace)
        if args.command == "run":
            result = run(workspace, cfg, mode=args.mode, strict=args.strict, base_ref=args.base_ref,
                         run_mutation=args.mutation)
            if args.out:
                state.write_json_atomic(Path(args.out), result)
            if args.json:
                sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
            _print_human(result)
            return 0 if result["status"] == PASS else 1
        if args.command == "migration-lint":
            check = migration_rules(workspace, args.base_ref, cfg)
        else:
            min_score = args.min_score if args.min_score is not None else float(
                cfg.get("ship_readiness.mutation.min_score", 0.6))
            check = mutation(workspace, args.base_ref, min_score, cfg, stryker=args.stryker)
        if args.json:
            sys.stdout.write(json.dumps(check.as_dict(), ensure_ascii=False) + "\n")
        sys.stderr.write("[ship-readiness] %s %s %s\n" % (check.id, check.status, check.detail))
        if check.status in (PASS, NOT_APPLICABLE):
            return 0
        if check.status == FAIL:
            return 1
        return 2
    except Exception as exc:
        sys.stderr.write("[ship-readiness] internal error: %s: %s\n" % (exc.__class__.__name__, str(exc)[:200]))
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

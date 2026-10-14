from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Optional

DEFAULTS = json.loads(r'''
{
 "version": 1,
 "state": {
  "dir": null
 },
 "workspace": {
  "ignored_dirs": [
   ".git",
   "__pycache__",
   ".venv",
   "venv",
   "node_modules",
   ".pytest_cache",
   ".ruff_cache",
   ".mypy_cache",
   ".turbo",
   ".next",
   "dist",
   "build",
   "coverage",
   "target",
   "dbt_packages",
   "logs",
   ".mutmut-cache",
   "mutants",
   ".omega/scratch"
  ],
  "scratch_globs": [
   ".scratch/**"
  ]
 },
 "session_start": {
  "context_cap_bytes": 12000,
  "inject": [
   "mental-models/architecture.md",
   "mental-models/database_rules.md",
   "mental-models/provider_contracts.md"
  ]
 },
 "guards": {
  "protected_globs": {
   "workspace": [
    ".claude/**",
    ".codex/**",
    ".gemini/**",
    ".git/**",
    ".omega/**",
    ".github/workflows/gauntlet.yml",
    ".gitleaks.toml"
   ],
   "harness": [
    "bin/**",
    "hooks/**",
    "schemas/**",
    "scripts/**",
    "omega.config.json",
    ".claude/**",
    ".codex/**"
   ]
  },
  "prod": {
   "rm_rf_allowlist": [
    "node_modules",
    "dist",
    "build",
    ".pytest_cache",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    "coverage",
    ".next",
    ".turbo",
    "target",
    ".scratch"
   ],
   "allow_local_docker": true,
   "allow_alembic_upgrade": true,
   "local_hosts": [
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "host.docker.internal"
   ],
   "strict_db": false,
   "extra_deny_regex": []
  }
 },
 "redaction": {
  "fixture_globs": [
   "tests/fixtures/**",
   "**/*.example",
   "**/fixtures/**"
  ],
  "pii_fail_globs": [
   "**/*.py",
   "**/*.ts",
   "**/*.tsx",
   "**/*.sql",
   "**/*.md",
   "**/*.json",
   "**/*.yml",
   "**/*.yaml"
  ]
 },
 "transcript": {
  "accept_unlabelled_user_turns": false
 },
 "gauntlet": {
  "omega_repo": null,
  "python": "3.12",
  "node": "22",
  "action_pins": {
   "actions/checkout": "v4",
   "actions/setup-python": "v5",
   "actions/setup-node": "v4",
   "actions/cache": "v4",
   "actions/upload-artifact": "v4",
   "gitleaks/gitleaks-action": "v2"
  }
 },
 "tdd": {
  "mode": "strict",
  "debounce_s": 0.8,
  "job_timeout_s": 240,
  "source_exts": [
   ".py",
   ".ts",
   ".tsx",
   ".js",
   ".jsx",
   ".mjs",
   ".cjs"
  ],
  "test_globs": [
   "tests/**",
   "test/**",
   "**/__tests__/**",
   "**/test_*.py",
   "**/*_test.py",
   "**/*.test.*",
   "**/*.spec.*",
   "**/conftest.py"
  ],
  "exempt_globs": [
   "docs/**",
   "**/*.md",
   "**/*.txt",
   "**/*.json",
   "**/*.yaml",
   "**/*.yml",
   "**/*.toml",
   "**/*.ini",
   "**/*.cfg",
   "**/*.lock",
   "**/*.env.example",
   "migrations/**",
   "**/migrations/**",
   "alembic/**",
   "prisma/**",
   "**/*.sql",
   "models/**",
   "macros/**",
   "seeds/**",
   "snapshots/**",
   "infra/**",
   "terraform/**",
   "**/*.tf",
   "**/*.tfvars",
   "Dockerfile*",
   "**/Dockerfile*",
   "docker-compose*",
   "**/*.html",
   "**/*.css",
   "**/*.scss",
   "**/*.svg",
   "**/*.png",
   ".github/**",
   "scripts/**",
   "**/__init__.py",
   "**/*.d.ts",
   "**/*.config.*",
   "**/*.stories.*",
   "buildtime/**"
  ],
  "mappings": [
   {
    "lang": "python",
    "source": "^(?:src/|app/|backend/|server/)?(?P<pkg>(?:[^/]+/)*)(?P<name>[^/]+)\\.py$",
    "tests": [
     "tests/{pkg}test_{name}.py",
     "tests/test_{name}.py",
     "{srcdir}tests/test_{name}.py",
     "{srcdir}test_{name}.py"
    ]
   },
   {
    "lang": "ts",
    "source": "^(?P<dir>(?:[^/]+/)*)(?P<name>[^/]+)\\.(?P<ext>tsx?|jsx?|mjs|cjs)$",
    "tests": [
     "{dir}{name}.test.{ext}",
     "{dir}{name}.spec.{ext}",
     "{dir}__tests__/{name}.test.{ext}",
     "{dir}__tests__/{name}.{ext}"
    ]
   }
  ],
  "overrides": {},
  "runners": {
   "python": {
    "argv": [
     "{python}",
     "-m",
     "pytest",
     "-q",
     "-x",
     "-p",
     "no:cacheprovider",
     "{test}"
    ]
   },
   "vitest": {
    "argv": [
     "npx",
     "vitest",
     "run",
     "--reporter=dot",
     "{test}"
    ]
   },
   "jest": {
    "argv": [
     "npx",
     "jest",
     "--ci",
     "{test}"
    ]
   }
  }
 },
 "contracts": {
  "dir": "docs/contracts",
  "seams": [
   "Unit",
   "Integration",
   "Functional",
   "Journey"
  ],
  "nontrivial": {
   "min_source_files": 3,
   "always_globs": [
    "migrations/**",
    "**/migrations/**",
    "alembic/**",
    "prisma/**",
    "**/*.tf",
    "infra/**",
    "terraform/**",
    "**/auth/**",
    "**/billing/**",
    "**/payments/**",
    "**/webhooks/**",
    "**/*secur*",
    "**/api/**",
    "**/routes/**"
   ],
   "new_source_file_counts": true
  },
  "min_quote_chars": 8
 },
 "proof": {
  "third_party_modules": [
   "pytest",
   "ruff",
   "mypy",
   "httpx",
   "requests",
   "sqlalchemy",
   "alembic",
   "fastapi",
   "pydantic",
   "psycopg",
   "psycopg2",
   "asyncpg",
   "redis",
   "boto3",
   "dbt",
   "braintrust",
   "langsmith",
   "anthropic",
   "openai",
   "google"
  ],
  "suites": [
   {
    "id": "pytest",
    "detect": [
     "pyproject.toml",
     "pytest.ini",
     "setup.cfg",
     "tests/"
    ],
    "argv": [
     "{python}",
     "-m",
     "pytest",
     "-q",
     "-x",
     "-p",
     "no:cacheprovider"
    ],
    "required": true,
    "timeout_s": 200
   },
   {
    "id": "ruff",
    "detect": [
     "pyproject.toml",
     "ruff.toml"
    ],
    "argv": [
     "{python}",
     "-m",
     "ruff",
     "check",
     "{changed_py}"
    ],
    "required": false,
    "timeout_s": 60
   },
   {
    "id": "vitest",
    "detect": [
     "vitest.config.ts",
     "vitest.config.js",
     "vitest.config.mts"
    ],
    "argv": [
     "npx",
     "vitest",
     "run",
     "--reporter=dot"
    ],
    "required": true,
    "timeout_s": 200
   },
   {
    "id": "jest",
    "detect": [
     "jest.config.js",
     "jest.config.ts",
     "jest.config.cjs"
    ],
    "argv": [
     "npx",
     "jest",
     "--ci"
    ],
    "required": true,
    "timeout_s": 200
   },
   {
    "id": "tsc",
    "detect": [
     "tsconfig.json"
    ],
    "argv": [
     "npx",
     "tsc",
     "--noEmit",
     "-p",
     "tsconfig.json"
    ],
    "required": true,
    "timeout_s": 120
   },
   {
    "id": "eslint",
    "detect": [
     "eslint.config.js",
     "eslint.config.mjs",
     ".eslintrc.json",
     ".eslintrc.cjs"
    ],
    "argv": [
     "npx",
     "eslint",
     "--max-warnings",
     "0",
     "{changed_js}"
    ],
    "required": false,
    "timeout_s": 60
   },
   {
    "id": "gitleaks",
    "detect": [],
    "argv": [
     "gitleaks",
     "dir",
     "{workspace}",
     "--no-banner",
     "--redact",
     "--exit-code",
     "1"
    ],
    "required": false,
    "timeout_s": 60
   }
  ],
  "settle_timeout_s": 15
 },
 "stop": {
  "max_attempts": 4,
  "gates": {
   "proof": {
    "required": true,
    "timeout_s": 600
   },
   "tdd": {
    "required": true,
    "timeout_s": 30
   },
   "contract": {
    "required": true,
    "timeout_s": 30
   },
   "review": {
    "required": true,
    "timeout_s": 30
   },
   "cost": {
    "required": true,
    "timeout_s": 15
   },
   "ship": {
    "required": true,
    "timeout_s": 120,
    "mode": "fast",
    "unverified_blocks": false
   }
  }
 },
 "ship_readiness": {
  "tiers": {
   "infra": {
    "detect": [
     "**/*.tf",
     "Dockerfile",
     "**/Dockerfile",
     "docker-compose.yml",
     "docker-compose.yaml",
     "compose.yml",
     "compose.yaml"
    ]
   },
   "database": {
    "detect": [
     "migrations/**",
     "**/migrations/**",
     "alembic.ini",
     "alembic/**",
     "prisma/schema.prisma",
     "**/*.sql"
    ]
   },
   "application": {
    "detect": [
     "pyproject.toml",
     "package.json",
     "requirements.txt",
     "setup.cfg"
    ]
   },
   "analytics": {
    "detect": [
     "dbt_project.yml",
     "**/dbt_project.yml",
     "models/**",
     "policies/**",
     "**/row_level_security*"
    ]
   },
   "observability": {
    "detect": [
     "**/braintrust*",
     "**/langsmith*",
     "**/*.eval.*",
     "evals/**",
     ".env.example",
     "**/otel*",
     "**/opentelemetry*"
    ]
   }
  },
  "migration_waiver_comment": "omega:allow destructive",
  "mutation": {
   "min_score": 0.6,
   "timeout_s": 900,
   "mutmut_version": "3.3.1",
   "stryker_break": 55
  }
 },
 "cost": {
  "caps": {
   "per_call_usd": 0.5,
   "per_session_usd": 5.0,
   "per_run_usd": 5.0,
   "monthly_usd": 100.0
  },
  "warn_ratio": 0.8,
  "safety_multiplier": 1.25,
  "price_version": "2026-10-13",
  "model_aliases": {
   "opus": "claude-opus-5-5",
   "sonnet": "claude-sonnet-5-5",
   "haiku": "claude-haiku-5-5",
   "fable": "claude-fable-5-1"
  },
  "prices": {
   "claude-fable-5-1": {
    "in": 10.0,
    "out": 50.0,
    "cache_read": 0.25,
    "cache_write_5m": 12.5,
    "cache_write_1h": 20.0,
    "verified": true,
    "source": "https://platform.claude.com/docs/en/about-claude/pricing",
    "fetched_at": "2026-10-13"
   },
   "claude-opus-5-5": {
    "in": 4.0,
    "out": 20.0,
    "cache_read": 0.2,
    "cache_write_5m": 5.0,
    "cache_write_1h": 8.0,
    "verified": true,
    "source": "https://platform.claude.com/docs/en/about-claude/pricing",
    "fetched_at": "2026-10-13"
   },
   "claude-sonnet-5-5": {
    "in": 2.0,
    "out": 10.0,
    "cache_read": 0.1,
    "cache_write_5m": 2.5,
    "cache_write_1h": 4.0,
    "verified": true,
    "source": "https://platform.claude.com/docs/en/about-claude/pricing",
    "fetched_at": "2026-10-13"
   },
   "claude-haiku-5-5": {
    "in": 0.1,
    "out": 0.5,
    "cache_read": 0.01,
    "cache_write_5m": 0.125,
    "cache_write_1h": 0.2,
    "verified": true,
    "source": "https://platform.claude.com/docs/en/about-claude/pricing",
    "fetched_at": "2026-10-13",
    "note": "prompts <=100k tokens; the higher tier above 100k is unverified"
   },
   "gpt-5.6-sol": {
    "in": 5.0,
    "out": 30.0,
    "cache_read": 0.5,
    "verified": false,
    "source": "https://benchlm.ai/openai/api-pricing",
    "fetched_at": "2026-10-13"
   },
   "gpt-5.6-luna": {
    "in": 1.0,
    "out": 6.0,
    "cache_read": 0.1,
    "verified": false,
    "source": "https://benchlm.ai/openai/api-pricing",
    "fetched_at": "2026-10-13"
   },
   "gemini-3.1-pro-preview": {
    "in": 2.0,
    "out": 12.0,
    "verified": true,
    "source": "https://ai.google.dev/gemini-api/docs/pricing",
    "fetched_at": "2026-10-13",
    "note": "<=200k tokens; 4/18 above"
   },
   "gemini-3.8-flash": {
    "in": 0.75,
    "out": 3.75,
    "verified": true,
    "effective_to": "2026-12-31",
    "successor": {
     "in": 1.5,
     "out": 7.5,
     "effective_from": "2027-01-01"
    },
    "source": "https://ai.google.dev/gemini-api/docs/pricing",
    "fetched_at": "2026-10-13"
   }
  },
  "roles": {
   "research": {
    "provider": "anthropic",
    "model": "claude-sonnet-5-5",
    "max_budget_usd": 3.0
   },
   "architect": {
    "provider": "anthropic",
    "model": "claude-fable-5-1",
    "max_budget_usd": 5.0
   },
   "implementer": {
    "provider": "anthropic",
    "model": "claude-opus-5-5",
    "max_budget_usd": 10.0
   },
   "utility": {
    "provider": "anthropic",
    "model": "claude-haiku-5-5",
    "max_budget_usd": 0.5
   }
  },
  "static": {
   "calls_per_month": 10000,
   "max_monthly_usd": 500.0,
   "block_unknown_models": true,
   "default_max_tokens": 1024
  }
 },
 "buildtime": {
  "dir": "buildtime",
  "min_support": 20,
  "min_purity": 0.995,
  "promote": {
   "min_n": 1000,
   "max_upper": 0.005,
   "z": 1.96,
   "min_days": 3,
   "min_per_label": 30
  },
  "canary": {
   "rate": 0.03,
   "demote_upper": 0.01,
   "window": 2000
  }
 },
 "ship": {
  "base": "main",
  "protected_branches": [
   "main",
   "master",
   "release/*",
   "production",
   "prod"
  ],
  "branch_prefix": "omega/",
  "draft": true,
  "exclude_globs": [
   ".env*",
   "*.pem",
   "*.key",
   "**/ledger.jsonl",
   "node_modules/**",
   ".omega/**",
   "**/*.secret*"
  ],
  "commit_trailers": [
   "Co-Authored-By: {model_display} <noreply@anthropic.com>"
  ],
  "pr_footer": "Generated with Omega",
  "omega_repo": null,
  "max_files": 200
 },
 "git": {
  "require_signed": true,
  "identity": {"name": null, "email": null, "signing_key": null, "format": null},
  "accept_signature_status": ["G","U"],
  "max_outgoing": 2000
 },
 "ui": {
  "host": "127.0.0.1",
  "port": 8787,
  "fallback_order": [
   "anthropic",
   "openai",
   "google"
  ],
  "runtimes": {
   "anthropic": "claude",
   "openai": "codex",
   "google": null
  },
  "backoff": {
   "base_s": 2,
   "max_s": 60,
   "attempts": 5
  },
  "run_timeout_s": 3600,
  "events_limit_bytes": 8388608
 }
}
''')

ENV_OVERRIDES = (
    ("OMEGA_STATE_DIR", "state.dir", str),
    ("OMEGA_TDD_MODE", "tdd.mode", str),
    ("OMEGA_BUDGET_PER_CALL_USD", "cost.caps.per_call_usd", float),
    ("OMEGA_BUDGET_PER_SESSION_USD", "cost.caps.per_session_usd", float),
    ("OMEGA_BUDGET_PER_RUN_USD", "cost.caps.per_run_usd", float),
    ("OMEGA_BUDGET_MONTHLY_USD", "cost.caps.monthly_usd", float),
)

ENV_NAMES = (
    "OMEGA_STATE_DIR", "OMEGA_WORKSPACE", "OMEGA_PROVIDER", "OMEGA_SESSION_ID",
    "OMEGA_RUN_ID", "OMEGA_DEBUG", "OMEGA_DEV", "OMEGA_HUMAN_LOG", "OMEGA_SECRET",
    "OMEGA_UI_TOKEN", "OMEGA_GIT_TOKEN", "OMEGA_TDD_MODE", "OMEGA_BUDGET_PER_CALL_USD",
    "OMEGA_BUDGET_PER_SESSION_USD", "OMEGA_BUDGET_PER_RUN_USD", "OMEGA_BUDGET_MONTHLY_USD",
    "OMEGA_ALLOW_UNHOOKED",
)

_MISSING = object()


class Config:
    def __init__(self, data: dict, sources: Optional[list] = None, errors: Optional[list] = None):
        self._data = data
        self.sources = list(sources or [])
        self.errors = list(errors or [])

    def get(self, dotted: str, default=None):
        node = self._data
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return copy.deepcopy(node)

    def as_dict(self) -> dict:
        return copy.deepcopy(self._data)

    def __repr__(self) -> str:
        return "Config(sources=%r)" % (self.sources,)


def deep_merge(base: dict, overlay: dict) -> dict:
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _set_dotted(data: dict, dotted: str, value) -> None:
    node = data
    parts = dotted.split(".")
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = value


def _read_overlay(path: Path, errors: list) -> Optional[dict]:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        errors.append("%s: unreadable (%s)" % (path, exc.__class__.__name__))
        return None
    if not isinstance(data, dict):
        errors.append("%s: not a JSON object" % path)
        return None
    return data


def env_overrides(environ=None) -> dict:
    environ = os.environ if environ is None else environ
    overlay: dict = {}
    for name, dotted, cast in ENV_OVERRIDES:
        raw = environ.get(name)
        if raw is None or raw == "":
            continue
        try:
            _set_dotted(overlay, dotted, cast(raw))
        except ValueError:
            continue
    return overlay


def default_harness_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load(harness_root: Optional[Path] = None, workspace: Optional[str] = None) -> Config:
    root = Path(harness_root) if harness_root is not None else default_harness_root()
    errors: list = []
    sources = ["defaults"]
    data = copy.deepcopy(DEFAULTS)
    shipped = _read_overlay(root / "omega.config.json", errors)
    if shipped is not None:
        data = deep_merge(data, shipped)
        sources.append(str(root / "omega.config.json"))
    if workspace:
        local = Path(workspace) / ".omega" / "config.json"
        overlay = _read_overlay(local, errors)
        if overlay is not None:
            data = deep_merge(data, overlay)
            sources.append(str(local))
    env = env_overrides()
    if env:
        data = deep_merge(data, env)
        sources.append("env")
    return Config(data, sources, errors)

# AGENTS.md

Instructions for coding agents (Claude Code, Codex CLI, Gemini CLI, Cursor and others) working on
the Omega repository itself. Human contributors: see [CONTRIBUTING.md](CONTRIBUTING.md).

## What this repo is

Omega is a supervisor that wraps AI coding agents with hooks: guards that fail closed, gates that
re-prove the work at every Stop, cost caps and signed git. It never reasons; it intercepts, records,
proves and refuses. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) is the binding specification;
deviations go in [`docs/DECISIONS.md`](docs/DECISIONS.md) as one appended line.

## You are probably being governed by it

This repo dogfoods itself: `.claude/settings.json` and `.codex/hooks.json` run Omega's hooks on
your tool calls. Expect these, and work with them rather than around them:

- **Contract first.** A non-trivial change (3+ source files, a new source file, or auth, billing,
  api, routes, migrations or infra paths) needs `docs/contracts/<slug>.md`. Post the scenarios in
  chat, run `contract_gate.py propose`, write the file, and wait for the human to approve it in
  their own words. Format: [`docs/contracts/README.md`](docs/contracts/README.md).
- **Observed-red TDD.** Write or change the test first and let it fail before you edit the source
  file it covers.
- **No shell writes into the workspace.** Use your edit/write tools. `>`, `tee`, `sed -i`,
  `python -c "open(...)"` and similar are refused.
- **Protected paths.** `bin/`, `hooks/`, `schemas/`, `scripts/`, `omega.config.json`, `.claude/`,
  `.codex/`, `.git/` and `.omega/` are read-only to you unless the human started the session with
  `OMEGA_DEV=1`. If an edit is refused, ask the human. Never try to work around a guard.
- **Signed git only.** Don't pass `--no-gpg-sign`, `--author`, `-c user.*` or `GIT_*` overrides, and
  don't edit `~/.gitconfig`, `~/.ssh` or `~/.gnupg`. Commit or push only when asked.
- **Stop waits for proof.** If Stop blocks, fix what it names. Don't try to talk past it.

## Code rules

- **Hook side (`bin/`, `hooks/`, `scripts/`) is Python 3.9+, standard library only.** No
  third-party imports, no 3.10+ syntax (`match`, `X | Y` types at runtime). It must run under
  `/usr/bin/python3 -I -B`.
- **Fail closed.** Every guard wraps `main` and exits 2 with a deny reason on any internal error.
  Exit 1 fails open on every runtime, so never let a traceback escape. Never emit
  `permissionDecision: ask` (Codex treats it as allow).
- **"Skipped" is not green.** A missing tool, missing dependency, zero tests or a running job is
  `UNVERIFIED`, never `PASS`.
- **Secrets travel in `env`, never argv.** Redact exact key values from anything the agent sees.
- **Match the surrounding code.** Production modules carry no docstrings or comments (see
  DECISIONS); keep names and idioms consistent with neighbouring files.
- **The web UI (`ui/`) is an experimental preview** on Python 3.11+ with FastAPI. Keep hook-side
  code independent of it.

## Commands

```sh
python3 -m pytest -q -p no:cacheprovider tests --ignore=tests/ui      # hook side (Python 3.9+)
.venv/bin/python -m pytest -q -p no:cacheprovider tests/ui            # web UI (Python 3.11+)
bash scripts/check-all.sh                                              # tests, --help smoke, adapter parity, launcher
ruff check --select E9,F63,F7,F82 .                                    # what CI lints
```

Run a single area while iterating (`tests/guards`, `tests/gates`, `tests/lib`), then the full
hook-side suite before you hand back.

## Layout

| Path | Contents |
|---|---|
| `bin/` | hook entry points (`session_start`, `pre_tool_use`, `post_tool_use`, `stop_orchestrator`) and `launch.sh` |
| `hooks/` | guards (`prod_guard`, `bash_write_guard`), gates (`contract_gate`, `tdd_gate`, `stop_proof`, `ship_readiness`, `tokentoll_gate`), `buildtime_compiler` |
| `hooks/lib/` | shared stdlib library: shell parsing, transcript classification, ledger, state, adapters |
| `schemas/` | JSON Schemas for `proof.json`, `contract.json`, `review.json` clearances |
| `scripts/` | `install_workspace`, `auto_ship`, `create_gauntlet`, `check-all.sh` |
| `mental-models/` | briefs injected into every session; [`architecture.md`](mental-models/architecture.md) lists the security traps that were real |
| `tests/` | `lib`, `guards`, `gates` (stdlib side) and `ui`; fixtures in `tests/fixtures` |
| `ui/` | experimental dashboard |

## Adding a new agent runtime

Each runtime needs an adapter in `hooks/lib/adapters.py` (config rendering and payload
normalisation), fixtures under `tests/fixtures/<runtime>/`, parity coverage in `check-all.sh`, and
a section in `mental-models/provider_contracts.md` covering how that runtime blocks, what fails
open, and what bypasses PreToolUse.

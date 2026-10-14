<div align="center">

# Ω Omega

**A fail-closed supervisor for AI coding agents.**
Contract first, observed-red TDD, proof at every Stop, capped spend, signed git.

[![CI](https://github.com/shassaan/omega/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/shassaan/omega/actions/workflows/ci.yml)
[![CodeQL](https://github.com/shassaan/omega/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/shassaan/omega/actions/workflows/codeql.yml)
[![Secret scan](https://github.com/shassaan/omega/actions/workflows/secret-scan.yml/badge.svg?branch=main)](https://github.com/shassaan/omega/actions/workflows/secret-scan.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
<br>
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](#requirements)
[![Hooks: stdlib only](https://img.shields.io/badge/hooks-stdlib%20only-success)](#requirements)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-supported-D97757)](#claude-code)
[![Codex CLI](https://img.shields.io/badge/Codex%20CLI-supported-412991)](#codex-cli)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

Omega wraps the coding agent you already use, such as **Claude Code** or **OpenAI Codex CLI**, with
hooks that it cannot talk its way past. It doesn't reason or write code itself. It intercepts,
records, proves and refuses:

- **Blocks dangerous commands** before they run: `git push --force`, `terraform apply`,
  `DROP DATABASE`, `rm -rf ~`, `curl | sh`, nested agents, and edits to its own hooks.
- **Requires a contract before code.** Non-trivial changes need a Given/When/Then contract that a
  human approved *in their own words*. The agent can't approve its own work.
- **Requires an observed failing test** before a source file can change.
- **Re-proves the work at every Stop.** Six gates (`proof`, `tdd`, `contract`, `review`, `cost`,
  `ship`) run in parallel and write clearances bound to the sha256 of every touched file.
- **Caps LLM spend** per call, session, run and month.
- **Signs git.** Commits and pushes only as the trusted signing identity; unsigned or foreign
  commits never leave the machine.

> **Status: early (v0.1).** The terminal integration with Claude Code and Codex CLI is the supported
> way to use Omega. The web dashboard is an experimental preview.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Hook map](#hook-map)
- [CLI reference](#cli-reference)
- [Safety model](#safety-model)
- [Configuration](#configuration)
- [Web dashboard (preview)](#web-dashboard-preview)
- [Development](#development)
- [Roadmap](#roadmap)
- [License](#license)

## How it works

```
 you (terminal)                       owns sign-off, the override token and the signing key
   │
   ▼
 coding agent (Claude Code │ Codex CLI)
   │ tool calls
   ▼
 Omega hooks  ── PreToolUse ──► guards: fail closed (exit 2) on anything they can't prove safe
   │          ── PostToolUse ─► change ledger, background test jobs, red/green observations
   │          ── Stop ────────► proof · tdd · contract · review · cost · ship  →  clearances
   ▼
 your workspace (the app being built): every write is ledgered or refused
```

There are three trust levels. The Omega repo is trusted and protected from the agent. The state
directory is written by Omega and readable by the agent. Your workspace is written by the agent and
governed by Omega. The full specification is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Requirements

- **Hooks** (`bin/`, `hooks/`, `scripts/`): Python 3.9+ **standard library only**. The macOS system
  `/usr/bin/python3` is enough; `bin/launch.sh` picks the interpreter.
- **An agent runtime**: [Claude Code](https://docs.anthropic.com/en/docs/claude-code) or
  [Codex CLI](https://github.com/openai/codex).
- **Optional tools** that sharpen ship readiness: `gitleaks`, `terraform`, `hadolint`, `squawk`,
  `ruff`, `dbt`, `mutmut`, `gh`. If one is missing, its check reports `UNVERIFIED` with an install
  hint. It never reports `PASS`.

## Quick start

```sh
git clone https://github.com/shassaan/omega.git ~/omega
```

### Claude Code

```sh
python3 ~/omega/scripts/install_workspace.py /path/to/your-app --provider claude
cd /path/to/your-app && claude
```

This merges Omega's hooks into `/path/to/your-app/.claude/settings.json` using absolute paths. It
keeps your other keys and hooks, adds `permissions.deny` rules as a second layer of protection,
and adds `.omega/` to `.gitignore`.

### Codex CLI

```sh
python3 ~/omega/scripts/install_workspace.py /path/to/your-app --provider codex
cd /path/to/your-app && codex
```

This writes `.codex/hooks.json` and sets `[features] hooks = true` in `.codex/config.toml`. Codex
asks you to trust project hooks the first time.

### What a session looks like

1. The session starts with Omega's laws, the commands and the workspace facts in context.
2. For a non-trivial change, the agent posts its scenarios in chat, proposes a contract under
   `docs/contracts/<slug>.md` and asks you to approve it. You answer in your own words.
3. The agent writes a failing test, Omega observes it fail, and only then does the source edit go
   through.
4. When the agent tries to stop, the six gates run. Missing proof blocks with actionable lines.
   After four blocked Stops the session is released and marked `NOT verified`.
5. You ship with `scripts/auto_ship.py`: branch, signed commit, push and a draft PR, but only when
   every clearance is fresh.

## Hook map

Every hook is started by `sh bin/launch.sh [--guard] <script> --provider claude|codex`.

| Event | Script | What it does |
|---|---|---|
| SessionStart | `bin/session_start.py` | git baseline, override token `hs-xxxxxx`, ≤ 12 KB of context (laws, commands, stack) |
| PreToolUse (guard) | `bin/pre_tool_use.py` | Bash → `prod_guard` (dangerous verbs, unwrapped recursively) and `bash_write_guard` (shell writes into governed files); edits → protected paths, contract write gate, secret-in-edit, TDD gate. Fails closed on any error. |
| PostToolUse / PostToolUseFailure | `bin/post_tool_use.py` | change ledger (sole writer), detached test/lint jobs, red/green observations, feedback |
| Stop | `bin/stop_orchestrator.py` | proof · tdd · contract · review · cost · ship gates in parallel, hash-bound clearances, loop guard |

Claude Code blocks with exit 2 and a reason on stderr. Codex blocks with exit 0 and a JSON decision.
A Python traceback (exit 1) would fail open on both, so Omega never lets one escape.

## CLI reference

Prefix each command with `sh bin/launch.sh`. Session-scoped commands take `--session S`. The
workspace defaults to `$OMEGA_WORKSPACE` or the current directory.

| Command | Purpose |
|---|---|
| `hooks/contract_gate.py propose --file docs/contracts/<slug>.md` | allow writing a contract after posting scenarios in chat |
| `hooks/contract_gate.py request` / `record --quote "<human's words>"` / `status --json` / `validate <file>` | sign-off flow; `record` accepts only a real human turn after the request |
| `hooks/tdd_gate.py status --json` / `run` / `map` | observed-red state per source file |
| `bin/stop_orchestrator.py status \| run --json \| override --token hs-… --reason R` | last verdict, run gates on demand, human-token release |
| `hooks/tokentoll_gate.py estimate \| record \| check \| report \| scan` | cost estimates, ledger, caps |
| `hooks/buildtime_compiler.py init \| mine \| synth \| shadow \| report \| promote \| demote \| canary` | compile bounded LLM call sites into rules; promote only when the Wilson upper bound of disagreement is < 0.5% |
| `hooks/ship_readiness.py run [--mode full] [--strict] --json` | infra · database · application · analytics · observability matrix |
| `scripts/auto_ship.py --dry-run \| --yes [--allow-unverified]` | branch, signed commit, push, draft PR (`gh`, or the REST fallback) |
| `scripts/create_gauntlet.py [--omega-repo owner/repo@ref]` | writes a CI gauntlet (`.github/workflows/gauntlet.yml`) and `.gitleaks.toml` into the workspace |
| `scripts/install_workspace.py <workspace> [--provider claude\|codex\|both]` | install hooks into a workspace |

Exit codes outside hooks: 0 ok, 1 refused/failed, 2 cannot determine (fail closed), 3 nothing to do.

## Safety model

- **Hooks enforce; prompts only inform.** Every rule lives at the highest level that can decide it
  (check > hook > rule > command > prompt).
- **Fail closed.** If a guard gets input it can't parse, or hits an internal error, it denies and
  says why. A required gate that can't prove something reports `UNVERIFIED`, which blocks.
- **The agent can't approve itself.** Sign-off counts only from an allow-listed human transcript
  turn. Assistant text, tool results, meta, SDK, compaction, slash-command and sidechain entries
  never count.
- **Hash-bound clearances.** `proof.json`, `contract.json` and `review.json` carry the sha256 of
  every changed file. Any later edit makes them stale.
- **Protected paths.** The agent can't edit hook configs, `.git/`, `.omega/`, Omega itself, the
  session transcript, or `~/.claude` and `~/.codex`, whether through edit tools or shell writes.
- **Signed git.** Requires `commit.gpgsign=true` plus the trusted `user.email` and
  `user.signingkey`. Identity or signing overrides are blocked, and `git push` is refused if any
  outgoing commit is unsigned or signed by someone else. Tokens never appear in argv or remote URLs.
- **Known limits** ([ARCHITECTURE §30](docs/ARCHITECTURE.md)): no hook sees what a program does once
  it's running (`make`, `npm run`, scripts), so credentials remain the real boundary. Codex
  `write_stdin` bypasses PreToolUse. The transcript format is undocumented, so if parsing breaks it
  degrades to "no human turn", never to "approved".

Found a way around a guard? Please report it privately; see [SECURITY.md](SECURITY.md).

## Configuration

Defaults live in [`omega.config.json`](omega.config.json): guards, TDD mappings, proof suites, Stop
gates, cost caps and prices, ship settings and the git identity. A workspace can pin its signing
identity in `.omega/config.json`.

| Environment variable | Purpose |
|---|---|
| `OMEGA_WORKSPACE` | workspace for CLI commands (default: cwd) |
| `OMEGA_STATE_DIR` | where ledgers, jobs and approvals live (default: `<omega>/.omega/state`) |
| `OMEGA_DEV=1` | dogfood mode: lift write protection on Omega's own files |
| `OMEGA_TDD_MODE` | override `tdd.mode` |
| `OMEGA_BUDGET_PER_CALL_USD`, `…_PER_SESSION_USD`, `…_PER_RUN_USD`, `…_MONTHLY_USD` | override cost caps |
| `OMEGA_GIT_TOKEN` | push token, handed to git through `bin/git-askpass.sh`, never argv |

## Web dashboard (preview)

> **Experimental.** The dashboard is a starting point, and its API and UI will change. For real
> work, use the terminal integration above.

`python -m ui.server` runs `claude -p` / `codex exec` headless with provider keys stored in the
dashboard (encrypted with Fernet at rest). Sign-off comes from an HMAC-signed human-turn log. It
needs Python 3.11+ and `ui/requirements.txt`.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r ui/requirements.txt
export OMEGA_SECRET="$(.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
.venv/bin/python -m ui.server --host 127.0.0.1 --port 8787
```

The server prints where its bearer token lives (`OMEGA_UI_TOKEN`, else `<state>/ui/ui_token`, mode
0600). On the first run for each runtime, it checks that hooks actually fire under
`--bare --settings`, and refuses runs if they don't.

## Development

Omega governs its own repository. Opening Claude Code here runs the checked-in hooks, so set
`OMEGA_DEV=1` when you need to edit `bin/`, `hooks/`, `schemas/` or `scripts/`. Coding agents should
read [`AGENTS.md`](AGENTS.md) first.

```sh
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q -p no:cacheprovider tests --ignore=tests/ui     # hook side, Python 3.9+
.venv/bin/python -m pytest -q -p no:cacheprovider tests/ui           # dashboard, Python 3.11+
bash scripts/check-all.sh                                             # everything CI runs
```

| Path | What lives there |
|---|---|
| `bin/` | hook entry points and the POSIX launcher |
| `hooks/` | guards, gates and the stdlib-only `hooks/lib` |
| `schemas/` | JSON Schemas for the clearances |
| `scripts/` | installer, auto-ship, CI gauntlet generator, `check-all.sh` |
| `mental-models/` | short briefs injected at session start |
| `ui/` | experimental web dashboard (FastAPI) |
| `docs/` | [architecture](docs/ARCHITECTURE.md), [decisions](docs/DECISIONS.md), [verification](docs/VERIFICATION.md), [contracts](docs/contracts/README.md) |

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## Roadmap

- More agent runtimes: Gemini CLI and other hook-capable agents (an adapter per runtime in
  `hooks/lib/adapters.py`).
- Install `AGENTS.md` into governed workspaces so any agent gets Omega's laws.
- A more complete web dashboard.
- Packaged releases (`pipx install`).

## License

Omega is licensed under the [GNU Affero General Public License v3.0](LICENSE). If you run a
modified version as a network service, you must offer its source to the users of that service.

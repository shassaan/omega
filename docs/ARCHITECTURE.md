# Omega — Binding Implementation Specification

Status: BINDING. Version 1 (2026-10-13). Author: architect phase (Fable 5.1).

Four implementers (CORE, GUARDS, GATES, UI) build from this document in parallel without talking
to each other. Every file path, module name, public signature, CLI flag, env var, exit code and JSON
shape below is fixed. "MUST" is a requirement; "SHOULD" is a default an implementer may change only
by recording the reason in `docs/DECISIONS.md`. Where this document and a research report disagree,
this document wins; where this document is silent, the research reports (`docs/research/01..03`) are
the fallback, in that order of precedence.

Sources: `docs/research/01-reference-harness-algorithms.md` (proven designs, adapted),
`docs/research/02-hook-protocols-and-security.md` (protocol facts, corrections),
`docs/research/03-cost-buildtime-evals-shipping.md` (cost, buildtime, ship, UI),
`docs/research/code/*.py` (tested reference code the implementers MUST port, not rewrite).

---

## 0. Decisions that shape everything

| # | Decision | Why |
|---|---|---|
| D1 | Hook-side code (`bin/`, `hooks/`, `scripts/`) targets **Python 3.9+, stdlib only**. `ui/` targets Python 3.11+ with `ui/requirements.txt`. | `/usr/bin/python3` on the dev Mac is 3.9.6; the task fixes JSON config because 3.9 has no `tomllib`. |
| D2 | The harness **governs a separate workspace** (`OMEGA_WORKSPACE`, default: the hook payload `cwd`). The harness repo is installed once and reused. Dogfood mode (workspace == harness root) is supported. | A generated SaaS app is the thing being guarded, not the harness. |
| D3 | Session state lives under `OMEGA_STATE_DIR` (default `<harness_root>/.omega/state`). **Clearances live in the workspace** at `<workspace>/.omega/clearances/`. | `auto_ship` and the UI look at a workspace, not a session; a clearance is a fact about files. |
| D4 | Output dialect: **Claude blocks with exit 2 + stderr; Codex blocks with exit 0 + schema-valid JSON**. Internal errors in guards print the deny JSON, write the reason to stderr and exit 2 on both providers. | Exit 1 (a Python traceback) fails OPEN on both providers (research 02 A.4, C.1). |
| D5 | `changed.jsonl` has exactly **one writer: `bin/post_tool_use.py`**. Git-snapshot reconciliation at Stop writes a separate `reconciled.jsonl`. Proof scope is the union. | Ownership clarity (GUARDS vs GATES) and the task's "sole writer" rule. |
| D6 | Human sign-off is proven only from an **allow-listed human transcript turn** (terminal) or from the **UI server's append-only human-turn log** (web). The agent cannot author either. | Mission rule 6. |
| D7 | The Stop gate has **four states** (`PASS`, `FAIL`, `UNVERIFIED`, `NOT_APPLICABLE`); `UNVERIFIED` blocks when the gate is required; missing proof is never `PASS`. | Research 01 §4, §12. |
| D8 | The loop guard is a per-session counter: after **4** blocked Stops the gate releases, records `verified:false, released:true`, resets the counter. A human-relayed token (`hs-<6hex>`) releases earlier. | Bounded trapping. |
| D9 | TDD gate default mode is **`strict`**: a source file may be edited only when its mapped test file exists on disk and `red.jsonl` holds a red observation for the **current sha256** of that test file. `red-or-green` mode is a documented relaxation. | Mission rule 7. |
| D10 | The agent may commit and push (and run `auto_ship.py --yes`), but only signed commits made as the trusted identity: `commit.gpgsign=true`, the trusted `user.email` and `user.signingkey` (the workspace repository's effective git config, or the `git.identity` pin in `.omega/config.json`). `prod_guard` enforces it before every commit-making command and verifies every outgoing commit before `git push` (§21a). | Revised 2026-10-13 at the human's request; replaces "human owns git". |
| D11 | Hook scripts, adapter configs and the state dir are **protected paths**; the agent cannot edit them through edit tools or shell writes. Dogfood development lifts harness-root protection with `OMEGA_DEV=1`. | Research 01 §12 residual weakness, closed here. |
| D12 | Gemini is a **key-store-only** provider in v1 (no runtime). Runtimes are `claude` (Anthropic) and `codex` (OpenAI). | No hook-capable Gemini runtime is specified. |
| D13 | All timestamps are written twice: `ts` (ISO-8601 UTC, `%Y-%m-%dT%H:%M:%SZ`) and `ts_ns` (`time.time_ns()`). Ordering always uses `ts_ns`. | Human-readable plus monotonic. |
| D14 | Code is comment-free. One module docstring per file; no inline comments; names carry meaning. | Mission §1.3. |

---

## 1. The Knowledge & Cost Hierarchy

`Check (static linter) > Hook (Python/Bash) > Rule (linter config) > Command (CLI) > Prompt`.
Higher levels are cheaper (zero tokens), deterministic and testable; lower levels cost tokens and
cannot be trusted to enforce anything. A behaviour MUST live at the highest level that can decide it.

| Level | When it runs / token cost | What lives here in this harness |
|---|---|---|
| **Check** | CI and Stop; zero tokens; repo-wide; deterministic | `hooks/ship_readiness.py` (5 tiers), stdlib migration rules, `gitleaks`, `ruff`/`eslint`/`tsc`, mutation gate, JSON-schema validation of clearances, `tokentoll_gate.py scan` (static call-site cost), `tests/guards/test_adapters.py` (adapter parity), `scripts/check-all.sh` |
| **Hook** | Per tool call and per Stop; zero tokens; sub-second | `prod_guard`, `bash_write_guard`, protected-path guard, secret-in-edit guard, `tdd_gate`, contract write gate, change ledger, detached background runner, `stop_orchestrator`, session context injection |
| **Rule** | Consumed by checks and hooks; never executes by itself | `omega.config.json` policy tables (prices, caps, test mappings, protected/exempt globs, allowlists, deny tables), generated `ruff`/`eslint`/`stryker`/`mutmut` config in the workspace, `.gitleaks.toml`, the three JSON schemas |
| **Command** | On demand by agent or human; zero tokens | `contract_gate.py propose/request/record/status/override`, `tdd_gate.py status/run/map`, `tokentoll_gate.py estimate/record/check/report/scan`, `buildtime_compiler.py *`, `ship_readiness.py run/mutation`, `auto_ship.py` (human), `create_gauntlet.py` |
| **Prompt** | Every turn; costs tokens; weakest | `bin/session_start.py` context (≤ 12 KB), `mental-models/*.md`, `docs/contracts/*.md`, the block and feedback messages hooks print |

Corollaries: a prompt never enforces; a hook never trusts a prompt; a check never trusts a hook's
summary (it re-runs). Every block message names the command that fixes the situation.

---

## 2. Final directory layout

```
omega/
├── README.md                          CORE  (skeleton; final verifier completes)
├── omega.config.json                CORE  (policy; full default in §9)
├── requirements-dev.txt               CORE  (pytest, jsonschema; dev only)
├── bin/
│   ├── launch.sh                      CORE  interpreter resolver; every hook starts here
│   ├── git-askpass.sh                 GATES prints $OMEGA_GIT_TOKEN for git pushes (UI mode)
│   ├── session_start.py               GUARDS
│   ├── pre_tool_use.py                GUARDS dispatcher: Bash → prod_guard, bash_write_guard; edits → protected, contract write gate, secret-in-edit, tdd_gate
│   ├── post_tool_use.py               GUARDS ledger writer, job launcher, feedback harvester
│   └── stop_orchestrator.py           GATES  parallel gates, clearances, loop guard
├── hooks/
│   ├── __init__.py                    CORE
│   ├── lib/                           CORE  shared library (§3)
│   │   ├── __init__.py                OMEGA_VERSION
│   │   ├── io.py        payload read, Decision, emit
│   │   ├── event.py     Event/Mutation normalization, apply_patch parser, provider detection
│   │   ├── config.py    omega.config.json + workspace overrides + env
│   │   ├── paths.py     harness_root, state_root, workspace, governed/protected/exempt/scratch
│   │   ├── state.py     session context, session dir, atomic json, counters, latest_session
│   │   ├── ledger.py    changed.jsonl / reconciled.jsonl readers, unparsed mutations, contracts_touched
│   │   ├── jobstore.py  detached jobs, harvest, settle, cancel, classification
│   │   ├── run_job.py   the detached runner process
│   │   ├── transcript.py  human-turn allow-list (Claude, Codex, UI log), quotes, usage extraction
│   │   ├── shell.py     command splitter, tokens, expansions masking, heredocs, redirects, unwrap
│   │   ├── hashing.py   sha256 helpers, snapshots, canonical json, fingerprints
│   │   ├── redaction.py secret/PII regexes (ported from docs/research/code/redaction.py), logging filter
│   │   ├── contracts.py contract parser, validator, fingerprint
│   │   ├── testmap.py   source↔test mapping, runner selection, interpreter resolution
│   │   ├── gitsnap.py   git status snapshot, deltas, baseline, reconcile
│   │   ├── costledger.py cost ledger rows, price lookup, token estimate, sums, locks
│   │   └── adapters.py  HOOK_TABLE, render_claude_settings, render_codex_hooks, harness_command
│   ├── prod_guard.py                  GUARDS
│   ├── bash_write_guard.py            GUARDS
│   ├── tdd_gate.py                    GUARDS
│   ├── contract_gate.py               GUARDS
│   ├── stop_proof.py                  GATES
│   ├── tokentoll_gate.py              GATES
│   ├── buildtime_compiler.py          GATES
│   └── ship_readiness.py              GATES
├── scripts/
│   ├── auto_ship.py                   GATES  branch, signed commit, push, PR
│   ├── create_gauntlet.py             GATES
│   ├── install_workspace.py           GUARDS renders adapter configs with absolute paths into a workspace
│   └── check-all.sh                   GATES
├── schemas/
│   ├── proof.schema.json              (written by architect; CORE validates in tests)
│   ├── contract.schema.json
│   └── review.schema.json
├── ui/
│   ├── __init__.py                    UI
│   ├── server.py                      UI   FastAPI app, REST + WebSocket
│   ├── provider_manager.py            UI   key store (Fernet), router, backoff, cost hooks
│   ├── runner.py                      UI   headless claude/codex subprocess, event normalization, hub
│   ├── requirements.txt               UI
│   └── static/                        UI   index.html, app.js, styles.css (no build step)
├── mental-models/
│   ├── architecture.md
│   ├── database_rules.md
│   └── provider_contracts.md
├── docs/
│   ├── ARCHITECTURE.md                this file
│   ├── DECISIONS.md                   implementers append deviations here (one line each)
│   ├── contracts/README.md            contract format spec
│   ├── contracts/example-user-signup.md
│   └── research/                      inputs
├── .claude/settings.json              GUARDS (rendered by adapters.render_claude_settings, dogfood form)
├── .codex/hooks.json                  GUARDS (rendered by adapters.render_codex_hooks, dogfood form)
├── .codex/config.toml                 GUARDS ([features] hooks = true)
├── .gitignore                         CORE  (.omega/, .venv/, __pycache__/, ui keys)
└── tests/
    ├── conftest.py                    CORE  shared fixtures (§27.5)
    ├── fixtures/                      CORE  claude/*.json, codex/*.json, transcripts/*.jsonl
    ├── lib/                           CORE
    ├── guards/                        GUARDS
    ├── gates/                         GATES
    └── ui/                            UI
```

Every Python entry script (`bin/*.py`, `hooks/*.py`, `scripts/*.py`) begins with the same four
lines, so `import hooks.lib...` works whether started via `launch.sh` or directly:

```python
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
```

(`hooks/lib/run_job.py` uses `parents[2]`.) `launch.sh` runs `python -I -B` so neither `PYTHONPATH`
nor the workspace cwd can inject a module; the harness root inserted by the bootstrap is a protected
path (§8.3).

Language rules for 3.9 compatibility (hook side): `from __future__ import annotations` in every
module; no `match`; no `X | Y` outside annotations; `typing.Optional`/`Union` at runtime; no
`tomllib`; no `zip(strict=)`; `dataclasses` allowed; `subprocess`, `json`, `re`, `shlex`,
`hashlib`, `hmac`, `fcntl`, `concurrent.futures`, `urllib.request` are the only I/O libraries.

---

## 3. `bin/launch.sh` — the interpreter resolver

```
sh bin/launch.sh [--guard] <script path relative to harness root> [args...]
```

- Resolves `root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)`.
- Candidate order: `$root/.venv/bin/python`, `python3.13`, `python3.12`, `python3.11`, `python3.10`,
  `python3.9`, `python3`; the first whose `sys.version_info >= (3, 9)` wins.
- Exports `OMEGA_HOME="$root"` and `PYTHONDONTWRITEBYTECODE=1`, then
  `exec "$py" -I -B "$root/$script" "$@"`.
- No interpreter found: prints `[omega] <script> NOT run: no Python 3.9+ found (checked
  $root/.venv and PATH)` to stderr; exits **2** with `--guard`, **1** otherwise.
- `--guard` MUST be used for every `PreToolUse` registration and for nothing else.
- The script never sources the user's shell rc and never reads the workspace.

Shell portability: POSIX `sh` only (no bashisms); the dev Mac's `/bin/sh` is what runs it.

---

## 4. Hook I/O contract

### 4.1 Input: the raw payload

Every hook reads **one JSON object from stdin**. Fields the harness relies on (all read with `.get`):
`session_id`, `hook_event_name`, `cwd`, `transcript_path`, `permission_mode`, `tool_name`,
`tool_input`, `tool_response`, `tool_use_id`, `stop_hook_active`, `last_assistant_message`,
`source` (SessionStart), `trigger` (PreCompact), `prompt`, `model` (Codex, Claude SessionStart),
`agent_id` (SubagentStop). Anything else is kept in `Event.raw`.

Provider is passed explicitly by the adapter config as `--provider claude|codex`; detection is only a
fallback (§4.2). Unknown payloads (not a JSON object) are an internal error (§4.6).

### 4.2 Normalized event (`hooks/lib/event.py`)

```python
@dataclass
class Mutation:
    path: str            # absolute (os.path.abspath; symlinks NOT resolved); as given by the tool
    kind: str            # "added" | "modified" | "deleted" | "renamed_from" | "renamed_to" | "unknown"

@dataclass
class Event:
    provider: str                      # "claude" | "codex"
    name: str                          # hook_event_name
    session_id: str
    transcript_path: Optional[str]
    cwd: str
    workspace: str                     # paths.workspace_of(payload) (§8.1), realpath
    tool_name: Optional[str]
    tool_input: dict
    tool_response: Optional[dict]
    tool_use_id: Optional[str]
    command: Optional[str]             # Bash command text, or apply_patch patch text
    is_patch: bool                     # tool is apply_patch, or Bash command contains "*** Begin Patch"
    mutations: list                    # list[Mutation] for edit tools / patches; [] otherwise
    unparsed_mutation: Optional[str]   # reason when an edit-tool payload yields no path (fail closed)
    stop_hook_active: bool
    last_assistant_message: Optional[str]
    source: Optional[str]              # SessionStart.source or PreCompact.trigger
    prompt: Optional[str]
    permission_mode: Optional[str]
    model: Optional[str]
    run_id: Optional[str]              # env OMEGA_RUN_ID (UI mode) else None
    raw: dict

def normalize(payload: dict, provider: Optional[str] = None) -> Event
def provider_of(payload: dict, explicit: Optional[str] = None) -> str
def mutations_of(payload: dict) -> tuple[list, Optional[str]]
def parse_apply_patch(text: str, cwd: str) -> list      # list[Mutation]
def is_edit_tool(tool_name: Optional[str]) -> bool
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit", "apply_patch")
```

`provider_of`: explicit arg → env `OMEGA_PROVIDER` → `tool_name == "apply_patch"` → codex →
`"/.codex/" in transcript_path or "rollout" in transcript_path` → codex → else `"claude"`.

`mutations_of` rules: Claude `Edit`/`Write` → `tool_input.file_path`; `MultiEdit` →
`file_path` (plus `edits[].file_path` if present); `NotebookEdit` → `notebook_path` (fallback
`file_path`); `apply_patch` or Bash containing `*** Begin Patch` → `parse_apply_patch` on
`tool_input.command` (`*** Add File: p` → added, `*** Update File: p` → modified,
`*** Delete File: p` → deleted, `*** Move to: p` → renamed_to with the preceding path renamed_from);
relative patch paths resolve against `cwd`. An edit tool with no path yields
`unparsed_mutation="<tool> payload has no file path"`. Kind for Claude `Write`: `added` if the file
does not exist at PreToolUse time else `modified`; `Edit`/`MultiEdit`/`NotebookEdit`: `modified`.

### 4.3 Output: `Decision` and `emit` (`hooks/lib/io.py`)

```python
@dataclass
class Decision:
    action: str            # "allow" | "deny" | "block" | "feedback"
    reason: str = ""       # agent-facing text on deny/block/feedback (already redacted)
    context: str = ""      # text injected on allow (SessionStart/PreToolUse additionalContext, PostToolUse pass lines)
    system_message: str = ""

def read_payload() -> dict                       # raises PayloadError on non-object / empty stdin
def emit(provider: str, event_name: str, decision: Decision) -> int   # prints, returns exit code
def fail_closed(provider: str, event_name: str, exc: BaseException, script: str) -> int  # §4.6
def debug(msg: str) -> None                      # appends to <session_dir>/hooks.log when OMEGA_DEBUG=1
```

`emit` output matrix (the ONLY place that knows these shapes):

| event | provider | allow / feedback-pass | deny / block / feedback-fail |
|---|---|---|---|
| PreToolUse | claude | exit 0; stdout empty, or `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":<context>}}` when `context` non-empty | **stderr** = reason; exit **2** |
| PreToolUse | codex | exit 0; stdout `{}` or the same allow JSON | exit 0; stdout `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":<reason>}}` |
| PostToolUse / PostToolUseFailure | claude | exit 0; stdout = context (pass lines) | stderr = reason; exit 2 (feedback only; never undoes the edit) |
| PostToolUse | codex | exit 0; `{}` or `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":<context>}}` | exit 0; `{"decision":"block","reason":<reason>}` |
| Stop / SubagentStop | claude | exit 0; stdout = context (advisory summary) | stderr = reason; exit 2 |
| Stop | codex | exit 0; `{}` | exit 0; `{"decision":"block","reason":<reason>}` |
| SessionStart | claude | exit 0; **plain stdout** = context | n/a (never blocks) |
| SessionStart | codex | exit 0; `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":<context>}}` | n/a |

Rules: a Codex block always carries a non-empty reason (`[omega] blocked without a stated reason`
if empty). Never emit `ask`/`defer`/`continue:false`/`suppressOutput` (Codex rejects `ask` and fails
open). Never print anything else to stdout. `reason` and `context` pass through
`redaction.redact()` inside `emit`.

### 4.4 Exit codes (hook mode)

| code | meaning |
|---|---|
| 0 | allow / context delivered |
| 2 | block (Claude; also honoured by Codex as block with stderr reason) |
| 1 | NEVER emitted deliberately: it is a fail-open hook error on both providers |

### 4.5 Dispatch per entrypoint

`bin/session_start.py --provider P`: `state.configure` → `gitsnap.ensure_baseline` → ensure
`.omega/` is in `<workspace>/.git/info/exclude` → `state.ensure_override_token` → compose context
(§25) → `emit(allow, context=...)`. Exceptions are swallowed into a one-line warning in the context;
exit 0 always.

`bin/pre_tool_use.py --provider P` (guard): `state.configure` → `Event`; then first deny wins:
1. `tool_name == "Bash"` and not `is_patch`: `prod_guard.judge(command, GuardContext)` →
   `bash_write_guard.judge(command, GuardContext)`.
2. `is_edit_tool(tool_name)` or `is_patch`: `unparsed_mutation` → deny `omega.unparsed_mutation`;
   `paths.is_protected(p)` for any mutation → deny `omega.protected_path`;
   `contract_gate.write_gate(event, ctx)`; `redaction.strict_secret_hits(new_content)` → deny
   `secrets.in_edit` (skipped for `redaction.fixture_globs`); `tdd_gate.judge(event.mutations, ctx, cfg)`.
3. Else allow.
Any exception → `io.fail_closed` (§4.6).

`bin/post_tool_use.py --provider P`: `state.configure` → `Event`; if `name ==
"PostToolUseFailure"`: harvest only. Else: for each mutation under the workspace and
`paths.is_governed` → `ledger.append(ctx, path, kind)`; `unparsed_mutation` →
`ledger.note_unparsed`; contract files → `ledger.note_contract_touched`; launch test jobs
(`testmap` scope per mutation; §14.4) and lint jobs; `jobstore.harvest(ctx)` → failures become
`Decision(feedback-fail, reason)` else `Decision(allow, context=pass lines)`. Never raises; never
blocks the edit.

`bin/stop_orchestrator.py --provider P`: §16.

### 4.6 Internal errors

`io.fail_closed(provider, event, exc, script)`: for PreToolUse and Stop prints the provider's deny/
block JSON to stdout with reason `[omega] <script> failed closed: <ExcType>: <msg[:200]> — fix the
harness or set OMEGA_DEBUG=1 and read <session_dir>/hooks.log`, writes the same to stderr, exits
**2**. For PostToolUse and SessionStart it writes the warning to stderr and exits 0 (those events
cannot block and must not fail the session). Unreadable stdin on a guard is an internal error.

---

## 5. State store

### 5.1 Root and session directory

`paths.state_root()` = `$OMEGA_STATE_DIR` else `<harness_root>/.omega/state` (created 0700).
`paths.workspace_hash(ws)` = first 16 hex chars of sha256 of `os.path.realpath(ws)` (utf-8).

```
<state_root>/
  observed/<provider>.json                 {"<EventName>": "<iso ts>"}  proof that each hook really fired
  cost/ledger.jsonl                        global spend ledger (§18.2)   writer: costledger.append
  cost/ledger.lock                         flock sidecar
  ui/keyfile                               0600; Fernet key when OMEGA_SECRET unset
  ui/keys.json                             ciphertext key store (§23.4)
  ui/ui_token                              0600; operator bearer token
  ui/runs/<run_id>/run.json | events.jsonl | human_turns.jsonl | stdout.log | stderr.log
  <wshash>/<provider>/<session_id>/        "session dir"
    context.json            {provider, workspace, session_id, transcript_path, run_id, created_ts, model}
    baseline.json           {ts, ts_ns, state: {<root>: {<abs path>: sha256|"<deleted>"|"<dir>"}}}
    changed.jsonl           writer: bin/post_tool_use.py only (§5.2)
    reconciled.jsonl        writer: bin/stop_orchestrator.py only (same row shape, kind reconciled|deleted)
    unparsed_mutation.txt   one reason per line
    contracts_touched.txt   one absolute contract path per line, append-only
    contract_proposal.json | contract_request.json | contract_approval.json | contract_override.json
    override_token          "hs-<6hex>", created by session_start, never rotated within a session
    stop_attempts           integer text file
    stop_override.json      {token, reason, turn_uuid, ts, ts_ns, consumed}
    red.jsonl | green.jsonl writer: hooks/lib/run_job.py only (§14.5)
    cost_cursor.json        {last_message_id} for transcript usage ingestion
    jobs/<job_id>.job.json | .pid | .result.json | .delivered
    last_stop.json          the aggregate verdict of the latest Stop (§16.6)
    hooks.log               debug only
```

`state.configure(event) -> SessionContext` runs first in every hook: resolves provider, workspace,
session dir (mkdir), records `observed/<provider>.json[event.name] = ts`, writes `context.json` if
absent (payload-less CLI commands read it back).

```python
@dataclass
class SessionContext:
    provider: str
    workspace: str
    session_id: str
    transcript_path: Optional[str]
    run_id: Optional[str]
    dir: Path                       # the session dir
    harness_root: Path
    cfg: "Config"

def configure(event: Event) -> SessionContext
def load_context(session_id: Optional[str], workspace: Optional[str] = None, provider: Optional[str] = None) -> SessionContext
def latest_session(workspace: str, provider: Optional[str] = None) -> str     # exactly one candidate with a changed.jsonl else raises AmbiguousSession(candidates)
def session_dir(ctx: SessionContext) -> Path
def read_json(path: Path, default=None)
def write_json_atomic(path: Path, obj) -> None          # tmp-<pid> + os.replace
def append_jsonl(path: Path, row: dict) -> None         # single write + flush
def counter_get(ctx, name) -> int; counter_incr(ctx, name) -> int; counter_reset(ctx, name) -> None
def ensure_override_token(ctx) -> str
```

`--session S` on every CLI; omitted → `latest_session(workspace, provider)`; ambiguity → exit 2 with
the candidate list. `OMEGA_SESSION_ID` env is honoured before `latest_session`.

### 5.2 Changed-file ledger (`hooks/lib/ledger.py`)

Row (one JSON object per line):

```json
{"ts":"2026-10-13T10:00:00Z","ts_ns":1760349600000000000,"path":"/abs/workspace/src/auth/signup.py","rel":"src/auth/signup.py","kind":"modified","tool":"Edit","tool_use_id":"toolu_01...","provider":"claude","session_id":"...","sha256_after":"<hex or <deleted>>"}
```

`kind` ∈ `added|modified|deleted|renamed_from|renamed_to` (`changed.jsonl`) and
`reconciled|deleted` (`reconciled.jsonl`). `sha256_after` is computed by post_tool_use after the
tool ran.

```python
def append(ctx, path: str, kind: str, tool: Optional[str], tool_use_id: Optional[str]) -> None   # changed.jsonl
def append_reconciled(ctx, path: str, kind: str) -> None                                           # reconciled.jsonl
def rows(ctx) -> list[dict]                 # both files, ts_ns order
def paths(ctx) -> list[str]                 # PROOF scope: every ABSOLUTE path ever mutated, first-seen order, incl. deleted/renamed
def existing(ctx) -> list[str]              # LINT scope: paths(ctx) filtered by os.path.isfile (absolute)
def source_paths(ctx, cfg=None) -> list[str]  # existing(ctx) ∩ testmap.is_source, as WORKSPACE-RELATIVE posix paths (cfg defaults to ctx.cfg)
def paths_rel(ctx, path: str) -> str        # paths.rel(path, ctx.workspace)
def note_unparsed(ctx, reason: str) -> None; def unparsed(ctx) -> list[str]
def note_contract_touched(ctx, path: str) -> None; def contracts_touched(ctx) -> list[str]
def touched_since(state_root: Path, workspace_hash: str, ts_ns: int) -> set[str]   # other sessions' rows, for reconcile
```

### 5.3 Background job records (`hooks/lib/jobstore.py`, `hooks/lib/run_job.py`)

Job file `jobs/<job_id>.job.json`, `job_id = re.sub(r"[^A-Za-z0-9_-]", "_", scope_key) + "-" + str(ts_ns)`:

```json
{"id":"test_tests_test_signup_py-1760349600000000000","scope_key":"test:tests/test_signup.py","kind":"test","label":"pytest tests/test_signup.py","argv":["/abs/ws/.venv/bin/python","-m","pytest","-q","-x","-p","no:cacheprovider","tests/test_signup.py"],"cwd":"/abs/ws","env_add":{"PYTHONDONTWRITEBYTECODE":"1","CI":"1"},"ts":"...","ts_ns":1760349600000000000,"session_id":"...","timeout_s":240,"test_files":{"tests/test_signup.py":"<sha256 at launch>"},"source_files":["src/auth/signup.py"],"session_dir":"/abs/state/.../<session>"}
```

Result file `jobs/<job_id>.result.json` (atomic; never overwrites an existing result):

```json
{"id":"...","rc":1,"status":"fail","output":"<redacted last 200 lines, ≤16384 chars>","started_ns":...,"finished_ns":...,"duration_ms":1234,"test_files":{"tests/test_signup.py":"<sha256 at launch>"},"cancelled_by":null}
```

`status` ∈ `pass|fail|skipped_env|skipped_no_tests|not_installed|timeout|cancelled|error`.
Classification (`jobstore.classify(rc, output, argv) -> str`), in this order:
1. `rc == 0` → `pass`
2. `rc == 127` or launch `FileNotFoundError` → `not_installed`
3. `rc == 124` or `TimeoutExpired` → `timeout`
4. `is_no_tests(output)` → `skipped_no_tests` (`no tests ran`, `no tests collected`, `collected 0 items`, `No test files found`, `No tests found`, pytest rc 5)
5. `is_environment_failure(output)` → `skipped_env` (only: `No module named '<name>'` where `<name>` ∈ `cfg.proof.third_party_modules`; `Cannot find module` when `<cwd>/node_modules` is absent; `ECONNREFUSED`; `Temporary failure in name resolution`; `Max retries exceeded`; `Could not find a version that satisfies`; `connection refused`; `could not connect to server`)
6. `rc == 4` and output contains `error: unrecognized arguments` or starts with `usage:` → `error`
7. else → `fail` (red-eligible)

A `ModuleNotFoundError` for a module not in `third_party_modules` is a **fail** (the test imports
code that does not exist yet: legitimate red).

```python
def launch(ctx, scope_key: str, kind: str, label: str, argv: list, cwd: str, test_files: list, source_files: list, timeout_s: int) -> dict   # cancels older same-scope jobs; Popen(run_job.py, start_new_session=True, DEVNULL); synthetic rc=1 result on OSError
def newest(ctx, scope_key: str) -> Optional[dict]        # newest job (+result if done) for the scope
def results(ctx) -> list[dict]                           # all completed results, ts_ns order
def running(ctx) -> list[dict]
def harvest(ctx) -> Harvest                              # Harvest(failures: list[dict], passes: list[dict], skipped: list[dict]); marks .delivered; newest-per-scope only
def settle(ctx, timeout_s: float) -> list[dict]          # wait for running jobs up to timeout; return newest per scope
def cancel(ctx, job_id: str) -> None                     # killpg SIGTERM + cancelled result
def classify(rc: Optional[int], output: str, argv: list, cfg=None, cwd: Optional[str] = None) -> str   # cfg None → config.load(); rc None → error
def is_environment_failure(output: str, cfg=None, cwd: Optional[str] = None) -> bool; def is_no_tests(output: str) -> bool
```

`run_job.py <job.json>`: sleeps `cfg.tdd.debounce_s` (0.8); exits `cancelled` if a newer job with
the same `scope_key` exists; `cwd` not a dir → rc 1 `error` "working directory does not exist";
runs `subprocess.run(argv, cwd, env=os.environ+env_add, timeout)` with stdout/stderr merged;
writes the result atomically; for `kind == "test"` appends to `red.jsonl` (status `fail`) or
`green.jsonl` (status `pass`) (§14.5). It never raises; any exception becomes an `error` result.

### 5.4 TDD records

`red.jsonl` / `green.jsonl` row:

```json
{"ts":"...","ts_ns":...,"job_id":"...","scope_key":"test:tests/test_signup.py","test_files":{"tests/test_signup.py":"<sha256 at launch>"},"source_files":["src/auth/signup.py"],"argv":[...],"cwd":"/abs/ws","rc":1,"status":"fail","output_tail":"<last 40 lines, redacted>"}
```

### 5.5 Loop-guard counter

`stop_attempts` (integer file). Incremented on every blocked Stop; reset to 0 on a passing Stop and
on release. Release when `attempts >= cfg.stop.max_attempts` (4). The override token
(`override_token`) is printed in every block message; it is useful only when a human relays it
(§12.5).

---

## 6. Workspace concept

- `paths.workspace_of(payload)`: `$OMEGA_WORKSPACE` → payload `cwd` → `$CLAUDE_PROJECT_DIR` →
  `os.getcwd()`; returned as `os.path.realpath`.
- `paths.harness_root()`: `Path(hooks.lib.__file__).resolve().parents[2]`.
- The harness MUST work when `workspace != harness_root` (installed mode) and when they are equal
  (dogfood). `scripts/install_workspace.py <workspace> [--provider claude|codex|both]` renders
  `<workspace>/.claude/settings.json` (merging `hooks` into an existing file, never deleting other
  keys) and `<workspace>/.codex/hooks.json` + `.codex/config.toml` with **absolute** harness paths
  (`adapters.render_*(absolute=True)`), and appends `.omega/` to `<workspace>/.gitignore` if the
  file exists and lacks it.
- Workspace-local overrides: `<workspace>/.omega/config.json` (same schema as
  `omega.config.json`, deep-merged on top; protected path, so only a human edits it).

---

## 7. Governed, protected, exempt and scratch paths (`hooks/lib/paths.py`)

```python
def harness_root() -> Path
def state_root() -> Path
def workspace_of(payload: dict) -> str
def workspace_hash(workspace: str) -> str
def is_governed(path: str, ctx) -> bool     # under workspace or harness_root, and not under an ignored dir
def is_protected(path: str, ctx) -> bool    # §7.2
def is_exempt(path: str, ctx) -> bool       # cfg.tdd.exempt_globs (TDD only)
def is_scratch(path: str, ctx) -> bool      # §7.3
def rel(path: str, root: str) -> str
def match_globs(path_rel: str, globs: list) -> bool   # fnmatch on posix rel path; "**" means any depth
```

7.1 Ignored dirs (not governed, never ledgered): `.git`, `__pycache__`, `.venv`, `venv`,
`node_modules`, `.pytest_cache`, `.ruff_cache`, `.mypy_cache`, `.turbo`, `.next`, `dist`, `build`,
`coverage`, `target`, `dbt_packages`, `logs`, `.mutmut-cache`, `mutants`, `.omega/scratch`
(config `workspace.ignored_dirs`).

7.2 Protected (deny every agent edit and shell write; `omega.protected_path`): relative to the
workspace: `.claude/**`, `.codex/**`, `.gemini/**`, `.git/**`, `.omega/**`,
`.github/workflows/gauntlet.yml`, `.gitleaks.toml`; relative to the harness root: `bin/**`,
`hooks/**`, `schemas/**`, `scripts/**`, `omega.config.json`, `.claude/**`, `.codex/**`
(config `guards.protected_globs`). When `OMEGA_DEV=1` the harness-root set is lifted and the
session context says so loudly.

7.3 Scratch (shell writes allowed): `/dev/null`, `/dev/stdout`, `/dev/stderr`,
`tempfile.gettempdir()`, `/tmp`, `/private/tmp`, `/var/folders`, `$TMPDIR`,
`<workspace>/.scratch/**` (config `workspace.scratch_globs`).

---

## 8. Secrets and redaction (`hooks/lib/redaction.py`)

Port `docs/research/code/redaction.py` verbatim as the rule tables, then add:

```python
@dataclass
class Hit: rule: str; start: int; end: int; path: Optional[str] = None; line: Optional[int] = None
def redact(text: str, pii: bool = True) -> tuple[str, list[str]]      # placeholders "[REDACTED:<rule>]"
def scan(text: str, pii: bool = True) -> list[Hit]
def strict_secret_hits(text: str) -> list[Hit]      # strict forms only: sk-ant-api03-…AA, OpenAI T3BlbkFJ / sk-proj-, AKIA…, ghp_/github_pat_, AIza…, xox[abp]-, (sk|rk)_live_, PEM private key block
def scan_file(path: str, pii: bool = True) -> list[Hit]
def register_exact(values: list) -> None            # exact-match scrub of secrets the harness injected (plus base64/urlencoded variants)
def is_fixture(path_rel: str, cfg) -> bool          # cfg.redaction.fixture_globs
class RedactingFilter(logging.Filter)
```

Allowlisted dummies (never hits): `AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
values containing `example`, `changeme`, `placeholder`, `<your-`, `xxxx`; `noreply@anthropic.com`,
`*@example.com`, `*@example.org`. Redaction is applied: inside `io.emit`, on every job `output`
before it is written, on every UI event before `events.jsonl`, on PR bodies, on `hooks.log`.

Secret-in-edit guard (pre_tool_use): `strict_secret_hits` over `Write.content`, `Edit.new_string`,
`MultiEdit.edits[].new_string`, `NotebookEdit.new_source`, and the `+` lines of an `apply_patch`
→ deny `secrets.in_edit` naming rule and line, never the value.

---

## 9. Configuration (`omega.config.json`, `hooks/lib/config.py`)

```python
class Config:
    def get(self, dotted: str, default=None)
    def as_dict(self) -> dict
def load(harness_root: Optional[Path] = None, workspace: Optional[str] = None) -> Config
# merge order: built-in DEFAULTS (identical to the shipped file) < omega.config.json < <workspace>/.omega/config.json < env overrides
```

Env overrides (exact names): `OMEGA_STATE_DIR`, `OMEGA_WORKSPACE`, `OMEGA_PROVIDER`,
`OMEGA_SESSION_ID`, `OMEGA_RUN_ID`, `OMEGA_DEBUG`, `OMEGA_DEV`, `OMEGA_HUMAN_LOG`,
`OMEGA_SECRET`, `OMEGA_UI_TOKEN`, `OMEGA_GIT_TOKEN`, `OMEGA_TDD_MODE`,
`OMEGA_BUDGET_PER_CALL_USD`, `OMEGA_BUDGET_PER_SESSION_USD`, `OMEGA_BUDGET_PER_RUN_USD`,
`OMEGA_BUDGET_MONTHLY_USD`, `OMEGA_ALLOW_UNHOOKED`.

The shipped `omega.config.json` (CORE writes exactly this; other packages read only their keys):

```json
{
  "version": 1,
  "state": {"dir": null},
  "workspace": {
    "ignored_dirs": [".git","__pycache__",".venv","venv","node_modules",".pytest_cache",".ruff_cache",".mypy_cache",".turbo",".next","dist","build","coverage","target","dbt_packages","logs",".mutmut-cache","mutants",".omega/scratch"],
    "scratch_globs": [".scratch/**"]
  },
  "session_start": {
    "context_cap_bytes": 12000,
    "inject": ["mental-models/architecture.md","mental-models/database_rules.md","mental-models/provider_contracts.md"]
  },
  "guards": {
    "protected_globs": {
      "workspace": [".claude/**",".codex/**",".gemini/**",".git/**",".omega/**",".github/workflows/gauntlet.yml",".gitleaks.toml"],
      "harness": ["bin/**","hooks/**","schemas/**","scripts/**","omega.config.json",".claude/**",".codex/**"]
    },
    "prod": {
      "rm_rf_allowlist": ["node_modules","dist","build",".pytest_cache","__pycache__",".mypy_cache",".ruff_cache","coverage",".next",".turbo","target",".scratch"],
      "allow_local_docker": true,
      "allow_alembic_upgrade": true,
      "local_hosts": ["localhost","127.0.0.1","::1","0.0.0.0","host.docker.internal"],
      "strict_db": false,
      "extra_deny_regex": []
    }
  },
  "redaction": {"fixture_globs": ["tests/fixtures/**","**/*.example","**/fixtures/**"], "pii_fail_globs": ["**/*.py","**/*.ts","**/*.tsx","**/*.sql","**/*.md","**/*.json","**/*.yml","**/*.yaml"]},
  "transcript": {"accept_unlabelled_user_turns": false},
  "gauntlet": {
    "omega_repo": null,
    "python": "3.12",
    "node": "22",
    "action_pins": {"actions/checkout": "v4", "actions/setup-python": "v5", "actions/setup-node": "v4", "actions/cache": "v4", "actions/upload-artifact": "v4", "gitleaks/gitleaks-action": "v2"}
  },
  "tdd": {
    "mode": "strict",
    "debounce_s": 0.8,
    "job_timeout_s": 240,
    "source_exts": [".py",".ts",".tsx",".js",".jsx",".mjs",".cjs"],
    "test_globs": ["tests/**","test/**","**/__tests__/**","**/test_*.py","**/*_test.py","**/*.test.*","**/*.spec.*","**/conftest.py"],
    "exempt_globs": ["docs/**","**/*.md","**/*.txt","**/*.json","**/*.yaml","**/*.yml","**/*.toml","**/*.ini","**/*.cfg","**/*.lock","**/*.env.example","migrations/**","**/migrations/**","alembic/**","prisma/**","**/*.sql","models/**","macros/**","seeds/**","snapshots/**","infra/**","terraform/**","**/*.tf","**/*.tfvars","Dockerfile*","**/Dockerfile*","docker-compose*","**/*.html","**/*.css","**/*.scss","**/*.svg","**/*.png",".github/**","scripts/**","**/__init__.py","**/*.d.ts","**/*.config.*","**/*.stories.*","buildtime/**"],
    "mappings": [
      {"lang":"python","source":"^(?:src/|app/|backend/|server/)?(?P<pkg>(?:[^/]+/)*)(?P<name>[^/]+)\\.py$","tests":["tests/{pkg}test_{name}.py","tests/test_{name}.py","{srcdir}tests/test_{name}.py","{srcdir}test_{name}.py"]},
      {"lang":"ts","source":"^(?P<dir>(?:[^/]+/)*)(?P<name>[^/]+)\\.(?P<ext>tsx?|jsx?|mjs|cjs)$","tests":["{dir}{name}.test.{ext}","{dir}{name}.spec.{ext}","{dir}__tests__/{name}.test.{ext}","{dir}__tests__/{name}.{ext}"]}
    ],
    "overrides": {},
    "runners": {
      "python": {"argv": ["{python}","-m","pytest","-q","-x","-p","no:cacheprovider","{test}"]},
      "vitest": {"argv": ["npx","vitest","run","--reporter=dot","{test}"]},
      "jest":   {"argv": ["npx","jest","--ci","{test}"]}
    }
  },
  "contracts": {
    "dir": "docs/contracts",
    "seams": ["Unit","Integration","Functional","Journey"],
    "nontrivial": {"min_source_files": 3, "always_globs": ["migrations/**","**/migrations/**","alembic/**","prisma/**","**/*.tf","infra/**","terraform/**","**/auth/**","**/billing/**","**/payments/**","**/webhooks/**","**/*secur*","**/api/**","**/routes/**"], "new_source_file_counts": true},
    "min_quote_chars": 8
  },
  "proof": {
    "third_party_modules": ["pytest","ruff","mypy","httpx","requests","sqlalchemy","alembic","fastapi","pydantic","psycopg","psycopg2","asyncpg","redis","boto3","dbt","braintrust","langsmith","anthropic","openai","google"],
    "suites": [
      {"id":"pytest","detect":["pyproject.toml","pytest.ini","setup.cfg","tests/"],"argv":["{python}","-m","pytest","-q","-x","-p","no:cacheprovider"],"required":true,"timeout_s":200},
      {"id":"ruff","detect":["pyproject.toml","ruff.toml"],"argv":["{python}","-m","ruff","check","{changed_py}"],"required":false,"timeout_s":60},
      {"id":"vitest","detect":["vitest.config.ts","vitest.config.js","vitest.config.mts"],"argv":["npx","vitest","run","--reporter=dot"],"required":true,"timeout_s":200},
      {"id":"jest","detect":["jest.config.js","jest.config.ts","jest.config.cjs"],"argv":["npx","jest","--ci"],"required":true,"timeout_s":200},
      {"id":"tsc","detect":["tsconfig.json"],"argv":["npx","tsc","--noEmit","-p","tsconfig.json"],"required":true,"timeout_s":120},
      {"id":"eslint","detect":["eslint.config.js","eslint.config.mjs",".eslintrc.json",".eslintrc.cjs"],"argv":["npx","eslint","--max-warnings","0","{changed_js}"],"required":false,"timeout_s":60},
      {"id":"gitleaks","detect":[],"argv":["gitleaks","dir","{workspace}","--no-banner","--redact","--exit-code","1"],"required":false,"timeout_s":60}
    ],
    "settle_timeout_s": 15
  },
  "stop": {
    "max_attempts": 4,
    "gates": {
      "proof":    {"required": true,  "timeout_s": 600},
      "tdd":      {"required": true,  "timeout_s": 30},
      "contract": {"required": true,  "timeout_s": 30},
      "review":   {"required": true,  "timeout_s": 30},
      "cost":     {"required": true,  "timeout_s": 15},
      "ship":     {"required": true,  "timeout_s": 120, "mode": "fast", "unverified_blocks": false}
    }
  },
  "ship_readiness": {
    "tiers": {
      "infra":         {"detect": ["**/*.tf","Dockerfile","**/Dockerfile","docker-compose.yml","docker-compose.yaml","compose.yml","compose.yaml"]},
      "database":      {"detect": ["migrations/**","**/migrations/**","alembic.ini","alembic/**","prisma/schema.prisma","**/*.sql"]},
      "application":   {"detect": ["pyproject.toml","package.json","requirements.txt","setup.cfg"]},
      "analytics":     {"detect": ["dbt_project.yml","**/dbt_project.yml","models/**","policies/**","**/row_level_security*"]},
      "observability": {"detect": ["**/braintrust*","**/langsmith*","**/*.eval.*","evals/**",".env.example","**/otel*","**/opentelemetry*"]}
    },
    "migration_waiver_comment": "omega:allow destructive",
    "mutation": {"min_score": 0.60, "timeout_s": 900, "mutmut_version": "3.3.1", "stryker_break": 55}
  },
  "cost": {
    "caps": {"per_call_usd": 0.50, "per_session_usd": 5.0, "per_run_usd": 5.0, "monthly_usd": 100.0},
    "warn_ratio": 0.8,
    "safety_multiplier": 1.25,
    "price_version": "2026-10-13",
    "model_aliases": {"opus": "claude-opus-5-5", "sonnet": "claude-sonnet-5-5", "haiku": "claude-haiku-5-5", "fable": "claude-fable-5-1"},
    "prices": {
      "claude-fable-5-1":  {"in": 10.0, "out": 50.0, "cache_read": 0.25, "cache_write_5m": 12.5, "cache_write_1h": 20.0, "verified": true,  "source": "https://platform.claude.com/docs/en/about-claude/pricing", "fetched_at": "2026-10-13"},
      "claude-opus-5-5":   {"in": 4.0,  "out": 20.0, "cache_read": 0.20, "cache_write_5m": 5.0,  "cache_write_1h": 8.0,  "verified": true,  "source": "https://platform.claude.com/docs/en/about-claude/pricing", "fetched_at": "2026-10-13"},
      "claude-sonnet-5-5": {"in": 2.0,  "out": 10.0, "cache_read": 0.10, "cache_write_5m": 2.5,  "cache_write_1h": 4.0,  "verified": true,  "source": "https://platform.claude.com/docs/en/about-claude/pricing", "fetched_at": "2026-10-13"},
      "claude-haiku-5-5":  {"in": 0.10, "out": 0.50, "cache_read": 0.01, "cache_write_5m": 0.125,"cache_write_1h": 0.20, "verified": true,  "source": "https://platform.claude.com/docs/en/about-claude/pricing", "fetched_at": "2026-10-13", "note": "prompts <=100k tokens; the higher tier above 100k is unverified"},
      "gpt-5.6-sol":       {"in": 5.0,  "out": 30.0, "cache_read": 0.50, "verified": false, "source": "https://benchlm.ai/openai/api-pricing", "fetched_at": "2026-10-13"},
      "gpt-5.6-luna":      {"in": 1.0,  "out": 6.0,  "cache_read": 0.10, "verified": false, "source": "https://benchlm.ai/openai/api-pricing", "fetched_at": "2026-10-13"},
      "gemini-3.1-pro-preview": {"in": 2.0, "out": 12.0, "verified": true, "source": "https://ai.google.dev/gemini-api/docs/pricing", "fetched_at": "2026-10-13", "note": "<=200k tokens; 4/18 above"},
      "gemini-3.8-flash":  {"in": 0.75, "out": 3.75, "verified": true, "effective_to": "2026-12-31", "successor": {"in": 1.5, "out": 7.5, "effective_from": "2027-01-01"}, "source": "https://ai.google.dev/gemini-api/docs/pricing", "fetched_at": "2026-10-13"}
    },
    "roles": {
      "research":    {"provider": "anthropic", "model": "claude-sonnet-5-5", "max_budget_usd": 3.0},
      "architect":   {"provider": "anthropic", "model": "claude-fable-5-1",  "max_budget_usd": 5.0},
      "implementer": {"provider": "anthropic", "model": "claude-opus-5-5",   "max_budget_usd": 10.0},
      "utility":     {"provider": "anthropic", "model": "claude-haiku-5-5",  "max_budget_usd": 0.5}
    },
    "static": {"calls_per_month": 10000, "max_monthly_usd": 500.0, "block_unknown_models": true, "default_max_tokens": 1024}
  },
  "buildtime": {
    "dir": "buildtime",
    "min_support": 20, "min_purity": 0.995,
    "promote": {"min_n": 1000, "max_upper": 0.005, "z": 1.96, "min_days": 3, "min_per_label": 30},
    "canary": {"rate": 0.03, "demote_upper": 0.01, "window": 2000}
  },
  "ship": {
    "base": "main",
    "protected_branches": ["main","master","release/*","production","prod"],
    "branch_prefix": "omega/",
    "draft": true,
    "exclude_globs": [".env*","*.pem","*.key","**/ledger.jsonl","node_modules/**",".omega/**","**/*.secret*"],
    "commit_trailers": ["Co-Authored-By: {model_display} <noreply@anthropic.com>"],
    "pr_footer": "Generated with Omega",
    "omega_repo": null,
    "max_files": 200
  },
  "ui": {
    "host": "127.0.0.1", "port": 8787,
    "fallback_order": ["anthropic","openai","google"],
    "runtimes": {"anthropic": "claude", "openai": "codex", "google": null},
    "backoff": {"base_s": 2, "max_s": 60, "attempts": 5},
    "run_timeout_s": 3600,
    "events_limit_bytes": 8388608
  }
}
```

---

## 10. Clearance contracts

Location: `<workspace>/.omega/clearances/proof.json`, `contract.json`, `review.json`.
Writer: `bin/stop_orchestrator.py` only (atomic). They are always written at the end of a Stop
(verified or not) so the UI can show the state; consumers require `verified == true` AND fresh.
A copy of all three is also written into `<session_dir>/clearances/` for audit (same bytes).

Common envelope (all three; validated by `schemas/*.schema.json`, draft 2020-12):

```json
{
  "schema": "omega/proof/1",
  "omega_version": "0.1.0",
  "ts": "2026-10-13T10:00:00Z", "ts_ns": 1760349600000000000,
  "session_id": "...", "provider": "claude", "workspace": "/abs/ws", "run_id": null,
  "verified": true, "released": false, "overridden": false, "attempt": 1,
  "files": {"src/auth/signup.py": "<sha256>", "tests/test_signup.py": "<sha256>", "docs/contracts/user-signup.md": "<sha256>", "src/old.py": "<deleted>"},
  "files_digest": "<sha256 of canonical_json(files)>"
}
```

`files` = every path in `ledger.paths(ctx)` (proof scope, workspace-relative posix) with the sha256
of its content at the moment the orchestrator snapshotted (before gates ran; the orchestrator
re-snapshots after gates and, if any hash differs, sets `verified:false` with detail
`files changed while gates ran`). The three files written by one Stop carry an identical `files`
map and `files_digest`.

Staleness (`hashing.fresh(clearance: dict, workspace: str, ledger_paths: list) -> tuple[bool, str]`):
fresh iff every `(rel, sha)` in `files` equals `sha256_file(workspace/rel)` (`"<deleted>"` for a
missing file) AND every ledger path is a key of `files`. Any further edit makes the clearance stale.

Body per file:

- **proof.json** (`schema: omega/proof/1`): `results` (list of check results §17.3), `tdd` (per
  source/test pair §14.6), `cost` (§18.5), `ship` (§20.4 output embedded), `blocking` (list of
  `{gate, check, status, detail}` that blocked, empty when verified), `unparsed_mutations` (list).
- **contract.json** (`schema: omega/contract/1`): `nontrivial` (bool), `reason`, `contracts`
  (list §11.6), `uncovered_paths` (ledger source paths that no in-scope contract's `code:` lists
  when `nontrivial`), `errors` (parser errors across contracts).
- **review.json** (`schema: omega/review/1`): `approvals` (list §12.6), `overrides` (list),
  `secrets_scan` `{status, hits:[{rule, path, line}]}` over the current content of every existing
  ledger path, `pii_scan` same shape (`FAIL` when a hit is in a path matching
  `redaction.pii_fail_globs` and not a fixture), `channel` (`"transcript"` | `"ui"`).

`verified` per file: proof → no blocking results; contract → every in-scope contract parses with
no errors, `tests:` and `code:` paths exist, `uncovered_paths` empty; review → every in-scope contract
has a matching approval (fingerprint equality, not superseded), `secrets_scan` PASS, `pii_scan` PASS.

`hooks/lib/hashing.py`:

```python
def sha256_file(path: str) -> str          # lowercase hex; "<deleted>" if missing; "<dir>" if directory
def sha256_text(text: str) -> str
def canonical_json(obj) -> str             # json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)
def snapshot(workspace: str, rel_paths: list) -> dict          # {rel: sha}
def files_digest(files: dict) -> str
def fresh(clearance: dict, workspace: str, ledger_paths: list) -> tuple[bool, str]
```

---

## 11. Contract-first development

Full format spec: `docs/contracts/README.md`; worked example: `docs/contracts/example-user-signup.md`.
This section pins what the code enforces.

### 11.1 File and metadata

`<workspace>/docs/contracts/<slug>.md`, `slug` = kebab-case, equal to the file stem. First
non-empty line `# Contract: <title>`. Then metadata lines, each `key: value`, in any order, before
the first `##`: `slug:` (required), `code:` (required, ≥1 comma-separated workspace-relative path),
`tests:` (required, ≥1 path), `owed:` (required; `none` allowed), `assumptions:` (required; `none`
allowed; may continue as an indented bullet block on following lines).

### 11.2 Seams and scenarios

Exactly four H2 sections, any order, exactly these titles: `## Unit`, `## Integration`,
`## Functional`, `## Journey`. Each contains ≥1 `### Scenario: <name>` (unique names within the
file) OR, for any seam except Unit, a single line `_Not applicable: <reason>_`. A scenario is bullet
steps `- Given …`, `- When …`, `- Then …`, `- And …`; at least one of each of Given/When/Then; order
Given → When → Then; `And` continues the preceding keyword; nothing else inside a scenario except
blank lines and non-bullet prose (ignored). Prose anywhere outside steps is ignored by the parser.

### 11.3 Parser and validator (`hooks/lib/contracts.py`)

```python
@dataclass
class Step: keyword: str; text: str                       # keyword ∈ Given|When|Then|And
@dataclass
class Scenario: name: str; steps: list                     # list[Step]
@dataclass
class Contract:
    path: str; slug: str; title: str
    code: list; tests: list; owed: str; assumptions: str
    seams: dict                                            # {"Unit": [Scenario,...] | "not_applicable:<reason>", ...}
    errors: list; warnings: list                           # list[str], each "E0xx: …" / "W0xx: …"
def parse(text: str, path: str) -> Contract
def validate(contract: Contract, workspace: str, strict_existence: bool) -> Contract   # fills errors/warnings
def fingerprint(contract: Contract) -> str
def load_all(workspace: str, cfg) -> list[Contract]
def covering(contracts: list, rel_path: str) -> list      # contracts whose code: lists rel_path
```

Validation codes (exact): `E001 missing title line`, `E002 slug does not match file name`,
`E003 missing metadata key <key>`, `E004 code path not found <p>` (strict only; `W004` otherwise),
`E005 tests path not found <p>` (strict only; `W005` otherwise), `E006 seam missing <seam>`,
`E007 seam <seam> has no scenario`, `E008 scenario <name> lacks <Given|When|Then>`,
`E009 duplicate scenario name <name>`, `E010 step out of order in <name>`,
`E011 unknown section <title>`, `E012 And without a preceding step in <name>`,
`E013 metadata line after the first section`, `E014 Unit seam cannot be not-applicable`,
`E015 empty code or tests list`.

Fingerprint = `sha256(canonical_json({"slug", "code": sorted, "tests": sorted, "assumptions":
normalise(assumptions), "seams": {seam: [{"name": normalise(name), "steps": [[kw, normalise(text)]…]}…] | {"not_applicable": normalise(reason)}}}))`.
Title, `owed`, prose and whitespace are excluded, so a typo fix does not re-open approval and any
scenario change does. `normalise(t) = " ".join(t.split()).casefold()`.

### 11.4 Non-trivial change (binding rule)

`contract_gate.is_nontrivial(ctx, cfg) -> tuple[bool, str]` is true iff ANY of:
1. `len(ledger.source_paths(ctx)) >= cfg.contracts.nontrivial.min_source_files` (3);
2. any ledger path matches `cfg.contracts.nontrivial.always_globs`;
3. `new_source_file_counts` and any ledger row has `kind == "added"` for a non-test source path.
Trivial otherwise (e.g. a bug fix touching one or two existing source files and their tests).

### 11.5 Scope of contracts at Stop

In-scope contracts = `ledger.contracts_touched(ctx)` ∪ `{c for c in load_all() if c.code ∩
ledger.source_paths(ctx)}`. If `nontrivial` and some ledger source path is covered by no in-scope
contract → contract gate FAIL `uncovered_paths`. If not `nontrivial` and no contracts touched →
contract gate `NOT_APPLICABLE` and review gate `NOT_APPLICABLE` (secret/PII scans still run inside
review and can FAIL).

### 11.6 contract.json entry per contract

```json
{"slug":"user-signup","path":"docs/contracts/user-signup.md","fingerprint":"<sha256>","valid":true,"errors":[],"warnings":[],"code":["src/auth/signup.py"],"tests":["tests/test_signup.py"],"seams":{"Unit":2,"Integration":1,"Functional":1,"Journey":1},"not_applicable":[],"code_in_ledger":["src/auth/signup.py"],"touched_this_session":true}
```

### 11.7 Write gate and state machine (`hooks/contract_gate.py`)

```
agent posts the scenarios in chat, names every judgment call, asks
agent: contract_gate.py propose --file docs/contracts/<slug>.md      -> contract_proposal.json {proposal_id:"cp-<8hex>", files:[rel...], ts, ts_ns}
PreToolUse write gate: a write to docs/contracts/*.md is REFUSED unless the newest proposal covers it (a proposal with files:[] covers every contract)
agent writes / iterates the file (post_tool_use appends to contracts_touched.txt)
agent: contract_gate.py request                                        -> contract_request.json {fingerprint, consumed:false, ts, ts_ns}
Stop: matching unconsumed request => allow ONE stop, mark consumed ("waiting is not agreeing")
human answers in chat (terminal) or clicks Approve with text (UI)
agent (terminal): contract_gate.py record --quote "<their words>"      -> contract_approval.json
UI server: runs the same record() with turns from human_turns.jsonl
Stop: approval.fingerprint == current fingerprint AND approval.proposal_id == newest proposal_id => review PASS
escape: human sends the session token hs-<6hex>; agent: contract_gate.py override --token T --reason R -> contract_override.json
```

```python
def write_gate(event: Event, ctx) -> Decision                 # PreToolUse for edit tools / patches
def is_contract_path(path: str, ctx) -> bool                  # under <workspace>/docs/contracts, suffix .md
def propose(ctx, files: list) -> dict
def request(ctx) -> dict
def record(ctx, quote: str, turns: list) -> tuple[bool, str]  # verify_human_answer then write approval
def override(ctx, token: str, reason: str, turns: list) -> tuple[bool, str]
def check(ctx, cfg) -> GateResult                             # the orchestrator's contract gate (validity, coverage)
def review(ctx, cfg) -> GateResult                            # the orchestrator's review gate (approvals, overrides, scans)
def status(ctx) -> dict
def is_nontrivial(ctx, cfg) -> tuple[bool, str]
def current_fingerprint(ctx, cfg) -> tuple[str, dict]         # combined, per-slug
```

Combined fingerprint = `sha256("\n".join(f"{slug}:{fp}" for slug, fp in sorted(per_slug)))`; a
deleted in-scope contract contributes `"<deleted>"`.

CLI (`sh bin/launch.sh hooks/contract_gate.py …`; every subcommand takes `--session S`, `--workspace W`):
`propose [--file F ...]`, `request`, `record --quote "<text>"`, `status [--json]`,
`override --token T --reason R`, `check [--json]` (exit 0 pass / 1 block / 2 error),
`validate <file>` (exit 0 / 1 with the error list). No subcommand → prints status.

Write-gate refusal text (verbatim skeleton):
`[contract-gate] refused: docs/contracts/<slug>.md is a contract. Post the scenarios in chat, say
which are new, changed or removed and every judgment call, ask the human, then run:
<harness_command("hooks/contract_gate.py")> propose --session <S> --file docs/contracts/<slug>.md`

---

## 12. Unforgeable human sign-off

### 12.1 Human turn (Claude transcript) — `hooks/lib/transcript.py`

```python
@dataclass
class Turn: text: str; ts: Optional[datetime]; ts_ns: Optional[int]; source: str; uuid: str; provider: str; channel: str   # channel: "transcript" | "ui"
HUMAN_PROMPT_SOURCES = ("typed", "suggestion_accepted", "queued")
SDK_HUMAN_ENTRYPOINTS = ("claude-vscode", "claude-desktop")
SYNTH = re.compile(r"^\s*<(local-command-stdout|local-command-caveat|bash-stdout|bash-stderr|bash-input|task-notification|system-reminder|command-name|command-message|command-args|agent-message)\b")
def read_human_turns(ctx) -> list       # dispatch: OMEGA_HUMAN_LOG set → parse_ui_log; provider codex → parse_codex; else parse_claude. Missing/unreadable → []
def parse_claude(lines) -> list
def parse_codex(lines) -> list
def parse_ui_log(lines) -> list
def turns_after(turns: list, ts_ns: Optional[int]) -> list   # strictly later; unstamped turns dropped; None keeps all
def normalise(text: str) -> str
def quoted_turn(turns: list, quote: str) -> Optional[Turn]         # substring on normalised text (override token)
def quoted_whole_words(turns: list, quote: str) -> Optional[Turn]  # whole-word regex (sign-off)
def last_human_turn(turns: list) -> Optional[Turn]
def assistant_usage(ctx) -> list       # [{message_id, model, in, out, cache_read, cache_write, ts_ns}] from assistant entries (§18.3)
```

A Claude JSONL record is a human turn iff ALL hold:
1. `type == "user"`; `isSidechain` falsy; `isMeta` falsy; `isCompactSummary` falsy;
   `isVisibleInTranscriptOnly` falsy.
2. No `toolUseResult`, `sourceToolUseID`, `sourceToolAssistantUUID` keys.
3. `message.content` is a string, or a list containing no `tool_result` block; the text (string, or
   the joined `text` blocks) is non-empty after strip, does not start with `[Request interrupted`,
   and does not match `SYNTH`.
4. Positive evidence of a person: `promptSource ∈ HUMAN_PROMPT_SOURCES`; OR `origin.kind == "human"`
   and `promptSource ∉ ("sdk", "system")`; OR `promptSource == "sdk"` and `origin.kind == "human"`
   and `entrypoint ∈ SDK_HUMAN_ENTRYPOINTS`.
5. Excluded by construction: assistant entries, `system`/`attachment` entries, slash-command
   expansions and stdout wrappers, bash-mode output, hook output (`attachment` type), task
   notifications, peer messages, compaction summaries, interrupts, subagent prompts.

Anything else, including unknown shapes, yields no human turn: callers fail closed.
`cfg.transcript.accept_unlabelled_user_turns` (default **false**) exists only for a Claude build that
labels typed prompts with neither `promptSource` nor `origin`; it is set by a human after running
verification scenario V7b, never by the agent.

### 12.2 Human turn (Codex rollout)

Accept only: `response_item` payloads with `role == "user"` whose
`internal_chat_message_metadata_passthrough.content_item_kinds` contains `user.text` (text from
`input_text` items); or `event_msg` payloads of type `user_message` with `is_automatic`/`isMeta`
falsy and `source ∈ {user, typed, queued, suggestion_accepted}`. Stable id from `payload.id` or
`record.id`. Transcript path from the payload; Codex hooks may pass `transcript_path: null` → `[]`.

### 12.3 Human turn (Web UI)

`OMEGA_HUMAN_LOG=<state_root>/ui/runs/<run_id>/human_turns.jsonl`, written **only** by
`ui/server.py` from authenticated requests. Row:

```json
{"ts":"...","ts_ns":...,"uuid":"<uuid4>","user_id":"local","kind":"prompt|approval|override|ship","text":"yes, approve the signup contract","run_id":"run-...","sig":"<hex hmac-sha256(OMEGA_SECRET, canonical_json(row without sig))>"}
```

Hooks read it as turns (channel `ui`) without verifying `sig` (the agent's env must never hold
`OMEGA_SECRET`). Verification happens where it matters: the server verifies `sig` before it runs
`record`, `override` or `auto_ship`. In UI mode the agent is told, in every block message, that
sign-off is given in the dashboard and that `record`/`override` are run by the server.

### 12.4 Quote verification (ported from research 01 §2, binding)

```python
REFUSAL = re.compile(r"(?<![\w'])(no|nope|nah|don'?t|do not|doesn'?t|not yet|not now|reject(?:ed)?|hold off|wait|stop|cancel|decline|disagree|never)(?![\w'])", re.IGNORECASE)
def verify_human_answer(turns: list, asked_at_ns: Optional[int], quote: str, min_chars: int = 8) -> tuple[bool, str]
# both live in hooks/lib/transcript.py (CORE), with matching_turn(turns, asked_at_ns, quote) -> Optional[Turn]
```

Accepted iff: quote non-empty; transcript has human turns; at least one turn strictly after
`asked_at_ns = max(proposal.ts_ns, request.ts_ns)`; a later turn contains the normalised quote as
whole words; that turn's text has no `REFUSAL` match; the normalised quote is the whole turn (after
stripping ` .!`) or ≥ `min_chars`. Each failure returns the exact reason strings of research 01
(ported verbatim). Binding problems: `record` is refused when a request exists whose fingerprint
differs from the current one ("the contract changed after you asked") and when the newest proposal
is newer than the request.

### 12.5 Override token

`override_token` = `hs-` + `secrets.token_hex(3)`, created by session_start. `override --token T`
succeeds iff `T == stored token` AND `quoted_turn(turns, T)` finds it in a human turn (any time).
It writes `contract_override.json` or `stop_override.json` `{token, reason, turn_uuid, ts, ts_ns,
consumed:false}`; a Stop consumes it (one release). The same token serves both gates.

### 12.6 review.json approval entry

```json
{"slug":"user-signup","fingerprint":"<sha256>","proposal_id":"cp-1a2b3c4d","quote":"yes, approve the signup contract","turn_uuid":"...","turn_ts":"...","turn_source":"typed","channel":"transcript","recorded_ts":"...","recorded_by":"contract_gate.record","superseded":false}
```

---

## 13. Guards

### 13.1 Shared shell parsing (`hooks/lib/shell.py`, CORE)

Port `docs/research/code/shell_guard.py` as the engine, split into reusable pieces:

```python
MAX_DEPTH = 6
WRAPPERS, SHELLS, INTERPS            # as in the reference file
def split_commands(cmd: str) -> list              # unquoted ; & | && || newline; handles \<newline>
def tokens(segment: str) -> list                  # shlex posix; raises ValueError on unbalanced quotes
def substitutions(cmd: str) -> list               # inner text of $(...), `...`, <(...), >(...)
def heredocs(cmd: str) -> list                    # [(head, body)]
def mask_expansions(cmd: str) -> str              # $(...), backticks, [[ ]] → placeholder keeping "$"
def strip_redirect_tokens(argv: list) -> list
def redirect_targets(segment: str) -> tuple[list, bool]     # (targets, opaque) for >, >>, N>, &>, >|; drops fd dups
def leading_assignments(argv: list) -> tuple[list, list]    # ([NAME=val...], rest)
def unwrap(argv: list) -> list                              # peel sudo/env/nohup/timeout/command/builtin/exec/nice/xargs… ; returns inner argv or [] when nothing left
def basename(tok: str) -> str
def is_opaque(tok: str) -> bool                             # contains $ ` * ? [ { or is empty
def git_subcommand(argv: list) -> tuple[str, list, list]    # (sub, rest, -c configs) skipping -C/-c/--git-dir/...
```

### 13.2 `hooks/prod_guard.py` (GUARDS)

```python
@dataclass
class Verdict: blocked: bool; rule: str; reason: str; alternative: str
@dataclass
class GuardContext: workspace: str; harness_root: Path; cfg: Config; env: dict
def judge(command: str, ctx: GuardContext) -> Verdict        # pure; never raises; unknown → blocked
def judge_argv(argv: list, ctx: GuardContext, depth: int = 0) -> Optional[Verdict]
def main(argv: list) -> int                                  # hook mode (stdin payload) or `--command "<text>"` dry run
```

Algorithm (fail closed): length > 20000 → block `dynamic.too_long`; `$'` / `$"` → block
`dynamic.ansi_quoting`; every heredoc body fed to a shell/interpreter is judged recursively; every
substitution is judged recursively (depth > 6 → block `dynamic.nesting`); pipeline regexes for
decoded/remote payloads piped to shells or interpreters; then per segment: strip leading control
words, leading assignments (dangerous names → block `env.dangerous_assignment`), unwrap wrappers,
`bash -c` recursion, `find -exec` recursion, interpreter `-c/-e` code via `INTERP_BAD`, dynamic
command word → block `dynamic.command_word`, `eval`/`source`/`.` → block `dynamic.eval`, bare shell
or shell reading a script/stdin → block `dynamic.opaque_shell`; then the deny tables.

Deny tables (rule ids are stable; tests and messages reference them):

| rule id family | blocked | allowed |
|---|---|---|
| `git.*` | `git.signing_required` (commit/merge/rebase/cherry-pick/revert/am/pull/commit-tree/push/tag creation when the target repository is not signing as the trusted identity); `git.signing_override` (`--no-gpg-sign`, `--no-sign`, `-S<other key>`, `-c user.*/author.*/committer.*/commit.gpgsign/tag.gpgsign`); `git.identity_override` (`--author`); `git.unsigned_tag`; `git.unsigned_push` (an outgoing commit that is unsigned, signed by another key, or authored/committed by another email); `git.config` (config writes); `git.config_injection` (`-c` exec keys, `--upload-pack`/`--exec`, `rebase -x`, `--template`, `clone --config`); `git.output_file`; `git.archive -o`; `git.submodule_foreach`; `git.bisect_run`; `git.credential/daemon/instaweb/send-email/svn/p4/filter-branch/filter-repo`; unknown subcommand | every other known subcommand, including reset, branch, checkout, switch, restore, stash, clean, remote, worktree, rm, mv, apply, notes, gc, and signed commit/push/tag/merge/rebase |
| `gh.*` | `repo delete/create/fork/edit`, `release *`, `issue delete/create/edit/close`, `workflow run/enable/disable`, `run rerun/cancel`, `secret *`, `variable set/delete`, `auth login/logout`, `api` with `-X` not GET/HEAD or with `-f/-F/--field/--raw-field/--input` | `pr *`, `issue view/list`, `repo view`, `run list/view/watch`, `auth status`, `api` GET |
| `terraform.*` | `apply destroy import taint untaint force-unlock refresh`, `state rm/mv/push/replace-provider`, `workspace new/delete/select`, `terragrunt run-all` | `init validate fmt plan show output providers version state list/show/pull graph` |
| `kubectl.*` | `delete apply replace patch edit drain cordon uncordon scale rollout exec cp create annotate label taint set run debug auth`; `helm install upgrade uninstall delete rollback` | `get describe logs top version explain api-resources config view/current-context`; `helm list/status/template/lint` |
| `docker.*` | any `prune`; `rm rmi kill stop volume(rm/prune) network(rm/prune) system push login`; `run exec compose up/down/rm` unless `allow_local_docker` and no `--context/-H/--host` arg and no `DOCKER_HOST`/`DOCKER_CONTEXT` leading assignment | `ps images logs inspect version info build compose(config/ps/logs/build)` |
| `db.*` | psql/mysql/mariadb/sqlite3/mongosh/redis-cli/clickhouse-client/bq/snowsql/sqlcmd/cockroach when the SQL text matches `SQL_BAD` (DROP/TRUNCATE/ALTER/GRANT/REVOKE/FLUSHALL/INSERT INTO/UPDATE…SET/CREATE TABLE|DATABASE|USER|ROLE|FUNCTION/COPY…PROGRAM/`\!`/pg_terminate_backend), `DELETE FROM` without WHERE, `UPDATE` without WHERE, any `DELETE FROM` (needs review); `dropdb dropuser pg_restore`; `strict_db` → block when read-only cannot be proven | read-only SQL (SELECT/WITH/SHOW/EXPLAIN without write keywords) |
| `migrations.*` | `prisma migrate (reset|deploy|dev|resolve)`, `prisma db (push|execute|seed)`; `alembic downgrade|stamp`; `alembic upgrade` when `allow_alembic_upgrade` is false; rails/rake `db:(drop|reset|schema:load|migrate:reset|rollback|setup)`; django/manage.py `flush|sqlflush|reset_db`; knex/sequelize/typeorm/drizzle-kit/flyway/liquibase `rollback|drop|clean|destroy|push|undo|revert` | `prisma generate/validate/format/migrate status/migrate diff`, `alembic revision/upgrade/heads/current/history/check`, `manage.py migrate/makemigrations/test` |
| `rm.*` | `rm`/`unlink`/`rmdir`/`shred`/`srm`/`trash` on `/ /* ~ ~/ $HOME * . .. ./* ../*` and `/usr /etc /var /bin /sbin /lib /opt /boot /dev /home /Users /System /Library /Applications`; `--no-preserve-root`; `find -delete`; `rm -rf` of any path not in `rm_rf_allowlist` (resolved relative to the workspace, must stay inside it) | `rm` of files without `-r`; `rm -rf` of allowlisted build dirs inside the workspace |
| `pipe.*` | `curl|wget|fetch … | sh|bash|zsh|python|perl|ruby|node|php`, `sh <(curl …)`, `base64|xxd -r|openssl enc … | sh`; `curl/wget` with `-X POST|PUT|DELETE|PATCH`, `-d/--data*`, `-F`, `-T/--upload-file` to a URL whose host is not in `local_hosts` or a dotless service name; `-o /…` or `-O` writes outside scratch | localhost requests, GET anywhere |
| `sys.*` | `dd mkfs fdisk parted shutdown reboot halt poweroff launchctl systemctl crontab mount umount iptables ufw passwd visudo sudoedit killall pkill`, `chmod/chown/chgrp -R`, `kill` with `-1` or a non-numeric target | `kill <pid>` numeric |
| `cloud.*` | aws/gcloud/az/gsutil verbs matching `(delete|rm|remove|terminate|destroy|purge|drop|deregister|detach|put-|create-|update-|modify-|run-instances|start-|stop-|reboot|deploy)`; pulumi/cdk/serverless/sls/vercel/netlify/fly/flyctl/heroku/railway/wrangler/supabase/firebase `up destroy deploy delete remove rm publish prod secrets db apps scale restart run push migrate release`; npm/pnpm/yarn `publish unpublish deprecate login adduser token access owner dist-tag`; pip/pip3/cargo/gem/twine/mvn/gradle `upload publish push deploy yank` | reads, `npm ci/install/test/run <script>` (opaque; see residual gaps) |
| `net.*` | `ssh scp sftp nc ncat netcat telnet ftp`; `rsync` with a `host:` operand | `rsync` local-to-local (then judged by the write guard) |
| `env.*` | leading assignment of `PATH LD_PRELOAD LD_LIBRARY_PATH DYLD_* GIT_* PAGER EDITOR SHELL BASH_ENV ENV IFS PYTHONPATH PYTHONSTARTUP NODE_OPTIONS DOCKER_HOST DOCKER_CONTEXT KUBECONFIG`; bare `env`, `printenv`, `export -p`, `set` with no args, `declare -p`/`-x`, `cat /proc/*/environ`, `echo`/`printf` of any `$VAR` whose name matches `(?i)(key|token|secret|password|passwd|credential)`, `os.environ` dumps in `-c` code | `env VAR=x cmd` (then unwrapped) |
| `omega.*` | `omega.nested_agent`: `claude`/`codex`/`gemini` CLI invocations; `omega.protected_path`: any write-ish command naming a protected path (§7.2); `omega.unparsed_mutation`: an `apply_patch` whose paths cannot be parsed (a parseable patch is handled as an edit, not a shell write) | `auto_ship.py --dry-run`, every other harness CLI |
| `dynamic.*` | as listed above; `shlex` parse failure → `dynamic.parse_failure` | — |

Every reason is `[prod-guard] blocked (<rule id>): <what the command does>. <alternative>` where
`<alternative>` names the sanctioned path (`Use the Edit tool`, `Ask the human to run
scripts/auto_ship.py --yes`, `Spell the command out as a literal`, `Run it against the local
database only (host in local_hosts)`, …). `cfg.guards.prod.extra_deny_regex` adds raw-string denies.

Residual gaps (documented in the block message footer and `mental-models/architecture.md`):
scripts on disk (`./deploy.sh`, `make deploy`, `npm run <script>`), `python script.py` contents,
aliases/functions from rc files, `docker run` bind-mounts, SQL obfuscation beyond comment stripping.
Enforcement at the credential boundary (no prod credentials in the agent's env) is the real limit.

### 13.3 `hooks/bash_write_guard.py` (GUARDS)

```python
def judge(command: str, ctx: GuardContext) -> Verdict        # Verdict.rule ∈ {"write.allow","write.refuse","write.unproven"}
def destinations(command: str, cwd: str) -> tuple[list, bool]  # (absolute targets, opaque)
```

Port research 01 §5 exactly: `_DEST_ONLY={cp,install,ln,rsync}`, `_ALL_ARGS={mv,rm,tee,truncate,
touch,patch,unlink,shred}`, `sed -i`/`perl -i` operands, `dd of=`, redirects (`>`, `>>`, `N>`, `&>`,
`>|`), inline `python -c`/`node -e`/`perl -e`/`ruby -e` and interpreter heredoc bodies matched by
`_WRITE_API` with string-literal paths (no literal path → UNPROVEN), one level of on-disk shell
script following (`bash x.sh`, `source x.sh`), `cd` tracking (opaque `cd` makes later relative
targets opaque), `xargs` handed a writer → UNPROVEN, `eval` → UNPROVEN, `mv` writes its sources.

Verdicts: a target under a governed root (workspace or harness root, §7) that is not scratch →
REFUSE `[bash-write-guard] this command writes into a path the harness governs: <paths>. Use the
Edit or Write tool on <first> instead; a shell write skips the change ledger, the TDD gate and the
contract gate.`; an opaque target → UNPROVEN `[bash-write-guard] this command writes somewhere the
guard cannot work out: <reason>. Spell the destination out as a literal path, or show what the
script writes.`; a protected path anywhere → REFUSE with `omega.protected_path`. Everything else
is allowed: the target decides, not the command. Never offers a skip.

### 13.4 Protected-path and secret-in-edit guards

Implemented inside `bin/pre_tool_use.py` using `paths.is_protected` and
`redaction.strict_secret_hits` (§4.5). Messages: `[omega] refused: <rel> is a protected path
(hook configuration, git internals or harness state). Ask the human to change it.` and
`[omega] refused: the new content contains what looks like a <rule> secret at line <n>. Put
secrets in the environment or a secret manager and reference them by name.`

---

## 14. TDD gate and background runner

### 14.1 Source and test classification (`hooks/lib/testmap.py`)

```python
def is_test(rel: str, cfg) -> bool                 # cfg.tdd.test_globs
def is_source(rel: str, cfg) -> bool               # ext in source_exts, not test, not exempt
def map_test(rel: str, ctx, cfg, contracts: Optional[list] = None) -> MappedTest   # MappedTest(candidates: list, existing: Optional[str], lang: str, from_contract: bool)
def runner_for(test_rel: str, ctx, cfg) -> Optional[list]    # argv with {python}/{test} substituted; None when no runner can be chosen
def workspace_python(workspace: str) -> str        # .venv/bin/python → venv/bin/python → $VIRTUAL_ENV/bin/python → "python3"; never sys.executable
def js_runner(workspace: str) -> Optional[str]     # "vitest" | "jest" from config files / package.json devDependencies; None otherwise
def scope_key(test_rel: str) -> str                # "test:" + test_rel
```

Mapping precedence: `cfg.tdd.overrides[rel]` → a contract whose `code:` lists `rel` (all its
`tests:` are candidates; any one red suffices) → `cfg.tdd.mappings` patterns in order (first regex
that matches; candidates rendered in order; `{srcdir}` is the source file's directory). `existing`
is the first candidate present on disk.

### 14.2 Gate decision (`hooks/tdd_gate.py`)

```python
def judge(mutations: list, ctx, cfg) -> Decision
def red_for(ctx, test_rel: str, test_sha: str) -> Optional[dict]     # newest red.jsonl row whose test_files[test_rel] == test_sha
def green_after(ctx, test_rel: str, test_sha: str, red_ts_ns: int) -> Optional[dict]
def status(ctx, cfg) -> dict                                       # per in-scope source: mapped test, sha, red, green, newest job
def green_check(ctx, cfg) -> GateResult                            # the orchestrator's tdd gate (§16.3)
def run(ctx, cfg, test_rel: str) -> dict                           # launches a test job synchronously-waited (CLI)
```

For each mutation with `kind ∈ {added, modified}` whose path is under the workspace:
- `is_exempt` or `is_test` or not `is_source` → allow.
- `map_test(...).existing is None` → deny `tdd.no_test_file`: `[tdd-gate] refused: <rel> has no
  test file yet. Expected one of: <candidates>. Write the failing test first (the Edit/Write tool on
  the test file is always allowed), let the background runner observe it red, then edit the source.`
- `strict`: `red_for(test, sha256_file(test))` is None → deny `tdd.not_red` with the newest job's
  state: `running (wait a moment, then retry)`, `pass (the test passed without the change — make it
  fail first)`, `skipped_no_tests`, `skipped_env (<detail>)`, `not_installed (<argv0>)`, `none (run:
  <harness_command("hooks/tdd_gate.py")> run --session S --test <test>)`.
- `red-or-green` (`cfg.tdd.mode` or `OMEGA_TDD_MODE`): newest completed job for the scope has
  status `fail` or `pass` with `test_files[test] == current sha` → allow; else deny as above.
- Deletions and renames are allowed; `kind == "unknown"` is denied `tdd.unknown_mutation`.
A test-file edit is always allowed. Exempt paths are listed in §9.

### 14.3 Which runner, which interpreter

`runner_for`: Python tests → `cfg.tdd.runners.python.argv` with `{python}` =
`workspace_python(ws)`; TS/JS tests → `js_runner(ws)` chooses `vitest` or `jest`; absent
`node_modules/` → the job still launches and classifies as `not_installed`/`skipped_env` (never
pass). Never run the workspace's tests with the harness interpreter.

### 14.4 Launch policy (`bin/post_tool_use.py`)

For each ledgered mutation: if it is a test file → launch `kind=test` for `scope_key(test)` with
`test_files={test: sha}`; if it is a source file with `map_test(...).existing` → launch for that
test with `source_files=[src]`; lint jobs: `kind=lint`, `scope_key="lint:<rel>"`, `ruff check
<file>` for `.py` when ruff is detected, `eslint <file>` for TS/JS when configured. Jobs are
deduplicated by scope key; a newer launch cancels the older. Harvest then reports only failures
(exit 2 stderr) and prints passes to stdout.

### 14.5 Observed red (binding)

`run_job.py` appends the result row to `red.jsonl` when `kind == "test"` and `status == "fail"`,
and to `green.jsonl` when `status == "pass"`; `skipped_*`, `not_installed`, `timeout`, `error`,
`cancelled` are written to neither. The hashes in `test_files` are the ones captured at launch, so a
test edited during the run is not credited.

### 14.6 proof.json `tdd` entry

```json
{"source":"src/auth/signup.py","test":"tests/test_signup.py","test_sha256":"<sha>","red":{"ts":"...","ts_ns":...,"job_id":"...","rc":1},"green":{"ts":"...","ts_ns":...,"job_id":"...","rc":0},"status":"PASS","detail":""}
```

`green_check` (Stop): for every ledger source path with a mapped existing test: `red_for(current
sha)` must exist and `green_after(red.ts_ns)` must exist for the same sha, else `FAIL` (`red
observed, no green since` / `no red observed for the current test`); a mapped test with a running
job → `UNVERIFIED`; sources with no mapped test are `FAIL` in strict mode (`no test file`) and
`UNVERIFIED` in `red-or-green`. No in-scope source paths → `NOT_APPLICABLE`.

CLI: `tdd_gate.py status [--session S] [--json]`, `tdd_gate.py run --test <rel> [--session S]`
(launches and waits up to `job_timeout_s`; exit 0 pass, 1 fail/red, 2 error/skipped),
`tdd_gate.py map <rel>` (prints candidates; exit 0).

---

## 15. `bin/post_tool_use.py` summary

Already specified in §4.5 and §14.4. Feedback format (stderr, exit 2 on Claude; Codex
`decision:block`): `[tests] FAIL pytest tests/test_signup.py (exit 1, 2.3s)` + last 40 lines
(redacted); `[lint] FAIL ruff src/auth/signup.py` + lines. Pass lines on stdout: `[tests] PASS
pytest tests/test_signup.py (1.9s)`; skipped: `[tests] skipped vitest: node_modules missing (run
npm ci)`. Good news never interrupts.

---

## 16. `bin/stop_orchestrator.py` (GATES)

### 16.1 GateResult

```python
@dataclass
class GateResult:
    gate: str                      # proof | tdd | contract | review | cost | ship
    status: str                    # PASS | FAIL | UNVERIFIED | NOT_APPLICABLE
    required: bool
    detail: str                    # one line, redacted
    items: list                    # gate-specific rows (check results, tdd pairs, contracts, approvals, …)
    duration_ms: int
PASS, FAIL, UNVERIFIED, NOT_APPLICABLE = "PASS", "FAIL", "UNVERIFIED", "NOT_APPLICABLE"
```

### 16.2 Flow

1. `state.configure`; `attempts = counter_get("stop_attempts")`; log `stop_hook_active`.
2. `stop_override.json` present and unconsumed → consume, write clearances with
   `overridden:true, verified:false`, allow with the advisory `[omega] stop released by human
   override hs-…: NOT verified`.
3. `gitsnap.reconcile(ctx)` → `reconciled.jsonl`; `ledger.unparsed(ctx)` non-empty → block
   (`omega.unparsed_mutation`, counts as an attempt).
4. Scope: `ledger.paths(ctx)`; empty and no contracts touched → allow `[omega] nothing changed in
   this session; nothing to prove` (no clearances written, counter untouched).
5. `files = hashing.snapshot(workspace, scope)`.
6. `jobstore.settle(ctx, cfg.proof.settle_timeout_s)`.
7. Run gates in `ThreadPoolExecutor(max_workers=6)`; each `future.result(timeout=gate.timeout_s)`;
   `TimeoutError` → `GateResult(gate, UNVERIFIED, required, "gate timed out after <n>s")`;
   exception → `UNVERIFIED` with the exception type.
   - `proof` → `stop_proof.prove(ctx, cfg, scope)`
   - `tdd` → `tdd_gate.green_check(ctx, cfg)`
   - `contract` → `contract_gate.check(ctx, cfg)`
   - `review` → `contract_gate.review(ctx, cfg)`
   - `cost` → `tokentoll_gate.stop_check(ctx, cfg)`
   - `ship` → `ship_readiness.run(ctx.workspace, cfg, mode=cfg.stop.gates.ship.mode, application_results=<proof results when done>)`; when `unverified_blocks` is false an UNVERIFIED ship result is reported as a warning and does not block.
8. `files_after = snapshot(...)`; differs → add blocking item `files changed while gates ran`.
9. `blocking = [r for r in results if r.required and r.status in (FAIL, UNVERIFIED)]` (ship
   per step 7).
10. Write `proof.json`, `contract.json`, `review.json` (§10) and `last_stop.json`.
11. `blocking` empty → `counter_reset`; allow with the summary (stdout). Else `attempts += 1`;
    `attempts >= max_attempts` → release: rewrite the clearances with `released:true,
    verified:false`, `counter_reset`, allow with `[omega] stop released after 4 blocked attempts:
    NOT verified. <summary>`; otherwise block with the message of §16.4.

### 16.3 Summary line format (one per gate, fixed width)

`  <gate:8> <status:14> <detail>` followed by indented item lines (≤ 12 per gate, `… n more`).

### 16.4 Block message (verbatim skeleton)

```
[omega] stop blocked (attempt <n>/<max>): the following must PASS before this work is done
  proof    FAIL           pytest: exit 1 — 2 failed (tests/test_signup.py::test_rejects_duplicate_email, …)
  tdd      UNVERIFIED     src/auth/signup.py ← tests/test_signup.py@a1b2c3d: red observed, green job still running
  contract FAIL           docs/contracts/user-signup.md: E007 seam Journey has no scenario
  review   FAIL           user-signup: awaiting human sign-off — ask in chat, then run: <cmd> record --session <S> --quote "<their words>"
  cost     PASS           session $1.23 / $5.00; month $41.10 / $100.00
  ship     PASS           infra n/a · database PASS · application PASS · analytics n/a · observability PASS (fast)
Fix these and stop again. Commands: <cmd contract_gate> status · <cmd tdd_gate> status · <cmd stop_orchestrator> status
A human can end this early by sending the token hs-3f9a2c in chat; then run:
  <cmd stop_orchestrator> override --session <S> --token hs-3f9a2c --reason "<why>"
```

`<cmd X>` = `adapters.harness_command("hooks/X.py")` = `sh "<abs harness_root>/bin/launch.sh"
hooks/X.py` (absolute; never `$CLAUDE_PROJECT_DIR`). In UI mode the review line reads `awaiting
human sign-off in the dashboard (Approvals tab)` and the override line is omitted.

### 16.5 CLI

`stop_orchestrator.py [--provider P]` (hook mode), `status [--session S] [--json]` (prints
`last_stop.json` summary, exit 0/1 by verified), `override --token T --reason R [--session S]`
(writes `stop_override.json` after `quoted_turn` succeeds; exit 0/1/2), `run [--session S]
[--json]` (runs the gates without a payload; writes clearances; exit 0 verified / 1 blocked / 2 error).

### 16.6 `last_stop.json`

`{ts, ts_ns, session_id, attempt, verified, released, overridden, results: [GateResult as dict],
files_digest, blocking: [...], message: "<the full stdout/stderr text>"}`.

---

## 17. `hooks/stop_proof.py` (GATES)

### 17.1 Suites

Detected from `cfg.proof.suites[*].detect` (any path exists under the workspace; an empty list
means "always try"). `{python}` = `testmap.workspace_python`; `{changed_py}`/`{changed_js}` =
`ledger.existing(ctx)` filtered by extension (a suite whose placeholder expands to nothing is
`NOT_APPLICABLE "no changed files of this kind"`); `{workspace}`.

### 17.2 `run_capability`

```python
@dataclass
class CheckResult: gate: str; check: str; status: str; required: bool; detail: str; rc: Optional[int]; duration_ms: int; argv: list; cwd: str; output_tail: str
def run_capability(suite: dict, ctx, cfg, scope: list) -> CheckResult     # never raises
def prove(ctx, cfg, scope: list) -> GateResult
def background_outcomes(ctx) -> list       # newest job per scope not rerun by prove; pending → rerun synchronously
```

Status mapping: cwd not a dir → FAIL `cannot run: directory does not exist`; `FileNotFoundError` →
UNVERIFIED `<argv0> not installed`; timeout (`timeout_s`, default 200) → FAIL; `OSError` → FAIL;
rc 0 → PASS; `jobstore.classify` `skipped_env`/`skipped_no_tests`/`not_installed` → UNVERIFIED
(blocking when required); else FAIL with `exit N` + last 40 lines. If every result is
UNVERIFIED/NOT_APPLICABLE an extra row `proof UNVERIFIED "UNPROVEN — nothing ran"` is added.

### 17.3 proof.json `results` row = `CheckResult` as dict (`output_tail` redacted, ≤ 4096 chars).

---

## 18. `hooks/tokentoll_gate.py` and `hooks/lib/costledger.py`

### 18.1 Library (CORE)

```python
@dataclass
class Price: model: str; in_usd: float; out_usd: float; cache_read: float; cache_write_5m: float; cache_write_1h: float; verified: bool; source: str
def resolve_model(name: str, cfg) -> Optional[str]      # alias → canonical; strips trailing -YYYYMMDD and "[1m]"; None when unknown
def price(model: str, cfg, on_date: Optional[str] = None) -> Optional[Price]   # honours effective_to/successor
def estimate_tokens(text: str, cfg) -> int               # tiktoken o200k_base if importable else ceil(len/4 * safety_multiplier)
def estimate_usd(model: str, in_tokens: int, out_tokens: int, cfg, cache_read: int = 0, cache_write: int = 0) -> float   # raises UnknownModel(KeyError) for an unpriced model
def append(row: dict, cfg) -> None                       # flock + O_APPEND + fsync on <state_root>/cost/ledger.jsonl
def rows(cfg, since_ts: Optional[str] = None) -> list
def sums(cfg, session_id=None, run_id=None, month=None) -> dict   # {"session": usd, "run": usd, "month": usd, "max_call": usd, "unknown_models": [..], "corrupt_lines": n}
def caps(cfg) -> dict                                    # env overrides applied
def check(cfg, session_id=None, run_id=None, month=None, allow_unknown=False) -> CostVerdict   # CostVerdict(status: PASS|FAIL|UNVERIFIED, breaches: list, warnings: list, sums: dict)
```

### 18.2 Ledger row (`<state_root>/cost/ledger.jsonl`)

```json
{"ts":"2026-10-13T10:00:00Z","ts_ns":1760349600000000000,"id":"<session_id>:<message_id>|<uuid4>","source":"transcript|cli_result|api|estimate","provider":"anthropic|openai|google","model":"claude-opus-5-5","role":"implementer","session_id":"...","run_id":null,"workspace_hash":"...","in":12034,"out":2210,"cache_read":8000,"cache_write":0,"usd":0.0914,"est_usd":null,"price_version":"2026-10-13","verified_price":true}
```

`id` is unique; `append` ignores a duplicate `id` (idempotent ingestion). A corrupt line makes
`check` return `UNVERIFIED` (fail closed) and `report` list the line number.

### 18.3 Ingestion at Stop (`tokentoll_gate.stop_check`)

`transcript.assistant_usage(ctx)` reads every `type == "assistant"` entry's `message.id`,
`message.model`, `message.usage.{input_tokens, output_tokens, cache_read_input_tokens,
cache_creation_input_tokens}`; rows with `id = "<session_id>:<message_id>"` are appended
(`source: "transcript"`); `cost_cursor.json` stores the last ingested uuid. Then `check(session_id)`.
Unknown model → `UNVERIFIED` with the model name (fail closed; fix the price table). Codex
transcripts carry no per-message usage: `stop_check` returns `NOT_APPLICABLE "codex: usage is
recorded by the UI runner from turn.completed"` in terminal mode.

### 18.4 CLI

```
tokentoll_gate.py estimate --model M (--input-file F | --input-text T) [--max-tokens N] [--json]   exit 0; prints est tokens/usd (worst case uses max_tokens)
tokentoll_gate.py record --model M --in N --out N [--cache-read N] [--cache-write N] [--usd X] [--role R] [--session S] [--run-id R] [--source api|cli_result|estimate] [--id ID]
tokentoll_gate.py check [--session S] [--run-id R] [--month YYYY-MM] [--ledger PATH] [--per-call X] [--per-session X] [--per-run X] [--monthly X] [--allow-unknown] [--json]
tokentoll_gate.py report [--month YYYY-MM] [--session S] [--run-id R] [--json]
tokentoll_gate.py scan --path DIR [--calls-per-month N] [--max-monthly X] [--json]      static call-site scan (§18.6)
```

Exit codes for `check`/`scan`: 0 under caps, 1 breach, 2 ledger unreadable/corrupt, 3 unknown model
(unless `--allow-unknown`). Warn at `warn_ratio` (80%) of any cap.

### 18.5 proof.json `cost` entry

`{"status":"PASS","session_usd":1.23,"run_usd":null,"month_usd":41.10,"max_call_usd":0.31,"caps":{...},"breaches":[],"warnings":["month at 82% of cap"],"unknown_models":[]}`

### 18.6 Static scan

Regex over `*.py`, `*.ts`, `*.tsx`, `*.js` excluding ignored dirs: call sites
`messages.create(`, `chat.completions.create(`, `responses.create(`, `generate_content(`,
`generateContent(`, `anthropic.messages`, `openai.chat`; model literals via
`model\s*[:=]\s*["']([\w.\-\[\]]+)["']` within 40 lines; `max_tokens` literal if present else
`cost.static.default_max_tokens`. Per site monthly estimate = `calls_per_month × estimate_usd(model,
prompt_chars/4, max_tokens)` where `prompt_chars` = string-literal chars inside the call (minimum
200). Output JSON `{"sites":[{"path","line","model","monthly_usd","verified_price"}],"total_monthly_usd":…,"unknown_models":[…],"status":"PASS|FAIL"}`.
If a `tokentoll` binary exists, `scan` additionally runs `tokentoll scan --format json` and attaches
it under `"tokentoll"` (informational).

### 18.7 UI integration

`ui/provider_manager.py` calls `costledger.estimate_usd` before a run (refuse when `est + run_total
> per_run_cap`), passes `--max-budget-usd min(per_run_cap − run_total, role.max_budget_usd)` to
`claude -p`, and appends a `source: cli_result` row from the `result` event (`total_cost_usd`,
`usage`) or, for Codex, from `turn.completed.usage` priced by the table (`verified_price:false`).

---

## 19. `hooks/buildtime_compiler.py` (GATES)

### 19.1 Call log

`<workspace>/.omega/buildtime/calls/<callsite>.jsonl`, written by the generated app through the
runtime helper. Row: `{"ts","ts_ns","callsite","input","output","model","prompt_hash","source":"llm|rule|canary","rule_id":null,"meta":{}}`.
Shadow rows: `<workspace>/.omega/buildtime/shadow/<callsite>.jsonl`:
`{"ts","ts_ns","callsite","input_hash","rule_out","rule_id","llm_out","agree":bool}`.

### 19.2 Runtime helper (generated into the workspace by `init`)

`<workspace>/buildtime/__init__.py` (committed; exempt from TDD) exposes:

```python
def route(callsite: str, x: str, llm: Callable[[str], str]) -> str
def log_call(callsite: str, x: str, y: str, model: str, meta: Optional[dict] = None) -> None
def status(callsite: str) -> str          # "unknown" | "logging" | "candidate" | "shadow" | "promoted" | "demoted"
```

`route`: `promoted` → `match(x)`; a label with `random() >= canary.rate` is returned (logged
`source: rule`); otherwise the LLM is called, logged, and a shadow row written. `shadow` → LLM is
authoritative, rule evaluated, shadow row written. Anything else → LLM, logged. The registry is
`<workspace>/buildtime/registry.json` `{"<callsite>": {"status","version","promoted_at","prompt_hash","stats_path"}}`.

### 19.3 Compiled artifact

`<workspace>/buildtime/compiled/<callsite>.py`:

```python
MANIFEST = {"callsite": "...", "version": 3, "generated_at": "...", "prompt_hash": "...", "labels": [...], "lookup_size": 412, "rules": 17, "generator": "omega 0.1.0"}
def normalize(x: str) -> str                               # casefold, collapse whitespace, digits→<N>, uuids→<ID>, emails→<EMAIL>
def match(x: str) -> tuple[Optional[str], Optional[str]]   # (label, rule_id); (None, None) abstains
```

Synthesis: exact lookup (`sha256(normalize(x))` → majority label where purity ≥ `min_purity` and
support ≥ `min_support`), then greedy covering regex rules per label (token/bigram with precision
≥ 0.995, support ≥ 20), emitted in precision order. Eligibility screen before synth: output
cardinality ≤ 64 distinct labels and every label a closed set; otherwise `synth` refuses (exit 1).

### 19.4 Promotion (binding statistics)

`wilson_upper(k, n, z)` as in research 03 §2.3. `promote` succeeds iff `n ≥ min_n` (1000)
non-abstained shadow comparisons, `wilson_upper(k, n, 1.96) < max_upper` (0.005), the sample spans
≥ `min_days` (3) distinct UTC days, and every label appears ≥ `min_per_label` (30) times. Canary:
rolling window `canary.window` (2000) rule hits re-checked by the LLM; `wilson_upper > demote_upper`
(0.01) → `demote` with reason and a registry status `demoted`. A prompt hash change invalidates
promotion (status back to `shadow`).

### 19.5 CLI

```
buildtime_compiler.py init [--workspace W]
buildtime_compiler.py mine --callsite NAME [--json]
buildtime_compiler.py synth --callsite NAME            exit 0 written / 1 ineligible / 2 insufficient data
buildtime_compiler.py shadow --callsite NAME
buildtime_compiler.py report --callsite NAME [--json]  coverage, k, n, wilson upper, savings estimate
buildtime_compiler.py promote --callsite NAME [--min-n N] [--max-upper X] [--z Z]   exit 0 promoted / 1 refused (stats printed) / 2 insufficient data
buildtime_compiler.py demote --callsite NAME --reason R
buildtime_compiler.py canary --callsite NAME           exit 0 healthy / 1 demoted
```

`<workspace>/.omega/buildtime/<callsite>.stats.json` holds `{n, k, coverage, labels: {label: n}, days: [..], wilson_upper, last_eval_ts}`.

---

## 20. `hooks/ship_readiness.py` (GATES)

### 20.1 Contract

```python
@dataclass
class Check: id: str; status: str; argv: list; rc: Optional[int]; duration_ms: int; detail: str; hint: str; required: bool
@dataclass
class Tier: name: str; status: str; applicable: bool; detected: list; checks: list
def detect(workspace: str, cfg) -> dict                      # {tier: [matched paths]}
def run(workspace: str, cfg, mode: str = "fast", strict: bool = False, application_results: Optional[list] = None, changed: Optional[list] = None) -> dict   # the JSON of §20.4
def migration_rules(workspace: str, base_ref: Optional[str], cfg) -> Check   # stdlib, zero tools
def mutation(workspace: str, base_ref: str, min_score: float, cfg) -> Check
```

Status per check: `PASS`, `FAIL`, `UNVERIFIED` (tool missing → `hint` holds the install command;
network needed and unavailable; timeout), `NOT_APPLICABLE`. Tier status: `NOT_APPLICABLE` when
nothing is detected; else `FAIL` if any check FAIL; else `UNVERIFIED` if any required check is
UNVERIFIED; else `PASS`. Overall: `FAIL` if any tier FAIL; `UNVERIFIED` if any tier UNVERIFIED and
`strict`; else `PASS`. Checks run in a `ThreadPoolExecutor(max_workers=4)` with per-check timeout
120 s (`full`) / 30 s (`fast`); every captured tail is redacted.

### 20.2 Tiers, detectors, checks

| tier | detectors (`cfg.ship_readiness.tiers.<tier>.detect`) | fast mode checks | full mode adds |
|---|---|---|---|
| infra | `**/*.tf`, `Dockerfile`, compose files | `terraform fmt -check -recursive` (rc 3 → FAIL); `hadolint --format json Dockerfile`; `docker compose config -q --env-file .env.example` (if the env file exists); stdlib: `Dockerfile` has no `latest` tag and no `ADD http` | `terraform init -backend=false -input=false -no-color && terraform validate -no-color` (offline without plugin cache → UNVERIFIED `providers unavailable`); `tflint --recursive`; `checkov -d . --framework terraform,dockerfile,github_actions --quiet --compact -o json` |
| database | migrations dirs, `alembic.ini`, `prisma/schema.prisma`, `*.sql` | stdlib `migration_rules` over added lines of migration files since `base_ref` (git) or all migration files (no git): research 03 §4.3 `RULES`; `high` → FAIL unless the file contains `-- omega:allow destructive (<reason>)` (SQL) or `# omega:allow destructive (<reason>)` (Python); `medium` → detail only; `alembic heads` must show exactly one head | `squawk --reporter json <files>`; `npx prisma validate` + `npx prisma format --check` (with `DATABASE_URL=postgresql://x:x@localhost/x` dummy); `alembic upgrade head --sql` renders; `atlas migrate validate --dir file://migrations` |
| application | `pyproject.toml`, `package.json`, `requirements.txt` | consumes `application_results` when given (Stop); else: `ruff check .`, `ruff format --check .`, `npx tsc --noEmit`, `npx eslint . --max-warnings 0`; stdlib: `.env.example` exists when any `os.environ[`/`process.env.` reference exists; every FastAPI/Express route file has a matching test file (via `testmap`) | `pytest -q -x -p no:cacheprovider` (rc 5 → UNVERIFIED `no tests collected`); `npx vitest run` / `npx jest --ci`; `pip-audit -r requirements.txt`; `npm audit --audit-level=high`; `gitleaks dir . --no-banner --redact --exit-code 1`; `mutation` when `--mutation` |
| analytics | `dbt_project.yml`, `models/**`, `policies/**` | stdlib: every `models/**/*.sql` has a `schema.yml` entry with `description` and ≥1 test; no `select *` from raw/bronze in gold models; access policies dir has ≥1 file when `policies/**` detected | `dbt parse --no-partial-parse` with `DBT_PROFILES_DIR` pointing at a generated duckdb stub profile; `sqlfluff lint models/` if installed |
| observability | braintrust/langsmith/eval/otel files, `.env.example` | stdlib (research 03 §3.3): dependency present; init present (`init_logger(`/`initLogger(`/`@traceable`/`wrap_openai`/`wrap_anthropic`); AST/regex coverage of LLM call sites (uncovered → FAIL when any call site exists); env var names used appear in `.env.example`; no key literals; `tokentoll_gate.py check` under caps and `scan` under `max_monthly_usd` | live score read is **never** attempted at Stop; in full mode, when `BRAINTRUST_API_KEY` or `LANGSMITH_API_KEY` is set, a GET of the project/experiment list must return 2xx (else UNVERIFIED `skipped: no <KEY>`) |

### 20.3 CLI

```
ship_readiness.py run [--workspace W] [--mode fast|full] [--strict] [--base-ref REF] [--json] [--out FILE]   exit 0 PASS / 1 FAIL (or UNVERIFIED with --strict) / 2 internal
ship_readiness.py migration-lint [--workspace W] [--base-ref REF] [--json]
ship_readiness.py mutation [--workspace W] --base-ref REF [--min-score 0.60] [--stryker] [--json]   exit 0 score ≥ min / 1 below / 2 could not run (never a pass)
```

`mutation`: Python → copy the workspace to a disposable dir (`tempfile.mkdtemp`), write a scoped
`[tool.mutmut]`/`setup.cfg` for the changed files' modules, run `python -m mutmut run` then
`mutmut results`, parse `<name>: killed|survived|timeout|suspicious|no tests|skipped` (parser
unit-tested against the pinned version `cfg.ship_readiness.mutation.mutmut_version`), `score =
killed / (killed+survived+timeout+suspicious)`; Python < 3.10 → `UNVERIFIED "mutmut 3.4+ needs
Python 3.10 (found 3.9)"`. JS → `npx stryker run --incremental --mutate <changed>` with
`thresholds.break` from config; score read from `reports/mutation/mutation.json` (NoCoverage counts
as survived).

### 20.4 Output JSON (`ship-readiness.json`; embedded in proof.json `ship`)

```json
{"schema":"omega/ship/1","ts":"...","workspace":"/abs/ws","mode":"fast","strict":false,"status":"PASS","tiers":{"infra":{"status":"NOT_APPLICABLE","applicable":false,"detected":[],"checks":[]},"database":{"status":"PASS","applicable":true,"detected":["alembic.ini"],"checks":[{"id":"migration_rules","status":"PASS","argv":[],"rc":null,"duration_ms":12,"detail":"3 files, 0 high, 1 medium (index-nonconcurrent alembic/versions/0003_x.py:14)","hint":"","required":true}]},"application":{...},"analytics":{...},"observability":{...}}}
```

---

## 21. `scripts/auto_ship.py` (GATES) — branch, signed commit, push, PR

```
auto_ship.py [--workspace W] [--base main] [--slug S] [--title T] [--dry-run] [--yes] [--no-draft] [--allow-unverified] [--json]
```

`--dry-run` is the default; `--yes` performs the ship. Exit: 0 ok (plan printed or PR created),
1 precondition failed (each printed as `BLOCKER: …`), 2 internal error, 3 nothing to commit.

Preconditions, in order, all must hold (every failure lists the fix):
1. `git rev-parse --is-inside-work-tree`; `origin` URL parses to `owner/repo` (https or ssh).
2. `.omega/clearances/{proof,contract,review}.json` exist, validate against the schemas,
   `verified:true`, `released:false`, `overridden:false`, identical `files_digest`, and
   `hashing.fresh` against the working tree (ledger paths from the session named in the clearance).
3. `contract.json.nontrivial` → every contract has an approval in `review.json.approvals` with equal
   fingerprint and `superseded:false`.
4. `proof.json.cost.status == PASS` and `tokentoll_gate.check` exit 0 now.
5. `ship_readiness.run(mode="full", strict=not allow_unverified)` status PASS (`--allow-unverified`
   accepts UNVERIFIED, never FAIL).
6. Dirty set (`git status --porcelain -z --untracked-files=all`) ⊆ clearance `files` ∪ ignored;
   every file to stage passes `ship.exclude_globs`; count ≤ `ship.max_files`.
7. Secrets: `gitleaks protect --staged --redact` (when installed) and `redaction.strict_secret_hits`
   over the staged diff `+` lines → any hit aborts (`rule path:line`, never the value).
8. PII: `redaction.scan(pii=True)` over staged `+` lines in `pii_fail_globs` paths → abort unless the
   path is a fixture.
9. Current branch is not in `protected_branches` (else a new branch is created from
   `origin/<base>`); `--force` is never used.

Execution with `--yes`: `git fetch origin <base>`; `git switch -c <branch> origin/<base>` where
`branch = ship.branch_prefix + slug + "-" + UTC %Y%m%d%H%M%S` (slug = `--slug` → first contract
slug → `change`); `git reset -q`; `git add -- <explicit paths>`; `git diff --cached --quiet` → exit
3; `git commit -m <title> -m <body>` where `title = --title → "# Contract:" title → "omega: <slug>"`
and `body` = contracts list + `clearances: <files_digest[:12]>` + trailers
(`{model_display}` from `context.json.model`); `git push -u origin <branch>`; `gh pr create --base
<base> --head <branch> --title <title> --body-file <tmp> [--draft]` (fallback: `POST
https://api.github.com/repos/{o}/{r}/pulls` with `Authorization: Bearer $OMEGA_GIT_TOKEN`,
`X-GitHub-Api-Version: 2022-11-28`, `draft` true); result written to
`<workspace>/.omega/ship/<ts>.json` `{branch, commit, pr_url, pr_number, files, files_digest}`.
Credentials: never in argv or the remote URL; UI mode sets `GIT_ASKPASS=<harness>/bin/git-askpass.sh`,
`GIT_TERMINAL_PROMPT=0`, `OMEGA_GIT_TOKEN` in env (the askpass script answers `x-access-token` to a
username prompt and the token to a password prompt). Every git call is `subprocess.run([...],
check=False, capture_output=True, timeout=120)` with explicit argv.

PR body (redacted through `redaction.redact` and refused if any strict secret hit remains):
`## Summary` (contract titles and scenario counts per seam), `## Clearances` (digest, gates table
from `last_stop.json`), `## Ship readiness` (tier table), `## Cost` (session/month), `## Contracts`
(links), footer `ship.pr_footer`. Never auto-merges.

---

## 21a. Signed git (`hooks/lib/git_signing.py`, enforced by `prod_guard`)

The agent commits and pushes itself, but every commit it publishes must be signed by the human's key
under the human's identity.

- **Trusted identity.** `git.identity.{email,signing_key,format}` in the workspace's
  `.omega/config.json` when set (a protected path), otherwise the workspace repository's effective
  `user.email`, `user.signingkey` and `gpg.format` (its `.git/config` and `~/.gitconfig` are both
  protected from agent edits and shell writes).
- **Before a commit-making command** (`commit merge rebase cherry-pick revert am pull commit-tree`,
  `push`, and `tag` creation), the target repository (resolved through `-C`, `--git-dir`,
  `--work-tree`) must have `commit.gpgsign=true` and the trusted email, format and key. Overrides are
  denied: `--no-gpg-sign`, `--no-sign`, `-S<other key>`, `--author`, `-c user.*|author.*|committer.*|
  commit.gpgsign|tag.gpgsign|gpg.*`, and any `GIT_*` assignment. A new tag must be `-s`/`-u` or
  `tag.gpgsign=true`.
- **Before `git push`**, every commit the push would publish (`git log <refs> --not --remotes`) must
  have signature status in `git.accept_signature_status` (default `G`, `U`), be signed by the trusted
  key (OpenPGP fingerprint/key-id suffix, or SSH fingerprint), and have author and committer email
  equal to the trusted email. SSH signatures need `gpg.ssh.allowedSignersFile` to be verifiable.
- **`auto_ship.py`** reports signing problems as blockers in its plan and verifies the new commit's
  signature before pushing.
- `git.require_signed: false` turns all of this off; `git.max_outgoing` (2000) caps one push.
- Working-tree changes made through git (`checkout --`, `restore`, `apply`, `stash pop`,
  `reset --hard`) bypass the edit ledger; Stop reconciliation against the git snapshot still sees them.

## 22. `scripts/create_gauntlet.py` (GATES)

```
create_gauntlet.py [--workspace W] [--omega-repo owner/repo@ref] [--python 3.12] [--node 22] [--force] [--dry-run]
```

Writes `<workspace>/.github/workflows/gauntlet.yml` (refuses to overwrite without `--force`) and
`<workspace>/.gitleaks.toml` (allowlist of fixture globs) from stack detection (`ship_readiness.detect`).
Third-party actions are referenced as `<action>@<ref>` with `<ref>` taken from
`cfg.gauntlet.action_pins` (shipped defaults are tags; a human SHOULD replace them with commit SHAs
before production; the generated file carries no comments). Jobs (research 03 §5.3 is the skeleton):
`lint` (ruff / eslint / tsc), `tests` (pytest / vitest|jest), `security` (gitleaks-action, checkov,
pip-audit, npm audit), `infra` (terraform fmt/validate when `*.tf`), `migrations`
(`ship_readiness.py migration-lint --base-ref origin/${{ github.base_ref }}`), `ship-readiness`
(`ship_readiness.py run --mode full --strict --json`), `cost` (`tokentoll_gate.py scan --path .` and
`tokentoll_gate.py check --ledger .omega-ci/ledger.jsonl` when such a ledger is committed; else
scan only), `mutation` (PR-only, `needs: [lint, tests]`, `ship_readiness.py mutation --base-ref
origin/${{ github.base_ref }} --min-score <cfg>` and `npx stryker run --incremental`), `verdict`
(`needs` all; fails if any failed — the single required status check). The harness scripts come from
a second checkout: `actions/checkout` with `repository: <omega_repo>`, `path: .omega-ci`,
`ref: <ref>`; `--omega-repo` → `cfg.ship.omega_repo` → the harness's own `origin` → else the
workflow's first step fails with `echo "set gauntlet.omega_repo" && exit 1`. `permissions:
contents: read`; `concurrency` cancel-in-progress; `timeout-minutes` per job (10/15/10/10/10/15/5/30/2).

---

## 23. Web UI (UI package)

### 23.1 Processes and boundaries

`python -m ui.server [--host H] [--port P]` (uvicorn programmatic). Single operator in v1:
`user_id = "local"`; auth = bearer token `OMEGA_UI_TOKEN` (else generated into
`<state_root>/ui/ui_token` 0600 and printed once at boot). Every REST call requires `Authorization:
Bearer <token>`; the WebSocket requires `?token=` and an `Origin` equal to the server's own origin
(or listed in `OMEGA_UI_ORIGINS`), checked before `accept()`. Responses on key endpoints carry
`Cache-Control: no-store`. All text rendered in the browser is escaped (`textContent`, never
`innerHTML`). The agent subprocess MUST NOT receive `OMEGA_SECRET`, `OMEGA_UI_TOKEN` or any key
other than the one provider key the run needs.

### 23.2 REST endpoints (JSON; errors `{"error": {"code", "message"}}` with 4xx/5xx)

| method path | body → response |
|---|---|
| `GET /api/health` | `{"ok":true,"version":"0.1.0","python":"3.11.x","runtimes":{"claude":"<version|null>","codex":"<version|null>"},"hooks_verified":{"claude":bool,"codex":bool}}` |
| `GET /api/keys` | `[{"provider":"anthropic","prefix":"sk-ant-","last4":"ab12","created_at":"...","last_used_at":null,"status":"verified|unverified|invalid","kid":1}]` (never the key) |
| `PUT /api/keys/{provider}` | `{"key":"..."}` → 200 masked entry; 400 on pattern mismatch (`redaction` provider regex) or length > 512 |
| `DELETE /api/keys/{provider}` | 204 (row overwritten then removed) |
| `POST /api/keys/{provider}/verify` | → `{"status":"verified|invalid|unverified","detail":"..."}` (network; never deletes) |
| `GET /api/projects` / `POST /api/projects` `{"name","path"}` / `GET /api/projects/{id}` | project = `{"id","name","path","created_at","clearances":{...},"contracts":[...]}`; `POST` runs `install_workspace.py` into the path |
| `POST /api/runs` | `{"project_id","role":"research|architect|implementer|utility","provider":null|"anthropic"|"openai","model":null,"prompt","budget_usd":null,"permission_mode":"acceptEdits"}` → `{"run_id":"run-<YYYYmmddHHMMSS>-<4hex>"}` (409 when the project has a running run) |
| `GET /api/runs` / `GET /api/runs/{id}` | `run.json`: `{"run_id","project_id","role","provider","model","runtime","status":"queued|running|done|failed|cancelled|budget_exceeded","started_at","ended_at","cost_usd","session_id","exit_code","budget_usd"}` |
| `POST /api/runs/{id}/cancel` | SIGINT to the process group, SIGKILL after 10 s → 202 |
| `GET /api/runs/{id}/events?after=N&limit=M` | replay from `events.jsonl` by `seq` |
| `GET /api/projects/{id}/clearances` | the three clearance files + `{"fresh":bool,"reason":str}` each, + `last_stop.json` summary |
| `GET /api/runs/{id}/approvals` | pending: `[{"slug","proposal_id","fingerprint","asked_ts","contract_path","scenarios":{...}}]` from the session dir |
| `POST /api/runs/{id}/approvals` | `{"slug","text"}` → appends a `kind:"approval"` row to `human_turns.jsonl` (signed), runs `contract_gate.record(ctx, quote=text, turns)` in the server process → `{"accepted":bool,"reason":str}` |
| `POST /api/runs/{id}/override` | `{"reason"}` → appends a `kind:"override"` row carrying the session token, runs `stop_orchestrator override` → `{"accepted","reason"}` |
| `POST /api/projects/{id}/ship` | `{"dry_run":true,"base":"main","title":null}` → `auto_ship` JSON (plan or result); `dry_run:false` appends a `kind:"ship"` human row first |
| `GET /api/cost/report?month=YYYY-MM&run_id=` | `tokentoll_gate report --json` |

### 23.3 WebSocket `/ws/runs/{run_id}?after=N&token=T`

Event (one JSON object per message; identical to the rows in `events.jsonl`):

```json
{"run_id":"run-…","seq":42,"ts":"...","ts_ns":...,"role":"implementer","runtime":"claude","kind":"text|tool_call|tool_result|hook|usage|status|approval_request|error|done|ping|raw","data":{}}
```

`data` by kind: `text` `{"delta":"…"}` (text deltas debounced to ≤ 10 messages/s); `tool_call`
`{"id","name","input_summary"}` (input redacted and truncated to 2000 chars); `tool_result`
`{"id","ok":bool,"summary"}`; `hook` `{"event","decision":"allow|deny|block","reason"}` (from
`attachment`/`system` stream entries when present, else from `observed/`); `usage`
`{"in","out","cache_read","cache_write","usd","cumulative_usd"}`; `status` `{"status"}`;
`approval_request` `{"slug","proposal_id"}` (emitted when a `contract_request.json` appears);
`error` `{"message"}`; `done` `{"exit_code","is_error","cost_usd","session_id"}`; `ping` `{}`
every 20 s; `raw` `{"type","truncated":"…"}`. Replay from disk by `seq` on connect, then live;
slow clients drop the oldest queued event (queue 1000).

### 23.4 `ui/provider_manager.py`

```python
class Secret(str):  # __repr__/__str__ → "****"; .reveal() → value
class ProviderManager:
    def __init__(self, state_root: Path, cfg: Config, secret: Optional[bytes] = None)   # Fernet key: OMEGA_SECRET (urlsafe b64 32 bytes) else <state_root>/ui/keyfile (0600, generated)
    def set_key(self, user_id: str, provider: str, key: str) -> dict          # validates pattern/length, seals {"u","p","k"} with MultiFernet, stores ciphertext + prefix + last4 + kid; returns the masked entry
    def get_key(self, user_id: str, provider: str) -> Secret                  # PermissionError on binding mismatch / InvalidToken
    def list_keys(self, user_id: str) -> list
    def delete_key(self, user_id: str, provider: str) -> None
    def verify_key(self, user_id: str, provider: str) -> dict                 # Anthropic GET /v1/models (x-api-key, anthropic-version: 2023-06-01); OpenAI GET /v1/models (Bearer); Google GET /v1beta/models (x-goog-api-key)
    def choose(self, role: str, provider: Optional[str] = None, model: Optional[str] = None) -> Choice   # Choice(provider, model, runtime, max_budget_usd); walks cfg.ui.fallback_order skipping providers without a key or runtime
    def env_for(self, user_id: str, choice: Choice, run: dict) -> dict        # minimal env: PATH, HOME, LANG, TMPDIR + the one provider key + OMEGA_* for the run (never OMEGA_SECRET/UI_TOKEN)
    def backoff(self, attempt: int) -> float                                  # min(base_s * 2**attempt, max_s) + jitter
    def record_usage(self, run: dict, usage: dict, usd: Optional[float], source: str) -> None   # costledger.append
    def rotate(self) -> int                                                   # MultiFernet.rotate over every stored token
```

Key store `<state_root>/ui/keys.json`: `{"<user_id>": {"<provider>": {"token":"<fernet b64>",
"prefix":"sk-ant-","last4":"ab12","kid":1,"created_at":"...","last_used_at":null,"status":"unverified"}}}`
written atomically under `fcntl.flock`. Provider key patterns for the 400 pre-check: anthropic
`^sk-ant-`, openai `^sk-`, google `^AIza`.

### 23.5 `ui/runner.py`

```python
async def start_run(run: dict, choice: Choice, env: dict, workspace: str, hub: Hub, cfg: Config) -> None
def claude_argv(prompt: str, model: str, budget_usd: float, settings_path: str, permission_mode: str, resume: Optional[str]) -> list
def codex_argv(prompt: str, model: Optional[str], sandbox: str, last_message_path: str) -> list
def normalize_claude(line: dict) -> list       # → [event dict]
def normalize_codex(line: dict) -> list
class Hub: sub(run_id) / unsub / pub(run_id, ev)
async def verify_hooks_fire(runtime: str, cfg: Config) -> bool   # one-time boot probe
```

`claude_argv` = `["claude","-p",prompt,"--model",model,"--output-format","stream-json","--verbose",
"--include-partial-messages","--permission-mode",permission_mode,"--bare","--settings",settings_path,
"--max-budget-usd",str(budget_usd)]` (+ `["--resume", id]`), where `settings_path` is a file rendered
by `adapters.render_claude_settings(absolute=True)` into `<state_root>/ui/claude-settings.json`.
`codex_argv` = `["codex","exec","--json","--sandbox",sandbox,"-o",last_message_path]` (+ `["-m",
model]` when the boot probe confirmed `-m` is accepted) + `[prompt]`. Subprocess:
`asyncio.create_subprocess_exec(..., cwd=workspace, env=env, stdin=DEVNULL, stdout=PIPE,
stderr=PIPE, start_new_session=True, limit=cfg.ui.events_limit_bytes)`; stderr drained concurrently;
timeout `cfg.ui.run_timeout_s` → `killpg(SIGINT)`, 5 s, `killpg(SIGKILL)`; exit 143 → status
`cancelled`. Every event is redacted, assigned `seq`, appended to `events.jsonl`, then published.

`verify_hooks_fire`: runs a one-line prompt (`Reply with OK`) with the harness settings against a
throwaway workspace (`tempfile.mkdtemp`, `git init`) and a `--max-budget-usd 0.05`, then checks
`observed/<provider>.json` gained a `SessionStart` stamp newer than the probe start. False →
`/api/health.hooks_verified[runtime] = false` and `POST /api/runs` returns 503 `hooks did not fire
under --bare --settings; set OMEGA_ALLOW_UNHOOKED=1 to override` unless that env is set. This
closes research 02's open item (hooks under `--bare`) at runtime instead of guessing.

### 23.6 `ui/static/`

`index.html`, `app.js`, `styles.css`; no build step, no framework, no CDN. Tabs: Keys (masked list,
add/replace/delete/verify), Projects, Runs (start form; live trace with kinds colour-coded; cancel),
Clearances (three cards: verified/fresh/stale with digests and gate table), Approvals (pending
contract requests; approve with typed text; the override button with a reason), Ship (dry-run plan,
then Ship), Cost (month/run totals and caps). WebSocket client reconnects with `?after=<last seq>`.

### 23.7 `ui/requirements.txt`

`fastapi>=0.115,<1`, `uvicorn[standard]>=0.30,<1`, `cryptography>=43,<46`, `websockets>=12,<14`.
(Versions SHOULD; the implementer pins exact versions after `pip install` succeeds.)

---

## 24. Session reconciliation (`hooks/lib/gitsnap.py`, CORE)

```python
def snapshot(roots: list) -> dict          # {root: {abs_path: sha256|"<deleted>"|"<dir>"} | None}  from `git status --porcelain=v1 -z --untracked-files=all`
def deltas(before: dict, after: dict) -> list
def ensure_baseline(ctx) -> None           # at SessionStart (source != "compact"); writes baseline.json once
def reconcile(ctx) -> Reconciliation       # Reconciliation(found: list, unreadable: list, note: Optional[str])
```

Port research 01 §7 verbatim: unexplained deltas since the baseline minus this session's ledger
minus other sessions' rows since the baseline → `ledger.append_reconciled(ctx, path, "reconciled"|"deleted")`.
Non-git workspaces are reported `unreadable`, never guessed.

---

## 25. `bin/session_start.py` context (GUARDS)

Composed in this order, cut at a line boundary to `cfg.session_start.context_cap_bytes` (12000):
1. Framing (≤ 600 bytes): `[omega] Omega 0.1.0 · provider <p> · workspace
   <abs> · session <id>. Laws: contract-first (docs/contracts/<slug>.md, propose before writing),
   observed-red TDD (write the failing test first), signed git (commit/push only as the trusted
   signing identity; never override it), Stop waits for proof (proof · tdd · contract ·
   review · cost · ship). Shell writes into the workspace are refused; use Edit/Write.`
2. Commands (≤ 1200 bytes): the absolute `harness_command` lines for `contract_gate.py propose/
   request/record/status`, `tdd_gate.py status/run`, `stop_orchestrator.py status`,
   `tokentoll_gate.py report`, `ship_readiness.py run`, `auto_ship.py --dry-run`.
3. Workspace facts (≤ 1500 bytes): detected stacks (`ship_readiness.detect`), contracts present,
   pending approval (if `contract_request.json` unconsumed), open reds without green, last Stop
   verdict line, cost so far, warnings (`OMEGA_DEV=1 lifts harness protection`, `python 3.9:
   mutation gate unavailable`, `transcript: no human turn found yet`).
4. `cfg.session_start.inject` files, whole, in order, while they fit; a file that does not fit is
   replaced by its path and the instruction to read it.
`source == "compact"` → parts 1–3 only. Any exception → a single warning line; exit 0.

---

## 26. Adapter configs (GUARDS, rendered by CORE `adapters.py`)

```python
@dataclass
class HookSpec: event: str; matcher_claude: Optional[str]; matcher_codex: Optional[str]; script: str; guard: bool; timeout_s: int
HOOK_TABLE = [
    HookSpec("SessionStart", "startup|resume|clear|compact", "startup|resume|clear|compact", "bin/session_start.py", False, 20),
    HookSpec("PreToolUse", "Bash|Edit|Write|MultiEdit|NotebookEdit", "^(Bash|apply_patch|Edit|Write|MultiEdit|NotebookEdit)$", "bin/pre_tool_use.py", True, 30),
    HookSpec("PostToolUse", "Edit|Write|MultiEdit|NotebookEdit", "^(apply_patch|Edit|Write|MultiEdit|NotebookEdit)$", "bin/post_tool_use.py", False, 30),
    HookSpec("PostToolUseFailure", "Edit|Write|MultiEdit|NotebookEdit", None, "bin/post_tool_use.py", False, 15),
    HookSpec("Stop", None, None, "bin/stop_orchestrator.py", False, 900),
]
def harness_command(script: str, root: Optional[Path] = None) -> str      # 'sh "<abs root>/bin/launch.sh" <script>'
def render_claude_settings(root: Path, absolute: bool) -> dict
def render_codex_hooks(root: Path, absolute: bool) -> dict
def render_codex_config_toml() -> str                                    # "[features]\nhooks = true\n"
```

`.claude/settings.json` (dogfood form, `absolute=False`): command strings are
`sh "$CLAUDE_PROJECT_DIR/bin/launch.sh" [--guard] <script> --provider claude`; `permissions.deny`
includes `Bash(git push *)`, `Bash(git commit *)`, `Bash(gh pr merge *)`, `Bash(terraform apply *)`,
`Bash(terraform destroy *)`, `Bash(kubectl delete *)` as belt-and-braces. `.codex/hooks.json`
commands are `sh -c 'R="$(git rev-parse --show-toplevel)"; exec sh "$R/bin/launch.sh" [--guard]
<script> --provider codex'`; `absolute=True` substitutes the literal root path for both. SubagentStop
and PreCompact are deliberately not registered in v1 (recorded in `docs/DECISIONS.md` by GUARDS).

`tests/guards/test_adapters.py` MUST fail when: a `HOOK_TABLE` script is missing; a `guard=True`
hook is registered without `--guard`; a matcher matches none of the adapter's edit tools; a hook
is missing from either adapter; any timeout is missing or the Stop timeout < 600; the checked-in
files differ from `render_*(absolute=False)`.

---

## 27. Work packages, ownership and public API

Build order: CORE first (its public API below is frozen the moment it lands; other packages code
against these signatures from day one using stubs if needed). GUARDS, GATES and UI then build in
parallel. Nobody edits another package's files; a needed change to CORE is requested by writing a
failing test in your own `tests/<area>/` and a line in `docs/DECISIONS.md`.

### 27.1 CORE — `hooks/lib/**`, `omega.config.json`, `schemas/*.json` (validation tests),
`bin/launch.sh`, `tests/conftest.py`, `tests/fixtures/**`, `tests/lib/`, `requirements-dev.txt`,
`.gitignore`, `README.md` skeleton

Exposes exactly the signatures in §4.2, §4.3, §5.1–5.3, §7, §8, §9, §10 (`hashing`), §11.3,
§12.1, §13.1, §14.1, §18.1, §24, §26. Consumes nothing outside itself. Tests: every reference
false-green path of research 01 §12 as a regression test; the research 02 shell bypass corpus
(47 denied / 21 allowed) as `tests/lib/test_shell.py` fixtures (the deny verdicts themselves are
GUARDS tests, but tokenisation/unwrapping is CORE); redaction positives/negatives from research 02
§E; transcript fixtures for every exclusion row of §12.1; jobstore classification table §5.3;
contract parser codes E001–E015; schema validation of a golden clearance triple.

### 27.2 GUARDS — `bin/session_start.py`, `bin/pre_tool_use.py`, `bin/post_tool_use.py`,
`hooks/prod_guard.py`, `hooks/bash_write_guard.py`, `hooks/tdd_gate.py`, `hooks/contract_gate.py`,
`scripts/install_workspace.py`, `.claude/settings.json`, `.codex/hooks.json`, `.codex/config.toml`,
`tests/guards/`

Exposes: `prod_guard.judge/judge_argv/main`, `bash_write_guard.judge/destinations/main`,
`tdd_gate.judge/red_for/green_after/status/green_check/run/main`, `contract_gate.write_gate/
propose/request/record/override/check/review/status/is_nontrivial/current_fingerprint/main`,
`GuardContext`, `Verdict`. Consumes: `io`, `event`, `state`, `ledger`, `jobstore`, `transcript`,
`shell`, `hashing`, `redaction`, `contracts`, `testmap`, `gitsnap`, `paths`, `config`, `adapters`.
Tests: the full bypass corpus with rule ids; write-guard REFUSE/UNPROVEN/allow table; TDD
red→green state machine through real `run_job.py` on a temp workspace with a real `pytest`;
forged vs genuine approval through transcript fixtures; adapter parity (§26).

### 27.3 GATES — `bin/stop_orchestrator.py`, `hooks/stop_proof.py`, `hooks/tokentoll_gate.py`,
`hooks/buildtime_compiler.py`, `hooks/ship_readiness.py`, `scripts/auto_ship.py`,
`scripts/create_gauntlet.py`, `scripts/check-all.sh`, `bin/git-askpass.sh`, `tests/gates/`

Exposes: `GateResult`, `stop_proof.prove/run_capability/background_outcomes`,
`tokentoll_gate.stop_check/main`, `buildtime_compiler.wilson_upper/mine/synth/promote/main`,
`ship_readiness.detect/run/migration_rules/mutation/main`, `auto_ship.plan/ship/main`,
`create_gauntlet.render/main`. Consumes: `io`, `event`, `state`, `ledger`, `jobstore`, `hashing`,
`redaction`, `contracts`, `testmap`, `gitsnap`, `costledger`, `transcript`, `paths`, `config`,
`adapters`, plus GUARDS' `tdd_gate.green_check` and `contract_gate.check/review` (imported; GATES
may stub them in tests). Tests: four-state aggregation and loop guard; clearance freshness; a fake
workspace per tier; migration rules corpus; mutmut `results` parser against pinned output; auto_ship
dry-run with a local bare remote; gauntlet YAML validates (`yaml` optional; else structural checks).

### 27.4 UI — `ui/**`, `tests/ui/`

Exposes: the HTTP/WS API of §23. Consumes: `config`, `paths`, `state`, `costledger`, `redaction`,
`transcript`, `contracts`, `adapters`, `hashing`, GUARDS' `contract_gate.record/override`, GATES'
`stop_orchestrator.override`, `auto_ship.plan/ship`, `tokentoll_gate.report`. Tests: key masking
(no endpoint returns a key; logs contain `****`), Fernet binding mismatch, WS replay by seq, event
normalization for both CLIs from fixture JSONL, `env_for` contains exactly one key, Origin check.

### 27.5 Shared test fixtures (`tests/conftest.py`, CORE) — names are binding

`harness_root` (Path); `tmp_state` (sets `OMEGA_STATE_DIR` to a tmp dir); `workspace` (tmp git
repo with `src/`, `tests/`, `docs/contracts/`, sets `OMEGA_WORKSPACE`); `claude_payload(event,
**overrides)` and `codex_payload(event, **overrides)` (dicts from `tests/fixtures/<provider>/
<event>.json`); `transcript_writer(tmp_path)` with `.human(text)`, `.sdk(text)`, `.meta(text)`,
`.assistant(text, usage=None)`, `.tool_result(text)`, `.compact_summary(text)`, `.slash("/clear")`
returning the JSONL path; `run_hook(script_rel, payload, provider, env=None) ->
subprocess.CompletedProcess` (through `bin/launch.sh`); `session(ctx)` → a configured
`SessionContext`; `fake_pytest(workspace, outcome)` → writes a test file that passes/fails/errors.

---

## 28. Global CLI exit-code table (non-hook invocations)

| code | meaning |
|---|---|
| 0 | ok / pass / allowed |
| 1 | refused / failed / blocked by policy |
| 2 | cannot determine (unreadable state, ambiguous session, internal error) — fail closed |
| 3 | nothing to do (nothing to commit, insufficient data) |

`--json` prints exactly one JSON object to stdout; human text goes to stderr in that mode.

---

## 29. End-to-end verification plan (executed by the final verifier)

Each scenario names the command, the expected observable and the pass criterion. All run on a
throwaway workspace created by `tests/conftest.py::workspace` semantics (`git init`, a `src/` and
`tests/` tree, a `.venv` with pytest) and `OMEGA_STATE_DIR` set to a temp dir.

| id | scenario | command(s) | expected |
|---|---|---|---|
| V1 | dangerous commands blocked | pipe each corpus line from `tests/fixtures/shell/deny.txt` as a `PreToolUse/Bash` payload into `sh bin/launch.sh --guard bin/pre_tool_use.py --provider claude`; repeat with `--provider codex` | Claude: exit 2 and stderr starts `[prod-guard] blocked (<rule>)`; Codex: exit 0 and stdout JSON `permissionDecision:"deny"`; every `allow.txt` line exits 0 with empty/allow output |
| V2 | shell-write bypass blocked | payloads `echo x > src/a.py`, `tee src/a.py`, `sed -i s/a/b/ src/a.py`, `python3 -c "open('src/a.py','w')"`, `bash -c 'cat > src/a.py'`, `cp /tmp/x src/a.py`, `cat <<EOF > src/a.py` | all refused with `[bash-write-guard]`; `echo x > /tmp/x`, `echo x > .scratch/x`, `cat src/a.py` allowed; `echo x > $DEST` → UNPROVEN |
| V3 | protected paths | Edit payloads on `.claude/settings.json`, `.omega/clearances/proof.json`, `<harness>/hooks/prod_guard.py` | refused `omega.protected_path`; with `OMEGA_DEV=1` only the harness-root one is allowed |
| V4 | TDD red→green | (a) Edit `src/calc.py` → refused `tdd.no_test_file`; (b) Write `tests/test_calc.py` with a failing test → allowed; PostToolUse launches a job; wait; `red.jsonl` has a row; (c) Edit `src/calc.py` → allowed; (d) edit the test to add a passing case (new sha) → Edit `src/calc.py` refused `tdd.not_red` until red for the new sha; (e) make it pass → job writes `green.jsonl`; `tdd_gate.py status --json` shows PASS | as stated; `OMEGA_TDD_MODE=red-or-green` allows (d) |
| V5 | contract write gate | Write `docs/contracts/x.md` without `propose` → refused; after `propose --file` → allowed; `validate` on a file missing the Journey seam → exit 1 `E006` | as stated |
| V6 | forged approval rejected | transcript fixture where the only "yes" is an assistant message, a `tool_result`, an `isMeta` entry and a `promptSource:"sdk"` entry; `contract_gate.py record --quote "yes"` | exit 1, reason `no human turn since the proposal contains 'yes'` (or `no human turn at all`) |
| V7 | genuine approval accepted | append a `promptSource:"typed"` turn `yes, approve the signup contract` after `request`; `record --quote "yes, approve the signup contract"` | exit 0; `review.json` approval with the turn uuid; a later scenario edit changes the fingerprint and `review` returns FAIL `stale` |
| V7b | live transcript probe | in a real `claude` session on this machine: type a prompt, then run `contract_gate.py status --json` | `human_turns ≥ 1`; if 0, record the build's user-entry fields in `docs/DECISIONS.md` and decide `transcript.accept_unlabelled_user_turns` |
| V8 | premature Stop blocked, hash-bound | after V4(c) with the test still red: Stop payload → exit 2 with `tdd … no green since`; after green: Stop → exit 0 and three clearance files with equal `files_digest` and `verified:true`; then Edit `src/calc.py` again → `hashing.fresh` false; Stop → gates rerun; `auto_ship.py --dry-run` before the rerun → `BLOCKER: clearance stale` | as stated |
| V9 | loop guard | four consecutive blocked Stops → fourth output contains `released after 4 blocked attempts: NOT verified`, `proof.json.released == true`, counter reset; human token: add a `typed` turn containing the token, run `stop_orchestrator.py override …` → next Stop releases with `overridden:true` | as stated |
| V10 | tokentoll breach halts | `tokentoll_gate.py record --model claude-opus-5-5 --in 2000000 --out 500000 --session S` then Stop | `cost FAIL session $… / $5.00`; `check` exits 1; `record --model unknown-x` then `check` exits 3; a corrupt ledger line → exit 2 |
| V11 | ship readiness matrix | run `ship_readiness.py run --json` on fixtures: empty dir (all NOT_APPLICABLE, PASS), a Dockerfile with `FROM x:latest` (infra FAIL), a migration with `DROP COLUMN` (database FAIL; with the waiver comment PASS), `*.tf` with terraform missing on PATH (`PATH=/usr/bin`) → UNVERIFIED with hint; `--strict` → exit 1 | as stated |
| V12 | auto_ship dry run | local bare remote as `origin`; clearances from V8 green → `auto_ship.py --dry-run --json` prints plan with branch `omega/<slug>-<ts>`, staged files = ledger paths, PR body redacted; a staged line containing `sk-ant-api03-…AA` → `BLOCKER: secret anthropic-key tests/x.py:3`; `--yes` as the agent is allowed only when signing is configured (§21a); `--yes` directly → branch pushed to the bare remote, no `gh` → REST fallback attempted and reported |
| V13 | UI key masking | `PUT /api/keys/anthropic` with a synthetic key; `GET /api/keys` → `last4`/`prefix` only; grep the server log and `keys.json` for the key → absent; `env_for` → exactly one `ANTHROPIC_API_KEY`; WS connect with a bad Origin → rejected before accept |
| V14 | adapter parity and smoke | `scripts/check-all.sh` | pytest green; every `bin/*.py hooks/*.py scripts/*.py --help` exits 0; `.claude/settings.json` and `.codex/hooks.json` equal the renderer output; `launch.sh --guard` with `PATH=/nonexistent` exits 2 |
| V15 | hooks under headless | `ui.runner.verify_hooks_fire("claude")` with a real key (budget $0.05) | `observed/claude.json` gains `SessionStart`; if not, `/api/health.hooks_verified.claude == false` and `POST /api/runs` → 503 |

---

## 30. Residual weaknesses (stated, not hidden)

1. No hook sees what a program does once it runs (`make`, `npm run`, `python script.py`, dbt);
   reconciliation at Stop puts the files into proof scope but cannot block the write. Credentials are
   the real boundary.
2. Same-uid UI deployments let a sufficiently creative agent write the human-turn log through an
   on-disk script; the server's HMAC check catches tampering of existing rows but not appended
   forged rows if the agent obtains `OMEGA_SECRET` — which is why it must never be in the agent's
   env. Multi-tenant deployments MUST run agents under separate uids or containers.
3. The transcript format is undocumented; the allow-list degrades to "no human turn", never to
   "approved".
4. `UNVERIFIED` ship checks do not block at Stop (only at ship time) by default.
5. Codex `write_stdin` bypasses PreToolUse; Codex hooks need trust; whether `codex exec` runs hooks
   is checked at boot by the probe, not assumed.
6. Both bounded releases (4 blocked Stops; unreadable transcript) trade trapping the operator for a
   loudly recorded `NOT verified`.

## 31. CORE implementation addenda (binding; written by the CORE implementer)

These record where the shipped CORE differs from, or is more specific than, sections 1–30. Other
packages code against this section where it is more specific.

1. **Comment-free**: production modules carry no docstrings and no comments (task rule; D14's
   "one module docstring" is not used). Every hook-side module starts with
   `from __future__ import annotations`.
2. **Ledger path forms**: `ledger.paths/existing` return absolute paths exactly as recorded
   (`os.path.abspath`, symlinks not resolved); `ledger.source_paths` returns workspace-relative posix
   paths (it is compared with contract `code:` lists). `hashing.snapshot` and `hashing.fresh` accept
   absolute or relative paths and key everything by workspace-relative posix path.
3. **Glob semantics** (`paths.match_globs`): `*` and `?` stay inside one path segment; `**/` matches
   zero or more directories; a trailing `/**` also matches the directory itself; a pattern with no
   `/` matches the basename at any depth (gitignore style, so `*.pem` and `.env*` match nested files).
4. **Protected paths** (`paths.is_protected`) add to §7.2, regardless of `OMEGA_DEV`: everything
   under `paths.state_root()`, the session's `transcript_path`, the file named by `OMEGA_HUMAN_LOG`,
   and anything under `~/.claude`, `~/.codex` or `~/.gemini` (an agent that can append to its own
   transcript could forge a typed turn; one that edits user-level settings could disable hooks). Every check is made on both the `abspath` and the
   `realpath` form of a path, so a symlink into a protected path is protected.
5. **Scratch** (`paths.is_scratch`): a path under the workspace or the harness root is scratch only
   when it matches `workspace.scratch_globs`; temp roots (`/tmp`, `/private/tmp`, `/var/folders`,
   `$TMPDIR`, `tempfile.gettempdir()`) are scratch only outside those governed roots. This keeps a
   workspace that itself lives under a temp dir (every pytest workspace) governed.
6. **Extra public helpers** (stable; other packages may use them):
   `io.render(provider, event, decision) -> (stdout, stderr, code)`, `io.bind_session_dir(path)`;
   `event.new_content(event) -> list[str]` (the text the secret-in-edit guard scans: Write.content,
   Edit/MultiEdit new_string, NotebookEdit new_source, `+` lines of a patch), `event.patch_text`;
   `state.stamp() -> (ts, ts_ns)`, `state.iso(ts_ns)`, `state.read_jsonl(path)`,
   `state.read_override_token(ctx)`, `state.safe_id(text)`, `SessionContext.model`;
   `redaction.redact_text(text)`, `redaction.clear_registered()`, `redaction.STRICT_RULES`;
   `contracts.load_file(path, workspace, strict_existence=False)`, `contracts.seam_counts(c)`,
   `contracts.not_applicable(c)`, `contracts.is_valid(c)`, `contracts.structure(c)`;
   `costledger.UnknownModel`, `costledger.ledger_path(path=None)`, `costledger.read_ledger(cfg, path)`,
   and optional `path=` on `append/rows/sums/check` plus `cap_overrides=` on `check` (for
   `tokentoll_gate.py --ledger/--per-call/...`); `CostVerdict.sums` also carries `caps`,
   `corrupt_line_numbers` and `month_key`.
7. **Shell engine extras** (`hooks/lib/shell.py`): `lex(segment) -> [Token(value, raw, op, opaque)]`
   (quote-aware, redirects split out), `argv_of(segment)` (unquoted argv with redirects and their
   targets removed — prefer it over `strip_redirect_tokens(tokens(...))`),
   `unwrap_with_assignments(argv) -> (inner, assignments)` (keeps `env PATH=… cmd` style assignments
   for `env.dangerous_assignment`), `strip_heredocs(cmd)`, `strip_control(argv)`, `is_shell`,
   `is_interpreter`, and `walk(cmd) -> Walk(commands, dynamic, code)`: the recursive expansion
   (heredoc bodies fed to shells, substitutions, `bash -c`, `eval`, `find -exec`, wrappers incl.
   `uv|poetry|pipenv|pdm|hatch|rye run`) that yields every simple command that would execute
   (`commands[i] = {"argv", "assignments", "depth", "raw"}`), every reason static resolution failed
   (`dynamic`: `ansi_quoting`, `command_word: …`, `eval`, `source: …`, `opaque_shell: …`,
   `parse_failure: …`, `nesting: …`, `too_long: …`) and every interpreter code body (`code`:
   `[(interpreter, code)]`). Heredoc detection is quote-aware (`echo "<<EOF"` opens no heredoc).
8. **Jobs**: the job JSON also carries `workspace` and `debounce_s`; a launch failure writes a
   synthetic result with `status: "error"`; `run_job.py` appends the `red.jsonl`/`green.jsonl` row
   **before** publishing the result file, so a consumer that sees a finished job also sees its
   observation. Views returned by `newest/results/running/harvest/settle` are the job JSON plus
   `done`, `result`, `delivered` and `state` (`result.status`, or `pending` while running);
   `settle` cancels superseded older jobs but leaves a still-running newest job running and reports
   it `pending`.
9. **Transcript**: `Turn.source` is the `promptSource` (or `origin.kind`, or `unlabelled`) for
   Claude, the Codex `source`, or `ui`. `parse_claude(lines, accept_unlabelled=False)`;
   `read_human_turns` passes `cfg.transcript.accept_unlabelled_user_turns`. `channel_of()` returns
   `ui` when `OMEGA_HUMAN_LOG` is set. `assistant_usage` rows also carry `uuid` and keep the last
   entry per `message.id` (streamed entries repeat the id).
10. **Contracts parser**: a seam heading repeated is `E011 unknown section <title> (duplicate)`; a
    path that is absolute or contains `..` is always `E004`/`E005`; `W003` (repeated metadata key)
    and `W007` (seam with both scenarios and a not-applicable line) are warnings; `load_all` skips
    `README.md`.
11. **launch.sh** uses only shell builtins before the interpreter is found (no `dirname`), resolves
    the root with `pwd -P`, runs `set -eu` (plus `pipefail` where the shell supports it), and exits
    2 (`--guard`) / 1 when no script argument is given.
12. **Schema gap closed**: `review.schema.json` override items accept an optional `ts_ns`, since
    §12.5 override records carry one.
13. **Tests**: `tests/` and `tests/lib/` are packages (`__init__.py`); import shared helpers as
    `from tests.conftest import wait_for, make_session_context`. Fixture details: an autouse fixture
    scrubs every `OMEGA_*` variable, `CLAUDE_PROJECT_DIR` and `VIRTUAL_ENV`, points
    `OMEGA_STATE_DIR` at a fresh temp dir and sets `GIT_CONFIG_GLOBAL=/dev/null`; `workspace`
    writes `<ws>/.omega/config.json` with `tdd.debounce_s = 0.05`; `session` is a ready
    `SessionContext` and `make_session(provider, session_id, transcript_path)` builds more;
    `fake_pytest(workspace, outcome, rel="tests/test_fake.py")` with outcome `pass|fail|error`;
    `transcript_writer` also offers `.sidechain`, `.interrupt`, `.raw(row)` and `.path`;
    `run_hook(script_rel, payload, provider, env=None, args=None)` adds `--guard` for
    `bin/pre_tool_use.py`. Fixture data: `tests/fixtures/{claude,codex}/<Event>.json`,
    `tests/fixtures/transcripts/*.jsonl`, `tests/fixtures/shell/{deny.txt,allow.txt,corpus.json}`
    (corpus.json also holds the multi-line cases), `tests/fixtures/clearances/*.json` (golden triple).


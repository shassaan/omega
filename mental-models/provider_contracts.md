# Mental model: provider contracts

How the harness holds, routes and spends provider API keys. Enforced by `ui/provider_manager.py`,
`hooks/lib/costledger.py`, `hooks/tokentoll_gate.py` and `hooks/prod_guard.py` (`env.*` rules).

## Key handling

| rule | mechanism |
|---|---|
| Keys are entered once and never shown again | `PUT /api/keys/{provider}` stores ciphertext; `GET /api/keys` returns `{provider, prefix, last4, created_at, last_used_at, status}`; there is no read endpoint |
| Encrypted at rest | Fernet (AES-128-CBC + HMAC) via `MultiFernet`; master key from `OMEGA_SECRET` (urlsafe-base64, 32 bytes) or a generated `<state_root>/ui/keyfile` with mode 0600; plaintext envelope `{"u": user_id, "p": provider, "k": key}` so a row cannot be swapped between users or providers |
| Env, never argv | the agent subprocess gets a minimal env (`PATH HOME LANG TMPDIR`) plus exactly one provider key (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`) and the `OMEGA_*` run variables; never `OMEGA_SECRET`, `OMEGA_UI_TOKEN`, `OMEGA_GIT_TOKEN` (the latter only for `auto_ship`, run by the server) |
| Never logged | `Secret(str)` prints `****`; `RedactingFilter` on every logger; exact-match scrub of every loaded key (plus base64/url-encoded forms) over every event, job output and PR body |
| The agent cannot read it back | `prod_guard` denies `env`, `printenv`, `export -p`, bare `set`, `declare -p`, `/proc/*/environ`, and `echo $…KEY…`; `PostToolUse` output passes through redaction |
| Validation on entry | pattern pre-check (`sk-ant-`, `sk-`, `AIza`), length ≤ 512, strip; optional provider-side `verify` (`GET /v1/models` with the provider's auth header) sets `status`; failure never deletes the key |
| Rotation | prepend a new key to `OMEGA_SECRET` (comma-separated, newest first) and run `ProviderManager.rotate()`; `kid` increments |
| Threat model | encryption protects dumps and backups, not a compromised host that holds the master key in memory; single-operator in v1; multi-tenant needs per-user uids or containers and a KMS |

Terminal mode uses the human's own shell environment; the harness neither stores nor reads keys
there, it only reports which provider env var names are present in the session context.

## Models, roles, prices (USD per MTok, `omega.config.json` is the source of truth)

| role | provider | model | per-role cap | price in/out | verified |
|---|---|---|---|---|---|
| research | anthropic | `claude-sonnet-5-5` | $3 | 2 / 10 | yes (2026-10-13) |
| architect | anthropic | `claude-fable-5-1` | $5 | 10 / 50 | yes |
| implementer | anthropic | `claude-opus-5-5` | $10 | 4 / 20 | yes |
| utility | anthropic | `claude-haiku-5-5` | $0.50 | 0.10 / 0.50 (≤100k prompt) | yes; >100k tier unverified |
| fallback | openai | `gpt-5.6-sol` / `gpt-5.6-luna` | role cap | 5 / 30, 1 / 6 | **no** (aggregators only) |
| stored only | google | `gemini-3.1-pro-preview`, `gemini-3.8-flash` | — | 2 / 12; 0.75 / 3.75 until 2026-12-31 then 1.5 / 7.5 | yes; no runtime in v1 |

Cache reads bill at `cache_read`; cache writes at 1.25× (5 min) or 2× (1 h) input for Anthropic.
A model absent from the table is a hard failure for gating (exit 3 / `UNVERIFIED`); a
`verified: false` price is accepted with a warning. Never fall back to a cheap default price.

## Budgets

Caps: per call $0.50, per session $5, per run $5, per month $100 (config and `OMEGA_BUDGET_*`
env). Warn at 80%. Measured, not guessed: at Stop the transcript's `assistant.message.usage` rows
are priced and appended to `<state_root>/cost/ledger.jsonl` (idempotent by message id); the UI
appends `result.total_cost_usd` (Claude, authoritative client-side estimate) or `turn.completed.usage`
priced by the table (Codex, `verified_price:false`). `claude -p` always gets
`--max-budget-usd min(per_run_cap − spent, role cap)` as the hard stop.

## Rate limits and backoff

| signal | action |
|---|---|
| HTTP 429 / 529, `system/api_retry` events, `overloaded_error` | exponential backoff `min(2 × 2^attempt, 60) s` + jitter, 5 attempts |
| 5 failed attempts | fall back to the next provider in `ui.fallback_order` that has a key **and** a runtime; record the switch as a `status` event |
| budget cap reached (`--max-budget-usd`, ledger check) | the run ends with status `budget_exceeded`; no fallback (a budget is not a transient error) |
| `claude` exit 143 | SIGTERM: turn unfinished, no result; the runner uses SIGINT first, SIGKILL after 5 s |
| concurrency | one running run per project; a global semaphore sized to the lowest provider tier in use |

## Fallback paths

```
role → cfg.cost.roles[role].provider/model
     → key present for that provider?        no → next provider in fallback_order
     → runtime available (claude | codex)?    no → next provider (google has none in v1)
     → est_cost(worst case) + run_total ≤ per_run_cap?   no → refuse to start (not a fallback)
     → launch; on 5× transient failure → next provider; on budget → stop
```

Each fallback changes the model and therefore the `Co-Authored-By` trailer and the price basis;
the run record keeps the full chain (`run.json.fallbacks: [...]`).

## Headless invocation lines (verified where marked)

- Claude: `claude -p <prompt> --model <m> --output-format stream-json --verbose
  --include-partial-messages --permission-mode acceptEdits --bare --settings <rendered>
  --max-budget-usd <n>` (verified flags; whether `--settings` hooks load under `--bare` is probed at
  boot by `verify_hooks_fire`, never assumed).
- Codex: `codex exec --json --sandbox workspace-write -o <last_message> [-m <m>] <prompt>`
  (`-m` unverified: probed; hooks under `codex exec` unverified: probed; hook trust must be
  granted once per harness version).
- Event normalization: Claude `stream_event.text_delta → text`, `assistant.tool_use → tool_call`,
  `user.tool_result → tool_result`, `result → usage + done`; Codex `item.completed(agent_message)
  → text`, `command_execution → tool_call/tool_result`, `turn.completed → usage`,
  `turn.failed|error → error`; unknown → `raw` (truncated), never a crash.

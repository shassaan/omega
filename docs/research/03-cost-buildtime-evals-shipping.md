# Research 03: Cost Gating, Buildtime Compilation, Evals, Ship-Readiness, Shipping, Orchestration

Date: 2026-10-13. Scope: Python-stdlib + Bash harness (`omega`) with a FastAPI web UI where users paste provider API keys.

Legend: **VERIFIED** = fetched from a cited URL this session. **KNOWLEDGE** = from background knowledge, not re-fetched today (re-check before hard-coding). **UNVERIFIED** = could not confirm; best-known figure given.

---

## 1. LLM cost gating ("Tokentoll")

### 1.1 Is Tokentoll real?

VERIFIED (secondary mirrors; original repo page summarized via WebFetch of github.com/Jwrede/tokentoll):
- Tokentoll is an open-source CI gate for LLM spend ("Infracost for LLM spend"). It **statically scans** Python/JS/TS source for LLM SDK call sites, estimates monthly cost, and scores a PR against a policy, posting PASS/WARN/FAIL.
- Sources: https://mcpservers.org/tr/servers/jwrede/tokentoll , https://glama.ai/mcp/servers/Jwrede/tokentoll , https://github.com/Jwrede/tokentoll
- CLI: `tokentoll scan [PATH...] [--format table|json|markdown] [--calls-per-month N] [--config F]`; `tokentoll diff [REF] [--base A --head B] [--format github-comment] [--fail-on-policy-violation]`; `tokentoll update` (refresh bundled LiteLLM pricing). Has an MCP server (`scan`, `diff`).
- Policy file `.tokentoll.yml`: `budgets.max_monthly_delta_usd`, `budgets.max_callsite_monthly_usd`, `budgets.max_relative_increase`, `policies.block_unknown_models`, `policies.fail_on_policy_violation`; also `default_models`, `calls_per_month`, `skip_dynamic_models`, `exclude`, `overrides`.
- Token estimate: **chars/4 heuristic** unless `tiktoken` is installed (`pip install tokentoll[tiktoken]`). Exit code 1 on FAIL with `--fail-on-policy-violation`; other exit codes UNDOCUMENTED.
- Note: Tokentoll is a *static, PR-time* tool (cost of code changes). It does not meter runtime spend. The harness needs both: static gate (like Tokentoll, or a stdlib re-implementation) and a runtime ledger.

Decision: do not take a hard dependency. Implement the same three layers in stdlib, optionally invoke `tokentoll diff --fail-on-policy-violation` in the generated app's CI if the binary exists (graceful skip otherwise).

### 1.2 Layered cost gating design

| Layer | When | Input | Failure action |
|---|---|---|---|
| L0 static scan | PR / CI | source code call sites, model names | exit 1 if monthly delta > cap or unknown model |
| L1 pre-call estimate | before each LLM call | prompt text + max_tokens | raise `BudgetExceeded` before the network call |
| L2 post-call ledger | after each call | API `usage` fields | append to JSONL ledger; re-check caps |
| L3 aggregate caps | per-run, per-day, per-month | ledger sums | stop run / block new runs |
| L4 CI gate | end of run | ledger summary | non-zero exit fails CI |

### 1.3 Pre-call estimation

Heuristics, in order of preference:
1. Provider token-count endpoint if key available and cost of call is trivial (Anthropic `POST /v1/messages/count_tokens` is free, rate limited; KNOWLEDGE). Do NOT call this by default in the harness (adds latency, needs network).
2. `tiktoken` for OpenAI-family if installed (optional import).
3. Fallback `ceil(len(text) / 4)` tokens (English prose; code/JSON are closer to 3 chars/token, non-Latin scripts 1-2). Apply a **safety multiplier of 1.25** to the fallback so the gate errs conservative.
4. Output estimate: assume `max_tokens` (worst case) for hard caps, or `0.5 * max_tokens` for "expected" reporting.

```python
import math
def est_tokens(text: str, safety: float = 1.25) -> int:
    try:
        import tiktoken  # optional
        return len(tiktoken.get_encoding("o200k_base").encode(text))
    except Exception:
        return math.ceil(len(text) / 4 * safety)

def est_cost(model, in_tok, out_tok, prices):
    p = prices[model]            # USD per MTok: {"in":..,"out":..,"cache_read":..}
    return (in_tok * p["in"] + out_tok * p["out"]) / 1_000_000
```

Gate rule: `est_cost(worst case) + ledger.run_total <= run_cap` else refuse. Also per-call cap (e.g. `$0.50`), per-run cap (e.g. `$5`), monthly cap (e.g. `$100`).

### 1.4 Spend ledger from API usage fields

Append-only JSONL `ledger.jsonl`, one row per call, written with `O_APPEND` + `fsync`; rows are never edited.

Usage field shapes (KNOWLEDGE, stable across versions):
- Anthropic Messages: `usage.input_tokens`, `usage.output_tokens`, `usage.cache_creation_input_tokens`, `usage.cache_read_input_tokens` (and `cache_creation.ephemeral_5m_input_tokens` / `ephemeral_1h_input_tokens` breakdown). Streaming: `message_start.message.usage` has input; `message_delta.usage.output_tokens` is cumulative output.
- OpenAI Chat Completions: `usage.prompt_tokens`, `usage.completion_tokens`, `usage.prompt_tokens_details.cached_tokens`, `usage.completion_tokens_details.reasoning_tokens`. Responses API: `usage.input_tokens`, `usage.output_tokens`, `input_tokens_details.cached_tokens`.
- Gemini: `usageMetadata.promptTokenCount`, `candidatesTokenCount`, `cachedContentTokenCount`, `thoughtsTokenCount`, `totalTokenCount`.
- Claude Code CLI: `--output-format json` result has `total_cost_usd` plus per-model breakdown (VERIFIED, https://code.claude.com/docs/en/headless); it is a client-side estimate and "can differ from your actual bill". Use `--max-budget-usd` as a hard per-invocation cap (VERIFIED, same page).

Ledger row:
```json
{"ts":"2026-10-13T10:00:00Z","run_id":"r1","agent":"implementer","provider":"anthropic",
 "model":"claude-opus-5-5","in":12034,"out":2210,"cache_read":8000,"cache_write":0,
 "usd":0.0914,"est_usd":0.11,"price_version":"2026-10-13"}
```
Record both `est_usd` and `usd` so you can report estimator error and tune the multiplier.

Cached reads: bill at the cache-read rate; cache writes at 1.25x (5m) or 2x (1h) base input for Anthropic (VERIFIED in table below). Batch API: 50% off input and output (VERIFIED for Anthropic).

### 1.5 Caps and failing CI

```
BUDGET_PER_CALL_USD=0.50  BUDGET_PER_RUN_USD=5  BUDGET_MONTHLY_USD=100
```
`harness cost check --ledger ledger.jsonl --run-cap 5 --month-cap 100` exits:
- 0 under all caps; 1 cap breached (CI fails); 2 ledger unreadable/corrupt (fail closed); 3 unknown model in ledger (price missing: fail closed unless `--allow-unknown`).

Monthly cap: sum rows whose `ts` starts with `YYYY-MM`; warn at 80%, fail at 100%. Concurrent writers: use `fcntl.flock` on a sidecar lock when checking-then-appending, otherwise two agents race past the cap.

### 1.6 Current prices (USD per 1M tokens)

**Anthropic**: VERIFIED 2026-10-13 from https://platform.claude.com/docs/en/about-claude/pricing

| Model | Input | 5m cache write | 1h cache write | Cache read | Output |
|---|---|---|---|---|---|
| claude-fable-5-1 (Claude Fable 5.1) | 10 | 12.50 | 20 | 0.25 | 50 |
| claude-opus-5-5 (Claude Opus 5.5) | 4 | 5 | 8 | 0.20 | 20 |
| claude-sonnet-5-5 (Claude Sonnet 5.5) | 2 | 2.50 | 4 | 0.10 | 10 |
| claude-haiku-5-5 (Claude Haiku 5.5, prompts <=100k tokens) | 0.10 | 0.125 | 0.20 | 0.01 | 0.50 |

Notes: Haiku 5.5 has a higher tier above 100k-token prompts (exact figure not captured: UNVERIFIED; treat as higher and re-read the page). Opus 5.5 and Sonnet 5.5 cache-read prices carry a footnote (2) on the page that I did not read; check it. `inference_geo` US-only adds a 1.1x multiplier; Batch is 50% off. Older: Opus 5 / 4.x is 5/25; Sonnet 4.x is 3/15. Model IDs: use exactly the strings the user specified (`claude-fable-5-1`, `claude-opus-5-5`, `claude-sonnet-5-5`, `claude-haiku-5-5`); confirm via `GET /v1/models` at runtime.

**OpenAI**: PARTIALLY VERIFIED (WebSearch aggregators only; openai.com/api/pricing returned HTTP 403 to WebFetch).
- Newest listing found (BenchLM, July 2026): GPT-5.6 Sol (flagship) $5 in / $30 out; GPT-5.6 Terra $2.50 / $15; GPT-5.6 Luna $1 / $6; GA July 9, 2026, 1M context. UNVERIFIED against OpenAI.
- Earlier (Morph, June 2026): GPT-5.5 $5 / $30 (cached $0.50); GPT-5.4-mini $0.75 / $4.50; GPT-5.4-nano $0.20 / $1.25.
- Sources: https://benchlm.ai/openai/api-pricing , https://morphllm.com/openai-api-pricing . Cached input about 10% of input; Batch 50%.
- Decision: treat "flagship = GPT-5.6 Sol $5/$30, mini-tier = GPT-5.6 Luna $1/$6 (or GPT-5.4-mini $0.75/$4.50)" as UNVERIFIED defaults; the price table must be user-overridable.

**Google Gemini**: VERIFIED via WebFetch of https://ai.google.dev/gemini-api/docs/pricing (Standard paid tier, summarized by a small model; spot-check):
| Model | Input | Output |
|---|---|---|
| Gemini 3.1 Pro Preview | 2.00 (<=200k) / 4.00 (>200k) | 12.00 / 18.00 |
| Gemini 2.5 Pro | 1.25 / 2.50 | 10.00 / 15.00 |
| Gemini 3.8 Flash and 3.6 Flash | 0.75 through 2026-12-31, then 1.50 | 3.75 through 2026-12-31, then 7.50 |
| Gemini 3 Flash Preview | 0.50 | 3.00 |
| Gemini 2.5 Flash | 0.30 | 2.50 |
Current pro = Gemini 3.1 Pro Preview (preview status: may change); current flash = Gemini 3.8 Flash (note the 2027-01-01 price step: encode date-effective prices).

Price table design: `prices.json` keyed by model id with `effective_from`, `source_url`, `verified: true|false`, `fetched_at`. A model not in the table is a hard failure for gating (fail closed); a `verified:false` entry produces a warning in the report. Never silently fall back to a cheap default price.

### 1.7 Key-handling note (web UI)
Users paste provider API keys: keep them server-side only, never log them, never write to the ledger or to the repo, redact in subprocess env dumps (`sk-ant-`, `sk-`, `AIza`), pass to subprocesses via env, not argv (argv is visible in `ps`). Store with 0600 perms or OS keyring; never echo back to the browser beyond last 4 chars.

---

## 2. "Algitex" / "Buildtime": compiling bounded LLM calls into deterministic code

### 2.1 Are they real?
- **algitex**: VERIFIED to exist on PyPI (https://pypi.org/project/algitex/; WebSearch snippet: "progressive algorithmization toolchain", `pip install algitex`, `algitex init`, `algitex go`; stages: discovery, extraction, rule generation, hybrid routing by confidence, optimization; v0.1.64 per a health-score page https://mcp.depscope.dev/pkg/pypi/algitex). The PyPI page itself failed to load for WebFetch, so internals are UNVERIFIED. The package appears LLM-generated and early (0.1.x): treat as inspiration, not a dependency.
- **"Buildtime"**: NO product found under that name tied to Algitex. UNVERIFIED / likely a term of art ("compile at build time vs. call at runtime").
- Same pattern under other names (VERIFIED existence via search): "Auto" paper (arXiv 2607.04542, https://www.emergentmind.com/papers/2607.04542) records agent behavior, finds deterministic parts, extracts verified programs; Long Tail compilation pipeline (https://cdn.jsdelivr.net/npm/@hotmeshio/long-tail@0.5.12/docs/compilation.md). Classical analogs: distillation, cascades/routers (FrugalGPT), memoization, "LLM as compiler".

### 2.2 The pattern

```
 LLM call site (bounded: classify / extract / map / normalize)
   |  log (input, output, model, ts) -> calls.jsonl
   v
 MINE   group by normalized input; check output cardinality is small and stable
   v
 SYNTHESIZE   candidates: exact lookup table -> regex/keyword rules -> decision list -> tiny tree
   v
 SHADOW   run rule engine beside the LLM on live traffic, LLM stays authoritative
   v
 PROMOTE only if disagreement upper bound < 0.5% over min sample
   v
 ROUTE   rule hit -> deterministic answer; miss/low-confidence -> LLM fallback (still logged)
```

Eligibility screen ("is this call compilable?"): output space is a closed set or a deterministic function of the input; temperature 0 yields >99% self-consistency (run the LLM twice on a sample; if it disagrees with itself, no rule will match it); inputs repeat or have templates; error cost is bounded. Reject free-form generation, anything needing world knowledge, or high-stakes decisions.

Mining steps (stdlib):
1. Normalize: lowercase, collapse whitespace, replace digits with `<N>`, UUIDs with `<ID>`, emails with `<EMAIL>`; hash the normal form.
2. Exact lookup: map normal-form -> majority output where purity >= 99.5%.
3. Rules: for each output label, find tokens/n-grams with precision >= 99.5% and support >= 20 (greedy covering: pick best rule, remove covered rows, repeat). Emit as regex list ordered by precision.
4. Emit `compiled_<callsite>.py` with a pure function `match(x) -> (label|None, rule_id)`; abstain (None) is first-class.

### 2.3 Shadow run and promotion statistics

Shadow row: `{callsite, input_hash, rule_out, rule_id, llm_out, agree}`. Count only inputs where the rule **did not abstain** for the disagreement rate (abstentions are routed to the LLM and cost nothing in correctness). Also track coverage = fraction of traffic the rules answer (savings come from coverage).

Promotion criterion: **upper confidence bound on the disagreement rate < 0.5%**, not the point estimate.

**Rule of three**: with 0 disagreements in n trials, the 95% upper bound is about 3/n. For 3/n < 0.005 you need n >= 600. (99%: about 4.6/n, so n >= 920.)

**Wilson score upper bound** (better when k > 0 or n is small):
```python
from math import sqrt
def wilson_upper(k, n, z=1.96):
    if n == 0: return 1.0
    p = k / n
    d = 1 + z*z/n
    c = p + z*z/(2*n)
    m = z * sqrt(p*(1-p)/n + z*z/(4*n*n))
    return (c + m) / d
```
Minimum n for Wilson upper < 0.5% (computed this session, z=1.96, one-sided-ish 95%):

| Observed disagreements k | Min matched samples n |
|---|---|
| 0 | 765 |
| 1 | 1130 |
| 2 | 1455 |
| 3 | 1760 |
| 0 at z=2.576 (99%) | 1321 |

Note Wilson with k=0 gives upper = z²/(n+z²), so 765 not 600; the rule of three (n=600) is slightly optimistic. Use Wilson as the gate, rule of three as a quick sanity number. Recommended default: **min n = 1000 non-abstained shadow comparisons, Wilson upper (z=1.96) < 0.005**, and also require the sample to span >= 3 distinct days and cover every output label at least 30 times (otherwise rare labels are untested). The LLM is itself noisy; disagreement against a noisy label overstates rule error, which is conservative.

After promotion: keep a **canary shadow**: continue sampling 2-5% of rule hits through the LLM; if the rolling Wilson upper bound exceeds 1%, demote automatically and alert. Version-pin rules to the prompt hash; changing the prompt invalidates promotion.

CLI sketch: `harness compile mine|synth|shadow-report|promote --callsite NAME`; `promote` exits 0 promoted, 1 refused (stats), 2 insufficient data.

Savings estimate (for the report): `coverage * calls_per_month * avg_call_cost`. Compare with cost of the shadow period.

---

## 3. Braintrust and LangSmith: minimal trace + score surface

### 3.1 Braintrust
Env: `BRAINTRUST_API_KEY` (VERIFIED), optional `BRAINTRUST_API_URL` (KNOWLEDGE). Base URLs: US `https://api.braintrust.dev`, EU `https://api-eu.braintrust.dev`, or self-hosted data plane (VERIFIED, https://www.braintrust.dev/docs/reference/api). Auth: `Authorization: Bearer $BRAINTRUST_API_KEY`.

Log an event (VERIFIED shape):
```bash
curl -sS -X POST "https://api.braintrust.dev/v1/project_logs/$PROJECT_ID/insert" \
  -H "Authorization: Bearer $BRAINTRUST_API_KEY" -H "Content-Type: application/json" \
  -d '{"events":[{"id":"'$(uuidgen)'","input":{"q":"2+2"},"output":"4",
        "scores":{"accuracy":1.0},"metadata":{"env":"ci"}}]}'
```
Spans/traces: the docs page I fetched shows no parent/span fields; from KNOWLEDGE, events carry `span_id`, `root_span_id`, `span_parents:[...]`, and `span_attributes:{name,type}` (type e.g. `llm`, `function`, `eval`), `metrics:{start,end,prompt_tokens,completion_tokens}`. UNVERIFIED today: confirm in the API reference before relying on it.

Read scores: `GET /v1/experiment?project_id=...` lists experiments (VERIFIED); aggregate with `POST /btql` `{"query":"..."}` (VERIFIED existence; example query not shown). Experiment summary endpoint: `GET /v1/experiment/{id}/summarize` (KNOWLEDGE, UNVERIFIED). Registering a project: `POST /v1/project {"name":...}` returns the id (KNOWLEDGE; idempotent get-or-create).

SDK (KNOWLEDGE): Python `pip install braintrust`; `braintrust.init_logger(project="x")`, `@braintrust.traced`, `wrap_anthropic(client)` / `wrap_openai(client)`; `Eval("proj", data=..., task=..., scores=[...])` run via `braintrust eval file.py` (exit non-zero on error; CI gating on score thresholds is user-coded). JS: `npm i braintrust`, `initLogger`, `wrapAnthropic`, `braintrust eval`.

### 3.2 LangSmith
Env (KNOWLEDGE except where marked): `LANGSMITH_API_KEY` (legacy `LANGCHAIN_API_KEY`), `LANGSMITH_TRACING=true` (legacy `LANGCHAIN_TRACING_V2`), `LANGSMITH_ENDPOINT` (default `https://api.smith.langchain.com`; EU `https://eu.api.smith.langchain.com`), `LANGSMITH_PROJECT` (legacy `LANGCHAIN_PROJECT`), `LANGSMITH_WORKSPACE_ID`. The REST doc page itself defines no endpoint env var and hardcodes the host (VERIFIED, https://docs.langchain.com/langsmith/trace-with-api); `LANGSMITH_ENDPOINT` is the SDK's variable.

REST (VERIFIED):
- Auth header `x-api-key: $LANGSMITH_API_KEY`; add `x-tenant-id` only if key spans multiple workspaces.
- Create run: `POST https://api.smith.langchain.com/runs` body `id, name, run_type, inputs, start_time, [parent_run_id, session_name]`.
- Update: `PATCH /runs/{run_id}` body `outputs, end_time`.
- Batch: documented path is `POST /runs/multipart` (needs `dotted_order`, `trace_id`); `/runs/batch` NOT documented on that page.
- The page recommends the SDKs because they batch in a background thread.

```bash
RID=$(python3 -c 'import uuid;print(uuid.uuid4())')
curl -sS -X POST "${LANGSMITH_ENDPOINT:-https://api.smith.langchain.com}/runs" \
  -H "x-api-key: $LANGSMITH_API_KEY" -H "Content-Type: application/json" \
  -d '{"id":"'$RID'","name":"ship-check","run_type":"chain","inputs":{"x":1},
       "start_time":"'$(date -u +%FT%T.%6NZ 2>/dev/null || date -u +%FT%TZ)'","session_name":"harness"}'
```
Read eval scores (KNOWLEDGE, UNVERIFIED): `GET /feedback?run=<run_id>` returns `{key, score, value}`; experiments are "sessions": `GET /sessions?name=...` with `POST /runs/query`. SDK: `from langsmith import Client; Client().list_feedback(run_ids=[...])`, `evaluate(...)`; `@traceable`; `wrappers.wrap_openai`.

### 3.3 Offline static checks that a project is instrumented
No network, grep/AST based, each returns a verdict `instrumented | partial | missing | n/a`:

1. Dependency present: `braintrust` or `langsmith` / `langchain` in `pyproject.toml`, `requirements*.txt`, `package.json`.
2. Init present: `init_logger(` / `initLogger(` / `from braintrust import` or `@traceable` / `from langsmith import` / `wrap_openai|wrap_anthropic`.
3. Coverage: use `ast` to find every LLM call site (`client.messages.create`, `chat.completions.create`, `generate_content`) and check that the client was constructed via a wrapper or the call is inside a `@traced`/`@traceable` function. Report uncovered call sites by file:line.
4. Config: env var names referenced in code are listed in `.env.example` (never real values); no key literals (regex `bt-|sk-|lsv2_`... plus gitleaks).
5. Evals: an `Eval(`/`evaluate(` file exists, and CI workflow runs `braintrust eval` or `pytest` with LangSmith's `@pytest.mark.langsmith`.
Exit: 0 all call sites covered, 1 uncovered call sites (when policy `require_tracing=true`), 0 with warning when no LLM calls found (not applicable).

```python
import ast, pathlib
LLM_ATTRS = {"create","generate_content","invoke","stream"}
def llm_calls(path):
    t = ast.parse(path.read_text())
    for n in ast.walk(t):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in LLM_ATTRS:
            yield n.lineno, ast.unparse(n.func)
```
Graceful degradation: the live-score read is optional; if the API key env var is unset, the harness reports `skipped: no BRAINTRUST_API_KEY` (not failure). Keys supplied via the web UI are injected only into the subprocess env of that check.

---

## 4. Offline, fast ship-readiness checks

All items are KNOWLEDGE (stable CLI behavior) unless marked. Common runner contract: each check is a record `{name, cmd, status: pass|fail|skip|error, exit, duration_s, tail}`. **Missing tool => `skip` with an install hint, never `pass`.** A `--strict` flag turns `skip` of required checks into failure. Run every check with a timeout (e.g. 120 s) and `cwd` = project; capture last 40 lines of output; sanitize secrets from captured output.

Detection helper: `shutil.which(tool)`; and trigger on file presence (`*.tf`, `Dockerfile`, `docker-compose*.yml`, `alembic.ini`, `prisma/schema.prisma`, `dbt_project.yml`, `package.json`, `pyproject.toml`).

### 4.1 Infrastructure as code

| Check | Command | Exit meaning | If missing |
|---|---|---|---|
| terraform fmt | `terraform fmt -check -recursive -diff` | 0 formatted; 3 unformatted files (fail); 1 error | skip, hint "brew install terraform" |
| terraform validate | `terraform init -backend=false -input=false -no-color && terraform validate -no-color` | 0 valid; 1 invalid/err. `init -backend=false` still downloads providers (needs network the first time, or a plugin cache `TF_PLUGIN_CACHE_DIR`); if offline and no cache: mark `skip: providers unavailable`, not fail | skip |
| tflint | `tflint --init && tflint --recursive --format=json` | 0 clean; 2 issues found; 1 error. (`--init` fetches ruleset plugins; offline: skip rule plugins) | skip |
| checkov | `checkov -d . --framework terraform,dockerfile,github_actions --quiet --compact -o json` | 0 pass; 1 failed checks; (>1 error) | skip |
| tfsec (merged into Trivy) | `tfsec . --no-colour --format json` or `trivy config --exit-code 1 --severity HIGH,CRITICAL .` | tfsec: 1 when findings (0 none); trivy: exit code per `--exit-code` | prefer checkov; skip |

Use `-lock=false` / read-only flags when running in CI on shared state; never run `terraform plan/apply` in the offline suite.

### 4.2 Containers

| Check | Command | Exit meaning |
|---|---|---|
| hadolint | `hadolint --format json Dockerfile` (or `--failure-threshold warning`) | 0 none at/above threshold; 1 findings |
| compose config | `docker compose -f docker-compose.yml config -q` | 0 valid; 1 invalid (needs Docker CLI, not daemon; missing env vars warn: supply `--env-file .env.example`) |
| fallback when no docker | parse YAML with `python3 -c "import yaml"` if available, else skip |

### 4.3 Database migrations

| Check | Command | Meaning |
|---|---|---|
| squawk (Postgres SQL lint) | `squawk migrations/*.sql` (`--reporter json`) | 0 clean; 1 violations (e.g. `adding-not-nullable-field`, `ban-drop-column`, `renaming-column`, `require-concurrent-index-creation`) |
| alembic | `alembic check` | 0 no new upgrade ops detected (models match head); 255 or 1 when autogenerate would produce changes or error (needs DB URL to compare: offline fallback `alembic heads` must show exactly 1 head and `alembic upgrade head --sql` must render) |
| prisma | `npx prisma validate` ; `npx prisma format --check` | 0 valid; 1 invalid. Needs `DATABASE_URL` set to any dummy string |
| atlas | `atlas migrate lint --dev-url "docker://postgres/16/dev" --latest 1` | 0 clean; 1 with findings (needs Docker dev DB; offline-degrade: skip) |
| atlas offline | `atlas migrate validate --dir file://migrations` | checksum (atlas.sum) integrity, no DB |

**Own destructive-migration rules (stdlib, works with zero tools)** regex over the added lines of `migrations/` in `git diff base...HEAD`, case-insensitive, comments stripped:
```python
RULES = [
 ("drop-column",   r"\bDROP\s+COLUMN\b|op\.drop_column\(", "high"),
 ("drop-table",    r"\bDROP\s+TABLE\b|op\.drop_table\(", "high"),
 ("truncate",      r"\bTRUNCATE\b", "high"),
 ("not-null-no-default", r"ADD\s+COLUMN\s+\w+\s+[\w()]+\s+NOT\s+NULL(?!.*\bDEFAULT\b)", "high"),
 ("alter-not-null", r"ALTER\s+COLUMN\s+\w+\s+SET\s+NOT\s+NULL|nullable=False", "medium"),
 ("rename-column", r"RENAME\s+COLUMN|op\.alter_column\([^)]*new_column_name", "high"),
 ("rename-table",  r"RENAME\s+TO|op\.rename_table\(", "high"),
 ("alter-type",    r"ALTER\s+COLUMN\s+\w+\s+(SET\s+DATA\s+)?TYPE", "medium"),
 ("index-nonconcurrent", r"CREATE\s+(UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY)", "medium"),
]
```
Policy: `high` => fail unless the migration file contains an explicit waiver comment `-- harness:allow destructive (reason)`; `medium` => warn. Rationale: renames and drops break the previous app version during rolling deploys (expand/contract pattern: add, backfill, switch, then drop in a later release).

### 4.4 dbt (offline)
- `dbt parse --no-partial-parse` : validates project and builds manifest without a warehouse connection if profiles resolve: set `DBT_PROFILES_DIR` to a stub profile (`type: duckdb` or any adapter with dummy creds). Exit 0 ok; 1 error.
- `dbt compile` needs a connection for introspective macros; `dbt parse` is the safe offline gate. If `dbt` missing: skip. Optional: `sqlfluff lint models/ --dialect <d>` (exit 1 violations; 0 clean; needs templater `dbt` or `jinja`).

### 4.5 Language checks

| Stack | Command | Exit meaning |
|---|---|---|
| pytest | `pytest -q -x --maxfail=1 -p no:cacheprovider` | 0 pass; 1 failures; 2 interrupted; 3 internal error; 4 usage error; 5 no tests collected (treat as `fail` for a feature PR, `skip` for bare scaffolds) |
| ruff | `ruff check .` and `ruff format --check .` | 0 clean; 1 violations / unformatted; 2 abnormal (config) |
| mypy/pyright (optional) | `mypy .` / `pyright` | 0 clean; 1 errors |
| vitest | `npx vitest run --reporter=dot` (CI mode, no watch) | 0 pass; 1 fail |
| jest | `npx jest --ci --passWithNoTests=false` | 0 pass; 1 fail |
| eslint | `npx eslint . --max-warnings 0` | 0 clean; 1 lint errors/warnings over cap; 2 config/crash |
| tsc | `npx tsc --noEmit -p tsconfig.json` | 0 clean; 1 diagnostics emitted (2 = errors with emit skipped in older builds): treat any non-zero as fail |
| gitleaks | `gitleaks detect --source . --no-banner --redact --exit-code 1` (history) or `gitleaks protect --staged --redact` (pre-commit; newer: `gitleaks git --staged` / `gitleaks dir .`) | 0 no leaks; 1 leaks found (default); other = error. Always pass `--redact` so secrets never reach logs |

Node commands need `node_modules`; if absent, skip with "run npm ci" rather than auto-installing (network). Python: prefer `python3 -m pytest` / `python3 -m ruff` so the project's venv is used; detect with `python3 -c "import ruff"` failing -> `shutil.which("ruff")`.

Suggested ordering (fast fail, cheapest first): gitleaks -> ruff/eslint -> tsc -> terraform fmt/hadolint/compose config -> migration rules/squawk -> unit tests -> terraform validate/tflint/checkov. Run independent checks in a `ThreadPoolExecutor(max_workers=4)`; total offline budget target under 60 s.

Aggregate exit code of `harness ship-check`: 0 all pass (skips allowed unless `--strict`), 1 any fail, 2 harness internal error. Emit machine-readable `ship-check.json` and a human table.

---

## 5. Mutation testing in CI

### 5.1 mutmut (Python)
- VERIFIED facts (https://mutmut.readthedocs.io , https://pypi.org/project/mutmut): config goes in `pyproject.toml` `[tool.mutmut]`, paths must be arrays; key names differ by version (older/PyPI page: `paths_to_mutate`, `tests_dir`; current readthedocs: `source_paths`, `pytest_add_cli_args_test_selection`). Runs resume and re-test functions modified since the last run. Pattern selection: `mutmut run "my_module*"`. A third-party note reports mutmut 3.x issues in some x86 Linux containers (single-project report, UNVERIFIED).
- KNOWLEDGE: mutmut 3.x commands: `mutmut run [patterns]`, `mutmut results` (lists survivors; `mutmut show <name>`, `mutmut apply <name>`), `mutmut browse` (TUI). mutmut 3 requires a Unix env (use WSL on Windows) and copies sources to `mutants/`. mutmut has **no built-in threshold flag**: compute the score yourself.

```toml
[tool.mutmut]
source_paths = ["src/"]          # older versions: paths_to_mutate = ["src/"]
pytest_add_cli_args_test_selection = ["tests/"]
```
Scoping to changed files:
```bash
CHANGED=$(git diff --name-only origin/main...HEAD -- 'src/**/*.py' | sed 's#^src/##; s#/#.#g; s#\.py$##' )
# mutmut 3 patterns are mutant-name globs of form module.path.x_func__mutmut_N
for m in $CHANGED; do mutmut run "${m}*"; done
```
Score script: parse `mutmut results` output lines `<name>: killed|survived|timeout|no tests|skipped|suspicious`; `score = killed / (killed + survived + timeout + suspicious)`; exit 1 if `score < 0.60` (starting threshold; ratchet toward 0.75-0.80). Output format of `results` varies by version: verify on the pinned version and unit-test the parser. Pin `mutmut==3.x` in a dev requirements file. Mutation runs are slow: run only on PR changed files, nightly full, `timeout-minutes: 30`, and require tests to be fast and deterministic first (mutmut relies on a clean baseline run).

### 5.2 Stryker (JS/TS)
KNOWLEDGE (stryker-mutator.io; re-verify):
```bash
npm i -D @stryker-mutator/core @stryker-mutator/vitest-runner   # or jest-runner
npx stryker init
npx stryker run
npx stryker run --mutate "src/**/*.ts,!src/**/*.test.ts"
npx stryker run --incremental            # reuses reports/stryker-incremental.json
npx stryker run --incremental --since main   # newer versions; else --mutate on git diff list
```
`stryker.config.json`:
```json
{
  "testRunner": "vitest",
  "mutate": ["src/**/*.ts", "!src/**/*.test.ts", "!src/**/*.d.ts"],
  "reporters": ["clear-text", "json", "html"],
  "thresholds": { "high": 80, "low": 60, "break": 55 },
  "incremental": true,
  "concurrency": 4,
  "coverageAnalysis": "perTest"
}
```
Exit: **non-zero (1) when mutation score < `thresholds.break`**; 0 otherwise (break unset => never fails). Scoping to changed files: `npx stryker run --mutate "$(git diff --name-only origin/main...HEAD -- 'src/**/*.ts' | paste -sd, -)"`; if the list is empty skip the run. Score read from `reports/mutation/mutation.json` (`files[*].mutants[*].status`: Killed, Survived, NoCoverage, Timeout, CompileError, Ignored).

Thresholds guidance: new/changed code `break` 60 initially; critical modules (billing, auth, key handling) 80. Count `NoCoverage` as survived. Cache `reports/stryker-incremental.json` between CI runs (actions/cache) so unchanged code is not re-mutated.

### 5.3 Example GitHub Actions "gauntlet"
Pin third-party actions to commit SHAs in production (tags shown for readability; versions KNOWLEDGE, verify).
```yaml
name: gauntlet
on:
  pull_request:
  push: { branches: [main] }
permissions: { contents: read }
concurrency: { group: gauntlet-${{ github.ref }}, cancel-in-progress: true }
jobs:
  lint:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12", cache: pip }
      - run: pip install ruff
      - run: ruff check . && ruff format --check .
      - uses: actions/setup-node@v4
        with: { node-version: 22, cache: npm }
      - run: npm ci && npx eslint . --max-warnings 0 && npx tsc --noEmit
  tests:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12", cache: pip }
      - run: pip install -r requirements-dev.txt && pytest -q
      - uses: actions/setup-node@v4
        with: { node-version: 22, cache: npm }
      - run: npm ci && npx vitest run
  security:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2
        env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
      - run: pip install checkov && checkov -d . --quiet --compact
      - run: pip install pip-audit && pip-audit -r requirements.txt
      - run: npm audit --audit-level=high
  cost:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: python3 harness/cost_check.py --ledger ledger.jsonl --run-cap 5 --month-cap 100
  mutation:
    needs: [lint, tests]
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: "3.12", cache: pip }
      - run: pip install -r requirements-dev.txt mutmut
      - name: mutmut on changed files
        run: python3 harness/mutation_gate.py --base origin/${{ github.base_ref }} --min-score 0.60
      - uses: actions/setup-node@v4
        with: { node-version: 22, cache: npm }
      - run: npm ci
      - uses: actions/cache@v4
        with: { path: reports/stryker-incremental.json, key: stryker-${{ github.base_ref }} }
      - run: npx stryker run --incremental   # thresholds.break in config fails the job
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: mutation-reports, path: reports/ }
```
Gauntlet ordering rationale: cheap gates first, mutation last and PR-only, nightly cron for the full run. Make the gauntlet required via branch protection (required status checks).

---

## 6. Shipping automation (branch, commit, push, PR)

### 6.1 Safety checks before anything leaves the machine
1. `git rev-parse --is-inside-work-tree` ok; resolve `git remote get-url origin` and parse owner/repo.
2. **Protected base**: refuse if the *current* branch is `main|master|release/*|production` (create `harness/<slug>-<ts>` first); refuse `--force`/`--force-with-lease` to protected branches; never push to the base. Optionally query `GET /repos/{o}/{r}/branches/{base}/protection` (404 = unprotected; 403 = no admin permission: treat as unknown).
3. **Clean tree**: `git status --porcelain` must be empty *after* the commit step, and before staging, only expected paths may be dirty. Refuse untracked files outside an allowlist; never `git add -A` blindly: stage explicit paths (`git add -- <paths>`), exclude `.env*`, `*.pem`, `*.key`, `ledger.jsonl`, `node_modules/`.
4. **No secrets in diff**: `git diff --cached -U0` scanned by (a) `gitleaks protect --staged --redact` if installed (b) built-in regexes: `sk-ant-[A-Za-z0-9_-]{20,}`, `sk-[A-Za-z0-9]{20,}`, `AIza[0-9A-Za-z_-]{35}`, `ghp_[A-Za-z0-9]{36}`, `github_pat_[A-Za-z0-9_]{50,}`, `AKIA[0-9A-Z]{16}`, `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`, `xox[baprs]-`, `lsv2_[a-z]{2}_[A-Za-z0-9]{20,}`, plus high-entropy string check (Shannon > 4.5 on 32+ char tokens). Any hit aborts; print file:line only, never the secret.
5. Run `ship-check` (section 4) and require exit 0 (or an explicit `--allow-failing`), and cost gate (section 1).
6. Size guard: diff > N files / N MB => confirm.
7. Dry-run default: print the plan; `--yes` required to push. For the web UI, require an explicit user click and show the diff stat.

### 6.2 Commands
```bash
set -euo pipefail
BR="harness/${SLUG}-$(date -u +%Y%m%d%H%M%S)"
git switch -c "$BR" "origin/$BASE"      # fresh from base; fetch first: git fetch origin "$BASE"
git add -- $PATHS
git diff --cached --quiet && { echo "nothing to commit"; exit 3; }
git commit -m "$TITLE" -m "$BODY" 
git push -u origin "$BR"                 # never --force
gh pr create --base "$BASE" --head "$BR" --title "$TITLE" --body-file pr_body.md --draft
```
Exit codes: `gh pr create` 0 success (prints URL); 1 failure (auth, no commits ahead, PR exists). Check `gh auth status` first; if missing, fall back to REST.

Commit trailers/attribution: end commit messages with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` and PR bodies with `🤖 Generated with [Claude Code](https://claude.com/claude-code)` (per the session's attribution instructions); make this configurable.

### 6.3 REST fallback (no `gh`)
```bash
curl -sS -X POST "https://api.github.com/repos/$OWNER/$REPO/pulls" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" \
  -d "$(python3 -c 'import json,sys;print(json.dumps({"title":sys.argv[1],"head":sys.argv[2],"base":sys.argv[3],"body":sys.argv[4],"draft":True}))' "$TITLE" "$BR" "$BASE" "$BODY")"
```
Responses (KNOWLEDGE): 201 created (`html_url`, `number`); 422 validation (no commits between base and head, or PR already exists; read `errors[].message`); 403/401 auth/scope (fine-grained token needs Pull requests: write and Contents: write); 404 repo not visible to token. Use `urllib.request` in stdlib. Token from env or the web UI session; never place it in the remote URL or argv; use `GIT_ASKPASS` helper or `http.extraheader` via `git -c` for the push so it does not persist in `.git/config`.

Post-PR: poll `GET /repos/{o}/{r}/commits/{sha}/check-runs` for the gauntlet status (optional); never auto-merge by default.

---

## 7. Multi-agent orchestration and streaming

### 7.1 Role split (per the user's request)
| Role | Model | Why |
|---|---|---|
| research | claude-sonnet-5-5 ($2/$10) | broad reading, cheap, parallel |
| architect / analysis | claude-fable-5-1 ($10/$50) | hardest reasoning, few tokens |
| implementer | claude-opus-5-5 ($4/$20) | long-running code edits |
| cheap utility (triage, log summarization, classification) | claude-haiku-5-5 ($0.10/$0.50) | bounded calls: candidate for section-2 compilation |

(Prices VERIFIED in 1.6.) The user-specified assignment is binding; make it config (`roles.yaml`/JSON) with defaults, with per-role `max_budget_usd`. Flow: research -> `docs/research/*.md` artifacts -> architect consumes them, emits a plan with tasks and acceptance checks -> implementer executes one task per subprocess in its own git worktree -> `ship-check` -> PR. Communicate via files and a run directory, not shared memory, so every step is replayable and resumable. Enforce a hard per-agent timeout and budget; on breach, kill the process group (`start_new_session=True`, `os.killpg`).

### 7.2 Running Claude Code as a subprocess (VERIFIED, https://code.claude.com/docs/en/headless)
```bash
claude -p "$PROMPT" --model claude-opus-5-5 --output-format stream-json --verbose \
  --include-partial-messages --permission-mode acceptEdits \
  --allowedTools "Read,Edit,Bash(git diff *),Bash(pytest *)" --max-budget-usd 3 --bare
```
- `--bare` recommended for scripted calls; it does NOT read OAuth/keychain: set `ANTHROPIC_API_KEY` (VERIFIED). Skips hooks, skills, MCP, CLAUDE.md unless passed explicitly.
- Exit 0 success; non-zero on failure; **143 on SIGTERM** (turn left unfinished, no result recorded). Use SIGINT to end a turn gracefully (VERIFIED). Reaching `--max-budget-usd` stops remaining background work.
- `--permission-mode dontAsk` / `--permission-prompts none` (v2.1.259+) for unattended runs; denials appear as `permission_denied` system messages and `permission_denials` in the result (VERIFIED).
- `--json-schema` + `--output-format json` returns `structured_output` (VERIFIED): use for architect plans.
- `--resume <session_id>` / `--continue` for follow-ups; `session_id` from any event.

Event shapes (each line one JSON object). VERIFIED: `system/init` (first event; fields incl. model, tools, `mcp_servers`, `mcp_server_errors`, `plugins`, `plugin_errors`, `capabilities`), `system/api_retry` (`attempt`, `max_retries`, `retry_delay_ms`, `error_status`, `error`, `uuid`, `session_id`), `stream_event` with `.event.delta.type == "text_delta"` and `.event.delta.text`, `assistant`/`user` messages with `parent_tool_use_id` (null for the main conversation, tool-use id for subagents), final `result` line with text, cost, session metadata. KNOWLEDGE (Agent SDK message types; verify field names against https://code.claude.com/docs/en/agent-sdk/typescript):
```json
{"type":"system","subtype":"init","session_id":"...","model":"claude-opus-5-5","tools":["Read","Edit","Bash"],"cwd":"..."}
{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hel"}},"session_id":"...","parent_tool_use_id":null}
{"type":"assistant","message":{"id":"msg_..","role":"assistant","content":[{"type":"text","text":"..."},{"type":"tool_use","id":"toolu_..","name":"Bash","input":{"command":"pytest -q"}}],"usage":{"input_tokens":1,"output_tokens":2}},"parent_tool_use_id":null,"session_id":"..."}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_..","content":"...","is_error":false}]},"parent_tool_use_id":null}
{"type":"result","subtype":"success","is_error":false,"duration_ms":12345,"num_turns":4,"result":"final text","session_id":"...","total_cost_usd":0.0412,"usage":{"input_tokens":..,"output_tokens":..},"permission_denials":[]}
```
`result.subtype` values (KNOWLEDGE): `success`, `error_max_turns`, `error_during_execution`, (budget error subtype name UNVERIFIED). Always check `is_error` AND process exit code. Subagent text appears only with `--forward-subagent-text` (v2.1.211+, VERIFIED).

Ledger integration: each `result` line (and optionally `assistant.message.usage`) feeds section-1 ledger; take `total_cost_usd` as the authoritative per-invocation figure but recompute from tokens as a cross-check (client-side estimate, VERIFIED caveat).

### 7.3 Running Codex as a subprocess (VERIFIED, https://learn.chatgpt.com/docs/non-interactive-mode, redirected from developers.openai.com/codex/noninteractive)
```bash
codex exec --json --sandbox workspace-write -o last_message.txt "$PROMPT"
```
- `--json`: stdout is JSONL. Event types: `thread.started` (`thread_id`), `turn.started`, `turn.completed` (`usage`: `input_tokens`, `cached_input_tokens`, `output_tokens`, `reasoning_output_tokens`), `turn.failed`, `item.started`/`item.completed` (`item`: `id`, `type`, type-specific e.g. `command`, `status`, `text`), `error`.
- Item types (VERIFIED list): agent message, reasoning, command execution, file change, MCP tool call, web search, plan update. Exact `type` strings (KNOWLEDGE, UNVERIFIED): `agent_message`, `reasoning`, `command_execution`, `file_change`, `mcp_tool_call`, `web_search`, `todo_list`.
- Default sandbox read-only; `--sandbox workspace-write` allows edits; `danger-full-access` only in isolated runners; `--full-auto` deprecated (VERIFIED). `-o/--output-last-message <path>` writes final message to file (VERIFIED). Model flag `-m/--model`: NOT confirmed on that page (UNVERIFIED; KNOWLEDGE says `-m` exists).
```json
{"type":"thread.started","thread_id":"0199..."}
{"type":"turn.started"}
{"type":"item.completed","item":{"id":"item_0","type":"command_execution","command":"bash -lc ls","status":"completed"}}
{"type":"item.completed","item":{"id":"item_1","type":"agent_message","text":"Done."}}
{"type":"turn.completed","usage":{"input_tokens":24763,"cached_input_tokens":24448,"output_tokens":122,"reasoning_output_tokens":0}}
```
Codex emits token counts but no USD: compute cost with the price table (OpenAI prices are UNVERIFIED, so flag `cost_confidence: low`).

### 7.4 Normalizing events and streaming to a web dashboard

Normalize both CLIs into one internal event schema so the UI is agent-agnostic:
```json
{"run_id":"r1","seq":42,"ts":"...","agent":"implementer","kind":"text|tool_call|tool_result|usage|status|error|done","data":{...}}
```
Mapping: claude `stream_event.text_delta` -> `text` (debounce into 50-100 ms chunks); `assistant.tool_use` -> `tool_call`; `user.tool_result` -> `tool_result`; `result` -> `usage` + `done`; codex `item.completed(agent_message)` -> `text`; `command_execution` -> `tool_call`/`tool_result`; `turn.completed` -> `usage`; `turn.failed|error` -> `error`. Unknown event types: forward as `kind:"raw"` (truncated) and never crash.

Subprocess reader (stdlib asyncio, in FastAPI):
```python
import asyncio, json, os, signal

async def run_agent(cmd, env, cwd, sink):
    proc = await asyncio.create_subprocess_exec(
        *cmd, cwd=cwd, env=env, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=True, limit=8 * 1024 * 1024)   # long JSON lines
    async def pump(stream, tag):
        async for raw in stream:                          # newline-delimited
            line = raw.decode("utf-8", "replace").strip()
            if not line: continue
            try: ev = json.loads(line)
            except json.JSONDecodeError: ev = {"type": "stderr" if tag == "err" else "stdout_text", "text": line[:2000]}
            await sink(ev)
    try:
        await asyncio.wait_for(asyncio.gather(pump(proc.stdout, "out"), pump(proc.stderr, "err")), timeout=3600)
    except asyncio.TimeoutError:
        os.killpg(proc.pid, signal.SIGINT); await asyncio.sleep(5)
        os.killpg(proc.pid, signal.SIGKILL)
    return await proc.wait()
```
Key points: default `StreamReader` line limit is 64 KiB: raise `limit` or tool outputs crash the reader; close stdin (`DEVNULL`) so the CLI never waits for input; drain stderr concurrently to avoid pipe deadlock; redact secrets from every event before it hits the sink; persist every normalized event to `runs/<id>/events.jsonl` (replay + resume) before broadcasting.

FastAPI WebSocket fan-out:
```python
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
app = FastAPI()
class Hub:
    def __init__(self): self.subs: dict[str, set[asyncio.Queue]] = {}
    def sub(self, run): q = asyncio.Queue(maxsize=1000); self.subs.setdefault(run, set()).add(q); return q
    def unsub(self, run, q): self.subs.get(run, set()).discard(q)
    async def pub(self, run, ev):
        for q in list(self.subs.get(run, ())):
            if q.full(): q.get_nowait()                   # drop oldest: slow client must not stall the agent
            q.put_nowait(ev)
hub = Hub()

@app.websocket("/ws/runs/{run_id}")
async def ws(ws: WebSocket, run_id: str, after: int = 0):
    await ws.accept()                                     # check auth/Origin BEFORE accept in production
    for ev in read_events_file(run_id, after): await ws.send_json(ev)   # replay from disk by seq
    q = hub.sub(run_id)
    try:
        while True: await ws.send_json(await q.get())
    except WebSocketDisconnect: pass
    finally: hub.unsub(run_id, q)
```
Design notes: client reconnect passes last `seq` (`?after=`) for gap-free replay; send heartbeat `{"kind":"ping"}` every 20 s; validate the `Origin` header and a session token on the WebSocket handshake (browsers do not apply CORS to WebSockets: cross-site WebSocket hijacking is possible otherwise); authorize that the user owns `run_id`; SSE (`text/event-stream`) is a simpler alternative if the dashboard is read-only. Stop button: `POST /runs/{id}/cancel` sends SIGINT to the process group, then SIGKILL after grace. API keys pasted in the UI: pass to the subprocess via env for that run only; scrub them from events, `/proc`-visible argv, and `events.jsonl`.

### 7.5 Orchestrator robustness checklist
- One worktree per implementer (`git worktree add ../wt-<task>`), merge sequentially; avoid two agents editing one tree.
- Idempotent steps with a `state.json` (`pending|running|done|failed`) so a crashed harness resumes.
- Per-role budget and global run budget; abort all children when the run cap trips (section 1).
- Treat all agent-produced text and subagent output as untrusted when rendering to the browser (escape HTML; no `innerHTML`).
- Concurrency limit (semaphore) matched to provider rate limits; backoff on `system/api_retry` and 429s.
- Record model id, CLI version (`claude --version`, `codex --version`), and prompt hash per run for reproducibility.

---

## 8. Open items / UNVERIFIED register

1. OpenAI current flagship and mini names and prices (GPT-5.6 Sol / Luna vs GPT-5.5 / 5.4-mini): aggregator sources only; openai.com returned 403.
2. Haiku 5.5 >100k-token tier price, and footnotes (1)/(2) on Anthropic cache-read prices for Fable 5.1 / Opus 5.5 / Sonnet 5.5: not read.
3. Gemini table came through a summarizing fetch; Gemini 3.1 Pro is "Preview".
4. Tokentoll exit codes beyond 1; original repo not read line by line.
5. Algitex internals (PyPI page failed to load); "Buildtime" not found as a product.
6. Braintrust span/parent field names and experiment-summary endpoint; LangSmith feedback/query endpoints and `LANGSMITH_ENDPOINT` semantics (SDK only).
7. Stryker flags (`--incremental`, `--since`), mutmut 3 `results` output format and config key names per version.
8. Codex `-m` flag and exact item `type` strings; Claude `result.subtype` budget-exceeded name.
9. All tool exit codes in section 4 are from background knowledge; test each against the pinned versions.

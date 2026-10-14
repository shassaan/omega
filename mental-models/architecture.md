# Mental model: architecture

The harness is a supervisor wrapped around an AI runtime (Claude Code or Codex CLI). It never
reasons; it intercepts, records, proves and refuses. The agent reasons, writes tests and code. A
human owns sign-off and the signing key; the agent may commit and push only signed commits made as that human. Read `docs/ARCHITECTURE.md` for the binding detail.

## Boundaries

```
 human terminal / web dashboard
   │ types prompts, answers "yes", relays the override token, owns the signing key
   ▼
 AI runtime (claude | codex)  ── tool calls ──►  hooks via bin/launch.sh ──► hooks/lib (stdlib, py3.9+)
   │                                              PreToolUse: guards (fail closed, exit 2)
   │ edits + shell                                PostToolUse: ledger + detached jobs + feedback
   ▼                                              Stop: six gates in parallel → clearances
 WORKSPACE (the generated SaaS app)   ◄── governed: every write is ledgered or refused
   .omega/clearances/{proof,contract,review}.json   ◄── bound to sha256 of touched files
   docs/contracts/<slug>.md                          ◄── Given/When/Then across 4 seams
 STATE (OMEGA_STATE_DIR/<wshash>/<provider>/<session>/)  ◄── ledger, jobs, red/green, approvals, counters
 OMEGA REPO (bin/ hooks/ schemas/ scripts/ ui/)    ◄── protected from the agent
```

Three directories, three trust levels: the harness repo is trusted and protected; the state dir is
harness-written and agent-readable; the workspace is agent-written and harness-governed.

## Data flows

1. **Edit** → `PreToolUse` (protected path? contract proposed? secret in content? test observed red?)
   → tool runs → `PostToolUse` appends `changed.jsonl`, launches a detached test/lint job keyed by
   scope, harvests earlier results (failures interrupt, passes do not).
2. **Shell** → `PreToolUse` `prod_guard` (dangerous verbs, unwrapped recursively, unresolvable →
   deny) then `bash_write_guard` (any write into the workspace → refuse; unreadable target →
   unproven). Writes to `/tmp` and `.scratch/` pass.
3. **Background job** → `run_job.py` sleeps, yields to a newer job in the same scope, runs the
   workspace's own interpreter, classifies the output (pass / fail / skipped_env /
   skipped_no_tests / not_installed / timeout), appends `red.jsonl` or `green.jsonl` with the test
   file's hash at launch.
4. **Stop** → reconcile git state (shell-opaque writes enter proof scope) → settle jobs → gates
   (`proof`, `tdd`, `contract`, `review`, `cost`, `ship`) in a thread pool → four-state aggregate →
   clearances written with the file hash map → block with actionable lines or allow with a summary.
   Four blocked Stops release with `NOT verified`; a human-relayed token releases earlier.
5. **Sign-off** → agent proposes, writes the contract, requests, ends the turn once → human answers
   → `record --quote` finds those words, whole-word, in a human transcript turn after the question,
   with no refusal word, bound to the structure fingerprint. In the web UI the server performs the
   record from its own signed human-turn log.
6. **Ship** → `auto_ship.py` (human or UI only): clearances fresh and verified, approvals match,
   cost under caps, ship readiness full+strict, no secrets or PII in the staged diff → branch from
   `origin/main`, explicit `git add`, commit, push, draft PR.

## Security traps (each one was real)

- Exit 1 is not a block. A crashing guard fails open on Claude, Codex and Gemini. Every guard wraps
  `main` and exits 2 with a deny JSON.
- `PostToolUse` cannot block; it can only talk. A failed edit fires `PostToolUseFailure`, so both
  are registered.
- Codex rejects `permissionDecision: ask` and then proceeds. Never emit `ask`.
- Nested shells, `eval`, `$(…)`, heredocs, `base64 | sh`, `env`/`xargs`/`find -exec` wrappers,
  `/usr/bin/git`, `git -c alias.x=push`: the guard unwraps recursively and denies what it cannot
  resolve. A regex on the raw string is not a guard.
- A shell write (`>`, `tee`, `sed -i`, `python -c open(...)`) never fires `PostToolUse`; an empty
  ledger makes every gate pass falsely green. Refuse the write; reconcile git at Stop as backstop.
- "Skipped" is not green. A missing tool, a missing dependency, zero tests collected, a running
  job: all `UNVERIFIED`, all block when required.
- The wrong interpreter turns `ModuleNotFoundError` into "environment, skipped". Run the workspace's
  `.venv/bin/python`, never the harness's.
- A stale artifact from an earlier run reads as fresh proof. `needs` + `fresh` (mtime vs producer
  start) demote it.
- The agent can write `approved_by: human`. Only the transcript allow-list, a verbatim quote after
  the question, the refusal regex and the fingerprint binding make sign-off unforgeable.
- Typo fixes that re-open approval teach people to approve without reading. Fingerprint the parsed
  structure, not the bytes.
- `env`/`printenv` dump the provider key into the transcript. Deny them; redact exact key values
  from everything the agent sees.
- Secrets in argv are visible in `ps` and shell history. Keys travel in `env`, never argv; git
  tokens via `GIT_ASKPASS`.
- `claude -p` runs repo hooks without a trust prompt; `--bare` skips them. The UI probes at boot
  that hooks fire under `--bare --settings` and refuses to start runs otherwise.
- Codex `write_stdin` bypasses `PreToolUse`; Codex hooks must be trusted; pair with `--sandbox`.
- Attempt counters that never reset silently disable the Stop gate for the rest of a long session.
  Reset on pass and on release.
- Nothing protected `hooks/` and `.claude/settings.json` from the agent's own edits. Now a protected
  path guard does.

## What the harness cannot see

Programs once running (`make`, `npm run build`, `python script.py`, dbt writing `target/`),
aliases from rc files, SQL hidden in string concatenation, `docker run` mounts, MCP tools. The
boundary that holds is credentials: the agent's environment carries one provider key and no cloud,
database-admin or push credentials.

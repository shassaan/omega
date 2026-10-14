# Contract files: format specification

A contract is the behavioural agreement for a non-trivial change, written **before** the code,
approved by a human in their own words, and bound to the code by the harness. One file per change
slug at `<workspace>/docs/contracts/<slug>.md`. The parser is `hooks/lib/contracts.py`; the write
gate and sign-off machinery are `hooks/contract_gate.py`; `docs/ARCHITECTURE.md` §11–12 is binding.

## When a contract is required

A change is **non-trivial** (and needs a contract plus human sign-off before Stop passes) when any of:
1. three or more source files are touched in the session;
2. any touched path matches the always-contract globs (migrations, infra `*.tf`, `auth/`,
   `billing/`, `payments/`, `webhooks/`, `api/`, `routes/`, anything `*secur*`);
3. a new non-test source file is added.

Editing a contract file is itself always in scope: the contract's new structure needs sign-off.

## Order of operations (the gate enforces it)

1. Post the scenarios in chat. Name every judgment call and every assumption. Ask.
2. `contract_gate.py propose --session <S> --file docs/contracts/<slug>.md` — before writing the file.
3. Write the file with the Edit/Write tool (a shell write is refused).
4. If you must end the turn to get an answer: `contract_gate.py request --session <S>` (buys one Stop).
5. The human answers in chat (terminal) or in the dashboard (web).
6. `contract_gate.py record --session <S> --quote "<their exact words>"` — terminal only; the web
   UI server records on the human's behalf.
7. Any later change to a scenario, step, code/tests list or assumption changes the fingerprint and
   re-opens sign-off. Typos in prose do not.

## File format

```
# Contract: <title>
slug: <kebab-case, equal to the file name without .md>
code: <path>[, <path>...]            workspace-relative source files this contract governs
tests: <path>[, <path>...]           workspace-relative test files that implement the scenarios
owed: <text | none>                  what this change deliberately leaves for a follow-up
assumptions: <text | none>           decisions a reviewer should know; may continue as an indented
  - bullet
  - list

## Unit
### Scenario: <unique name>
- Given <precondition>
- And <precondition>
- When <action>
- Then <observable outcome>
- And <observable outcome>

## Integration
### Scenario: ...

## Functional
### Scenario: ...

## Journey
### Scenario: ...
```

Rules:
- Line 1 (first non-empty line) is `# Contract: <title>`. The title is free text and is not part of
  the fingerprint.
- Metadata lines are `key: value`, in any order, all before the first `##`. All five keys are
  required; `owed` and `assumptions` accept `none`.
- Exactly these four `##` sections, each present once, in any order: `Unit`, `Integration`,
  `Functional`, `Journey`. Any other `##` heading is an error.
- Each section has one or more `### Scenario: <name>` blocks. Names are unique within the file.
- A section other than `Unit` may instead contain the single line `_Not applicable: <reason>_`.
  The reason is part of the fingerprint and is read by the human at sign-off.
- Steps are bullets beginning with `Given`, `When`, `Then` or `And`. Every scenario has at least
  one Given, one When and one Then, in that order; `And` continues the keyword before it. Other
  prose inside a scenario is ignored by the parser (it is still read by humans).
- Paths are posix, workspace-relative, no leading `/`, no `..`.

## The four seams

| seam | what it proves | typical runner |
|---|---|---|
| Unit | one function or class in isolation; pure inputs and outputs | pytest / vitest on `tests/test_<name>.py` or `<name>.test.ts` |
| Integration | the component with its real neighbours (database, queue, HTTP client) inside one process or container | pytest with a local Postgres/Redis; supertest / testcontainers |
| Functional | one API surface or feature end to end through its public interface, as a client sees it | FastAPI `TestClient`, Playwright API mode, `httpx` against a running app |
| Journey | a user's path across features, including failure and recovery, from the outside | Playwright browser flows, CLI session scripts |

A seam marked not applicable needs a reason a reviewer would accept ("library-only change, no
user-facing surface").

## Validation codes

`E001` missing title line · `E002` slug does not match file name · `E003` missing metadata key ·
`E004`/`W004` code path not found (error at Stop, warning at propose) · `E005`/`W005` tests path not
found (same) · `E006` seam missing · `E007` seam has no scenario · `E008` scenario lacks
Given/When/Then · `E009` duplicate scenario name · `E010` step out of order · `E011` unknown
section · `E012` And without a preceding step · `E013` metadata line after the first section ·
`E014` Unit seam cannot be not-applicable · `E015` empty code or tests list.

`contract_gate.py validate docs/contracts/<slug>.md` prints them and exits 1 on any `E`.

## What the fingerprint covers

`slug`, sorted `code`, sorted `tests`, normalised `assumptions`, and for each seam the scenario
names and `[keyword, text]` step pairs (or the not-applicable reason), all casefolded with
whitespace collapsed. Not covered: title, `owed`, prose, ordering of seams, blank lines.

## How the harness uses the contract after sign-off

- The `code:` list drives TDD mapping: a source file listed in `code:` maps to the contract's
  `tests:` files (any one observed red suffices to edit it).
- At Stop, `contract.json` records validity and coverage; `review.json` records the approval bound
  to the fingerprint; both are stale as soon as any touched file changes.
- `auto_ship.py` refuses to ship a non-trivial change whose contracts are not approved at the
  current fingerprint, and uses the contract title as the commit title and the scenarios as the PR
  summary.

See `example-user-signup.md` in this directory for a complete worked example.

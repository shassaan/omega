# Reference harness algorithms (for omega)

Source: `analytics-engineering-harness` snapshot in `/Users/hassaan/personal/notebooklm-harness/` (08 hook sources, 09 checks and gauntlet, 06 test trees, 01-03 docs and gotchas). Code blocks are verbatim line ranges from 08 (ranges omit unrelated helpers; elisions are described in prose). Target: Python 3.11 stdlib + Bash, Claude Code and Codex hooks. Every hook reads one JSON payload on stdin.

---

## 1. `hooks/lib/transcript.py`: what counts as a human turn

Principle: an agent writes `assistant` records and tool results; it cannot author a `user` record with `promptSource` of `typed`. The parser is an ALLOW-LIST on that one field and never widens it, so any unknown shape yields zero human turns and callers fail closed.

| Record | Judged |
|---|---|
| `type=user`, `promptSource` in `typed`, `suggestion_accepted`, `queued` | human |
| `promptSource=sdk` | not human, unless `entrypoint=claude-vscode` AND `origin.kind=human` (the VS Code extension runs on the Agent SDK; a background-agent report there carries `origin.kind=task-notification`; an absent or unknown kind is not human) |
| `promptSource=system` | task notification, not human |
| no `promptSource` + `isMeta` | hook/skill injection, not human |
| no `promptSource` + `toolUseResult` key | tool result, not human |
| `type=assistant`, sidechain, compaction summary, slash-command expansion | no explicit branch; excluded because none carries a human `promptSource` (add a fixture per exclusion in the new harness) |

```python
HUMAN_PROMPT_SOURCES = ("typed", "suggestion_accepted", "queued")

PROJECTS_ROOT = Path.home() / ".claude" / "projects"

def _typed_in_vscode(record: dict) -> bool:
    """The VS Code extension runs on the Agent SDK, so a person's turn there says ``sdk``; only its
    ``origin`` kind separates that person from a task notification carrying the same label."""
    origin = record.get("origin")
    return (record.get("promptSource") == "sdk"
            and record.get("entrypoint") == "claude-vscode"
            and isinstance(origin, dict) and origin.get("kind") == "human")


def parse_human_turns(lines: Iterable[str], provider: str = "claude") -> list[dict]:
    """Every turn a person typed, oldest first: {text, ts, source, uuid}.

    Anything the agent can produce — a tool result, a hook injection, a task notification, an SDK
    prompt — is left out, because the point of the list is that the agent cannot add to it.
    """
    if provider == "codex":
        return parse_codex_human_turns(lines)
    turns: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict) or record.get("type") != "user":
            continue
        if record.get("promptSource") not in HUMAN_PROMPT_SOURCES and not _typed_in_vscode(record):
            continue
        if record.get("isMeta") or "toolUseResult" in record:
            continue
        text = _text_of(record.get("message"))
        if not text.strip():
            continue
        stable_id = record.get("uuid") or ""
        turns.append({"text": text,
                      "ts": parse_time(record.get("timestamp")),
                      "source": record.get("promptSource"),
                      "uuid": stable_id,
                      "stable_id": stable_id,
                      "provider": "claude"})
    return turns
```

`_text_of` takes `message.content` if it is a string, else joins `type=text` blocks; empty text is skipped. Turn shape: `{text, ts (aware UTC or None), source, uuid, stable_id, provider}`. Codex (`parse_codex_human_turns`) is also an allow-list: it accepts only `response_item` payloads with `role=user`, `internal_chat_message_metadata_passthrough.content_item_kinds` containing `user.text` (text from `input_text` items), or `event_msg` payloads of type `user_message` that are not `is_automatic`/`isMeta` and whose `source` is in `{user, typed, queued, suggestion_accepted}`; stable id from `payload.id`/`record.id`.

Ordering and matching:

`turns_after(turns, moment)` keeps turns with `ts > moment` (`None` moment keeps all; an unstamped turn is dropped). `normalise(text) = " ".join(text.split()).casefold()`. `quoted_turn(turns, quote)` returns the first turn whose normalised text contains the normalised quote (empty quote => None); it is used for the override token, while sign-off quotes use the stricter whole-word match in section 2.

- Normalisation: casefold + whitespace collapse only. "After the proposal" = strictly later than `max(proposal.ts, request.ts)`; an unstamped turn is never "after". `read_human_turns` returns `[]` for a missing/unreadable file, so anything needing proof of a person fails closed.
- Transcript location: hooks get `transcript_path` in the payload (persisted to `context.json`); the CLI derives `~/.claude/projects/<cwd with "/"->"-">/<session>.jsonl`, else scans all project dirs. Recorded assumption (06 tree): VS Code never stamps `origin.kind=human` on a program-sent turn (306 transcripts, 2,857 human turns checked).

---

## 2. `tree_gate.py` + `tree_write_gate.py`: unforgeable human sign-off

Generalisation for the new harness: any contract artifact needing a human yes (acceptance criteria, test plan, migration plan).

State machine (files in the per-session dir, section 3):

```
write attempt on a contract file
  PreToolUse write gate: REFUSED unless tree_proposal.json covers the file          ("was asked")
agent: tree_gate.py propose [--file F]  -> tree_proposal.json {files, ts, proposal_id: "tp-<8hex>"}
agent writes/iterates (PostToolUse note_touched appends to trees_touched.txt)
agent: tree_gate.py request             -> tree_request.json {fingerprint, consumed:false, ts}
  Stop: matching unconsumed request => allow ONE stop, mark consumed ("waiting is not agreeing")
human replies in chat
agent: tree_gate.py record --quote "<their words>"   (verified, below)
                                        -> tree_approval.json {fingerprint, quote[:400], proposal_id, asked_about, ts}
  Stop: approval.fingerprint == current AND not superseded by a newer proposal_id => pass
escape: human sends the per-session token (tree-<6hex>, stable in tree_token)
agent: tree_gate.py override --token T --reason R -> tree_override.json
  only if T == session token AND T appears in a human turn (transcript.quoted_turn)
```

Fingerprint: sha256 over each file's PARSED STRUCTURE (kind, subject, coverage axes, background and scenario names and steps; prose and wrapping excluded), `<deleted>` for a missing file, raw text if the parser is unavailable. A typo fix does not re-open the contract; any added/changed/removed scenario does ("re-approving a typo teaches people to approve without reading"). Every tree touched is logged in `trees_touched.txt`, so deleting one keeps it in scope.


Verifying a claimed yes (the core). Over-blocking is intentional: "no problem, yes" is refused and the agent must ask again.

```python
REFUSAL = re.compile(r"(?<![\w'])(no|nope|nah|don'?t|do not|doesn'?t|not yet|not now|reject(?:ed)?"
                     r"|hold off|wait|stop|cancel|decline|disagree|never)(?![\w'])", re.IGNORECASE)
MIN_QUOTE_CHARS = 8


def _quoted_whole_words(turns: list, quote: str) -> Optional[dict]:
    """The turn containing `quote` as whole words, not as a fragment of some other word."""
    needle = transcript.normalise(quote)
    if not needle:
        return None
    pattern = re.compile(r"(?<!\w)" + re.escape(needle) + r"(?!\w)")
    for turn in turns:
        if pattern.search(transcript.normalise(turn["text"])):
            return turn
    return None


def verify_human_answer(turns: list, asked_at: Optional[datetime],
                        quote: str) -> tuple[bool, str]:
    """(accepted, reason) for a claimed human yes, judged against the session transcript.

    Fails closed: no transcript, no turn after the question, a quote nobody said, a fragment too
    short to carry a yes, or an answer that contains a refusal or a condition all mean the agent
    has not shown that a person agreed. The gate does not read intent; it refuses to record words
    that plainly say no, and sends the agent back to ask when an answer is mixed.
    """
    if not quote or not quote.strip():
        return False, ("no --quote was given. Quote the words the human actually used to agree, "
                       "so the sign-off records their answer and not your reading of it")
    if not turns:
        return False, ("this session's transcript shows no human turn at all, so their answer "
                       "cannot be confirmed")
    later = transcript.turns_after(turns, asked_at)
    if not later:
        return False, ("the human has not spoken since you proposed the tree — you are recording "
                       "an answer they have not given yet")
    match = _quoted_whole_words(later, quote)
    if match is None:
        return False, (f"no human turn since the proposal contains {quote.strip()[:60]!r} — "
                       "quote what they actually wrote, verbatim")
    refusal = REFUSAL.search(match["text"])
    if refusal:
        return False, (f"their reply contains {refusal.group(0)!r}, which reads as a refusal or "
                       "a condition — ask again and record an unambiguous yes")
    whole = transcript.normalise(match["text"]).strip(" .!")
    needle = transcript.normalise(quote).strip(" .!")
    if needle != whole and len(needle) < MIN_QUOTE_CHARS:
        return False, (f"{quote.strip()!r} is too short to carry a yes on its own — quote the "
                       "whole sentence they agreed with")
    return True, "the human answered in their own words after the proposal"

```

`gate_decision(approval, fp, request, override, proposal)` returns (block, reason) in this order: override present => pass; approval with matching fingerprint and not superseded (approval.proposal_id differs from the newest proposal) => pass; matching request and not consumed => pass once (the Stop hook then calls `consume_request`); matching request already consumed => block "waiting is not agreeing"; superseded => block; stale approval => block; none => block. Binding: `binding_problem` refuses `record` if a request exists whose fingerprint differs from the current one ("the trees changed after you asked"). `record` takes `asked_at = max(proposal.ts, request.ts)`, calls `verify_human_answer(turns, asked_at, quote)`, and writes the approval with the current proposal id. No auto-release while the transcript is readable; `should_release` is true only if the transcript is unreadable AND attempts >= `MAX_ATTEMPTS` (4), and the release message states that NO human approval could be confirmed.

CLI (all take `--session`; omitted => `latest_session_id()`, which resolves only when exactly one session has a ledger, else refuses to guess): `propose [--file]`, `request`, `record --quote`, `override --token --reason`; no subcommand = Stop mode (`_stop`: no touched trees -> allow; else `gate_decision`; allow = one advisory line on stdout, exit 0; block = message on stderr, exit 2 for both providers). The block message holds: the file list; "put it to the human, then `propose`" or "`request` when you must end a turn to ask"; the `record --quote` command; "a sign-off you were not given cannot be recorded"; the override token; all commands as absolute `python script` via `harness_command` (never `$CLAUDE_PROJECT_DIR`, unset under Codex).

Write gate (`tree_write_gate.py`, PreToolUse on Edit|Write|MultiEdit|NotebookEdit|apply_patch, `--guard`): `decide(tool, path, proposal)` blocks iff the tool is a write tool, the path ends in the contract suffix (`.test_trees.md`, case-insensitive) and `proposal_covers` is false; a proposal naming no files covers every tree; an `apply_patch` whose paths cannot be parsed is refused; allowed writes call `note_touched`. Refusal text: post the scenarios in chat, say which are new/changed/removed and every judgment call, ask, then `propose --file <path>`.

---

## 3. `jobstore.py` + `run_job.py`: session store and detached jobs

Root `Path(tempfile.gettempdir())/"aeh-feedback"`; namespaced layout (legacy: `<root>/<session>/`):

```
<root>/<sha256(workspace)[:16]>/<provider>/<session_id>/
  context.json            {provider, workspace, session_id, transcript_path}   written by configure(payload)
  changed.txt             append-only abs paths (lint scope, filtered by os.path.exists)
  changed.jsonl           {path, kind: modified|added|deleted|renamed_from|renamed_to|reconciled, ts: time_ns, provider, workspace}
  unparsed_mutation.txt   reason a mutation could not be attributed (Stop blocks on it)
  <id>.job.json {id, scope_key, label, argv, cwd, ts} | <id>.pid | <id>.result.json {id, rc, output} | <id>.delivered
  proof_attempts, tree_attempts, review_attempts (int counters) | proof.json | reconcile_baseline.json
  tree_{proposal,request,approval,override}.json, tree_token, trees_touched.txt, review_verdict.json
<root>/observed/<provider>.json   {event: epoch}  runtime evidence that a real session ran each hook
```

Env: `CLAUDE_PROJECT_DIR` (workspace fallback), `HARNESS_WORKSPACE`, `PYTHONDONTWRITEBYTECODE=1` for jobs. Every hook calls `jobstore.configure(payload)` first (sets provider/workspace, records `observed`, persists `context.json` for payload-less CLI commands). `session_dir` = `_ROOT/workspace_hash(workspace)/provider/session_id` (mkdir), or `_ROOT/session_id` with no context.

Ledger semantics: `ledger_paths` = every path ever mutated, in first-seen order including deleted/renamed-away (PROOF scope); `changed_files` = those still existing (LINT scope; a dead path passed to a linter is an unrunnable-path error). `overlapping_changes` flags later edits by other sessions to this session's paths.

Launch (`jobstore.launch(session_id, cmd)`): cancel any older not-done job with the same `scope_key`; id = `<scope_key with : and / -> _>-<time_ns>`; write `<id>.job.json`; `subprocess.Popen([sys.executable, run_job.py, job.json], stdout/stderr=DEVNULL, start_new_session=True, close_fds=True, env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"})` and write `<id>.pid`; on `OSError` write a synthetic `rc=1` result "could not launch background job" so something is always reported.

Runner `run_job.py`: sleep `DEBOUNCE_S=0.8`; if another job with the same `scope_key` has a larger `ts`, write a `cancelled` result and exit (only the last edit of a burst pays for the suite); `Path(cwd).is_dir()` else rc 1 ("working directory does not exist", because `FileNotFoundError` is identical for a missing binary and a missing cwd); `subprocess.run(..., timeout=240)`: missing binary rc 127 `"<argv0> not installed"`, timeout rc 124, OSError rc 1. Result is written via tmp + `replace` (atomic) and never overwrites an existing result (a cancelled one wins). It never raises.


Harvest: `select_deliverable` returns, per `scope_key`, only the NEWEST job if it is done, undelivered and not cancelled (an older result describes code edited since). `harvest` -> `(failures, passes)` and marks delivered (only completed jobs, so a running one stays deliverable). `_fmt`: rc 0 pass; rc 127 "not installed", `is_environment_failure`, `is_no_tests` => "skipped" (non-failure); else failure with last 40 lines. `settle` is the Stop proof's view:


`cancel` = `os.killpg(pid, SIGTERM)` on the stored pid plus a `cancelled` result row.

Recording "observed red" (design sketch; the reference has no red-first concept, only these pieces: per-scope `result.json {rc, output}`, `changed.jsonl` with `time_ns`, and `is_environment_failure`/`is_no_tests`):

```python
# in harvest(), when a TEST job's newest result has rc not in (0, None) and is neither env-failure nor no-tests:
append(session_dir/"red.jsonl", {"ts": time_ns, "scope_key": k, "argv": argv, "rc": rc,
        "test_files": {path: sha256(content)}, "output_tail": last_40_lines})
# gate: a production-code edit in a "feature" scope is allowed only if red.jsonl has a record whose test_files
# hashes equal the current test file hashes (red was observed for THIS test), and "done" additionally needs a
# later green result for the same scope_key with ts > red.ts. Exclude non-assertion failures or a missing dependency
# would count as a legitimate red.
```

---

## 4. `stop_proof.py`: "Stop waits for truth"

States: `PASS` (ran, rc 0), `FAIL` (ran and failed; 40-line tail kept), `UNVERIFIED` (nothing verified it: tool absent, runtime dep absent, no tests authored, a producer did not pass, background job still running, or a repo with no proof defined), `NOT_APPLICABLE` (not run, reason stated). Only `FAIL`/`UNVERIFIED` block, and only if `required`. Missing proof is never PASS (the old gate counted a repo proved once any one command ran). If every result in a repo is UNVERIFIED/N-A, an extra `proof` row says "UNPROVEN - nothing ran".

`run_capability(repo, cmd)` never raises and returns: `na_reason` => NOT_APPLICABLE; cwd not a dir => FAIL "cannot run: directory does not exist"; `FileNotFoundError` => UNVERIFIED "<argv0> not installed"; `TimeoutExpired` => FAIL; `OSError` => FAIL; rc 0 => PASS; `is_environment_failure(output)` => UNVERIFIED; `is_no_tests(output)` => UNVERIFIED; else FAIL with `exit N` + last 40 lines.

`needs`: a check runs only if all producers PASSED, else UNVERIFIED naming them. `fresh`: PASS is demoted to FAIL if the artifact mtime is older than the producer's start minus 1s ("read a stale artifact"). `PER_CMD_TIMEOUT=200`.

Degrade-to-skipped rules (`repos.py`), applied to OUTPUT not rc: `is_environment_failure` = any of `hub.getdbt.com`, `Failed to get index`, `Request failed after`, `No module named 'mcp'|'httpx'|'airflow'|'cosmos'`, `Temporary failure in name resolution`, `Max retries exceeded`, `Could not find a version that satisfies` (scoped to named external deps so a missing first-party module still fails loudly); `is_no_tests` = `no tests ran` | `no tests collected` | `file or directory not found:`. In the proof both are UNVERIFIED (blocking when required); in the in-loop feedback they are non-blocking "skipped" lines. Run a repo's own tests with its own `.venv/bin/python` (`repo_python`), never the harness interpreter, or `ModuleNotFoundError` is classified as environment failure, reported skipped and reads green.

Flow (`prove`): reconcile, then `ledger_paths`, `jobstore.settle(15s)`, then per repo `run_suite`, tree checks, comment check, and background outcomes whose `(cwd, tool)` key the proof did not rerun (a `pending` job is rerun synchronously). `main`: unparsed mutation => block (attempt counter); nothing in scope => allow; `blocking = [r for r in results if r.required and r.status in (FAIL, UNVERIFIED)]`; none => write `proof.json` verified, print "[proof] all green for: <repos>" + per-capability lines, plus a concurrent-session overlap warning; else increment attempts and print "[proof] the following must PASS before this work is done (attempt n/4)" + lines to stderr, exit 2.

Loop guard: `_attempts` increments the integer file `proof_attempts` on every blocked stop and is never reset; at `MAX_ATTEMPTS=4` the gate releases with `proof.json {verified:false, released:true}` and the text "NOT verified". An unparsed mutation (Codex `apply_patch` with no parseable path) blocks the same way. `proof.json`: `{ts, repos, verified, released, results:[{repo,label,status,detail,required}]}`. Block = stderr + exit 2 (Claude); pass = stdout + exit 0; Codex = `provider.emit` JSON, exit 0. The reference ignores the payload's `stop_hook_active`. Config timeouts: Stop proof 600s (compat checker requires >= 300), tree/review gates 30s.

---

## 5. `bash_writes.py` + `bash_write_guard.py`: shell-write detection

Why: a shell write never fires PostToolUse, so the ledger is empty and every Stop gate passes falsely green. The guard refuses governed writes AND writes it cannot read (UNPROVEN); it never skips. Hook contract: PreToolUse `Bash`, exit 0 allow, exit 2 + stderr refuse, malformed payload exits 0. REFUSE message: "this command writes into a repo the harness governs: <paths>. Use the Edit, Write or MultiEdit tool on <first> instead. A shell write skips the rule router and the changed-file ledger..."; UNPROVEN message: "writes somewhere the guard cannot work out: <reason>. Spell the destination out as a literal path, or show what the script writes" (never offers a skip).

Constants: `_DEST_ONLY={cp,install,ln,rsync}` (write only their destination), `_ALL_ARGS={mv,rm,tee,truncate,touch,patch,unlink,shred}` (every operand), `_RUNNERS={bash,sh,zsh,source,.}`, `_INTERPRETERS=^(python(3(.N)?)?|node|perl|ruby)$`, `_OPAQUE_CHARS=($,`)`, `_VALUE_OPTIONS` (options whose value is not a path: `-t -S -m -o -g -s -r -e --exclude ...`), `_WRITE_API` regex (`.write_text(`, `open(..."w|a|x")`, `shutil.copy|move|rmtree(`, `os.remove|unlink|rename|replace|truncate(`, `.unlink(`, `.touch(`, `writeFileSync`, `fs.writeFile`, `File.write`).

Tokenisation (`_scan`, hand-written, not shlex): `_heredocs` strips heredoc bodies (judged separately only if the opener's head is an interpreter); `_mask_expansions` replaces `$(...)`, backticks and `[[ ... ]]` with a placeholder (keeps `$` so a substitution used as a destination stays opaque, and so `>` inside arithmetic is not a redirect); `_scan` splits quoted spans whole, strips comments, turns newlines into `;`, normalises every writing redirect (`>`, `>>`, `N>`, `&>`, `>|`) to `>`/`>>`, and DROPS fd duplications (`2>&1`, `>&2`, `2>&-`).

Per-segment writes:

```python
def _writes(segment: list[str]) -> tuple[list[str], bool]:
    """Every destination one simple command writes to, and whether any of them is unreadable."""
    found: list[str] = []
    opaque = False
    for idx, tok in enumerate(segment):
        if tok in _REDIRECTS:
            nxt = segment[idx + 1] if idx + 1 < len(segment) else ""
            if not nxt or _is_opaque(nxt):
                opaque = True
            else:
                found.append(_unquote(nxt))

    name, args = _command_and_args(segment)
    destinations: list[str] = []
    if name in _DEST_ONLY:
        operands, target_dir = _operands(name, args)
        if target_dir is not None:
            destinations = [target_dir]
        elif operands:
            destinations = [operands[-1]]
        else:
            opaque = True
    elif name in _ALL_ARGS:
        operands, target_dir = _operands(name, args)
        destinations = operands + ([target_dir] if target_dir else [])
        if not destinations and name not in ("tee", "patch"):
            opaque = True
    elif name == "sed" or name == "perl":
        in_place = any(_unquote(a) in ("-i", "--in-place") or
                       re.match(r"^-[a-zA-Z]*i", _unquote(a)) for a in args)
        if in_place:
            skip_next = name == "perl"
            files = []
            for a in args:
                if _unquote(a).startswith("-"):
                    skip_next = _unquote(a).endswith("e") and name == "perl"
                    continue
                if skip_next or _quoted(a):
                    skip_next = False
                    continue
                files.append(a)
            destinations = files
            if not files:
                opaque = True
    elif name == "dd":
        destinations = [a.split("=", 1)[1] for a in map(_unquote, args) if a.startswith("of=")]
    for dest in destinations:
        if _is_opaque(dest):
            opaque = True
        else:
            found.append(_unquote(dest))
    return found, opaque

```

`_judge` (whole command): `eval` => UNPROVEN; `xargs` handed a writer => UNPROVEN; track `cd` (an opaque `cd` makes later relative writes opaque); collect redirect/writer targets, run `_scripts` (`bash|sh|zsh|source|. script`; opened and judged recursively ONE level, unreadable or nested script => UNPROVEN), judge inline `python -c`/`node -e`/heredoc interpreter code with `_WRITE_API` + string-literal paths (a write with no literal path => UNPROVEN). Any target with `detect_repo(resolved) is not None` => REFUSE (sorted unique paths); any opaque destination => UNPROVEN.

Allowlisted: `/dev/null` and resolved temp roots (`tempfile.gettempdir()`, `/tmp`, `/private/tmp`); everything outside governed repos is allowed ("the target decides, not the command"). Copying a governed file OUT is allowed (only the destination is written); `mv` also writes its sources.

Acknowledged bypasses: nothing sees what a program does once running (dbt writing `target/`, a Python script file handed to `python`, aliases, Makefiles); only shell scripts one level deep are followed. The backstop is `reconcile.py` (section 7), which compares real git state at Stop, so opaque writes still enter proof scope.

---

## 6. `prod_write_guard.py` + `dbt_guard.py`: dangerous-command blocking

Shape to copy: thin hook (`decide(payload) -> (exit, message)`; `main` fails open only on an unreadable payload; wired with `--guard` so a missing interpreter blocks) over a pure `judge(command, cwd, env) -> Verdict(blocked, reason)`; `judge_invocation(argv, ...)` lets harness-built commands use the same checked path.


Algorithm: (1) pre-filter: no "dbt" and no shell word => ALLOW; (2) `shlex` with `punctuation_chars=";&|()"`; unbalanced quotes AND the tool mentioned => BLOCK; (3) walk simple commands tracking `export`/`unset`/`cd`/inline `NAME=val` env state (last assignment wins); (4) peel wrappers (`env [-i -u]`, `timeout`, `nice nohup time command exec sudo`, `uv|poetry|... run`, `python -m dbt`, `bash -c` recursion, a script body read once); a variable/substitution head, or `eval`/`xargs` containing the tool, => BLOCK "spell the command out"; (5) only write subcommands (`build run seed snapshot test run-operation clone retry`) are judged; resolve the EFFECTIVE target (`--target/-t`, `DBT_TARGET`, profiles-dir / project / `~/.dbt/profiles.yml`, default target, `env_var()` rendering of the schema); BLOCK a prod target (`^(prod|production|prd)([_-].*)?$`), a prod schema (`^(analytics(_.*)?|public|staging)$`) or anything unresolvable (fails closed); (6) every reason is prefixed `[prod-write-guard]` and names the safe alternative. Limit: a Makefile or program running dbt is invisible; the real boundary is credentials. Read-only SQL gate (`readonly_sql.py`): one tokenised statement headed SELECT/WITH/SHOW/EXPLAIN/VALUES, no write keyword anywhere (`WITH ... DELETE`, `EXPLAIN UPDATE`, `INTO`), no side-effect function, rolled-back transaction.

---

## 7. `test_feedback.py` + `reconcile.py`

PostToolUse hook (Claude matcher `Edit|Write|MultiEdit|NotebookEdit`; Codex `^(apply_patch|Edit|Write)$`): (1) `configure`; `mutations_of(payload)`; an `apply_patch` with no parseable path calls `note_unparsed_mutation`; (2) each mutation whose repo is known and `governed()` (not under `.git __pycache__ .venv venv .pytest_cache .ruff_cache .mypy_cache node_modules target dbt_packages logs .mutmut-cache mutants`) is written to the ledger whatever its file type; which checks a file triggers is decided separately by the repo command manifest (`changed_commands`); (3) launch each affected repo's changed-scope jobs (detached) and return at once; (4) `harvest` earlier jobs: failures -> stderr exit 2 (Codex: `emit(PostToolUse)`, which never rejects a completed patch); passes -> stdout only ("good news never interrupts"). It never raises and never blocks the edit.

Reconciliation: at SessionStart (non-compact) `ensure_baseline` saves `{ts, state}` where `state[root][abs_path] = sha256(bytes) | "<deleted>" | "<dir>"` for every path in `git status --porcelain=v1 -z --untracked-files=all` (rename/copy entries contribute both paths; a root that is not the git toplevel yields `None`). At Stop, re-snapshot, take the delta (newly dirty, edited again, deleted, reverted), subtract paths already in this session's ledger and paths another session's ledger recorded since the baseline, and write the rest as `reconciled`/`deleted`.

```python
def reconcile(session_id: str) -> Reconciliation:
    """Add unexplained changes since the baseline to this session's ledger, and return them."""
    path = _baseline_path(session_id)
    if not path.exists():
        ensure_baseline(session_id)
        return Reconciliation([], [], "no session-start baseline was recorded, so writes made "
                                      "outside the edit hooks before now cannot be detected")
    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return Reconciliation([], [], "the session-start baseline is unreadable")
    roots = [Path(root) for root in baseline.get("state", {})]
    current = snapshot(roots)
    unreadable = sorted(root for root, state in current.items()
                        if state is None or baseline["state"].get(root) is None)
    recorded = set(jobstore.ledger_paths(session_id))
    explained = _explained_elsewhere(jobstore.session_dir(session_id), int(baseline.get("ts") or 0))
    found = [p for p in deltas(baseline["state"], current)
             if p not in recorded and p not in explained]
    for changed in found:
        kind = "deleted" if not Path(changed).exists() else "reconciled"
        jobstore.note_changed(session_id, changed, kind)
    return Reconciliation(found, unreadable)
````



---
```

Limits (stated in the module): non-git checkouts are reported unreadable, not guessed; pre-baseline changes are unattributable; with no baseline a note says outside-hook writes cannot be detected.

---

## 8. `session_start.py`

Output via `provider.emit({"provider": p}, "SessionStart", text)`: Claude = plain stdout, exit 0; Codex = JSON `hookSpecificOutput.additionalContext`. `CONTEXT_BUDGET = 9500` (hook output past ~10k chars is cut, so style and principles must arrive whole). Ordinary start, in order: workflow framing line; full `rules/answer-style.md` + route line; full `rules/engineering-principles.md`; mental-model FILE NAMES only; per-repo counts of top-level trees plus the exact command to load a repo packet on demand (load cost is set by WHEN a mechanism loads: inject short whole text and pointers). `source == "compact"` instead consumes one bounded rollover file (`# Rollover Context`, size capped, deleted after reading) or a warning that native compaction stays authoritative. Side effects: `jobstore.use_context`, `observe`, `reconcile.ensure_baseline` (exceptions swallowed so a failing hook cannot break session start); invalid session id => warning text.

---

## 9. `provider.py`: Claude vs Codex

```python
_CONTEXT_EVENTS = frozenset({"PreToolUse", "PostToolUse", "PermissionRequest",
                             "SessionStart", "SubagentStart", "UserPromptSubmit"})
_BLOCK_EVENTS = frozenset({"PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop",
                           "SubagentStop"})
_UNEXPLAINED_BLOCK = "the hook blocked this step without giving a reason"


def codex_output(event: str, message: str = "", block: bool = False) -> str:
    """Render one hook reply in the shape Codex accepts for THIS event.

    Codex validates each event against its own schema with `additionalProperties: false`, so a key
    that is right for one event is a parse failure on another. Only `_CONTEXT_EVENTS` define
    `hookSpecificOutput` and only `_BLOCK_EVENTS` define `decision`/`reason`; everything else
    carries its text on `systemMessage`, which every event accepts. A block always states a reason,
    because Codex rejects `decision: block` without one. An event outside `_BLOCK_EVENTS` has no
    JSON block channel at all, so its reason is delivered as a message and such a hook must block
    by exiting 2 instead.
    """
    if block:
        reason = message or _UNEXPLAINED_BLOCK
        if event in _BLOCK_EVENTS:
            return json.dumps({"decision": "block", "reason": reason})
        return json.dumps({"systemMessage": reason})
    if not message:
        return json.dumps({})
    if event in _CONTEXT_EVENTS:
        return json.dumps({"hookSpecificOutput": {"hookEventName": event,
                                                  "additionalContext": message}})
    return json.dumps({"systemMessage": message})


def emit(payload: dict, event: str, message: str = "", block: bool = False) -> int:
    """Emit provider-correct output. Advisory Codex PostToolUse never rejects code mode."""
    if provider_of(payload) == "codex":
        print(codex_output(event, message, block))
        return 0
    if message:
        import sys
        print(message, file=sys.stderr if block else sys.stdout)
    return 2 if block else 0
````



---
```

- `provider_of`: explicit `provider` key; else `tool_name == "apply_patch"` => codex; else `/.codex/` or `rollout` in `transcript_path` => codex; default claude. `workspace_of`: `cwd`, else `CLAUDE_PROJECT_DIR`, else `os.getcwd()`; `workspace_hash` = first 16 hex of sha256 of the resolved path.
- `mutations_of`: Claude `tool_input.file_path | notebook_path | edits[].file_path`; any `apply_patch` (or a command containing `*** Begin Patch`) parsed as above, giving `added|modified|deleted|renamed_from|renamed_to`, absolute, deduped. A governed path anywhere in a multi-file patch makes the whole patch unsafe.
- Output dialects: Claude blocks with exit 2 + stderr, allows with stdout text. Codex hooks exit 0 and speak JSON validated per event with `additionalProperties:false`: only `_CONTEXT_EVENTS` accept `hookSpecificOutput.additionalContext`, only `_BLOCK_EVENTS` accept `{"decision":"block","reason"}`, all else use `systemMessage`; a block always has a reason; the empty allow is `{}`.
- State is isolated by workspace hash + provider + session id, so one agent's consent or proof never authorises the other's; an ambiguous manual `record` (more than one provider/session active) is refused.

---

## 10. `launch.sh` and hook registration

```sh
#!/bin/sh
# launch.sh — start a harness script under a supported interpreter (Python 3.11+).
#
#   sh hooks/launch.sh [--guard] <path relative to the harness root> [args...]
#
# Order: the harness .venv, then python3.13 / python3.12 / python3.11 / python3 on PATH, each
# accepted only if it really is 3.11 or newer. Every hook, in both adapters, and both MCP servers
# start here, so one resolver decides what "python" means everywhere.
#
# When nothing supported exists: a --guard (a PreToolUse safety hook) exits 2, blocking the tool
# call, because a guard that cannot run must not wave writes through; any other hook exits 1,
# which both adapters show as a hook error without blocking — and says the hook did NOT run.
guard=0
if [ "$1" = "--guard" ]; then
  guard=1
  shift
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
script="$1"
shift
for candidate in "$root/.venv/bin/python" python3.13 python3.12 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1 &&
     "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    exec "$candidate" "$root/$script" "$@"
  fi
done
echo "[harness] $script NOT run: no Python 3.11+ found (checked $root/.venv and PATH)." \
     "Run scripts/setup.sh to create the harness .venv." >&2
if [ "$guard" = 1 ]; then
  exit 2
fi
exit 1
```

`--guard` => exit 2 when no interpreter (a safety hook that cannot run must block); any other hook exits 1 (hook error, not blocking, says it did NOT run). Every hook in both adapters, and the MCP servers (`sh -c "exec sh hooks/launch.sh mcp_servers/x.py"`), start here.

`.claude/settings.json` (command prefix `L` = `sh "$CLAUDE_PROJECT_DIR/hooks/launch.sh"`; each entry `{"type":"command","command":"L ...","timeout":N}`): SessionStart `hooks/session_start.py --provider claude` (20); PreCompact matcher `auto` `hooks/prepare_rollover.py --provider claude` (240); PreToolUse matcher `Bash`: `L --guard hooks/prod_write_guard.py` (30), `L --guard hooks/bash_write_guard.py` (15); PreToolUse matcher `Edit|Write|MultiEdit|NotebookEdit`: `L --guard hooks/tree_write_gate.py` (15); PostToolUse same matcher: `hooks/test_feedback.py` (30), `hooks/rules_router.py` (15); Stop (no matcher), in this order: `hooks/stop_proof.py` (600), `hooks/tree_gate.py` (30), `hooks/review_gate.py` (30).

Also `permissions.deny` for every Slack write tool name and a narrow `permissions.allow`. `.codex/hooks.json`: same events and scripts; commands are `sh -c 'R="$(git rev-parse --show-toplevel)"; exec sh "$R/hooks/launch.sh" ...'` (no `CLAUDE_PROJECT_DIR`); matchers are anchored regexes (`^Bash$`, `^(apply_patch|Edit|Write)$`); `.codex/config.toml` needs `[features] hooks = true`; MCP uses `enabled_tools` allow-lists and approval modes.

Parity (`check_agent_compat.py`) FAILS on: missing target script; Codex hooks off; a matcher that matches none of the adapter's edit tools; a gate removed from both adapters; a handler bypassing `launch.sh`; a `--guard` hook without `--guard` (fails open); missing timeout or Stop timeout < 300s; shared mapping drift. `harness_canary.py` runs every configured hook command as the adapter would, with sanitized fixtures (`hooks/fixtures/{claude,codex}.json`, no real identifiers), into a throwaway TMPDIR (blocked prod write, blocked shell write, blocked unproposed tree write, edit reaches ledger, failure fed back, unverified Stop blocks, empty Stop passes) and records the config digest so a later change reads "stale". `--status` keeps configured / observed / canary / trusted separate.

---

## 11. Ship-readiness, CI, gauntlet, mutation testing

`check_ship_readiness.py` (copy the shape): pure validators over plain dicts, IO loaders at the bottom, three severities, graceful degradation.

```python
FAIL, WARN, INFO = "FAIL", "WARN", "INFO"
@dataclass(frozen=True)
class Finding: dimension: str; severity: str; message: str   # render: "[dim] SEV: msg"
# validate_defined   -> FAIL: wrong layer prefix, not in a co-located schema.yml, no description, no test
# validate_scheduled -> FAIL: gold models not reachable from the prod scheduler selector (passes all CI, deploys, never runs in prod)
# validate_governed  -> WARN;  validate_dashboarded -> INFO (description opt-out regex)
# main: exit 1 iff any FAIL; prints BLOCKERS / WARNINGS / NOTES + "Summary: n blocker(s)..."; a missing sibling repo is a WARN, never a crash.
```

New harness: generalise to "feature exists but is never wired" (migration reversible, route registered, auth guard, env vars declared, tests, CI).

CI (`checks.yml`: PR + push to main, Python 3.11): `python -m pytest tests/ -q`; `check_agent_compat.py`; `check_doc_references.py`; `check_command_contracts.py --offline`; smoke loop `for c in checks/*.py; do python "$c" --help >/dev/null; done`. The validators are the ground truth the agent trusts, so a bug in one must fail CI.

Two "gauntlets": (a) analytics-engineering CI: 16-18 stateless offline gates in `.gauntlet/gates.yml`, each run as `python -m scripts.ci_run_gate <gate> --results f.json`, closed by `--assert-clean` (a results file that recorded nothing is also a failure), aggregated into the required check `gauntlet-verdict`; rules judge the diff through `GAUNTLET_CHANGED_PATHS_FILE`, `GAUNTLET_ADDED_PATHS_FILE`, `GAUNTLET_BASE_REF` (an empty list means every diff rule judges nothing and reports success). (b) harness `gauntlet/`: an adversarial corpus for a linter. `Sandbox` copies the real subject to a tempdir, applies a mutation with asserted anchors (exact text and occurrence count, or exact line), re-parses with `ast.parse` before judging, never writes the subject. `@case(name, "CLEAN"|"REPORTED", needle=...)`; every "must be CLEAN" refactor case is paired with a `-CONTROL` case that must be REPORTED, so a switched-off rule cannot pass. CLASS 1 = false positives (de Morgan, extract-method, `is None`, truthiness); CLASS 2 = bypasses (rebinding the guard name, `and False`, dead `else`, shadowing a flag, tail `return True`, a guard that mentions but does not decide). `gauntlet/spec.md`: acceptance criteria AC1-AC12, critic non-goals, "every violation message must be true of the code".

Mutation testing (`scripts/harness_mutate.py`, mutmut 3): scope = changed files that are the `code:` of a Unit tree inside the repo's `[tool.mutmut]` paths, run against that tree's `tests:` (`--full` = configured paths); disposable `copytree` (mutmut writes `mutants/` into cwd) with a scoped `setup.cfg`; `python -m mutmut run` (900s default), `export-cicd-stats`, `results --all true`; survivors = non-`killed` lines; statuses `ran | nothing to mutate | timed out | could not run` (exit 2, never a pass), exit 1 = survivors; synchronous final gate, not in the optimistic loop. Never delete a test to raise the score. Gotchas: mutmut >= 3.4 needs Python >= 3.10 (on 3.9 pip silently installs 3.3.1: every score 0%, workers segfault); a test spawning a child interpreter in another cwd aborts the whole campaign (mutmut reads `setup.cfg` from cwd at import), so mark it `spawns_python` and exclude it.

---

## 12. Failure modes, false-green paths, lessons

Each of these was a real defect; each should become a regression test before the new gate ships.
1. Skipped counted as green (a skipped mandatory check beside a passing one). Fix: four states, UNVERIFIED blocks, explicit "UNPROVEN - nothing ran".
2. Empty ledger via shell writes. Fix: bash guard + git-snapshot reconciliation; a governed mutation payload with no recordable path blocks as unproven.
3. Wrong interpreter turned `ModuleNotFoundError` into "environment, skipped, green". Fix: per-repo `.venv` first; harness-owned checks keep the harness interpreter so reviewed code has no say in the process judging it.
4. Stale artifact (`target/manifest.json` from an earlier run). Fix: `needs` + `fresh`.
5. Deleted or renamed files dropped out of scope. Fix: proof scope from the full ledger, lint scope from existing files, deleted trees stay in the touched log.
6. Missing cwd looked like "tool not installed". Fix: check `is_dir()` first, FAIL.
7. A background failure already shown stopped counting. Fix: newest job per scope is truth until something newer passes; running jobs are cancelled and rerun.
8. Agent self-approval (`record` wrote `approved_by: human`). Fix: transcript proof, quote, after-proposal, whole words, refusal regex, fingerprint binding, proposal supersession, human-only token.
9. A wrong flag read as a failing gate: the proof passed a flag the script never had (exit 2 "unrecognized arguments"), hidden because the command ran only once `target/manifest.json` existed. Read the usage line before hunting a violation; test invocations against the real signature.
10. Local green, CI red: different tool versions (a stale linter has fewer rules and is silent), Python 3.9 vs 3.11, env vars set only in CI (`GAUNTLET_BASE_REF`, `DBT_PROFILES_DIR`), artifacts left locally from earlier runs. Fixes: a doctor script comparing versions to pins, tests that clear gate env vars, fresh artifacts in a throwaway worktree.
11. Fingerprint noise (re-asking after a typo) trains approval without reading: fingerprint structure.
12. CI facts: `GITHUB_TOKEN` pushes fire no workflows and cannot bypass rulesets (use a deploy key); bot-created PRs do not trigger `pull_request`; YAML 1.1 `on/off/yes/no` parse as booleans.

Residual weaknesses: attempt counters are non-atomic files never reset on success and are the only Stop re-entry defence (no `stop_hook_active` use); "skipped" is inferred by substring (`"skipped" in line`, `"not installed"`), so a structured status field is safer; nothing protects `hooks/`, `.claude/settings.json`, `.codex/` or `.gauntlet/` from the agent's own edits (the reference calls it a CODEOWNERS decision; add a PreToolUse guard); no hook sees a program's runtime behavior, so credentials are the real boundary; the transcript format is not a stable API (the allow-list degrades to "no human turn", never "approved"); both bounded releases (unreadable transcript, proof still red after 4 stops) trade trapping the operator for a loudly recorded "NOT verified".

---

## 13. Reuse checklist

1. Hooks: pure `decide()` + thin stdin/exit-code `main()`; fail open only on an unreadable payload; guards via `launch.sh --guard` fail closed.
2. One store keyed by workspace hash, provider, session id; `configure(payload)` first.
3. Append-only mutation ledger plus Stop-time git reconciliation.
4. Detached scope-keyed jobs, newest-wins delivery, atomic results; Stop settles and reruns.
5. Four-state proof with `needs`/`fresh`; bounded release that records NOT verified.
6. Consent only from an allow-listed human transcript turn, quote after the proposal, structure fingerprint, human-only token.
7. Bash guard: refuse governed and unreadable writes; allow scratch and `/dev/null`.
8. Provider module owns every dialect difference; compat checker + canary + CI smoke loop catch drift.

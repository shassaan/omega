# 02 - Hook protocols and security research

Date: 2026-10-13. Scope: Claude Code hooks, transcript JSONL, Codex CLI / Gemini CLI hooks, shell-guard design, secret/PII regexes, user API key storage.

Evidence legend: **[DOC]** fetched from official docs this session; **[LOCAL]** observed in real transcripts under `~/.claude/projects` on this machine (Claude Code CLI + claude-desktop entrypoints, 2026); **[TESTED]** code I executed here; **[MEMORY/UNVERIFIED]** from prior knowledge, not confirmed by a fetch; **[GAP]** docs silent.

Sources: https://code.claude.com/docs/en/hooks , https://code.claude.com/docs/en/headless , https://code.claude.com/docs/en/tools-reference , https://developers.openai.com/codex/hooks (308-redirects to https://learn.chatgpt.com/docs/hooks) , https://developers.openai.com/codex/noninteractive (-> https://learn.chatgpt.com/docs/non-interactive-mode) , https://geminicli.com/docs/hooks/ and /docs/hooks/reference/ , https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml .

Caveat on method: the hooks page is ~269k characters; WebFetch summarises through a small model, so quoted JSON is as returned by that tool. Anything marked verbatim should still be smoke-tested by logging real stdin (recommended in section A.12).

---

## A. Claude Code hooks protocol

### A.1 Event list [DOC]

The current hooks reference lists 33 events: SessionStart, Setup, UserPromptSubmit, UserPromptExpansion, PreToolUse, PermissionRequest, PermissionDenied, PostToolUse, PostToolUseFailure, PostToolBatch, Notification, MessageDisplay, SubagentStart, SubagentStop, TaskCreated, TaskCompleted, Stop, StopFailure, TeammateIdle, InstructionsLoaded, ConfigChange, CwdChanged, DirectoryAdded, FileChanged, WorktreeCreate, WorktreeRemove, PreCompact, PostCompact, PreModelSwitch, PostModelSwitch, Elicitation, ElicitationResult, SessionEnd.

The seven the harness cares about: SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Stop, SubagentStop, PreCompact. Extra useful ones: PostToolUseFailure (a failed tool call fires this, NOT PostToolUse - harness "after edit" checks must register both or accept misses), PermissionRequest, SessionEnd, PostCompact.

### A.2 Common stdin fields [DOC]

```json
{
  "session_id": "abc123",
  "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
  "transcript_path": "/home/user/.claude/projects/.../transcript.jsonl",
  "cwd": "/home/user/my-project",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse"
}
```

- `permission_mode` is one of `default`, `plan`, `acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`. Not every event example in the docs shows it (SessionStart, PreCompact and ConfigChange examples omit it) - treat all common fields except `session_id`, `hook_event_name`, `cwd` as optional and use `.get()`.
- `prompt_id` is shown in the common-fields block; it appeared in only some examples. In transcripts the same concept is `promptId` on user entries [LOCAL] (see B). Do not require it.
- `transcript_path` is an absolute path to the session JSONL. Subagent hooks additionally get `agent_transcript_path`.
- Hooks run with cwd = Claude's cwd; `$CLAUDE_PROJECT_DIR` is the project root where the session started and stays fixed even if Claude enters a worktree [DOC].

### A.3 Per-event stdin examples [DOC unless noted]

**PreToolUse (Bash)**

```json
{
  "session_id": "abc123",
  "cwd": "/home/user/my-project",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "npm test",
    "description": "Run test suite",
    "timeout": 120000,
    "run_in_background": false
  },
  "tool_use_id": "toolu_01ABC123..."
}
```

**tool_input shapes**

| Tool | Fields | Source |
|---|---|---|
| Bash | `command` (str), `description` (str, optional), `timeout` (ms, optional), `run_in_background` (bool, optional); local transcripts also show `dangerouslyDisableSandbox` | DOC + LOCAL |
| Write | `file_path` (absolute), `content`; local transcripts also show an optional `description` | DOC + LOCAL |
| Edit | `file_path` (absolute), `old_string`, `new_string`, `replace_all` (bool) | DOC + LOCAL |
| NotebookEdit | docs describe modes `replace` (default) / `insert` / `delete`, target by `cell_id`, `insert` requires `cell_type` of `code` or `markdown`. Exact key names `notebook_path`, `cell_id`, `new_source`, `cell_type`, `edit_mode` are MEMORY/UNVERIFIED: the hooks page does not give a schema and no NotebookEdit call exists in the local transcripts | partial |
| MultiEdit | **Not listed in the current tools reference at all [DOC]**; no MultiEdit call in ~160k local transcript lines. Treat as legacy: match it defensively (`Edit|Write|MultiEdit|NotebookEdit`) but do not depend on its shape. If seen, MEMORY says `{file_path, edits:[{old_string,new_string,replace_all}]}` | GAP |
| Agent (subagent spawn) | `description`, `prompt`, `subagent_type`, `model`, `run_in_background` [LOCAL]. The old tool name was `Task`; the current tools table names it `Agent` [DOC]. Match `Agent|Task` | DOC + LOCAL |

Matcher note [DOC]: only letters, digits, `_`, `-`, space, `,`, `|` -> exact-name list (`Edit|Write` works). Any other character makes it an unanchored JS regex, so `Edit.*` also matches `NotebookEdit`; use `^Edit$`. MCP tools are `mcp__<server>__<tool>`.

**PostToolUse** (adds `tool_response`, `tool_use_id`, `duration_ms`)

```json
{
  "session_id": "abc123",
  "transcript_path": "/Users/.../.claude/projects/.../00893aaf-....jsonl",
  "cwd": "/Users/...",
  "permission_mode": "default",
  "hook_event_name": "PostToolUse",
  "tool_name": "Write",
  "tool_input": { "file_path": "/path/to/file.txt", "content": "file content" },
  "tool_response": { "filePath": "/path/to/file.txt", "type": "create" },
  "tool_use_id": "toolu_01ABC123...",
  "duration_ms": 12
}
```

`tool_response` shape is tool-specific. For Bash the docs' `updatedToolOutput` example implies `{stdout, stderr, interrupted, isImage}` [DOC, inferred]. Do not assume an `exit_code` key exists; Bash failures are routed to PostToolUseFailure [MEMORY - verify by logging].

**UserPromptSubmit**

```json
{
  "session_id": "abc123",
  "transcript_path": "/Users/.../.claude/projects/.../00893aaf-....jsonl",
  "cwd": "/Users/...",
  "permission_mode": "default",
  "hook_event_name": "UserPromptSubmit",
  "prompt": "Write a function to calculate the factorial of a number"
}
```

**Stop**

```json
{
  "session_id": "abc123",
  "transcript_path": "~/.claude/projects/.../00893aaf-....jsonl",
  "cwd": "/Users/...",
  "permission_mode": "default",
  "hook_event_name": "Stop",
  "stop_hook_active": true,
  "last_assistant_message": "I've completed the refactoring. Here's a summary...",
  "background_tasks": [ { "id": "task-001", "type": "shell", "status": "running", "description": "tail logs", "command": "tail -f /var/log/syslog" } ],
  "session_crons": [ { "id": "cron-001", "schedule": "0 9 * * 1-5", "recurring": true, "prompt": "check the build" } ]
}
```

- `stop_hook_active` is `true` when Claude Code is already continuing because of a stop hook. **Loop guard: if it is true and the condition is unresolved, exit 0 (or cap retries by counter file keyed on session_id) - otherwise infinite loop.**
- `last_assistant_message` gives the final text without parsing the transcript.

**SubagentStop**: same as Stop plus `agent_id`, `agent_type` (e.g. "Explore"), `agent_transcript_path` (`.../<session>/subagents/agent-<id>.jsonl`). `decision:"block"` keeps the subagent running and delivers `reason` as its next instruction.

**SessionStart**: `source` in `startup | resume | clear | compact | fork` (matcher values are the same); optional `model`, `agent_type`, `session_title`; on `resume`/`fork` also `seconds_since_last_response`, `context_tokens`, `prompt_cache_likely_expired`, `estimated_cache_write_usd` (v2.1.251+). Only `command` and `mcp_tool` hook types are supported for SessionStart.

**PreCompact**: matcher values `manual | auto`. Input adds `trigger` and `custom_instructions` (`custom_instructions` is what the user typed after `/compact`, `null` if nothing, always `null` for `auto`):

```json
{ "session_id": "abc123", "transcript_path": "...", "cwd": "/Users/...", "hook_event_name": "PreCompact", "trigger": "manual", "custom_instructions": null }
```

Exit 2 or `decision:"block"` blocks compaction; `systemMessage` and `continue` are discarded for PreCompact.

### A.4 Exit codes [DOC]

| Exit | Meaning |
|---|---|
| 0 | Success. If stdout is a single JSON object it is parsed; otherwise plain text. For UserPromptSubmit, UserPromptExpansion, SessionStart and PostModelSwitch plain stdout becomes context for Claude. Claude never sees stderr on exit 0. |
| 2 | Blocking error: on blockable events the action stops and **stderr is the reason**. Exit 2 blocks even if JSON says allow. |
| other (incl. 1) | Non-blocking error: action continues, a "hook error" notice is shown. **Exit 1 is NOT a block** - a crashing Python hook (traceback -> exit 1) fails OPEN. |

Exit 2 blocks: PreToolUse, UserPromptSubmit, UserPromptExpansion, Stop, SubagentStop, TeammateIdle, TaskCreated, TaskCompleted, ConfigChange, PreCompact, PreModelSwitch, Elicitation, ElicitationResult, WorktreeCreate, WorktreeRemove, PostToolBatch. Exit 2 does NOT block PostToolUse (stderr is only shown to Claude), PostToolUseFailure, PermissionDenied, Notification, StopFailure, SessionEnd, PostCompact, PostModelSwitch.

**Implementation consequence:** every guard hook must wrap `main()` in `try/except BaseException` and `sys.exit(2)` (or emit a deny JSON) on internal error. The docs also add an `onFailure: "block"` hook option (v2.1.295+) that makes a failed or timed-out command hook block - use it as a belt-and-braces setting where the installed Claude Code version supports it, and gate on version.

### A.5 JSON output [DOC]

Universal fields: `continue` (default true; `false` stops Claude entirely, `stopReason` shown to user), `suppressOutput` (accepted but **no effect**), `systemMessage` (warning shown to the user), `terminalSequence` (ignored in `-p`/SDK).

PreToolUse (new style; top-level `decision`/`reason` is deprecated, `"approve"->allow`, `"block"->deny`):

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "git push is blocked in this harness",
    "updatedInput": { "command": "..." },
    "additionalContext": "optional text injected for Claude"
  }
}
```

- `permissionDecision`: `allow | deny | ask | defer`. Precedence across multiple hooks: `deny > defer > ask > allow`. `updatedInput` replaces the whole input object. `ask` and `defer` are Claude Code only (Codex rejects `ask`, see C).
- Careful: `allow` from a hook does not override a `deny` permission rule from settings; and exit 2 beats everything.

PostToolUse:

```json
{ "decision": "block", "reason": "Lint failed: ...",
  "hookSpecificOutput": { "hookEventName": "PostToolUse", "additionalContext": "This file is generated.", "updatedToolOutput": { "stdout": "[redacted]", "stderr": "", "interrupted": false, "isImage": false } } }
```

`decision:"block"` after the fact cannot undo the tool; it feeds `reason` to Claude. `updatedToolOutput` changes only what Claude sees (useful for secret redaction of tool results). `additionalContext` is wrapped in a system reminder; strings over 10,000 chars are written to a file and replaced by a 2,000-char preview.

Stop / SubagentStop / UserPromptSubmit / PreCompact / ConfigChange: top-level `{"decision":"block","reason":"..."}` - only valid value is `"block"`; omit to allow. For Stop, `reason` is required when blocking and becomes Claude's next instruction.

UserPromptSubmit extras: `hookSpecificOutput.additionalContext`, `sessionTitle`, `suppressOriginalPrompt`.

SessionStart:

```json
{ "hookSpecificOutput": { "hookEventName": "SessionStart",
    "additionalContext": "Current branch: feat/x\nUncommitted: src/a.ts",
    "sessionTitle": "auth-refactor" } }
```

Other SessionStart outputs: `initialUserMessage` (becomes the first user message in `-p` mode), `watchPaths`, `reloadSkills`. Plain stdout also becomes context. `CLAUDE_ENV_FILE` is available to SessionStart hooks: append `export K=V` lines to persist env vars into later Bash calls.

### A.6 settings.json registration [DOC]

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash",
        "hooks": [ { "type": "command",
                     "command": "python3 \"$CLAUDE_PROJECT_DIR/hooks/bash_guard.py\"",
                     "timeout": 10 } ] }
    ],
    "PostToolUse": [
      { "matcher": "Edit|Write|MultiEdit|NotebookEdit",
        "hooks": [ { "type": "command", "command": "python3 \"$CLAUDE_PROJECT_DIR/hooks/post_edit.py\"", "timeout": 30 } ] }
    ],
    "Stop":         [ { "hooks": [ { "type": "command", "command": "python3 \"$CLAUDE_PROJECT_DIR/hooks/stop_gate.py\"" } ] } ],
    "SessionStart": [ { "matcher": "startup|resume|clear|compact", "hooks": [ { "type": "command", "command": "python3 \"$CLAUDE_PROJECT_DIR/hooks/session_start.py\"" } ] } ]
  }
}
```

- Exec form without a shell: `"command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/x.sh", "args": []` avoids quoting issues. `"if": "Bash(rm *)"` (permission-rule syntax) pre-filters on tool events.
- Timeouts (seconds): default 600 for command/http/mcp_tool, 30 prompt hooks, 60 agent hooks; UserPromptSubmit 30. Set explicit short timeouts on gating hooks.
- Locations: `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`, managed policy, plugin `hooks/hooks.json`, skill/subagent frontmatter. Matching hooks from all layers run (in parallel - see Limitations).
- The local environment shows hooks registered as `sh -c 'python3 "$CLAUDE_PROJECT_DIR/hooks/stop_proof.py"'` and a launcher `sh "$CLAUDE_PROJECT_DIR/hooks/launch.sh" hooks/rules_router.py` [LOCAL]: a `launch.sh` indirection that picks an interpreter is a pattern already in use here.

### A.7 Headless: do hooks fire? [DOC]

- `claude -p` **does** run hooks from the project's `.claude/settings.json`, and connects `.mcp.json` servers, "even in a folder you've never trusted"; no trust dialog and no per-server approval in `-p`. Security consequence for a web UI that runs untrusted repos: repo-controlled hooks execute. Counter-measure: `--bare` skips auto-discovery of hooks, skills, plugins, MCP, CLAUDE.md, auto memory; then supply your own via `--settings <file-or-json>`, `--mcp-config`, `--append-system-prompt`, `--agents`, `--plugin-dir`. `--bare` also ignores OAuth/keychain: needs `ANTHROPIC_API_KEY` (or `apiKeyHelper` in the `--settings` JSON, or Bedrock/Vertex/Foundry creds). Docs say `--bare` will become the default for `-p` in future - pin behaviour explicitly. **[GAP]: docs fetched do not state whether `--settings` hooks are honoured under `--bare`; the table implies `--settings` is the supported way to load settings, so hooks inside it should run - smoke-test this.**
- Flags [DOC]: `--output-format text|json|stream-json`; `stream-json` needs `--verbose` (and `--include-partial-messages` for token deltas); `--json-schema` with `json` -> `structured_output` field; `--allowedTools "Bash(git diff *),Read"` (prefix match with ` *`; space before `*` matters); `--permission-mode auto|dontAsk|acceptEdits|plan|default|bypassPermissions`; `dontAsk` denies everything not pre-approved (good for locked-down CI); `--permission-prompts none` (v2.1.259+) denies anything that would prompt unless a PermissionRequest hook allows; `--continue`, `--resume <id|path.jsonl>`; `--append-system-prompt`; `--max-budget-usd`; `--forward-subagent-text`. A run with no explicit mode takes the built-in starting mode, **which can be `auto`** - always pass `--permission-mode` explicitly.
- `--max-turns`: **not covered by the headless page fetched; [MEMORY/UNVERIFIED]** it exists as a `-p` flag in the CLI reference. Check https://code.claude.com/docs/en/cli-reference before relying on it.
- Exit codes: 0 success, non-zero failure, 143 on SIGTERM. SIGTERM runs only `SessionEnd` hooks. Stdin piping capped at 10MB.
- stream-json events: first is `system/init` (model, tools, `mcp_servers`, `plugins`, `plugin_errors`, `capabilities`); before it, `hook_started`/`hook_progress`/`hook_response` for SessionStart/Setup hooks; `system/api_retry` (fields `attempt, max_retries, retry_delay_ms, error_status, error, uuid, session_id`); `assistant`/`user` messages with `parent_tool_use_id` (null for main thread, `toolu_...` for subagents, `forked-command-...` for slash-forked skills); denials appear as `permission_denied` system messages and in the final `result.permission_denials`; last line is `result` with cost (`total_cost_usd`), `session_id`, `result`.
- Headless-specific hook facts [DOC]: `SessionStart` may emit `initialUserMessage`; `Setup` fires with `--init`/`--maintenance`/`--init-only`; `terminalSequence` ignored; `systemMessage` surfaces as `SDKInformationalMessage`; slash commands/skills work in `-p` (expanded before running) but terminal-UI built-ins do not.
- Agent SDK equivalent: Python and TypeScript packages (https://code.claude.com/docs/en/agent-sdk/overview) expose the same loop with `canUseTool` callback, native message objects and programmatic hook callbacks ("Agent SDK callback hooks that exceed their timeout block the tool call" [DOC]). Exact option names (`hooks=`, `permission_mode=`, `setting_sources=`, `allowed_tools=`) are [MEMORY/UNVERIFIED] - fetch the SDK pages before coding. For the web UI, a long-lived SDK process (streaming input) beats spawning `claude -p` per message because you get `canUseTool` for interactive approvals.

### A.8 Implementation rules (Claude)

Fail closed (top-level try/except -> exit 2); one JSON object on stdout, debug to stderr; Stop gates must check `stop_hook_active` and keep a per-session retry counter; register PostToolUse AND PostToolUseFailure; enforce with `permissions.deny`/`dontAsk`/sandbox as the real boundary (hooks are layer two). Reference hook shape: parse stdin, call `analyse(command)` from `code/shell_guard.py`, print the deny JSON from A.5, wrap in try/except -> exit 2.

---

## B. Transcript JSONL: telling a human prompt from everything else

All of B is **[LOCAL]** (observed across ~165k lines in 60 recent session files plus 273 subagent files) unless noted; the transcript format is not a documented stable interface (Codex docs say the same about theirs; Claude docs silent) - parse defensively and re-verify per Claude Code version. Files: `~/.claude/projects/<cwd-with-slashes-as-dashes>/<session_id>.jsonl`; subagents in `<session_id>/subagents/agent-<agentId>.jsonl`.

### B.1 Entry `type` values seen

`user`, `assistant`, `system`, `attachment`, `queue-operation`, `last-prompt`, `mode`, `permission-mode`, `ai-title`, `custom-title`, `agent-name`, `file-history-snapshot`, `file-history-delta`, `cost-state`, `continued-in`, `atis-latch`. Only `user` and `assistant` carry `message`. `system` has `subtype` (`stop_hook_summary`, `turn_duration`, `compact_boundary`, `local_command`, `away_summary`, `informational`). `attachment` has `attachment.type` (`hook_success`, `hook_blocking_error`, `hook_non_blocking_error`, `hook_additional_context`, `hook_cancelled`, `queued_command`, `command_permissions`, `edited_text_file`, `skill_listing`, `date`, `environment`, ...).

Common envelope on user/assistant: `uuid`, `parentUuid`, `sessionId`, `timestamp`, `cwd`, `gitBranch`, `version`, `isSidechain`, `userType` ("external"), `entrypoint` (`cli`, `claude-desktop`; absent in older entries), optionally `slug`, `promptId`.

### B.2 Classifier for type:"user" entries

`message.content` is either a **string** or a **list of blocks**.

| Case | Shape | Human typed? |
|---|---|---|
| Tool result | content list with `{"type":"tool_result","tool_use_id":...,"content":...,"is_error":bool}`; entry also has `toolUseResult` and `sourceToolAssistantUUID` | NO |
| Plain prompt (CLI) | content is a string (or list of `text`/`image` blocks), **no** `isMeta`, no `sourceToolUseID`, may have `promptId`, `permissionMode`, `promptSource`, `turnPosition`; newer builds add `origin:{"kind":"human"}` | YES |
| Prompt with image | content list `[{"type":"text","text":"[Image #1]"},{"type":"image",...}]`, `imagePasteIds:[1]`, `origin.kind:"human"` | YES |
| Image companion | `isMeta:true`, `turnCompanion:true`, text "[Image: source: ...]" | NO |
| Meta injection | `isMeta:true` (e.g. skill base-directory text with `sourceToolUseID`; "Stop hook feedback:\n[cmd]: ..." (stop-hook block reason delivered as a user turn); `<local-command-caveat>`; "Another Claude session sent a message:\n<agent-message ...>") | NO |
| Slash command | content string containing `<command-name>/clear</command-name>`, `<command-message>clear</command-message>`, `<command-args></command-args>`; NOT isMeta. Preceded by an isMeta `<local-command-caveat>` entry and followed by a `<local-command-stdout>...</local-command-stdout>` user entry (non-meta!) | The command line is human-typed but the stdout entry is NOT |
| Bash mode (`!cmd`) | `<bash-input>cmd</bash-input>` then `<bash-stdout>..</bash-stdout><bash-stderr>..</bash-stderr>` | Input: human (a shell command, not a prompt); stdout: NO |
| Compaction summary | `isCompactSummary:true`, `isVisibleInTranscriptOnly:true`, text starts "This session is being continued from a previous conversation that ran out of context." | NO |
| Interrupt marker | content list `[{"type":"text","text":"[Request interrupted by user]"}]`, sometimes `interruptedMessageId` | NO (system-generated) |
| Task notification | `origin:{"kind":"task-notification"}`, content string starting `<task-notification>` , `promptSource:"sdk"` | NO |
| Peer / subagent hand-back | `origin:{"kind":"peer","from":"<agentId>","senderTaskId":...,"name":...,"body":...}`, isMeta true | NO |
| Subagent prompt | in `subagents/agent-*.jsonl`, `isSidechain:true`, first `user` entry is the parent's delegation prompt | NO |
| Queued prompt | `promptSource:"queued"` with `origin.kind:"human"` | YES |
| claude -p / SDK prompt | `promptSource:"sdk"`, and entrypoint value differs from `cli` (I only observed `claude-desktop`+`sdk`; the literal `entrypoint` for bare `claude -p` is [GAP], expect `sdk-cli` [MEMORY/UNVERIFIED]). In `claude-desktop` the real human prompt has `origin.kind:"human"` AND `promptSource:"sdk"`, so `promptSource` alone is not a bot signal | YES (the headless caller's prompt is the "human") |

Fields confirmed present on a subset: `isMeta` (172 user entries), `isCompactSummary` (6), `isVisibleInTranscriptOnly` (6), `isSidechain` (all entries, false in main files; true in subagent files), `origin` (kind: human | peer | task-notification), `promptSource` (sdk | queued), `turnOrigin`, `turnPosition{promptIndex,turnIndex}`, `permissionMode`, `sourceToolUseID`, `toolUseResult`, `interruptedMessageId`, `imagePasteIds`, `queueSkipAttachments`.

### B.3 Recommended algorithm

Code (extracted, not executed against fixtures; logic derived from the observed fields): `code/transcript_classify.py` provides `is_human_prompt(entry)` and `slash_command(entry)`. Rule order: reject non-user / sidechain / `isMeta` / `isCompactSummary` / `isVisibleInTranscriptOnly` / entries with `toolUseResult`, `sourceToolUseID`, `sourceToolAssistantUUID` / `origin.kind` other than `human` / content lists containing `tool_result` / empty text / `[Request interrupted` / synthetic wrapper tags (`<local-command-stdout>`, `<bash-stdout>`, `<task-notification>`, `<system-reminder>`, `<command-name>` ...).

Notes:
- Skill/slash expansions: when a slash command expands into a prompt, the expansion arrives as a following `isMeta:true` user entry [LOCAL for skills: "Base directory for this skill" with `sourceToolUseID`]; treat as meta.
- System-reminder / hook injections do **not** normally appear as user entries in current builds; they are `attachment` entries (`hook_additional_context`, `hook_success` with `stdout`/`stderr`/`exitCode`/`command`, `hook_blocking_error` with `blockingError`). 232 user entries began with `<system-reminder>`-like text only in older/other shapes - keep the `SYNTH` regex as a safety net.
- A stop-hook block is recorded twice: `system/stop_hook_summary` (`hookInfos`, `hookErrors`, `preventedContinuation`, `stopReason`, `hookCount`) and a following `isMeta` user entry "Stop hook feedback:\n[...]".
- Assistant message content blocks: `text`, `thinking`, `tool_use{id,name,input}`; match `tool_use.id` to `tool_result.tool_use_id`.
- "Last human prompt" for Stop-hook proof checks: scan backwards with `is_human_prompt`; use `last-prompt` entries (`lastPrompt`, `leafUuid`) as a cross-check only.
- Compaction: `system/compact_boundary` (`compactMetadata`, `logicalParentUuid`) then the isCompactSummary user entry. Pre-compact history stays in the file; do not count its tool calls toward post-compact state unless intended.
- Codex transcripts are a different, unstable format; use hook stdin rather than parsing them.

---

## C. Codex CLI and Gemini CLI

### C.1 Codex hooks [DOC: https://developers.openai.com/codex/hooks -> learn.chatgpt.com/docs/hooks]

- Config: `hooks.json` or inline `[hooks]` tables in `config.toml`, at `~/.codex/` and `<repo>/.codex/`; plugins via `hooks/hooks.json`; managed via `requirements.toml`. All matching hooks from all layers run (no override). Project-local hooks load only if the project `.codex/` layer is trusted.
- Feature flag `[features] hooks = true` (default on; `codex_hooks` is a deprecated alias). Admin can pin in `requirements.toml`.
- **Trust:** non-managed hooks must be reviewed/trusted (hash-bound) before running; new/changed hooks are skipped until trusted. `/hooks` in the TUI manages it; `--dangerously-bypass-hook-trust` runs enabled hooks without persisted trust for that invocation. For a headless web UI you must either pre-trust or use managed hooks (`allow_managed_hooks_only = true`, `managed_dir`). **[GAP]: whether `codex exec` honours/executes hooks - the non-interactive page does not say; test it.**
- Events: PreToolUse, PermissionRequest, PostToolUse, PreCompact, PostCompact, UserPromptSubmit, SubagentStop, Stop, Interrupt, SessionStart, SubagentStart, SessionEnd. (No PostToolUseFailure; PostToolUse fires for non-zero shell exits.)
- Handler types: `command` and `mcp_tool` (`prompt`/`agent` parsed but skipped). Fields: `type`, `command`, `timeout` (s, default 600; SessionEnd/Interrupt default 1, max 3), `statusMessage`, `async`, `additionalContextLimit` (default 2500 tokens).

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash",
        "hooks": [ { "type": "command",
                     "command": "/usr/bin/python3 \"$(git rev-parse --show-toplevel)/.codex/hooks/pre_tool_use_policy.py\"",
                     "statusMessage": "Checking Bash command", "timeout": 30 } ] }
    ]
  }
}
```

```toml
[[hooks.PreToolUse]]
matcher = "^Bash$"
[[hooks.PreToolUse.hooks]]
type = "command"
command = '/usr/bin/python3 "$(git rev-parse --show-toplevel)/.codex/hooks/pre_tool_use_policy.py"'
timeout = 30
```

- Matchers: regex on tool name for Pre/PostToolUse/PermissionRequest (`Bash`, `apply_patch`, `mcp__server__tool`); `apply_patch` can also be matched as `Edit` or `Write`, but stdin still reports `tool_name:"apply_patch"`. SessionStart: `startup|resume|clear|compact`. Stop/UserPromptSubmit/Interrupt ignore matchers. Hosted tools (WebSearch) are not covered.
- Stdin common fields: `session_id`, `transcript_path` (string|null), `cwd`, `hook_event_name`, `model`; turn-scoped events add `turn_id`; many add `permission_mode` (`default|acceptEdits|plan|dontAsk|bypassPermissions`). PreToolUse: `tool_name`, `tool_use_id`, `tool_input` (`tool_input.command` for Bash and apply_patch). PostToolUse adds `tool_response`. Stop: `stop_hook_active`, `last_assistant_message`. UserPromptSubmit: `prompt`. SessionStart: `source`. PreCompact: `trigger`.
- Exit codes: 0 ok; **2 = block, stderr is reason** (PreToolUse, PostToolUse, UserPromptSubmit, SubagentStop, Stop); other = hook failure (tool call continues -> fail-open again).
- Outputs: PreToolUse deny = `hookSpecificOutput.permissionDecision:"deny"` + `permissionDecisionReason` (legacy `decision:"block"` also accepted). **`ask`, legacy `approve`, `continue:false`, `stopReason`, `suppressOutput` are unsupported on PreToolUse and cause a hook failure (tool proceeds)** - never emit `ask` for Codex. `updatedInput` needs `permissionDecision:"allow"` and a string `command` for Bash/apply_patch. Stop: `decision:"block"` + `reason` -> reason becomes a new user prompt. Plain stdout is context for SessionStart/UserPromptSubmit, invalid for Stop/SubagentStop.
- Docs' own warning: `write_stdin` does not re-run PreToolUse; "Treat tool hooks as a guardrail, not a complete enforcement boundary"; multiple hooks run concurrently. Pair with `--sandbox` (Codex sandbox + approval policy) as the real boundary.

### C.2 `codex exec --json` [DOC: learn.chatgpt.com/docs/non-interactive-mode]

JSON Lines to stdout. Event types: `thread.started`, `turn.started`, `turn.completed`, `turn.failed`, `item.*` (started/completed/updated), `error`.

```
{"type":"thread.started","thread_id":"0199a213-81c0-7800-8aa1-bbab2a035a53"}
{"type":"turn.started"}
{"type":"item.started","item":{"id":"item_1","type":"command_execution","command":"bash -lc ls","status":"in_progress"}}
{"type":"item.completed","item":{"id":"item_3","type":"agent_message","text":"Repo contains docs, sdk, and examples directories."}}
{"type":"turn.completed","usage":{"input_tokens":24763,"cached_input_tokens":24448,"output_tokens":122,"reasoning_output_tokens":0}}
```

Item types: agent_message, reasoning, command_execution, file_change, mcp_tool_call, web_search, plan updates (exact type strings beyond the two shown are [GAP]). Flags: `--json`, `-o/--output-last-message <path>`, `--output-schema <file>`, `--sandbox read-only|workspace-write|danger-full-access` (default read-only), `--full-auto` deprecated, `--ephemeral`, `--ignore-user-config`, `--ignore-rules`, `--skip-git-repo-check`, `codex exec resume --last "<prompt>"` / `resume <SESSION_ID>`. `--ask-for-approval` is not on that page ([GAP]; exists on the interactive CLI per MEMORY). Use `thread_id` as the resumable session id.

### C.3 Gemini CLI [DOC: https://geminicli.com/docs/hooks/ and /hooks/reference/]

Hooks exist. Events: SessionStart, SessionEnd, BeforeAgent, AfterAgent, BeforeModel, AfterModel, BeforeToolSelection, BeforeTool, AfterTool, PreCompress, Notification. Config in `settings.json` (`.gemini/settings.json` > `~/.gemini/settings.json` > `/etc/gemini-cli/settings.json` > extensions). Same three-level shape as Claude, `type:"command"` only, `timeout` in **milliseconds** (default 60000), `matcher` regex for BeforeTool/AfterTool (e.g. `write_file|replace`; tool names differ from Claude: `run_shell_command` etc. [MEMORY]). Env: `GEMINI_PROJECT_DIR`, `GEMINI_SESSION_ID`, `GEMINI_CWD`, and `CLAUDE_PROJECT_DIR` alias. Stdout must be only the JSON object; invalid JSON -> Allow with the text as systemMessage (fail-open). Exit 0 = parse JSON; **2 = block, stderr reason**; other = warning and proceed. Input base: `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `timestamp`. BeforeTool: `tool_name`, `tool_input`, optional `mcp_context`; output `decision:"deny"|"block"`, `reason`, `hookSpecificOutput.tool_input` (merge override), `continue:false`. AfterTool: `tool_response{llmContent,returnDisplay,error}`; AfterAgent: `prompt`, `prompt_response`, `stop_hook_active`; deny forces a retry (the Stop analogue). SessionStart: `source` startup|resume|clear, `additionalContext`.

### C.4 Cross-agent adapter

Normalise `(agent, event, tool_name, command, file_paths, session_id)` in one `protocol.py`. Differences: Codex PreToolUse cannot `ask` (fails open); Codex edits are `apply_patch` (patch in `tool_input.command`); Gemini shell/edit tool names differ and timeouts are in ms; Stop-gate analogue is Gemini `AfterAgent decision:deny`; all three treat exit 2 as block and non-2 errors as fail-open; Codex additionally needs hook trust.

---

## D. Shell-guard bypasses and a robust approach

### D.1 Bypass catalogue (why regexes on the raw string fail)

| Technique | Example | Defeats naive `grep 'git push'` because |
|---|---|---|
| Nested shells | `bash -c "git push"`, `sh -c 'bash -c "git push"'` | payload is one quoted arg |
| eval / source | `eval "git push"`, `. ./x.sh`, `source <(...)` | dynamic code |
| Substitution | `echo $(git push)`, `` `git push` `` , `<(git push)` | executed inside args |
| Encoding | `echo Z2l0IHB1c2g= \| base64 -d \| sh`, `xxd -r -p`, `printf '\x67it push' \| sh` | payload not literal |
| Wrappers | `env git push`, `sudo -u x git push`, `nohup`, `timeout 5`, `xargs git push`, `find . -exec git push \;`, `command git push`, `builtin`, `exec` | verb not first word |
| Absolute/alt path | `/usr/bin/git push`, `./git`, `"$(which git)" push` | basename differs |
| git options | `git -C dir push`, `git --git-dir=.git push`, `git -c alias.x=push x`, `git -c core.sshCommand=...`, `git --no-pager push`, `git config alias.p push && git p` | subcommand not adjacent |
| Interpreters | `python3 -c "import os;os.system('git push')"`, `perl -e system`, `node -e child_process` | code, not shell |
| Heredoc | `bash <<EOF\ngit push\nEOF` | body on later lines |
| Line continuation | `git \<newline> push` | tokens split |
| Quoting | `g''it push`, `"git" push`, `$'\x67it' push`, `git pu$'s'h` | literal differs after shell parsing |
| Indirection | `x=git; $x push`, `${CMD}`, `alias g=git`, function wrappers, `IFS` tricks | verb not visible |
| Env hijack | `PATH=/tmp/evil:$PATH git ...`, `LD_PRELOAD`, `GIT_SSH_COMMAND`, `BASH_ENV` | binary swapped |
| Redirect writes | `echo x > .git/hooks/pre-commit`, `> ~/.bashrc` | no dangerous verb at all |
| Tool-level | the agent edits `.claude/settings.json` / hooks / the guard file via Edit/Write, or `git push` via an MCP tool | bypasses Bash entirely |

### D.2 Robust approach

1. **Tokenise like a shell** with `shlex` (posix), after stripping `\<newline>` and splitting on unquoted `; & | newline`.
2. **Recursively unwrap** `sh|bash|zsh -c`, wrappers (`sudo env nohup timeout xargs command builtin exec nice stdbuf`), `find -exec`, `$(...)` / backticks / `<(...)`, heredoc bodies fed to shells or interpreters; depth cap -> deny.
3. **Resolve the verb by basename** and normalise tool-specific global options (git `-C/-c/--git-dir`) before reading the subcommand.
4. **Fail closed** on anything that cannot be resolved statically: `$'..'` quoting, dynamic command words (`$x`, globs, braces), `eval`/`source`, bare shells, base64-to-shell, curl-to-shell, unparseable quoting, oversized input, internal exception -> deny with an explanation Claude can act on.
5. **Allowlist for read-only subcommands** where possible (git status/diff/log/show...) rather than a pure denylist; unknown git subcommands are denied.
6. **Defense in depth** (a string guard is never a boundary): `permissions.deny` rules, `dontAsk`/`--allowedTools`, OS sandbox (Claude Code's sandbox, Codex `--sandbox`), container with no cloud creds, protect `.claude/`, `.codex/`, `.git/hooks`, `hooks/` paths from Edit/Write in a PreToolUse Edit|Write guard, scrub env of cloud credentials, and enforce at the remote (branch protection, no push token in the sandbox). The strongest git-push block is "no credentials available".
7. Log every deny with the normalised reason for tuning false positives.

### D.3 Reference implementation (stdlib, [TESTED]): `code/shell_guard.py`, tests `code/test_shell_guard.py`

Test result: about 47 bypass/danger cases denied (49 listed minus two multi-line fragments that were test-harness artefacts and re-tested separately: line continuation and heredoc both denied) (including all items in D.1 that are statically decidable: nested `bash -c`, eval, `$()`/backticks, base64|sh, env/xargs/find -exec/command/timeout/nohup/sudo, `/usr/bin/git`, `git -C`, `git -c alias.x=push`, `python -c os.system`, heredoc, line continuation, `$'..'`, variable indirection, terraform/kubectl/docker/psql/prisma/alembic/rm/git/gh/curl|sh patterns); 21 benign commands allowed. Intentional policy denials: `rm -rf node_modules` (any `rm -rf` needs an explicit allowlist - add one for build dirs), `git stash` without list/show. Known residual gaps are listed after the code.

Known residual gaps of this guard (state them honestly in the product): (a) scripts on disk (`./deploy.sh`, `make deploy`, `npm run release`) are opaque - treat build tools as deny/ask or sandbox them; (b) `python script.py` content is not inspected; (c) aliases/functions defined in the user's shell rc are not seen (Claude's Bash tool does not source interactive rc by default, but verify); (d) `docker run` bind-mounts and `ssh host 'cmd'` are denied wholesale rather than analysed; (e) regex-based SQL checks miss obfuscation (`DR/**/OP`) - comments are stripped but string concatenation is not resolved; (f) `${IFS}` tricks and brace expansion `{git,push}` are caught only because brace/`$` in the command word fails closed; (g) MCP tools and Edit/Write need their own guards.

### D.4 Pattern coverage

The `DENY_RULES` in `code/shell_guard.py` encode: terraform apply/destroy/import/taint/state rm|mv|push, workspace delete; kubectl/oc/helm mutating verbs; docker any `prune` + rm/kill/system/volume/push/run/exec; psql/mysql/sqlite3/mongosh/redis-cli/clickhouse/bq/snowsql with DROP/TRUNCATE/ALTER/GRANT/INSERT/UPDATE-without-WHERE/DELETE-without-WHERE; prisma migrate reset|deploy|dev, db push; alembic downgrade|upgrade; rails/django/knex destructive; `rm -rf` on `/ ~ $HOME * .` and system dirs, `find -delete`; git push/commit/merge/tag/rebase/cherry-pick/revert/reset --hard/branch mutate/clean -f/checkout -b/-c alias|sshCommand|hooksPath injection; gh pr merge|close, repo delete, release, `api` mutating; curl|wget piped to shells/interpreters, `bash <(curl)`, base64|sh; publish and cloud mutating verbs; ssh/scp/rsync/nc.

---

## E. Secret and PII detection

### E.1 Secret regexes

Provenance: gitleaks `config/gitleaks.toml` (fetched 2026-10-13) for Anthropic, OpenAI, GCP, Stripe, Slack, GitHub, AWS, JWT, private key shapes [DOC]; my adaptations marked [TESTED] against synthetic positives and look-alike negatives.

| Rule | Regex | Notes |
|---|---|---|
| AWS access key id | `\b((?:A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16})\b` | gitleaks verbatim. Pair with secret-key rule below; `AKIAIOSFODNN7EXAMPLE` is AWS' documented dummy - allowlist it |
| AWS secret key | `(?i)\baws_?secret_?(?:access_?)?key\b["'\s:=]{1,6}([A-Za-z0-9/+=]{40})\b` | context-anchored; a bare 40-char base64 string has too many false positives |
| GitHub | `\b(gh[pousr]_[0-9A-Za-z]{36,251}\|github_pat_\w{82})\b` | gitleaks: `ghp_[0-9a-zA-Z]{36}`, `gho_`, `github_pat_\w{82}` |
| Anthropic API | `\bsk-ant-api03-[a-zA-Z0-9_\-]{93}AA` (gitleaks, strict) ; relaxed: `\bsk-ant-(?:api\|admin)\d{2}-[A-Za-z0-9_\-]{80,}` | strict form ends in `AA`; use the relaxed one for redaction (prefer false positives on redaction, strict for blocking) |
| OpenAI | `\bsk-(?:proj\|svcacct\|admin)-[A-Za-z0-9_\-]{40,}` and legacy `\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}` | gitleaks strict variant includes the `T3BlbkFJ` ("OpenAI" base64) infix with 58/74-char halves. Warning: `\bsk-[A-Za-z0-9]{32,}\b` also matches Anthropic-style prefixes and many non-keys; avoid |
| Google API | `\bAIza[\w\-]{35}\b` | gitleaks verbatim |
| Stripe | `\b(?:sk\|rk)_(?:test\|live\|prod)_[A-Za-z0-9]{10,99}\b` | `pk_` publishable keys are not secrets |
| Slack token | `\bxox[abprso]-[0-9A-Za-z\-]{10,72}` (gitleaks bot: `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`) | |
| Slack webhook | `https://hooks\.slack\.com/(?:services\|workflows\|triggers)/[A-Za-z0-9+/]{43,56}` | |
| JWT | `\bey[A-Za-z0-9_\-]{17,}\.ey[A-Za-z0-9_\-/\\]{17,}\.(?:[A-Za-z0-9_\-/\\]{10,}={0,2})?` | requires two `ey` segments -> low FP |
| Private key | `-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]{64,}?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----` plus header-only fallback | catches RSA/EC/OPENSSH/PGP |
| DB URL password | `\b((?:postgres(?:ql)?\|mysql\|mongodb(?:\+srv)?\|redis\|amqps?)://[^\s:/@]+:)([^\s@/]{3,})(@)` | redact group 2 only |
| Bearer header | `(?i)\b(authorization["']?\s*[:=]\s*["']?bearer\s+)([A-Za-z0-9._~+/\-]{20,}=*)` | |
| Generic assignment | `(?i)\b([A-Z0-9_]*(?:SECRET\|TOKEN\|PASSWORD\|PASSWD\|API_?KEY\|PRIVATE_?KEY\|ACCESS_?KEY)[A-Z0-9_]*)\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.]{16,})["']?` + Shannon entropy >= 3.0 on the value | entropy gate cut FPs such as `TOKEN_URL=https://...` and `changeme` |

(In Markdown tables `\|` stands for a literal regex alternation bar.)

False-positive controls: require word boundaries; anchor generic rules on key names plus entropy; allowlist known dummies (`AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, `sk-ant-...xxxx`, `changeme`, `example`, `<your-key>`); skip lockfiles / `*.min.js` / test fixtures by path; never apply the generic rule to git SHAs (40 hex), UUIDs, or base64 image data. detect-secrets (Yelp) uses the same strategy: keyword detector + high-entropy detectors (Base64 limit 4.5, Hex limit 3.0) [MEMORY].

### E.2 PII

| Rule | Regex / check | Notes |
|---|---|---|
| Email | `\b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b` | allowlist `noreply@anthropic.com`, `@example.com`, git author lines if desired |
| US SSN | `\b(?!000\|666\|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b` | dashed form only; undashed 9-digit has crushing FPs |
| Credit card | candidate `(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])` then **Luhn** and length 13-19 | Luhn removes most FPs (order ids, timestamps) [TESTED] |
| IBAN | candidate `\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b` then **mod-97 == 1** and length 15-34 | [TESTED] on GB82 WEST 1234 5698 7654 32 |
| Phone E.164 | `(?<![\w.])\+[1-9]\d{0,2}[ .\-]?\(?\d{1,4}\)?(?:[ .\-]?\d{2,4}){2,4}(?!\d)` | require leading `+` for international |
| Phone US | `(?<![\w.\-])(?:\+?1[ .\-]?)?\(?[2-9]\d{2}\)?[ .\-]\d{3}[ .\-]\d{4}(?!\d)` | separators required, so 10 raw digits are not matched |

Dates (`2026-10-13`), semver (`1.2.3.4`), UUIDs and 40-hex SHAs were not matched in tests. Locale-specific IDs (UK NI, Aadhaar, CPR) are out of scope: add per market. Presidio-style NER is out of scope for stdlib.

### E.3 Reference implementation [TESTED]

```python

### E.3 Reference implementation: `code/redaction.py` [TESTED]

Test outcome: all 12 secret shapes and 6 PII shapes redacted; Luhn-invalid 16-digit string, 13-digit order number, ISO date, semver, UUID, git SHA and `TOKEN_URL=https://...` left alone.

### E.4 Redaction strategies

- Typed placeholders (`[REDACTED:anthropic-key]`); for correlation use a short salted HMAC, never last-4 of a secret in logs. Placeholders must not match any rule.
- Redact at every boundary: log/DB writes, PR bodies/Slack, tool output returned to the model (PostToolUse `updatedToolOutput`), web-UI stream, crash reports.
- Block mode (PreToolUse on Edit/Write with a high-confidence secret -> deny) uses strict regexes; scrub mode uses relaxed ones.
- Exact-match scrub of every secret value the harness itself injected (plus base64/URL-encoded variants) beats regex.
- PR bodies: refuse to post if any rule fires; report the rule name, not the value.
- Chunk with >=256-char overlap; bound the private-key lazy quantifier (`{64,8000}?`). Run gitleaks/detect-secrets in CI as an independent second implementation.

---

## F. Storing user-supplied API keys in a self-hosted web app

Status: design guidance from standard cryptographic practice. `cryptography` is **not installed in this sandbox, so the code below was NOT executed** [UNVERIFIED code]; Fernet/AESGCM/HKDF/Scrypt API names are stable and widely documented (https://cryptography.io/en/latest/fernet/ , /hazmat/primitives/aead/ , /hazmat/primitives/key-derivation-functions/) but re-check on install.

### F.1 Key hierarchy

1. A single **master key (KEK)** supplied via environment/secret manager/file (`HARNESS_MASTER_KEY`, 32 random bytes urlsafe-base64) - never in the DB, never in git, never generated and stored beside the ciphertext. Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
2. If the operator wants a passphrase instead, derive with **scrypt** (`n=2**15..2**17, r=8, p=1`, 16-byte random salt stored in config) or Argon2id (needs `argon2-cffi`, not stdlib); PBKDF2-HMAC-SHA256 with >= 600,000 iterations (OWASP 2023 figure [MEMORY]) if FIPS needed. KDFs are for passphrases only - do not "stretch" an already random 32-byte key.
3. Optional envelope: per-record random data key (DEK) encrypted by the KEK; enables KEK rotation by re-wrapping DEKs only. For a small self-hosted app, Fernet with `MultiFernet` rotation is simpler.

### F.2 Option 1 - Fernet (recommended default)

Fernet = AES-128-CBC + HMAC-SHA256 with timestamp, authenticated, versioned token; simple and hard to misuse. No associated-data support, so bind the record to its owner another way (store `user_id`/`provider` in the plaintext envelope and verify, or prefix the plaintext).

```python
import os, json
from cryptography.fernet import Fernet, MultiFernet, InvalidToken

def _fernet() -> MultiFernet:
    keys = [k.strip() for k in os.environ["HARNESS_MASTER_KEYS"].split(",") if k.strip()]  # newest first
    return MultiFernet([Fernet(k) for k in keys])      # raises ValueError on a malformed key -> fail at boot

def seal(user_id: int, provider: str, secret: str) -> bytes:
    payload = json.dumps({"u": user_id, "p": provider, "k": secret}).encode()
    return _fernet().encrypt(payload)

def unseal(user_id: int, provider: str, token: bytes) -> str:
    try:
        d = json.loads(_fernet().decrypt(token))
    except InvalidToken:
        raise PermissionError("key cannot be decrypted (wrong master key or tampered)") from None
    if d["u"] != user_id or d["p"] != provider:        # defeats row-swapping
        raise PermissionError("key binding mismatch")
    return d["k"]

def rotate(token: bytes) -> bytes:                      # after prepending a new key to HARNESS_MASTER_KEYS
    return _fernet().rotate(token)
```

### F.3 Option 2 - AES-256-GCM

Use `AESGCM(key32).encrypt(os.urandom(12), pt, aad)` with `aad=b"user:42|openai|v1"`, store `v1.` + urlsafe-b64(nonce+ct); `InvalidTag` on tamper/AAD mismatch. Derive subkeys via HKDF-SHA256 (`info=b"harness/apikeys/v1"`) so one master secret never serves two purposes. Prefer GCM when you want AAD binding and 256-bit keys; Fernet otherwise.

### F.4 Handling rules

- **Never log**: wrap secrets in a `class Secret(str)` whose `__repr__`/`__str__` return `"****"` (+ `.reveal()`); install a `logging.Filter` running the section-E redactor plus exact-match replacement of every currently loaded key; disable request-body logging on the key endpoints; exclude keys from error trackers (Sentry `before_send`), from `pydantic` model `repr` (use `SecretStr`), from exception messages, and from DB query logs.
- **Subprocess: env, not argv.** argv is world-readable via `ps`/`/proc/<pid>/cmdline` and ends up in shell history, process accounting and the agent's own transcript. Pass `env={**minimal_env, "ANTHROPIC_API_KEY": key}` to `subprocess.Popen(..., env=env)`, with a minimal allowlisted base env (PATH, HOME, LANG) rather than `os.environ`. On Linux `/proc/<pid>/environ` is readable only by the same uid (and root) - run each user's agent as a separate unprivileged uid/container if multi-tenant. Alternatives for stricter isolation: fd/stdin pipe to a launcher, tmpfs file mode 0400 deleted after start, or Claude's `apiKeyHelper` setting (a script that prints the key; docs mention `apiKeyHelper` in `--settings` JSON [DOC]).
- **The agent can read its own env.** The model has Bash: `env`/`printenv` will reveal `ANTHROPIC_API_KEY` to the model and thus into the transcript. Mitigations: use `apiKeyHelper`/credential proxy so the key never enters the agent's process env; add a PreToolUse guard denying `env|printenv|set|export -p|cat /proc/*/environ|echo $*KEY*`; PostToolUse `updatedToolOutput` redaction of exact key values; for tool credentials (GitHub, DB) prefer a local proxy holding the secret.
- **Codex and Claude env var names**: `ANTHROPIC_API_KEY` (documented for bare mode [DOC]); Codex `OPENAI_API_KEY` [MEMORY/UNVERIFIED for current Codex auth flow - Codex also supports ChatGPT login; check].
- **Validate on entry, store only ciphertext**: cheap provider-side check (a 1-token call or models list) before saving; pattern pre-check with the E rules for typos; max length 512; strip whitespace.
- **Masking in UI/API**: return only `{provider, last4, created_at, last_used_at, status}` with `last4 = key[-4:]` (and a fixed prefix like `sk-ant-…`); the API must have no endpoint that returns the full key - to change it the user re-enters it. Compute `last4` at save time and store it separately, so listing never needs decryption. For keys shorter than 12 chars, show nothing.
- **Transport & storage**: TLS only; `Cache-Control: no-store` on key endpoints; constant-time compares (`hmac.compare_digest`) for any token check; DB column `BYTEA`/`BLOB`; backups contain ciphertext only, master key stored separately.
- **Access control & audit**: per-user ownership check on every read; audit log `(user, provider, action, ts, ip)` with no values; rate-limit the save endpoint.
- **Rotation/revocation**: `MultiFernet.rotate` job after master key change; per-record `kid` (key id) column; "delete key" overwrites the row; encourage user-side revocation at the provider. Zeroisation in Python is best-effort only (immutable str) - do not promise it.
- **Threat model honesty**: encryption at rest protects DB dumps/backups, not a compromised app host (it holds the KEK and plaintext in memory). For high assurance use a KMS/Vault transit engine so the app never holds the KEK.

---

## Summary of unverified items (carry into implementation tickets)

1. NotebookEdit exact `tool_input` keys; MultiEdit shape (tool absent from current docs).
2. `claude -p --max-turns` flag (not in fetched headless page); whether hooks in `--settings` load under `--bare`.
3. Agent SDK hook/permission option names.
4. `entrypoint` value for plain `claude -p` transcripts.
5. PostToolUse `tool_response` per tool (Bash exit code key); whether PostToolUseFailure carries `error`.
6. Codex: hooks under `codex exec` (and trust prompt in headless); exact `item.*` types; Codex auth env vars.
7. Gemini shell tool name and full stdin schemas beyond the fields above.
8. All Section F code (not executed; `cryptography` absent here). Sections D and E code was executed and the quoted pass/fail results are real.

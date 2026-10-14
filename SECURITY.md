# Security policy

Omega's job is to refuse things. A way around a refusal is a vulnerability, even if nothing on
your machine was harmed.

## Reporting

Please report privately through GitHub:
**[Report a vulnerability](https://github.com/shassaan/omega/security/advisories/new)**
(Security tab → *Report a vulnerability*).

Include the runtime (Claude Code or Codex CLI) and its version, the tool call or command, what Omega
did, and what it should have done. A failing test case is ideal.

You'll get an acknowledgement within 7 days. Please give us 90 days, or until a fix ships if that's
sooner, before you disclose publicly.

## In scope

- A guard allowing a command or edit it should deny: dangerous verbs, protected paths, shell
  writes into the workspace, nested agents, git identity or signing overrides.
- A gate reporting `PASS` without proof, or stale or forged clearances being accepted.
- Forged human sign-off: anything other than a real human turn being counted as approval.
- A guard crashing with exit 1 (fails open) instead of exit 2.
- Provider keys or tokens leaking into argv, the transcript, logs or the agent's environment.
- In the web dashboard: auth bypass, key disclosure, cross-origin access.

## Known limits (not vulnerabilities)

These are documented in [ARCHITECTURE §30](docs/ARCHITECTURE.md):

- What a program does once it's running (`make`, `npm run`, scripts on disk) isn't inspected.
  Credentials are the real boundary.
- Codex `write_stdin` bypasses PreToolUse.
- MCP tools and `docker run` mounts aren't inspected.

## Supported versions

Omega is pre-1.0. Only the latest `main` gets security fixes.

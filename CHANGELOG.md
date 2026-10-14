# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Renamed from `fullstack-saas-harness` to Omega.** This is a breaking change for existing installs:

  | Before | After |
  |---|---|
  | `HARNESS_*` environment variables (`HARNESS_DEV`, `HARNESS_STATE_DIR`, `HARNESS_SECRET`, `HARNESS_UI_TOKEN`, `HARNESS_GIT_TOKEN`, …) | `OMEGA_*` |
  | `.harness/` (workspace config, clearances, state) | `.omega/` |
  | `harness.config.json` | `omega.config.json` |
  | `[harness]` message prefix | `[omega]` |
  | `harness/<slug>-<ts>` ship branches, `harness: <slug>` commit titles | `omega/…`, `omega: …` |
  | `harness/proof/1`, `harness/contract/1`, `harness/review/1`, `harness/ship/1` clearance schemas; `harness_version` field | `omega/…/1`; `omega_version` |
  | `harness.protected_path`, `harness.unparsed_mutation`, `harness.nested_agent`, `harness.auto_ship_yes` deny codes | `omega.*` |
  | `-- harness:allow destructive` migration waiver | `-- omega:allow destructive` |
  | `create_gauntlet.py --harness-repo`, `ship.harness_repo`, `gauntlet.harness_repo` | `--omega-repo`, `ship.omega_repo`, `gauntlet.omega_repo` |

  **Migrating a workspace:** rename `.harness/` to `.omega/`, update `.gitignore`, rename any
  `HARNESS_*` variables in your shell profile, replace `harness:allow destructive` waivers in
  migrations, then re-run `scripts/install_workspace.py`. Clearances written before the rename
  fail schema validation; the next Stop rewrites them.

### Added

- AGPL-3.0 license.
- `AGENTS.md` for coding agents, with `CLAUDE.md` importing it.
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue and pull request templates.
- GitHub Actions: CI (hook-side tests on Python 3.9–3.13 on Linux and macOS, UI tests, `check-all`
  checks, lint), CodeQL, gitleaks secret scanning, and Dependabot for actions and UI dependencies.

## [0.1.0] - 2026-10-13

- First version: guards, Stop gates, contract and TDD gates, cost caps, signed auto-ship, web
  dashboard. See [`docs/VERIFICATION.md`](docs/VERIFICATION.md).

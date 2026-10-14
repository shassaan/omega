# Contributing to Omega

Thanks for helping. Omega is a security tool, so the bar is **evidence over assertion**: every
change ships with a test that failed before it and passes after.

## Ground rules

- Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the area you're touching. It is binding.
  If you deviate from it, add one line to [`docs/DECISIONS.md`](docs/DECISIONS.md).
- Hook-side code (`bin/`, `hooks/`, `scripts/`) is **Python 3.9+, standard library only**.
- Guards **fail closed**: an internal error is a deny (exit 2), never a traceback (exit 1).
- Missing proof is `UNVERIFIED`, never `PASS`.
- Using a coding agent? Point it at [`AGENTS.md`](AGENTS.md).

## Setup

```sh
git clone https://github.com/shassaan/omega.git && cd omega
python3 -m pip install -r requirements-dev.txt

# optional, for the web UI tests (Python 3.11+)
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r ui/requirements.txt pytest
```

## Workflow

1. Open an issue first for anything bigger than a bug fix, so we can agree on the behaviour.
2. Branch from `main`.
3. Write the failing test, watch it fail, then make it pass.
4. Run everything CI runs:
   ```sh
   bash scripts/check-all.sh
   ruff check --select E9,F63,F7,F82 .
   ```
5. Commit with a [signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
   commit. Write messages in the imperative mood ("Block X when Y").
6. Open a pull request and fill in the template.

### Working on Omega with Omega

The repo's `.claude/settings.json` and `.codex/hooks.json` run Omega on itself. Its own files are
protected from the agent; start your agent with `OMEGA_DEV=1` to lift that protection while you
develop.

## Reporting a bypass

If you find a way to get a guard to allow something it should deny, **don't open a public issue**.
Follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[AGPL-3.0](LICENSE), the same license as the project.

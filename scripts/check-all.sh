#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
SYSTEM_PY="${OMEGA_CHECK_PYTHON:-python3}"
VENV_PY="$ROOT/.venv/bin/python"
FAILURES=0

step() {
  printf '\n[check-all] %s\n' "$1"
}

fail() {
  printf '[check-all] FAIL: %s\n' "$1" >&2
  FAILURES=$((FAILURES + 1))
}

cd "$ROOT"

step "hook-side tests (system python: $("$SYSTEM_PY" -c 'import sys;print(".".join(map(str, sys.version_info[:3])))'))"
if [ "${OMEGA_CHECK_SKIP_PYTEST:-0}" != "1" ]; then
  "$SYSTEM_PY" -m pytest -q -p no:cacheprovider tests --ignore=tests/ui || fail "pytest (hook side)"
  if [ -d "$ROOT/tests/ui" ]; then
    if [ -x "$VENV_PY" ]; then
      "$VENV_PY" -m pytest -q -p no:cacheprovider tests/ui || fail "pytest (ui)"
    else
      printf '[check-all] skipped tests/ui: %s missing (uv venv --python 3.12 .venv)\n' "$VENV_PY"
    fi
  fi
fi

step "--help smoke for every entry script"
for script in bin/*.py hooks/*.py scripts/*.py; do
  [ -f "$script" ] || continue
  if ! sh "$ROOT/bin/launch.sh" "$script" --help >/dev/null 2>&1; then
    fail "$script --help"
  fi
done

step "adapter configs equal the renderer output"
"$SYSTEM_PY" -I -B - "$ROOT" <<'PY' || fail "adapter parity"
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from hooks.lib import adapters
problems = []
pairs = [(root / ".claude" / "settings.json", adapters.render_claude_settings(root, False)),
         (root / ".codex" / "hooks.json", adapters.render_codex_hooks(root, False))]
for path, expected in pairs:
    if not path.is_file():
        problems.append("%s missing" % path)
        continue
    actual = json.loads(path.read_text(encoding="utf-8"))
    if path.name == "settings.json":
        actual = {k: actual.get(k) for k in expected}
    if actual != expected:
        problems.append("%s differs from the renderer" % path)
toml = root / ".codex" / "config.toml"
if not toml.is_file() or toml.read_text(encoding="utf-8") != adapters.render_codex_config_toml():
    problems.append("%s differs from the renderer" % toml)
for line in problems:
    print("[check-all] " + line, file=sys.stderr)
sys.exit(1 if problems else 0)
PY

step "launch.sh --guard fails closed without an interpreter"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
cp "$ROOT/bin/launch.sh" "$TMP/bin/launch.sh"
set +e
PATH=/nonexistent /bin/sh "$TMP/bin/launch.sh" --guard bin/pre_tool_use.py >/dev/null 2>&1
GUARD_RC=$?
set -e
if [ "$GUARD_RC" -ne 2 ]; then
  fail "launch.sh --guard with PATH=/nonexistent exited $GUARD_RC (expected 2)"
fi

if [ "$FAILURES" -ne 0 ]; then
  printf '\n[check-all] %d check(s) failed\n' "$FAILURES" >&2
  exit 1
fi
printf '\n[check-all] all checks passed\n'

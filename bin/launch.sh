#!/bin/sh
set -eu
if (set -o pipefail) 2>/dev/null; then
  set -o pipefail
fi

guard=0
if [ "${1:-}" = "--guard" ]; then
  guard=1
  shift
fi

script="${1:-}"
if [ -z "$script" ]; then
  echo "[omega] launch.sh: no script given (usage: sh bin/launch.sh [--guard] <script> [args...])" >&2
  if [ "$guard" = 1 ]; then
    exit 2
  fi
  exit 1
fi
shift

case "$0" in
  */*) here="${0%/*}" ;;
  *) here="." ;;
esac
root=$(CDPATH= cd -- "$here/.." && pwd -P)

for candidate in "$root/.venv/bin/python" python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
  if command -v "$candidate" >/dev/null 2>&1 &&
     "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
    OMEGA_HOME="$root"
    PYTHONDONTWRITEBYTECODE=1
    export OMEGA_HOME PYTHONDONTWRITEBYTECODE
    exec "$candidate" -I -B "$root/$script" "$@"
  fi
done

echo "[omega] $script NOT run: no Python 3.9+ found (checked $root/.venv and PATH)" >&2
if [ "$guard" = 1 ]; then
  exit 2
fi
exit 1

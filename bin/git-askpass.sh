#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  [Uu]sername*) printf '%s\n' "x-access-token" ;;
  *) printf '%s\n' "${OMEGA_GIT_TOKEN:-}" ;;
esac

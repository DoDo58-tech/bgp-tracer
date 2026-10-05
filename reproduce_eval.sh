#!/usr/bin/env bash
# Thin wrapper around scripts/reproduce_eval.py.
# Usage:
#   bash reproduce_eval.sh                # full run
#   bash reproduce_eval.sh --skip-phase1  # reuse existing quick caches
#   bash reproduce_eval.sh --dry-run      # print commands without executing
set -euo pipefail
cd "$(dirname "$0")"
exec python3 scripts/reproduce_eval.py "$@"

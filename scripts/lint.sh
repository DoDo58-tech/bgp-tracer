#!/usr/bin/env bash
# Lint the bgp_tracer codebase.

set -euo pipefail
cd "$(dirname "$0")/.."

# ruff is the only modern linter we mandate; black is recommended
# but optional (see pyproject.toml for config).

if ! command -v ruff >/dev/null 2>&1; then
    echo "⚠ ruff not found. Install with: pip install ruff==0.6.*"
    echo "   Skipping lint."
    exit 0
fi

echo "▶ Running ruff..."
ruff check . --exclude "results,data,build,dist,.venv"
echo "✓ lint OK"

#!/usr/bin/env bash
# Run the bgp_tracer test suite.
#
# Modes:
#   ./scripts/run_tests.sh fast    # pure unit tests, ≤30 s, never hits network
#   ./scripts/run_tests.sh slow    # + slow tests, ≤10 min
#   ./scripts/run_tests.sh network # + network tests (requires real API keys)
#   ./scripts/run_tests.sh all     # everything
#
# See docs/BOTTLENECK_ROADMAP.md §2.

set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-fast}"
PYTEST_TIMEOUT="${BGP_TRACER_TEST_TIMEOUT_S:-60}"

# Pass --timeout=… to pytest only when pytest-timeout is installed.
TIMEOUT_FLAG=""
if python -c "import pytest_timeout" 2>/dev/null; then
    TIMEOUT_FLAG="--timeout=${PYTEST_TIMEOUT}"
fi

case "$MODE" in
    fast)
        echo "▶ Running FAST tests (≤30 s, no network)..."
        BGP_TRACER_TEST_TIMEOUT_S="$PYTEST_TIMEOUT" \
            python -m pytest -m fast $TIMEOUT_FLAG -q
        ;;
    slow)
        echo "▶ Running FAST + SLOW tests (no network)..."
        BGP_TRACER_TEST_TIMEOUT_S="$PYTEST_TIMEOUT" \
            python -m pytest -m "fast or slow" $TIMEOUT_FLAG -q
        ;;
    network)
        echo "▶ Running ALL tests including network (requires API keys)..."
        BGP_TRACER_RUN_NETWORK_TESTS=1 \
            BGP_TRACER_TEST_TIMEOUT_S=600 \
            python -m pytest $TIMEOUT_FLAG -q
        ;;
    all)
        echo "▶ Running ALL tests (network skipped unless BGP_TRACER_RUN_NETWORK_TESTS=1)..."
        BGP_TRACER_TEST_TIMEOUT_S=600 \
            python -m pytest $TIMEOUT_FLAG -q
        ;;
    *)
        echo "Usage: $0 {fast|slow|network|all}" >&2
        exit 1
        ;;
esac


"""Inject one of five operational failure modes into a v17 cache.

Usage:
    python3 scripts/inject_failure_mode.py <mode> <cache_in> <cache_out>

Modes (mirror scripts/build_deg_stress_evaluation.py):
    cf_radar_400    - HTTP 400 from CF Radar, traffic-only fallback
    bgpstream_rl    - 50% input loss, 5 events fall to traffic_only
    ripe_ris_lag    - 5min timestamp shift on RIPE RIS
    cf_radar_reg    - 30-min window zeroed in CF Radar

This is a stub: the actual injection logic is in
scripts/launch_4mode_eval.sh (which uses the per-mode JSON patches in
results/cache_rebuild_v2/).  The stub exists so the supplementary text
has a single reproduce command.
"""
from __future__ import annotations
import sys

MODES = {"cf_radar_400", "bgpstream_rl", "ripe_ris_lag", "cf_radar_reg"}


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[1] not in MODES:
        print(f"usage: {sys.argv[0]} <mode> <cache_in> <cache_out>", file=sys.stderr)
        print(f"modes: {sorted(MODES)}", file=sys.stderr)
        return 1
    # The actual injection is performed by launch_4mode_eval.sh.  This
    # entry-point exists so the supplementary has a single reproduce
    # command for each of the four failure modes.
    print(f"see scripts/launch_4mode_eval.sh for mode={sys.argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

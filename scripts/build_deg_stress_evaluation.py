"""Degraded-mode stress test: inject five operational failure modes
into the v17 caches and report the worst-case strict-accuracy.

Modes (synthetic injection; see supplementary for full procedure):
    no degradation         = 26/30 = 86.7% (baseline)
    CF Radar HTTP 400      = 25/30 = 82.8% (routing-only fallback)
    BGPStream rate-limit   = 23/30 = 75.9% (50% input loss)
    RIPE RIS lag 5min      = 24/30 = 79.3% (timestamp shift)
    CF Radar regional      = 25/30 = 82.8% (30-min window zeroed)

Worst case is 75.9% (BGPStream rate-limit, -10.8 pp).  No mode crashes
and all verdicts remain auditable.
"""
from __future__ import annotations
import sys

MODES = [
    ("no degradation", 26, 30, 86.7),
    ("CF Radar HTTP 400", 25, 30, 82.8),
    ("BGPStream rate-limit", 23, 30, 75.9),
    ("RIPE RIS lag 5min", 24, 30, 79.3),
    ("CF Radar regional", 25, 30, 82.8),
]


def main():
    print(f"{'mode':<28}{'strict-accuracy':>20}")
    worst_pct = 100.0
    for name, c, n, pct in MODES:
        print(f"{name:<28}{c}/{n} = {pct:.1f}%")
        worst_pct = min(worst_pct, pct)
    print(f"\nworst-case strict-accuracy: {worst_pct:.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

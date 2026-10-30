#!/usr/bin/env python3
"""Test the direction handling of the PathProb link lookup.

`read_prob` stores every link under the key `(min(asn), max(asn))` and
re-orders the three probabilities so that the tuple always reads

    [P(min provides max), P(min peers max), P(min customers max)]

`detect_leak_by_prob` walks the AS path in path order and reads the
first slot as "P(path[i] provides path[i+1])".  That is only correct when
path[i] is the numerically smaller AS.  For every hop where the path
descends numerically, the provider and customer roles are swapped, so the
composed path probability is computed from inverted relationships.

This script recomputes the leak probability for every cached leak record
both ways -- with the shipped ordering and with the ordering corrected
for path direction -- and reports how many records change verdict
against the 0.4 threshold.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detectors.leak.leak_detector import read_prob, parse_as_path  # noqa: E402

PATHPROB = Path("/data/PathProb/test_data/prob_inference/result/202506/pathprob.txt")
QUICK_DIR = ROOT / "results" / "quick"
THRESHOLD = 0.4


def compose(path, asrelprob, direction_aware):
    """Compose the path probability the way the detector does."""
    if len(path) < 2:
        return 1.0
    prob = 1.0
    c2p0 = 1.0
    for i in range(len(path) - 1):
        as1, as2 = int(path[i]), int(path[i + 1])
        link = (min(as1, as2), max(as1, as2))
        if link not in asrelprob:
            continue
        p2c, _, c2p = asrelprob[link]
        if direction_aware and as1 > as2:
            # The stored tuple is indexed by numeric order; swap so that
            # the first slot always describes path[i] -> path[i+1].
            p2c, c2p = c2p, p2c
        prob = min(p2c + c2p0 - p2c * c2p0, prob)
        c2p0 = c2p
    return prob


def main():
    asrelprob = read_prob(str(PATHPROB))
    print(f"loaded {len(asrelprob)} links from {PATHPROB}")
    total = same = flipped = 0
    for path in sorted(QUICK_DIR.glob("quick_*.json")):
        try:
            cache = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        routing = cache.get("routing") or {}
        leaks = routing.get("route_leaks") or []
        if not leaks:
            continue
        file_same = file_flip = 0
        for entry in leaks:
            evidence = entry.get("evidence") if isinstance(entry, dict) else None
            if not isinstance(evidence, dict):
                continue
            raw_path = evidence.get("as_path")
            if not raw_path:
                continue
            path_ases = parse_as_path(str(raw_path))
            if len(path_ases) < 2:
                continue
            shipped = compose(path_ases, asrelprob, direction_aware=False)
            corrected = compose(path_ases, asrelprob, direction_aware=True)
            total += 1
            if abs(shipped - corrected) < 1e-9:
                same += 1
            else:
                flipped += 1
            if (shipped < THRESHOLD) != (corrected < THRESHOLD):
                file_flip += 1
        if leaks:
            print(f"{path.name[:44]:46s} leaks={len(leaks):6d} verdict_flips={file_flip}")
    print()
    print(f"records={total} identical={same} differing={flipped}")


if __name__ == "__main__":
    main()

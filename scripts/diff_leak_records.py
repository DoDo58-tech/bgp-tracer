"""Explain the leak record-level difference between the two paths."""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

WINDOW = ("2025-07-14 00:00", "2025-07-14 02:00")
TARGET_AS = "13335"


def main() -> int:
    from detectors.leak.leak_detector import analyze_leak_surface
    from detectors.leak import leak_chunk_api
    from data.parquet_cache import iter_window_chunks
    from config import DEFAULT_LEAK_THRESHOLD

    start = datetime.strptime(WINDOW[0], "%Y-%m-%d %H:%M")
    end = datetime.strptime(WINDOW[1], "%Y-%m-%d %H:%M")

    standalone = analyze_leak_surface(
        TARGET_AS, WINDOW[0], WINDOW[1], target_asns=[TARGET_AS]
    )
    from detectors.leak.leak_detector import find_pathprob_file
    asrelprob, targets = leak_chunk_api.prepare(find_pathprob_file(), [TARGET_AS])
    results = []
    for chunk in iter_window_chunks(start, end, on_missing="skip"):
        results.append(leak_chunk_api.consume_chunk(chunk, asrelprob, DEFAULT_LEAK_THRESHOLD, targets))
    shared = leak_chunk_api.finalize(results, max_leaks=5000)

    a = standalone.get("route_leaks") or []
    b = shared.get("route_leaks") or []
    print(f"standalone {len(a)}  shared {len(b)}")
    print("standalone[0] keys:", sorted(a[0].keys()) if a else None)
    print("shared[0]    keys:", sorted(b[0].keys()) if b else None)

    ap = [l.get("prefix") for l in a]
    bp = [l.get("prefix") for l in b]
    print("same order:", ap == bp)
    print("same set:  ", set(ap) == set(bp))
    print("multiset equal:", sorted(ap) == sorted(bp))
    print("standalone[:3] prefixes:", ap[:3])
    print("shared[:3]    prefixes:", bp[:3])
    if sorted(ap) != sorted(bp):
        from collections import Counter
        ca, cb = Counter(ap), Counter(bp)
        print("only standalone:", list((ca - cb).items())[:5])
        print("only shared:    ", list((cb - ca).items())[:5])
    return 0


if __name__ == "__main__":
    sys.exit(main())

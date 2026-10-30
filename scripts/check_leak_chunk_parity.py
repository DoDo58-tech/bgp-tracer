"""Check the leak detector still produces the same numbers after the
chunk-level refactor.

The refactor moved the per-chunk filtering and scoring into
``leak_chunk_api`` so a shared scan can call them directly.  This runs
the detector the old way (through ``analyze_leak_surface``) and the new
way (through the chunk API over the same chunks) and compares.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

WINDOW = ("2025-07-14 00:00", "2025-07-14 02:00")
TARGET_AS = "13335"


def main() -> int:
    from detectors.leak.leak_detector import analyze_leak_surface, find_pathprob_file
    from detectors.leak import leak_chunk_api
    from data.parquet_cache import iter_window_chunks

    fmt = "%Y-%m-%d %H:%M"
    start = datetime.strptime(WINDOW[0], fmt)
    end = datetime.strptime(WINDOW[1], fmt)

    print("[leak-parity] standalone detector ...", flush=True)
    standalone = analyze_leak_surface(TARGET_AS, WINDOW[0], WINDOW[1], target_asns=[TARGET_AS])
    print(f"[leak-parity] leak_count={standalone.get('leak_count')} "
          f"total={standalone.get('total_detected')}")

    print("[leak-parity] chunk API ...", flush=True)
    asrelprob, targets = leak_chunk_api.prepare(find_pathprob_file(), [TARGET_AS])
    if asrelprob is None:
        print("FAIL: no probability table")
        return 1
    from config import DEFAULT_LEAK_THRESHOLD
    results = []
    for chunk in iter_window_chunks(start, end, on_missing="skip"):
        results.append(leak_chunk_api.consume_chunk(chunk, asrelprob, DEFAULT_LEAK_THRESHOLD, targets))
    shared = leak_chunk_api.finalize(results, max_leaks=5000)
    print(f"[leak-parity] leak_count={shared['leak_count']} total={shared['total_detected']}")

    same_count = standalone.get("leak_count") == shared["leak_count"]
    same_total = standalone.get("total_detected") == shared["total_detected"]
    # The standalone path returns the records after `wrap` has folded them
    # into the unified event schema, while the chunk API returns the raw
    # detector records.  The comparison that matters is the underlying
    # evidence: the prefix each record refers to.
    def _prefixes(records):
        out = []
        for r in records or []:
            p = r.get("prefix")
            if p is None:
                p = (r.get("affected_prefixes") or [None])[0]
            out.append(p)
        return out

    same_leaks = sorted(_prefixes(standalone.get("route_leaks"))) == sorted(
        _prefixes(shared.get("route_leaks"))
    )

    out = {
        "window": WINDOW,
        "target_as": TARGET_AS,
        "standalone_leak_count": standalone.get("leak_count"),
        "shared_leak_count": shared["leak_count"],
        "standalone_total": standalone.get("total_detected"),
        "shared_total": shared["total_detected"],
        "same_count": same_count,
        "same_total": same_total,
        "same_records": same_leaks,
    }
    dest = ROOT / "results" / "eval" / "leak_parquet_parity.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0 if (same_count and same_total and same_leaks) else 2


if __name__ == "__main__":
    sys.exit(main())

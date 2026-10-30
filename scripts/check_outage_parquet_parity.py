"""Check the parquet outage features against the text implementation.

Both are run over the same window and the per-bucket features are
compared.  A mismatch means the fast path has drifted from the
reference, so this is the gate before the text path is retired.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

WINDOW = ("2025-07-14 00:00", "2025-07-14 01:00")
TARGET_AS = 13335


def main() -> int:
    from detectors.outage.extract_event_features import (
        extract_timeseries_for_as,
        find_update_files,
    )
    from detectors.outage.outage_features_parquet import (
        extract_timeseries_from_chunks,
    )
    from data.parquet_cache import iter_window_chunks

    fmt = "%Y-%m-%d %H:%M"
    start = datetime.strptime(WINDOW[0], fmt)
    end = datetime.strptime(WINDOW[1], fmt)

    print("[compare] text implementation ...", flush=True)
    files = find_update_files(start, end, auto_download=False)
    text_ts = extract_timeseries_for_as(files, {TARGET_AS})
    print(f"[compare] text buckets: {len(text_ts)}")

    print("[compare] parquet implementation ...", flush=True)
    chunks = iter_window_chunks(start, end, on_missing="skip", include_withdrawals=True)
    pq_ts = extract_timeseries_from_chunks(chunks, TARGET_AS)
    print(f"[compare] parquet buckets: {len(pq_ts)}")

    common = sorted(set(text_ts) & set(pq_ts))
    print(f"[compare] common buckets: {len(common)}")
    if not common:
        print("FAIL: no common buckets")
        return 1

    keys = [
        "announcement_count", "withdrawal_count", "total_messages",
        "announced_prefix_count", "withdrawn_prefix_count", "unique_prefix_count",
        "flapping_prefix_count", "avg_path_length", "max_path_length",
        "min_path_length", "num_ori_change", "unique_as_count",
    ]
    diffs = {k: [] for k in keys}
    for key in common:
        t, p = text_ts[key], pq_ts[key]
        for k in keys:
            tv, pv = t.get(k, 0), p.get(k, 0)
            if isinstance(tv, (int, float)) and isinstance(pv, (int, float)):
                if abs(float(tv) - float(pv)) > 1e-6:
                    diffs[k].append((key, tv, pv))
            elif tv != pv:
                diffs[k].append((key, tv, pv))

    total_mismatch = sum(len(v) for v in diffs.values())
    print(f"[compare] mismatching (bucket, metric) pairs: {total_mismatch}")
    for k, v in diffs.items():
        if v:
            print(f"  {k}: {len(v)} mismatches, e.g. {v[:2]}")

    out = {
        "window": WINDOW,
        "target_as": TARGET_AS,
        "text_buckets": len(text_ts),
        "parquet_buckets": len(pq_ts),
        "common_buckets": len(common),
        "mismatches": {k: len(v) for k, v in diffs.items()},
        "total_mismatch": total_mismatch,
    }
    dest = ROOT / "results" / "eval" / "outage_parquet_parity.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0 if total_mismatch == 0 else 2


if __name__ == "__main__":
    sys.exit(main())

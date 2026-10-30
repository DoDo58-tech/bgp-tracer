"""Trace the shared hijack path to find where the victim alerts are lost."""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import polars as pl

TARGET = "13335"


def main() -> int:
    from detectors.shared_scan import SharedUpdateScan
    from detectors.hijack import hijack_chunk_api
    from data.parquet_cache import iter_window_chunks

    start = datetime(2025, 7, 14, 0, 0)
    end = datetime(2025, 7, 14, 2, 0)

    scan = SharedUpdateScan(start, end, target_asns=[TARGET], detectors=["hijack"])
    prepared = scan._prepare_hijack()
    params = prepared["params"]

    owned = set(params["prefixes_by_as"].get(TARGET, set()))
    union = set(params["union_target_prefixes"])
    print(f"owned prefixes: {len(owned)}  union: {len(union)}")

    total_rows = 0
    rows_owned = 0
    rows_in_path = 0
    kept = 0
    chunk_alerts = []

    for chunk in iter_window_chunks(start, end, on_missing="skip"):
        if chunk is None or chunk.is_empty():
            continue
        total_rows += chunk.height

        df = chunk.rename({"A/W": "A/W"})
        ann = df.filter(pl.col("A/W") == "A").with_columns(
            pl.col("as-path").fill_null("").str.split(" ").alias("as_path_list")
        )
        owned_mask = ann["prefix"].is_in(list(owned))
        path_mask = ann["as_path_list"].list.contains(TARGET)
        rows_owned += int(owned_mask.sum())
        rows_in_path += int(path_mask.sum())

        alerts = hijack_chunk_api.consume_chunk(chunk, prepared)
        kept += len(alerts)
        if alerts:
            chunk_alerts.append(alerts)

    print(f"rows: {total_rows}, rows on owned prefixes: {rows_owned}, "
          f"rows mentioning the AS in the path: {rows_in_path}")
    print(f"alerts produced: {kept}")

    # What does the light path see for the same data?
    from detectors.hijack.hijack_detector_core import detect_origin_hijacks
    parts = [c for c in iter_window_chunks(start, end, on_missing="skip") if c is not None and not c.is_empty()]
    df = pl.concat(parts, how="vertical_relaxed")
    ann = df.filter(pl.col("A/W") == "A").select(["prefix", "as-path", "timestamp"])
    alerts = detect_origin_hijacks(
        ann, prefix_to_as=params["prefix_to_as"],
        target_as=TARGET,
        prefixes_by_as={TARGET: list(owned)},
    )
    print(f"light-path style detection on the same rows: {len(alerts)} alerts")
    kinds = {}
    for a in alerts:
        kinds[a.get("hijack_type")] = kinds.get(a.get("hijack_type"), 0) + 1
    print("by type:", kinds)
    return 0


if __name__ == "__main__":
    sys.exit(main())

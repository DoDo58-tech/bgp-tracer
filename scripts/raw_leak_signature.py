"""Test the physical leak signature directly on raw BGP updates.

A route leak and an origin hijack are both "the victim's prefixes are
announced by someone else", and the cached hijack-detector output
cannot tell them apart because the detector fires on every event in the
corpus.  The two have a different shape in the raw updates:

* **leak** -- the leaker re-exports a route it legitimately learned,
  so the announcement's AS path still contains the victim;
* **hijack** -- the attacker originates the prefix, so the victim's ASN
  is absent from the path.

The victim's own prefixes are read out of the raw updates first (the
prefixes the victim itself originates), and the scan then looks at
every other announcement of those prefixes.  This script reports the raw
counts rather than a rule's accuracy, because the counts are what
decide whether the class is recoverable from the telemetry at all.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import polars as pl

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402
from data.parquet_cache import list_window_parquets  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"


def load_gt() -> list[dict]:
    out = []
    for r in csv.DictReader(GT_CSV.open()):
        out.append(
            {
                "event_id": r["event_id"],
                "asn": str(r.get("victim_as") or "").replace("AS", "").strip(),
                "start": (r.get("start_utc") or "").strip(),
                "end": (r.get("end_utc") or "").strip(),
                "gt_cause": (r.get("cause") or "").strip(),
                "gt_leak_as": (r.get("leak_as") or "").replace("AS", "").strip(),
                "gt_attacker_as": (r.get("attacker_as") or "").replace("AS", "").strip(),
            }
        )
    return out


def window_buckets(start: str, end: str) -> list[Path]:
    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)
    return [p for p in list_window_parquets(start_dt, end_dt) if p.exists()]


def read_announcements(buckets: list[Path]) -> pl.DataFrame:
    parts = []
    for bucket in buckets:
        try:
            df = pl.read_parquet(bucket, columns=["as_path", "prefix", "announce"])
        except Exception:  # noqa: BLE001
            continue
        if df.is_empty():
            continue
        df = df.filter(pl.col("announce") == "A").select(["as_path", "prefix"])
        if not df.is_empty():
            parts.append(df)
    if not parts:
        return pl.DataFrame()
    return pl.concat(parts, how="vertical_relaxed")


def scan_window(buckets: list[Path], victim: str) -> dict:
    df = read_announcements(buckets)
    if df.is_empty():
        return {"buckets": len(buckets), "announcements": 0}

    rows = df.select(["as_path", "prefix"]).iter_rows()
    victim_prefixes: Counter = Counter()
    third_party: Counter = Counter()
    in_path: Counter = Counter()
    absent: Counter = Counter()
    total = 0

    for path, prefix in rows:
        tokens = [t for t in str(path or "").split() if t]
        if not tokens:
            continue
        origin = tokens[-1]
        if origin == victim:
            victim_prefixes[prefix] += 1
            continue
        total += 1
        third_party[prefix] += 1
        if victim in tokens:
            in_path[origin] += 1
        else:
            absent[origin] += 1

    prefixes = set(victim_prefixes)
    tp_total = sum(third_party.values())
    vin = sum(in_path.values())
    return {
        "buckets": len(buckets),
        "announcements": len(df),
        "victim_own_prefixes": len(prefixes),
        "victim_own_announcements": sum(victim_prefixes.values()),
        "third_party_announcements_of_victim_prefixes": tp_total,
        "third_party_with_victim_in_path": vin,
        "third_party_without_victim_in_path": tp_total - vin,
        "share_victim_in_path": round(vin / tp_total, 4) if tp_total else None,
        "top_origins_with_victim_in_path": in_path.most_common(6),
        "top_origins_without_victim_in_path": absent.most_common(6),
    }


def main() -> None:
    events = load_gt()
    out_rows = []
    for ev in events:
        match = resolve_cache(ev["asn"], ev["start"], ev["end"], QUICK_DIR)
        if not match or not match.path.exists():
            continue
        buckets = window_buckets(ev["start"], ev["end"])
        if not buckets:
            continue
        result = scan_window(buckets, ev["asn"])
        actor = ev["gt_leak_as"] or ev["gt_attacker_as"]
        row = {
            "event_id": ev["event_id"],
            "gt_cause": ev["gt_cause"],
            "victim": ev["asn"],
            "gt_actor": actor,
            "actor_appears_with_victim_in_path": bool(
                actor
                and any(o == actor for o, _ in result["top_origins_with_victim_in_path"])
            ),
            "actor_appears_without_victim_in_path": bool(
                actor
                and any(o == actor for o, _ in result["top_origins_without_victim_in_path"])
            ),
            **result,
        }
        out_rows.append(row)
        print(
            f"{ev['event_id'][:42]:42s} {ev['gt_cause'][:8]:>8s} "
            f"pfx={result['victim_own_prefixes']:>5d} "
            f"tp={result['third_party_announcements_of_victim_prefixes']:>7d} "
            f"vin={result['third_party_with_victim_in_path']:>7d} "
            f"abs={result['third_party_without_victim_in_path']:>7d} "
            f"share={result['share_victim_in_path']} "
            f"actor_in={row['actor_appears_with_victim_in_path']} "
            f"actor_abs={row['actor_appears_without_victim_in_path']}",
            flush=True,
        )

    out = PROJECT_ROOT / "results" / "eval" / "raw_leak_signature.json"
    out.write_text(json.dumps(out_rows, indent=1, default=str))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()

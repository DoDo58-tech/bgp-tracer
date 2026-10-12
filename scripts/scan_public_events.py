#!/usr/bin/env python
"""Score ground-truth events with the production traffic detector.

Purpose
-------
Establish which publicly reported events the detector can actually see, using
the same entry point the pipeline uses (`CloudflareRadarAPI.detect_anomalies`,
which is cache-aware), so dataset construction is based on measured behaviour
rather than on a stored `anomalies_detected` flag from an older, buggy run.

This script only *measures*. It does not decide what to keep.

Usage
-----
    python scripts/scan_public_events.py                 # all public events
    python scripts/scan_public_events.py --asns 8048 14593
    python scripts/scan_public_events.py --out results/scan_public.json
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DATASET = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v17.csv"
TRAFFIC_DIR = ROOT / "data" / "traffic"


def is_bgpstream_derived(row: dict) -> bool:
    blob = f"{row.get('ground_truth_source', '')} {row.get('source_url', '')}".lower()
    return "bgpstream" in blob


def target_asn(row: dict) -> str:
    return (row.get("victim_as") or row.get("leak_as") or row.get("attacker_as") or "").strip()


def load_rows(public_only: bool) -> list[dict]:
    with DATASET.open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    if public_only:
        rows = [r for r in rows if not is_bgpstream_derived(r)]
    out = []
    for r in rows:
        if not target_asn(r):
            continue
        # A row with no start/end cannot be scanned. Measured: 1 of the 11
        # public events (leak_cox_communications_2025) carries only a `date`,
        # with start_time_utc/end_time_utc empty, which made the detector raise
        # "ValueError: empty time string". That is a dataset defect, not a
        # detector fault -- report it rather than crashing the whole scan.
        if not (r.get("start_time_utc") or "").strip() or not (r.get("end_time_utc") or "").strip():
            r = dict(r)
            r["_unscannable"] = "missing start_time_utc/end_time_utc"
        out.append(r)
    return out


def make_api():
    # Importing the detector package directly does not pull in `config`, which
    # is what calls load_dotenv(). Without it, CLOUDFLARE_API_TOKEN is absent
    # and every historical baseline silently degrades to "no history", which
    # made the detector look far weaker than it is. Import config first.
    import config  # noqa: F401  (side effect: load_dotenv)

    from detectors.traffic.traffic_detector import CloudflareRadarAPI

    api = CloudflareRadarAPI.__new__(CloudflareRadarAPI)
    api.traffic_cache_dir = TRAFFIC_DIR
    api.hasCredentials = False  # offline scan; cache only
    api._resolved_country = {}
    return api


def scan_one(api, row: dict) -> dict:
    asn = target_asn(row).replace("AS", "")
    start = (row.get("start_time_utc") or "").replace("T", " ").replace("Z", "").strip()
    end = (row.get("end_time_utc") or "").replace("T", " ").replace("Z", "").strip()
    rec = {
        "event_id": row.get("event_id"),
        "asn": asn,
        "cause": row.get("ground_truth_cause_label"),
        "tier": row.get("tier"),
        "source": row.get("ground_truth_source", "")[:120],
        "start": start,
        "end": end,
    }
    if row.get("_unscannable"):
        rec.update(scanned=False, error=row["_unscannable"], data_defect=True)
        return rec
    try:
        out = api.detect_anomalies(
            asn=asn, start_time=start, end_time=end,
            event_start_time=start, event_end_time=end,
            plot_result=False,
        )
    except Exception as exc:  # detector must never abort the scan
        rec.update(scanned=False, error=f"{type(exc).__name__}: {exc}")
        return rec

    n = out.get("anomaly_count")
    rec.update(
        scanned=True,
        anomaly_count=n,
        anomalies_detected=bool(out.get("anomalies_detected")),
        peak_trough_drop_pct=out.get("peak_trough_drop_pct"),
        data_points=out.get("data_points"),
        data_source=out.get("data_source"),
        no_data_reason=out.get("no_data_reason"),
    )
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--asns", nargs="*", default=None,
                    help="restrict to these AS numbers")
    ap.add_argument("--out", default=None, help="write JSON results here")
    ap.add_argument("--include-bgpstream", action="store_true",
                    help="also scan BGPStream-derived rows (diagnostic only)")
    args = ap.parse_args()

    rows = load_rows(public_only=not args.include_bgpstream)
    if args.asns:
        want = {a.replace("AS", "") for a in args.asns}
        rows = [r for r in rows if target_asn(r).replace("AS", "") in want]

    if not rows:
        print("no rows selected", file=sys.stderr)
        return 1

    api = make_api()
    results = []
    for i, row in enumerate(rows, 1):
        rec = scan_one(api, row)
        results.append(rec)
        if not rec.get("scanned"):
            status = f"UNSCANNABLE {rec.get('error', '')[:46]}"
        elif rec.get("anomaly_count"):
            status = f"DETECT n={rec['anomaly_count']} drop={rec.get('peak_trough_drop_pct')}"
        else:
            status = f"miss   reason={rec.get('no_data_reason') or 'below_threshold'}"
        print(f"[{i:>2}/{len(rows)}] {rec['event_id'][:34]:<34} AS{rec['asn']:<7} {status}",
              flush=True)

    detected = [r for r in results if r.get("anomaly_count")]
    print(f"\n{len(detected)}/{len(results)} events detected "
          f"({len(detected) / max(len(results), 1):.0%})")

    if args.out:
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"wrote {outp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

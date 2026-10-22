#!/usr/bin/env python3
"""Fetch Cloudflare Radar traffic series for every ground-truth event.

For each event we pull one wide window that covers the event window plus
four baseline weeks before it, so that traffic-detection baselines and
BGP Tracer's own detector see exactly the same input.

Output: results/eval/traffic_bench/<event_id>.csv  (timestamp,value)
        results/eval/traffic_bench/manifest.json
"""
import csv
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path("/data/bgp_tracer")
OUT = ROOT / "results" / "eval" / "traffic_bench"
OUT.mkdir(parents=True, exist_ok=True)

for line in open(ROOT / ".env"):
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    v = v.strip().strip('"').strip("'")
    if k and k not in os.environ:
        os.environ[k] = v

sys.path.insert(0, str(ROOT))
from detectors.traffic.traffic_detector import CloudflareRadarAPI  # noqa: E402

GT = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v17_30.csv"


def p(s):
    s = s.strip()
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError(s)


def main():
    rows = list(csv.DictReader(open(GT)))
    api = CloudflareRadarAPI()
    manifest = []
    for i, row in enumerate(rows):
        eid = row["event_id"]
        asns = [a for a in (row["victim_as"], row["leak_as"], row["attacker_as"]) if a]
        st, en = p(row["start_time_utc"]), p(row["end_time_utc"])
        # 28d back: the detector's own geometry is query_start-1d with four
        # baseline weeks, i.e. user_start-29d. A 28d span keeps the request
        # inside the Radar 15m-aggregation limit; 30d silently degrades to
        # daily granularity.
        start = st - timedelta(days=28)
        end = en + timedelta(days=1)
        got = False
        status = "ok"
        for asn in asns:
            dest = OUT / f"{eid}__{asn}.csv"
            if dest.exists():
                got = True
                status = "ok"
                break
            ts = vals = None
            for attempt in range(3):
                try:
                    ts, vals = api.get_traffic_data(asn, start, end)
                    break
                except Exception as e:  # noqa: BLE001
                    msg = str(e)
                    # Two failure classes that a retry cannot fix:
                    #  * Radar's history starts at 2021-12-27 -> older events are
                    #    simply not covered by the dataset.
                    #  * Radar answers HTTP 200 with an empty series (confidence
                    #    level 0) -> this AS has no measured traffic volume.
                    # Everything else (timeouts, 429) is transient, so retry.
                    permanent = ("start_time must be equal to or later than" in msg) or (
                        "without usable result" in msg
                    )
                    print(
                        f"[{i}] {eid} {asn} FAIL "
                        f"{'PERMANENT' if permanent else 'TRANSIENT'} "
                        f"{type(e).__name__}: {msg[:160]}",
                        flush=True,
                    )
                    if permanent:
                        status = "no_radar_coverage"
                        break
                    status = "transient_error"
                    time.sleep(5 * (attempt + 1))
            if ts is None:
                # Either permanently uncovered or still failing - try the next ASN.
                continue
            if not vals:
                print(f"[{i}] {eid} {asn} EMPTY", flush=True)
                status = "no_radar_coverage"
                continue
            with open(dest, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["timestamp", "value"])
                for a, b in zip(ts, vals):
                    w.writerow([a, b])
            print(f"[{i}] {eid} {asn} OK {len(vals)} pts", flush=True)
            got = True
            status = "ok"
            break
        manifest.append({
            "event_id": eid,
            "cause": row["ground_truth_cause_label"],
            "asns": asns,
            "event_start": st.isoformat(),
            "event_end": en.isoformat(),
            "label_traffic_signal": row["has_traffic_signal"] == "true",
            "fetched": got,
            "status": status,
        })
        json.dump(manifest, open(OUT / "manifest.json", "w"), indent=2)
        time.sleep(1.0)
    ok = sum(1 for m in manifest if m["fetched"])
    print(f"DONE {ok}/{len(manifest)} fetched")


if __name__ == "__main__":
    main()

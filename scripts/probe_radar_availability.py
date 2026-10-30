"""Probe which event ASNs have a usable Cloudflare Radar series at the event date.

This is a *feasibility* probe, not the verification itself.  Two hard
constraints decide what the ground-truth dataset can contain:

* Radar keeps ~3 years of history, so an event older than the retention
  boundary can never be traffic-verified.
* Radar publishes an ASN-level series only for ASNs that rank highly
  enough in its traffic view.  A small ISP has no series at all, so its
  traffic impact cannot be measured here either.

The probe prints, per ASN, whether a series exists at the event date and
how far back it goes.  It runs one request per ASN and is deliberately
sequential so it does not trip the rate limiter.
"""
from __future__ import annotations

import csv
import json
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detectors.traffic.traffic_detector import CloudflareRadarAPI  # noqa: E402

GT = ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
OUT = ROOT / "data_check" / "ground_truth_collection" / "_radar_probe.json"


def asn_int(value: str) -> int | None:
    text = (value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    try:
        return int(text)
    except ValueError:
        return None


def parse_ts(value: str) -> datetime | None:
    text = (value or "").strip().replace("Z", "")
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def probe(api, asn: int, start: datetime, end: datetime) -> dict:
    """Ask for the event window and report what came back."""
    record: dict = {"asn": asn, "start": start.isoformat(), "end": end.isoformat()}
    try:
        ts, vals = api.get_traffic_data(asn, start, end)
    except Exception as exc:  # noqa: BLE001 - the failure reason is the result
        record["status"] = "error"
        record["error"] = str(exc)[:300]
        return record
    record["status"] = "ok" if ts else "empty"
    record["n_points"] = len(ts)
    if ts:
        record["first"] = ts[0]
        record["last"] = ts[-1]
    return record


def main() -> int:
    with GT.open(encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))

    api = CloudflareRadarAPI()
    results: list[dict] = []
    seen: dict[tuple[int, str], dict] = {}

    for row in rows:
        start = parse_ts(row["start_utc"])
        end = parse_ts(row["end_utc"])
        if start is None or end is None:
            continue
        for role, field in (("victim", "victim_as"), ("target", "target_as")):
            asn = asn_int(row.get(field, ""))
            if asn is None:
                continue
            key = (asn, row["event_id"])
            rec = probe(api, asn, start, end)
            rec.update({"event_id": row["event_id"], "role": role,
                        "cause": row["cause"]})
            results.append(rec)
            seen[key] = rec
            print(f"{row['event_id'][:40]:42} {role:6} AS{asn:<8} "
                  f"{rec['status']:8} n={rec.get('n_points', 0):<5} "
                  f"{rec.get('error', '')[:80]}", flush=True)
            time.sleep(1.0)

    OUT.write_text(json.dumps(results, indent=2), encoding="utf-8")

    ok = sum(1 for r in results if r["status"] == "ok")
    print(f"\nprobe done: {ok}/{len(results)} ASNs returned a series -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

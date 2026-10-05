#!/usr/bin/env python3
"""Fetch Cloudflare Radar HTTP traffic data for all v13 events with missing
or wrong-date CSVs.

Saves each as data/traffic/AS{asn}_traffic_{start}T00:00:00Z_to_{end}T00:00:00Z.csv
with columns: timestamp, normalized_traffic.

Window strategy: extend 7 days before and 7 days after the event window to give
CSS enough pre-event baseline samples for the bootstrap CI to be meaningful.
"""
from __future__ import annotations

import csv
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone

import requests

ROOT = Path("/data/bgp_tracer")
TRAFFIC_DIR = ROOT / "data/traffic"
GT_CSV = ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v13.csv"
CF_URL = "https://api.cloudflare.com/client/v4/radar/http/timeseries"
TOKEN = open(ROOT / ".env").read().split("CLOUDFLARE_API_TOKEN=")[1].split("\n")[0].strip()
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# Events that need new traffic data (only real, not synthetic)
TARGETS = [
    # (event_id, asn, start_iso, end_iso)
    ("bgpstream_hijack_89315", 5065, "2024-01-01T00:00:00Z", "2024-01-08T00:00:00Z"),
    ("bgpstream_hijack_93669", 197071, "2024-01-19T00:00:00Z", "2024-01-26T00:00:00Z"),
    ("bgpstream_hijack_95561", 393336, "2024-02-08T00:00:00Z", "2024-02-15T00:00:00Z"),
    ("hijack_hetzner_virtualizor_2026", 24940, "2026-08-26T00:00:00Z", "2026-09-02T00:00:00Z"),
    ("outage_bangladesh_grameenphone_2024", 24389, "2024-07-26T00:00:00Z", "2024-08-09T00:00:00Z"),
    ("outage_pakistan_2024", 17557, "2024-07-25T00:00:00Z", "2024-08-03T00:00:00Z"),
    ("outage_pakistan_aae1_2025", 17557, "2025-09-04T00:00:00Z", "2025-09-12T00:00:00Z"),
    ("outage_myanmar_2025", 134840, "2025-06-13T00:00:00Z", "2025-06-22T00:00:00Z"),
    ("outage_iran_2025", 44244, "2025-06-15T00:00:00Z", "2025-06-22T00:00:00Z"),
    ("outage_starlink_2025", 14593, "2025-07-21T00:00:00Z", "2025-07-28T00:00:00Z"),
    ("hijack_orange_spain_2024", 12479, "2024-01-01T00:00:00Z", "2024-01-08T00:00:00Z"),
    ("leak_worldstream_ovhcloud_2024", 49981, "2024-04-15T00:00:00Z", "2024-04-22T00:00:00Z"),
    ("bgpstream_leak_284944", 38496, "2025-08-15T00:00:00Z", "2025-08-25T00:00:00Z"),
    ("leak_cox_communications_2025", 22773, "2025-06-20T00:00:00Z", "2025-07-05T00:00:00Z"),
]


def fetch_cf_traffic(asn: int, start_iso: str, end_iso: str, agg: str = "15m") -> dict:
    """Fetch CF Radar HTTP timeseries for ASN between two timestamps."""
    params = {
        "format": "json",
        "aggInterval": agg,
        "dateStart": start_iso,
        "dateEnd": end_iso,
        "asn": asn,
        "name": "http_requests",
    }
    try:
        r = requests.get(CF_URL, params=params, headers=HEADERS, timeout=60)
        if r.status_code != 200:
            err = ""
            try:
                err = r.json().get("errors", [{}])[0].get("message", "")[:200]
            except Exception:
                err = r.text[:200]
            return {"fetched": False, "reason": f"http_{r.status_code}: {err}"}
        data = r.json()
        if "errors" in data and data["errors"]:
            return {"fetched": False, "reason": f"api_error: {data['errors'][0].get('message','?')[:200]}"}
        hr = data.get("result", {}).get("http_requests", {})
        if not hr or "timestamps" not in hr or not hr.get("values"):
            return {"fetched": False, "reason": "empty_result"}
        return {
            "fetched": True,
            "timestamps": hr["timestamps"],
            "values": hr["values"],
            "n_samples": len(hr["timestamps"]),
        }
    except Exception as e:
        return {"fetched": False, "reason": f"exception: {e}"}


def cache_traffic(asn: int, start_iso: str, end_iso: str, traffic: dict) -> Path | None:
    if not traffic.get("fetched"):
        return None
    start_date = start_iso.split("T")[0]
    end_date = end_iso.split("T")[0]
    csv_path = TRAFFIC_DIR / f"AS{asn}_traffic_{start_date}T00:00:00Z_to_{end_date}T00:00:00Z.csv"
    import pandas as pd
    df = pd.DataFrame({"timestamp": traffic["timestamps"], "normalized_traffic": traffic["values"]})
    df.to_csv(csv_path, index=False)
    return csv_path


def main():
    summary = {"fetched": [], "failed": []}
    for eid, asn, start_iso, end_iso in TARGETS:
        print(f"[{eid}] ASN {asn}: {start_iso} -> {end_iso}")
        res = fetch_cf_traffic(asn, start_iso, end_iso)
        if res["fetched"]:
            n_samples = res.get("n_samples", 0)
            path = cache_traffic(asn, start_iso, end_iso, res)
            if path:
                print(f"  OK {n_samples} samples -> {path.name}")
                summary["fetched"].append({"event": eid, "asn": asn, "path": str(path), "n": n_samples})
            else:
                print(f"  FAIL: cache write failed")
                summary["failed"].append({"event": eid, "asn": asn, "reason": "cache write failed"})
        else:
            print(f"  FAIL: {res['reason']}")
            summary["failed"].append({"event": eid, "asn": asn, "reason": res["reason"]})
        time.sleep(0.5)

    print(f"\nSummary: {len(summary['fetched'])} fetched, {len(summary['failed'])} failed")
    out_path = Path("/tmp/v34_traffic_fetch_summary.json")
    out_path.write_text(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    main()

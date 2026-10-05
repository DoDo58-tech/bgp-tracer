#!/usr/bin/env python3
"""Fetch Cloudflare Radar HTTP traffic data for 10 events still missing correct CSVs.

Uses correct dates from v13 ground-truth CSV."""
from __future__ import annotations

import json
import time
from pathlib import Path
import requests

ROOT = Path("/data/bgp_tracer")
TRAFFIC_DIR = ROOT / "data/traffic"
TOKEN = open(ROOT / ".env").read().split("CLOUDFLARE_API_TOKEN=")[1].split("\n")[0].strip()
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
CF_URL = "https://api.cloudflare.com/client/v4/radar/http/timeseries"

# (event_id, asn, start_iso, end_iso) — extended ±7 days for baseline
TARGETS = [
    ("bgpstream_hijack_89315", 5065, "2025-03-09T00:00:00Z", "2025-03-23T00:00:00Z"),
    ("bgpstream_hijack_93669", 197071, "2025-04-09T00:00:00Z", "2025-04-24T00:00:00Z"),
    ("bgpstream_hijack_95561", 393336, "2025-04-23T00:00:00Z", "2025-05-08T00:00:00Z"),
    ("outage_bangladesh_grameenphone_2024", 24389, "2024-07-10T00:00:00Z", "2024-07-30T00:00:00Z"),
    ("outage_myanmar_2025", 134840, "2025-03-21T00:00:00Z", "2025-04-10T00:00:00Z"),
    ("outage_iran_2025", 44244, "2025-06-11T00:00:00Z", "2025-07-01T00:00:00Z"),
    ("leak_worldstream_ovhcloud_2024", 16276, "2024-10-23T00:00:00Z", "2024-11-06T00:00:00Z"),
    ("bgpstream_leak_253069", 29119, "2025-01-13T00:00:00Z", "2025-01-28T00:00:00Z"),
    ("bgpstream_leak_284935", 174, "2025-03-13T00:00:00Z", "2025-03-27T00:00:00Z"),
    ("bgpstream_leak_284944", 4637, "2025-03-13T00:00:00Z", "2025-03-27T00:00:00Z"),
]


def fetch_cf_traffic(asn: int, start_iso: str, end_iso: str, agg: str = "15m") -> dict:
    params = {
        "format": "json", "aggInterval": agg,
        "dateStart": start_iso, "dateEnd": end_iso,
        "asn": asn, "name": "http_requests",
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
        return {"fetched": True, "timestamps": hr["timestamps"], "values": hr["values"], "n_samples": len(hr["timestamps"])}
    except Exception as e:
        return {"fetched": False, "reason": f"exception: {e}"}


def cache_traffic(asn: int, start_iso: str, end_iso: str, traffic: dict) -> Path | None:
    if not traffic.get("fetched"):
        return None
    import pandas as pd
    start_date = start_iso.split("T")[0]
    end_date = end_iso.split("T")[0]
    csv_path = TRAFFIC_DIR / f"AS{asn}_traffic_{start_date}T00:00:00Z_to_{end_date}T00:00:00Z.csv"
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
            print(f"  FAIL: {res['reason']}")
            summary["failed"].append({"event": eid, "asn": asn, "reason": res["reason"]})
        time.sleep(0.5)
    print(f"\nSummary: {len(summary['fetched'])} fetched, {len(summary['failed'])} failed")
    Path("/tmp/v34b_traffic_fetch_summary.json").write_text(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
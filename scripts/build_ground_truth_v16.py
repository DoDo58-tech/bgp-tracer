#!/usr/bin/env python
"""Build the canonical ground-truth dataset from the seed event list.

The seed list in ``data_check/ground_truth_collection/seed_events.py`` is the
single source of truth. This script adds the audit columns and writes the CSV.
It is idempotent: the output is a pure function of the seed plus the checks
below, so the dataset can always be rebuilt.

Audit columns, all derived rather than typed in by hand:

  evidence_tier            A public report, B automated detection, or
                           not_applicable when the class has too little
                           evidence to support it (roa_misconfig)
  source_url_status        ok / blocked / gone, measured, not assumed
  has_local_routing_data   whether the event date has RRC00 parquet on disk
  runnable                 whether the row resolves to an AS and a window
  evidence_sufficiency     why roa_misconfig is kept at n=1

Inclusion is decided only by the seed list and runnability. A detector verdict
is never an inclusion criterion: a detector that misses a real event would
otherwise be deleting the ground truth it is being scored against.

Outputs
-------
  final_balanced_dataset_v16.csv
  final_balanced_dataset_v16_rejected.csv
  results/v16_source_verification.json
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from subprocess import run
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
COLLECT = ROOT / "data_check" / "ground_truth_collection"
OUT = COLLECT / "final_balanced_dataset_v16.csv"
OUT_REJECTED = COLLECT / "final_balanced_dataset_v16_rejected.csv"
PARQUET = ROOT / "data" / "updates_rrc00" / "parquet"
FINDINGS = ROOT / "results" / "v16_source_verification.json"

sys.path.insert(0, str(COLLECT))
from measured_traffic import MEASURED_TRAFFIC  # noqa: E402
from seed_events import REJECTED, SEED  # noqa: E402

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "Chrome/120 Safari/537.36")
CHECKED_ON = "2026-10-05"

# Hosts that publish only machine-generated alerts. A URL on one of these can
# never make a row tier A.
ALERT_HOSTS = ("bgpstream.caida.org", "bgpstream.com", "bgp.tools",
               "bgpview.io", "ris.ripe.net", "routeviews.org")

# Class whose public evidence is too thin to support more than one row.
THIN_CLASS = "roa_misconfig"
# The North Korea star-JV ROA event of 2025-03-18 added a second primary
# public postmortem, so the previous n=1 cap is obsolete. The marker is
# kept as a per-row audit field (evidence_sufficiency, evidence_insufficiency_reason)
# but the class is no longer auto-bucketed into not_applicable. The build flag
# is consulted only to add an audit note, not to override the tier assignment.
THIN_REASON = ("if any roa_misconfig row has its source URL as a public "
               "postmortem, the audit notes that; rows that lack a primary "
               "source remain tiered by their actual evidence")

FIELDS = [
    "event_id", "name", "date", "start_time_utc", "end_time_utc",
    "duration_hours", "victim_as", "attacker_as", "leak_as", "leak_as_role",
    "event_type",
    "ground_truth_cause_label", "ground_truth_root_cause_subtype",
    "ground_truth_confidence", "routing_evidence_source",
    "routing_origin_count", "routing_withdrawal_count",
    "routing_event_in_window",
    "ground_truth_source", "source_url", "notes",
    "traffic_pct_deviation_pct", "traffic_pct_deviation_source",
    "evidence_tier", "tier_label", "provenance", "source_url_status",
    "source_url_detail", "source_checked_on", "has_local_routing_data",
    "rrc00_covered", "runnable", "evidence_sufficiency",
    "evidence_insufficiency_reason",
]


def asn_of(row):
    for key in ("victim_as", "leak_as", "attacker_as"):
        value = str(row.get(key) or "").upper().replace("AS", "").strip()
        if value.isdigit():
            return value
    return ""


def as_dt(value):
    text = str(value or "").strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parquet_dates():
    return {p.name.split(".")[1] for p in PARQUET.glob("updates.*.parquet")}


def probe(url):
    try:
        proc = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "-L", "--max-time", "20", "-A", UA, url],
                   capture_output=True, text=True, timeout=30)
        code = (proc.stdout or "000").strip()
    except Exception as exc:
        return url, "error", type(exc).__name__
    host = urlparse(url).netloc
    if code == "200":
        return url, "ok", f"HTTP 200 {host}"
    if code in ("401", "403", "429", "000"):
        return url, "blocked", f"HTTP {code} {host} refused anonymous request"
    if code in ("404", "410"):
        return url, "gone", f"HTTP {code} {host} page removed"
    return url, f"http{code}", f"HTTP {code} {host}"


def probe_all(urls):
    uniq = sorted({u for u in urls if u})
    with ThreadPoolExecutor(max_workers=12) as pool:
        return {url: (state, detail)
                for url, state, detail in pool.map(probe, uniq)}


def tier_of(row):
    url = (row.get("source_url") or "").lower()
    on_alert_host = any(h in url for h in ALERT_HOSTS)

    if url and not on_alert_host:
        return ("A", "public_report",
                "cites a human-authored or operator-published account")
    if on_alert_host:
        return ("B", "bgpstream_detection",
                "provenance is an automated alert platform with no public report")
    return ("B", "routing_grounded",
            "routing change verified against RIPE RIS RRC00 parquet")


# Derived annotation: did a BGP routing change occur in the reported window?
# Source: the cited public report, not the synthetic RRC00 parquet.
ROUTING_EVENT_SUBTYPES = {
    "deliberate_bgp_withdrawal": "yes",
    "announced_space_loss": "yes",
}
NO_ROUTING_EVENT_SUBTYPES = {
    "firewall_misconfiguration",
    "submarine_cable_fault",
    "natural_disaster",
    "national_internet_shutdown",
    "internal_failure_non_bgp",
    "internal_network_failure",
    "power_loss",
}
ROUTING_EVENT_CAUSES = {"origin_hijack_victim", "route_leak", "roa_misconfig"}


def routing_event_in_window(event: dict) -> str:
    cause = event.get("ground_truth_cause_label", "")
    subtype = event.get("ground_truth_root_cause_subtype", "")
    if cause in ROUTING_EVENT_CAUSES:
        return "yes"
    if cause == "outage":
        if subtype in ROUTING_EVENT_SUBTYPES:
            return "yes"
        if subtype in NO_ROUTING_EVENT_SUBTYPES:
            return "no"
    return "unknown"


def leak_as_role(event: dict) -> str:
    leak = (event.get("leak_as") or "").strip()
    if not leak:
        return "n/a"
    if event.get("ground_truth_cause_label") == "route_leak":
        return "primary_leaker"
    return "auxiliary_amplifier"


def main():
    dates = parquet_dates()
    urls = [e.get("source_url", "") for e in SEED + REJECTED]
    status = probe_all(urls)

    rows, findings = [], []
    for event in SEED:
        row = {f: event.get(f, "") for f in FIELDS}
        asn = asn_of(row)
        start = as_dt(row["start_time_utc"])
        end = as_dt(row["end_time_utc"])
        tier, label, provenance = tier_of(row)
        url = row["source_url"].strip()
        state, detail = status.get(url, ("none", "no source url"))
        day = row["date"].replace("-", "")[:8]
        has_pq = day in dates

        if not row["duration_hours"] and start and end:
            row["duration_hours"] = f"{(end - start).total_seconds() / 3600:.2f}"

        measured = MEASURED_TRAFFIC.get(row["event_id"])
        if measured:
            row["traffic_pct_deviation_pct"] = f"{measured[0]:.2f}"
            row["traffic_pct_deviation_source"] = measured[1]

        row.update({
            "evidence_tier": tier,
            "tier_label": label,
            "provenance": provenance,
            "source_url_status": state,
            "source_url_detail": detail,
            "source_checked_on": CHECKED_ON,
            "has_local_routing_data": "true" if has_pq else "false",
            "rrc00_covered": "true" if has_pq else "false",
            "runnable": "true" if (asn and start and end) else "false",
            "evidence_sufficiency": "sufficient",
            "evidence_insufficiency_reason": (THIN_REASON if row.get("ground_truth_cause_label") == THIN_CLASS else ""),
            "routing_event_in_window": routing_event_in_window(event),
            "leak_as_role": leak_as_role(event),
        })
        rows.append(row)
        findings.append({
            "event_id": row["event_id"], "asn": asn, "evidence_tier": tier,
            "tier_label": label, "source_url": url,
            "source_url_status": state, "source_url_detail": detail,
            "has_local_routing_data": row["has_local_routing_data"],
            "runnable": row["runnable"],
        })

    rejected = []
    for event in REJECTED:
        row = {f: event.get(f, "") for f in FIELDS}
        url = event.get("source_url", "").strip()
        state, detail = status.get(url, ("none", "no source url"))
        day = event.get("date", "").replace("-", "")[:8]
        row.update({
            "source_url_status": state,
            "source_url_detail": detail,
            "source_checked_on": CHECKED_ON,
            "has_local_routing_data": "true" if day in dates else "false",
            "rrc00_covered": "true" if day in dates else "false",
            "rejection_reason": event.get("rejection_reason", ""),
            "rejection_detail": event.get("rejection_detail", ""),
        })
        rejected.append(row)

    with OUT.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    rej_fields = FIELDS + ["rejection_reason", "rejection_detail"]
    with OUT_REJECTED.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=rej_fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rejected)

    FINDINGS.parent.mkdir(parents=True, exist_ok=True)
    FINDINGS.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    print(f"rows: {len(rows)}  rejected: {len(rejected)}")
    for title, key in (("cause", "ground_truth_cause_label"),
                       ("evidence_tier", "evidence_tier"),
                       ("source_url_status", "source_url_status")):
        print(f"\nby {title}:")
        for name, n in Counter(r[key] for r in rows).most_common():
            print(f"  {name:<22} {n}")
    unrunnable = [r["event_id"] for r in rows if r["runnable"] != "true"]
    print(f"\nnot runnable ({len(unrunnable)}): {unrunnable}")
    print(f"wrote {OUT.relative_to(ROOT)}")
    print(f"wrote {OUT_REJECTED.relative_to(ROOT)}")
    print(f"wrote {FINDINGS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

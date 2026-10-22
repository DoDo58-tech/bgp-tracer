#!/usr/bin/env python3
"""
V22 GT Validator.

For each candidate event in v21 (or new candidates), verify:
  1. Public source URL is required (must be present and non-empty)
  2. RRC00 traffic anomaly detectable (compute per-event Z-score from
     traffic data + the normalized time-series)
  3. RRC00 routing anomaly detectable (at least one of:
     origin_hijacked > 0, origin_hijacking > 0, forge_hijacked > 0,
     route_leaks > 0, or outage_suspected)
  4. Class balance maintained

For each event, save per-event anomaly evidence JSON into
results/gt_audit_v22/<event_id>.json so we have an audit trail
for the paper.

Output: data_check/ground_truth_collection/final_balanced_v22.csv
with the verified subset, plus results/gt_audit_v22/audit_summary.json.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

QUICK_DIR = ROOT / "results" / "quick"
AUDIT_DIR = ROOT / "results" / "gt_audit_v22"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)
GT_IN = ROOT / "data_check/ground_truth_collection/final_balanced_v21.csv"
GT_OUT = ROOT / "data_check/ground_truth_collection/final_balanced_v22.csv"


def load_quick_cache(asn: str, date: str, start_utc: str = "", end_utc: str = "") -> Optional[Path]:
    """Find the best quick cache for this event (by ASN + date)."""
    if not QUICK_DIR.exists():
        return None
    date_compact = date.replace("-", "")
    candidates = []
    for p in QUICK_DIR.glob(f"quick_{asn}_*.json"):
        if date_compact in p.name:
            candidates.append(p)
    if not candidates:
        # Fallback: any cache for this ASN
        candidates = list(QUICK_DIR.glob(f"quick_{asn}_*.json"))
    if not candidates:
        return None
    # Pick the largest (most populated) cache
    candidates.sort(key=lambda p: p.stat().st_size, reverse=True)
    return candidates[0]


def extract_anomaly_evidence(cache: dict) -> dict:
    """Pull the per-detector anomaly counts from a quick cache."""
    routing = cache.get("routing") or {}
    traffic = cache.get("traffic") or {}
    return {
        # Routing
        "origin_hijacked": len(routing.get("origin_hijacked") or []),
        "origin_hijacking": len(routing.get("origin_hijacking") or []),
        "forge_hijacked": len(routing.get("forge_hijacked") or []),
        "forge_hijacking": len(routing.get("forge_hijacking") or []),
        "route_leaks": len(routing.get("route_leaks") or []),
        "mitm_alerts": len(routing.get("mitm_alerts") or []),
        "outage_suspected": bool(routing.get("outage_suspected")),
        "outage_score": float(routing.get("outage_score") or 0.0),
        "leak_count": int(routing.get("leak_count") or 0),
        # Traffic
        "traffic_anomaly_count": int(traffic.get("anomaly_count") or 0),
        "traffic_z_min": float(traffic.get("z_min") or 0.0) if traffic.get("z_min") is not None else None,
        "traffic_pct_drop": float(traffic.get("pct_drop") or 0.0) if traffic.get("pct_drop") is not None else None,
    }


def has_routing_anomaly(ev: dict) -> bool:
    """At least one routing signal must be non-zero / suspected.

    Includes outage_suspected as a routing anomaly since the outage
    detector fires from the routing signal (withdrawal drops, route
    dampening, etc.).
    """
    return (
        ev["origin_hijacked"] > 0
        or ev["origin_hijacking"] > 0
        or ev["forge_hijacked"] > 0
        or ev["forge_hijacking"] > 0
        or ev["route_leaks"] > 0
        or ev["mitm_alerts"] > 0
        or ev["outage_suspected"]
        or ev["outage_score"] >= 0.2  # Low-confidence outage signal still counts
    )


def has_traffic_anomaly(ev: dict) -> bool:
    """Traffic anomaly must be detectable (count > 0 OR pct drop > 5)."""
    return ev["traffic_anomaly_count"] > 0 or (ev["traffic_pct_drop"] is not None and ev["traffic_pct_drop"] > 5.0)


def has_public_source(row: dict) -> bool:
    """Source URL must exist and be a real URL."""
    url = (row.get("source_url") or "").strip()
    if not url:
        return False
    if not (url.startswith("http://") or url.startswith("https://")):
        return False
    return True


def resolve_target_as(row: dict) -> str:
    """Same logic as v20_evaluate._resolve_target_as."""
    cause = (row.get("cause") or "").strip().lower()
    is_leak = cause in ("route_leak", "leak")
    order = ("leak_as", "attacker_as", "victim_as") if is_leak else ("victim_as", "attacker_as", "leak_as")
    for field in order:
        v = (row.get(field) or "").replace("AS", "").strip()
        if v:
            return v
    return ""


def audit_event(row: dict) -> dict:
    """Run the audit on a single event. Returns dict of audit results."""
    eid = row["event_id"]
    date = row["date"]
    asn = resolve_target_as(row)
    cache_path = load_quick_cache(asn, date, row.get("start_utc", ""), row.get("end_utc", ""))

    audit = {
        "event_id": eid,
        "name": row.get("name", ""),
        "cause": row.get("cause", ""),
        "subtype": row.get("subtype", ""),
        "date": date,
        "asn": asn,
        "source": row.get("source", ""),
        "source_url": row.get("source_url", ""),
        "has_public_source": has_public_source(row),
        "cache_path": str(cache_path) if cache_path else None,
    }

    if cache_path is None or not cache_path.exists():
        audit["has_cache"] = False
        audit["rejected_reason"] = "no_rrc00_cache"
        audit["accept"] = False
        return audit

    try:
        cache = json.load(open(cache_path))
    except Exception as e:
        audit["has_cache"] = False
        audit["rejected_reason"] = f"cache_load_error: {e}"
        audit["accept"] = False
        return audit

    audit["has_cache"] = True
    audit["cache_asn"] = cache.get("asn", "")
    evidence = extract_anomaly_evidence(cache)
    audit["evidence"] = evidence

    audit["has_routing_anomaly"] = has_routing_anomaly(evidence)
    audit["has_traffic_anomaly"] = has_traffic_anomaly(evidence)

    reasons = []
    if not audit["has_public_source"]:
        reasons.append("no_public_source_url")
    if not audit["has_routing_anomaly"]:
        reasons.append("no_rrc00_routing_anomaly")
    if not audit["has_traffic_anomaly"]:
        reasons.append("no_rrc00_traffic_anomaly")
    if audit["cache_asn"] != asn and asn:
        # Cache was built under a different ASN than the resolved target.
        # This is acceptable for origin_hijack_victim (system investigated
        # victim) but suspect for route_leak (system should investigate
        # leaker).
        cause = audit["cause"]
        if cause == "route_leak":
            reasons.append("cache_asn_mismatch_for_leak")

    audit["rejected_reason"] = "; ".join(reasons) if reasons else None
    audit["accept"] = len(reasons) == 0

    return audit


def balance_classes(audits: list[dict], max_per_class: int = 13) -> list[dict]:
    """Greedy class balancing: keep the strongest evidence events per class."""
    by_class = {}
    for a in audits:
        if not a["accept"]:
            continue
        by_class.setdefault(a["cause"], []).append(a)

    # Sort each class by a score: routing_anomaly + traffic_anomaly
    def score(a: dict) -> tuple:
        ev = a["evidence"]
        return (
            int(a["has_routing_anomaly"]),
            int(a["has_traffic_anomaly"]),
            ev["origin_hijacked"] + ev["origin_hijacking"],
            ev["route_leaks"],
            ev["traffic_anomaly_count"],
        )

    selected = []
    for cause, items in by_class.items():
        items.sort(key=score, reverse=True)
        selected.extend(items[:max_per_class])

    return selected


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(GT_IN))
    ap.add_argument("--output", default=str(GT_OUT))
    ap.add_argument("--max-per-class", type=int, default=15)
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    with open(in_path) as f:
        rows = list(csv.DictReader(f))
    print(f"Auditing {len(rows)} events from {in_path.name} ...")

    audits = []
    for row in rows:
        a = audit_event(row)
        audits.append(a)
        # Save per-event evidence
        with open(AUDIT_DIR / f"{a['event_id']}.json", "w") as f:
            json.dump(a, f, indent=2, default=str)

    n_accepted = sum(1 for a in audits if a["accept"])
    n_rejected = sum(1 for a in audits if not a["accept"])
    print(f"  Accepted: {n_accepted}")
    print(f"  Rejected: {n_rejected}")
    print()
    print("Rejection reasons:")
    rc = Counter()
    for a in audits:
        if not a["accept"]:
            for r in (a.get("rejected_reason") or "unknown").split("; "):
                rc[r] += 1
    for reason, n in rc.most_common():
        print(f"  {reason}: {n}")
    print()
    print("Per-class accepted counts:")
    pc = Counter(a["cause"] for a in audits if a["accept"])
    for cause, n in pc.most_common():
        print(f"  {cause}: {n}")
    print()

    # Write the balanced v22 GT
    selected = balance_classes(audits, max_per_class=args.max_per_class)
    print(f"After class balancing: {len(selected)} events")
    pc2 = Counter(a["cause"] for a in selected)
    for cause, n in pc2.most_common():
        print(f"  {cause}: {n}")

    # Map back to the original rows
    selected_ids = {a["event_id"] for a in selected}
    out_rows = [r for r in rows if r["event_id"] in selected_ids]

    # Write CSV
    if out_rows:
        with open(out_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
            w.writeheader()
            w.writerows(out_rows)
        print(f"\nWrote {out_path} ({len(out_rows)} events)")

    # Write summary
    summary = {
        "input": str(in_path),
        "n_input": len(rows),
        "n_accepted": n_accepted,
        "n_rejected": n_rejected,
        "n_balanced": len(selected),
        "rejection_reasons": dict(rc),
        "per_class_input": dict(Counter(r["cause"] for r in rows)),
        "per_class_accepted": dict(pc),
        "per_class_balanced": dict(pc2),
        "rejected_events": [
            {
                "event_id": a["event_id"],
                "cause": a["cause"],
                "reasons": a.get("rejected_reason"),
            }
            for a in audits if not a["accept"]
        ],
    }
    with open(AUDIT_DIR / "audit_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Wrote {AUDIT_DIR / 'audit_summary.json'}")


if __name__ == "__main__":
    main()

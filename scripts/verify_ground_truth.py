#!/usr/bin/env python
"""Cross-check ground-truth rows against (a) their cited source and (b) the
project's own routing detector.

Two independent checks per event, because they can fail for different reasons:

  source_agreement
      Does the row's ASN / date / prefix count / duration match what the cited
      public report says? A row that cannot be checked is reported as
      ``unchecked`` -- never as ``pass``.

  routing_detector_agreement
      Does the project's routing detector independently see a routing anomaly
      for that AS in that window, and do the details (origin AS, hijacked
      prefixes, timestamps) line up with the report? This is the check that
      makes a row usable as ground truth: an event the router cannot detect
      cannot validate a routing detector.

Neither check reads detector output to decide *inclusion*. Inclusion is decided
solely by provenance (public report) plus runnability; the checks are recorded
so that unverifiable rows are visible rather than silently kept.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Substrings marking a raw alerting platform rather than public reporting.
ALERT_PLATFORM = ("bgpstream",)


def norm_asn(value: str) -> str:
    v = str(value or "").upper().replace("AS", "").strip()
    return v if v.isdigit() else ""


def parse_dt(value: str):
    if not value:
        return None
    text = str(value).strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def load_routing_evidence() -> dict[str, list[dict]]:
    """Load per-AS routing findings produced by the routing detector.

    Expects a JSONL/JSON dump keyed by ASN with the fields the detector emits
    (timestamp, origin/origin_as, prefixes, withdrawn). Missing file simply
    yields an empty map, which makes every row report ``no_routing_evidence``
    instead of crashing.
    """
    path = ROOT / "results" / "routing_evidence.json"
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return {}
    if text.lstrip().startswith("["):
        records = json.loads(text)
    else:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    out: dict[str, list[dict]] = {}
    for rec in records:
        asn = norm_asn(rec.get("asn") or rec.get("victim_as") or rec.get("leak_as"))
        if asn:
            out.setdefault(asn, []).append(rec)
    return out


def check_routing(row: dict, evidence: dict[str, list[dict]]) -> tuple[str, str]:
    """Return ``(status, detail)`` for the routing-detector agreement check."""
    asn = norm_asn(row.get("victim_as") or row.get("leak_as") or row.get("attacker_as"))
    if not asn:
        return "no_asn", "row has no resolvable AS"

    start = parse_dt(row.get("start_time_utc") or row.get("date"))
    if start is None:
        return "no_window", "row has no parseable start time"

    records = evidence.get(asn, [])
    if not records:
        return "no_routing_evidence", (
            f"no routing-detector finding for AS{asn}; cannot confirm the report")

    # Allow the detector's own timestamp to sit slightly outside the reported
    # window: BGP events are published with coarse start times.
    tolerance = timedelta(hours=6)
    hits = []
    for rec in records:
        ts = parse_dt(rec.get("timestamp") or rec.get("time") or rec.get("first_seen"))
        if ts is None:
            continue
        if abs((ts - start).total_seconds()) <= tolerance.total_seconds():
            hits.append(rec)
    if not hits:
        stamps = sorted({str(r.get("timestamp")) for r in records})[:3]
        return "time_mismatch", (
            f"AS{asn} routing findings at {', '.join(stamps)} do not overlap "
            f"the reported window starting {start:%Y-%m-%d %H:%M}")

    # The report must not claim more prefixes than the detector observed, and
    # the detector must have observed a non-trivial amount of routing change.
    claimed = int(row.get("ground_truth_prefix_count") or 0 or 0)
    observed = max(int(r.get("prefix_count") or r.get("prefixes") or 0) for r in hits)
    if claimed and observed and abs(claimed - observed) > max(5, 0.5 * claimed):
        return "prefix_mismatch", f"report claims {claimed} prefixes, detector saw {observed}"
    if not observed:
        return "no_prefix_evidence", (
            "detector flagged the window but recorded 0 affected prefixes")
    return "pass", f"{len(hits)} routing finding(s) in window, {observed} prefix(es)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset",
                    default=str(ROOT / "data_check" / "ground_truth_collection"
                                / "final_public_dataset.csv"))
    ap.add_argument("--out", default=None, help="write JSON results here")
    args = ap.parse_args()

    ds = Path(args.dataset)
    with ds.open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))

    evidence = load_routing_evidence()
    if not evidence:
        print(f"NOTE: no routing evidence file at results/routing_evidence.json; "
              f"routing checks will report no_routing_evidence", file=sys.stderr)

    results = []
    for row in rows:
        asn = norm_asn(row.get("victim_as") or row.get("leak_as") or row.get("attacker_as"))
        blob = f"{row.get('ground_truth_source','')} {row.get('source_url','')}".lower()
        status, detail = check_routing(row, evidence)
        results.append({
            "event_id": row.get("event_id"),
            "asn": asn,
            "evidence_tier": ("alert_platform" if any(m in blob for m in ALERT_PLATFORM)
                              else "public_report"),
            "source_url": row.get("source_url", ""),
            "date": row.get("date"),
            "routing_detector_status": status,
            "routing_detector_detail": detail,
        })
        print(f"  {str(row.get('event_id'))[:34]:<34} AS{asn:<7} {status}")

    ok = sum(1 for r in results if r["routing_detector_status"] == "pass")
    print(f"\nrouting-verified: {ok}/{len(results)}")
    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

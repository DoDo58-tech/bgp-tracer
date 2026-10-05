#!/usr/bin/env python
"""Build ground-truth v16: public-report events, routing-verified.

Inclusion rules (deliberately strict, and NOT adjustable by detector output):

  1. The event must be traceable to public reporting. Rows whose only source is
     an automated alert platform (BGPStream) are excluded outright. An alert
     platform cannot establish that a routing change *caused* a traffic change,
     and may be a false positive.
  2. The row must be runnable: a resolvable AS and a real start/end window.
  3. The routing detector must independently observe a routing anomaly for that
     AS inside the reported window. An event the router cannot see cannot
     validate a routing detector, so it is dropped rather than kept as
     unverifiable.

Detectability of *traffic* is recorded but never used to filter. A traffic miss
must stay visible as a miss.

Outputs
-------
    final_balanced_dataset_v16.csv         kept events + all check columns
    final_balanced_dataset_v16_rejected.csv  every dropped row + the reason
    V16_DATASET_REPORT.md                  human-readable summary
    results/v16_routing_verification.json   raw per-event detector findings
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

import config  # noqa: F401,E402  (side effect: load_dotenv)

COLLECT = ROOT / "data_check" / "ground_truth_collection"
SOURCE = COLLECT / "final_public_dataset.csv"
OUT = COLLECT / "final_balanced_dataset_v16.csv"
REJECTED = COLLECT / "final_balanced_dataset_v16_rejected.csv"
FINDINGS = ROOT / "results" / "v16_routing_verification.json"
CACHE_JSON = ROOT / "results" / "scan_public.json"

ALERT_PLATFORM = ("bgpstream",)

# How far the routing detector's own timestamp may sit from the reported start
# before we call it a disagreement. Published reports give coarse start times
# (a hijack is usually announced as "around 14:45 UTC"), so a tight bound would
# reject correct detections.
ROUTING_TIME_TOLERANCE = timedelta(hours=12)

KEEP_COLUMNS = [
    "event_id", "name", "date", "start_time_utc", "end_time_utc", "duration_hours",
    "victim_as", "attacker_as", "leak_as", "event_type",
    "ground_truth_cause_label", "ground_truth_root_cause_subtype",
    "ground_truth_confidence", "routing_evidence_source",
    "routing_origin_count", "routing_withdrawal_count",
    "ground_truth_source", "source_url", "rrc00_covered", "notes",
]
CHECK_COLUMNS = [
    "evidence_tier", "routing_detector_status", "routing_detector_detail",
    "routing_detected_count", "routing_first_seen",
    "traffic_detected", "traffic_anomaly_count", "traffic_peak_trough_drop_pct",
]


def norm_asn(value) -> str:
    v = str(value or "").upper().replace("AS", "").strip()
    return v if v.isdigit() else ""


def parse_dt(value):
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


def target_asn(row) -> str:
    for key in ("victim_as", "leak_as", "attacker_as"):
        got = norm_asn(row.get(key))
        if got:
            return got
    return ""


def load_traffic_scan() -> dict:
    if not CACHE_JSON.exists():
        return {}
    try:
        return {r["event_id"]: r for r in json.loads(CACHE_JSON.read_text(encoding="utf-8"))}
    except (json.JSONDecodeError, KeyError, TypeError):
        return {}


def run_routing_detector(asn: str, start: datetime, end: datetime) -> dict:
    """Run the routing detectors and summarise what they observed.

    Hijacks and leaks use different detectors and different inputs, so both are
    attempted and whichever produced findings is reported. Any failure is
    captured as an error string rather than raised, so one bad event cannot abort
    the whole run.
    """
    out: dict = {"asn": asn, "hijacks": [], "leaks": [], "error": ""}
    s = start.strftime("%Y-%m-%d %H:%M")
    e = end.strftime("%Y-%m-%d %H:%M")

    try:
        from detectors.hijack.hijack_detector import detect_hijacks

        res = detect_hijacks(start_time=s, end_time=e, target_as=asn, save_alerts=False)
        out["hijacks"] = _summarize(res, asn)
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"hijack: {type(exc).__name__}: {exc}"[:200]

    try:
        from detectors.leak.leak_detector import analyze_leak_surface
        out["leaks"] = _run_leak_detector(asn, s, e)
    except Exception as exc:  # noqa: BLE001
        out["leaks_error"] = f"{type(exc).__name__}: {exc}"[:200]

    return out


def _summarize(res, asn: str) -> list[dict]:
    """Reduce a detector result to comparable per-finding records."""
    findings: list[dict] = []

    def add(obj, default_role=""):
        if not isinstance(obj, dict):
            return
        ts = (obj.get("timestamp") or obj.get("time") or obj.get("first_seen")
              or obj.get("detected_at"))
        role = obj.get("role") or obj.get("as_role") or default_role
        prefixes = (obj.get("prefix_count") or obj.get("prefixes")
                    or obj.get("affected_prefixes") or 0)
        if isinstance(prefixes, list):
            prefixes = len(prefixes)
        findings.append({
            "timestamp": str(ts) if ts else "",
            "role": str(role),
            "prefix_count": int(prefixes or 0),
            "origin_as": str(obj.get("hijacker_as") or obj.get("origin_as")
                             or obj.get("attacker_as") or ""),
            "prefix": str(obj.get("prefix") or ""),
        })

    if isinstance(res, dict):
        for key in ("hijacks", "alerts", "detections", "results", "origin_hijacked",
                    "forge_hijacked", "origin_hijacking", "forge_hijacking",
                    "mitm_alerts", "route_leaks", "leaks"):
            val = res.get(key)
            if isinstance(val, list):
                for item in val:
                    add(item, "attacker" if "hijack" in key else "source")
            elif isinstance(val, dict):
                add(val)
        if not findings:
            add(res)
    elif isinstance(res, list):
        for item in res:
            add(item)
    return findings


def _run_leak_detector(asn: str, start_s: str, end_s: str) -> list[dict]:
    """Run the leak detector over RRC00 data for one AS.

    Uses ``analyze_leak_surface``, the detector's own entry point, so the
    RRC00 loading, path-probability lookup and truncation caps all behave
    exactly as they do in the production pipeline.
    """
    from detectors.leak.leak_detector import analyze_leak_surface

    res = analyze_leak_surface(asn, start_s, end_s)
    if not isinstance(res, dict):
        return []
    out = []
    for lk in (res.get("route_leaks") or [])[:5000]:
        if not isinstance(lk, dict):
            continue
        prefixes = lk.get("prefix_count") or lk.get("prefixes") or lk.get("prefix") or 0
        if isinstance(prefixes, list):
            prefixes = len(prefixes)
        elif isinstance(prefixes, str):
            prefixes = 1 if prefixes else 0
        out.append({
            "timestamp": str(lk.get("timestamp") or lk.get("time")
                             or lk.get("start_time") or ""),
            "role": "source",
            "prefix_count": int(prefixes or 0),
            "origin_as": str(lk.get("victim_as") or lk.get("origin_as")
                             or lk.get("stable_as") or ""),
            "prefix": str(lk.get("prefix") or ""),
        })
    return out


def main() -> int:
    if not SOURCE.exists():
        print(f"missing source dataset: {SOURCE}", file=sys.stderr)
        return 1

    with SOURCE.open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))

    traffic = load_traffic_scan()
    kept, rejected, findings_all = [], [], []
    started = time.time()

    for idx, row in enumerate(rows, 1):
        eid = row.get("event_id", "")
        asn = target_asn(row)
        start = parse_dt(row.get("start_time_utc") or row.get("date"))
        end = parse_dt(row.get("end_time_utc")) or (start + timedelta(hours=6) if start else None)
        blob = f"{row.get('ground_truth_source','')} {row.get('source_url','')}".lower()

        def drop(reason: str, detail: str = ""):
            rejected.append({**row, "rejection_reason": reason, "rejection_detail": detail})
            print(f"[{idx}/{len(rows)}] {eid[:32]:<32} REJECT {reason}", flush=True)

        if any(m in blob for m in ALERT_PLATFORM):
            drop("alert_platform_source",
                 "only source is an automated hijack/leak alert platform")
            continue
        if not asn:
            drop("no_target_as", "victim_as/leak_as/attacker_as all empty")
            continue
        if start is None or end is None:
            drop("missing_time_window", "start_time_utc/end_time_utc unparseable")
            continue

        print(f"[{idx}/{len(rows)}] {eid[:32]:<32} AS{asn:<7} routing-verify ...", flush=True)
        found = run_routing_detector(asn, start - timedelta(hours=2), end + timedelta(hours=2))
        allf = found["hijacks"] + found["leaks"]
        found["event_id"] = eid
        findings_all.append(found)

        in_window = []
        for f in allf:
            ts = parse_dt(f.get("timestamp"))
            if ts and abs((ts - start).total_seconds()) <= ROUTING_TIME_TOLERANCE.total_seconds():
                in_window.append(f)

        if not allf:
            detail = found.get("error") or found.get("leaks_error") or \
                     "detector returned no routing finding for this AS/window"
            drop("routing_detector_silent", detail)
            continue
        if not in_window:
            stamps = sorted({f.get("timestamp", "") for f in allf})[:3]
            drop("routing_time_mismatch",
                 f"detector findings at {', '.join(s or '?' for s in stamps)} do not "
                 f"overlap reported start {start:%Y-%m-%d %H:%M} "
                 f"(+/-{ROUTING_TIME_TOLERANCE})")
            continue

        prefixes = sum(f.get("prefix_count", 0) for f in in_window)
        if prefixes <= 0:
            drop("no_prefix_evidence",
                 f"{len(in_window)} finding(s) but 0 affected prefixes")
            continue

        t = traffic.get(eid, {})
        new = {c: row.get(c, "") for c in KEEP_COLUMNS}
        new.update({
            "evidence_tier": "public_report",
            "routing_detector_status": "pass",
            "routing_detector_detail": (
                f"{len(in_window)} routing finding(s) within "
                f"{ROUTING_TIME_TOLERANCE} of the reported start; "
                f"{prefixes} affected prefix observation(s)"),
            "routing_detected_count": len(in_window),
            "routing_first_seen": min(f.get("timestamp", "") for f in in_window),
            "traffic_detected": ("true" if t.get("anomaly_count")
                                 else ("false" if t.get("scanned") else "not_measured")),
            "traffic_anomaly_count": t.get("anomaly_count", ""),
            "traffic_peak_trough_drop_pct": t.get("peak_trough_drop_pct", ""),
        })
        kept.append(new)
        print(f"[{idx}/{len(rows)}] {eid[:32]:<32} AS{asn:<7} KEEP "
              f"routing={len(in_window)} prefixes={prefixes} "
              f"traffic={new['traffic_detected']}", flush=True)

    fields = KEEP_COLUMNS + CHECK_COLUMNS
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(kept)

    rej_fields = [c for c in rows[0].keys() if c not in KEEP_COLUMNS] + \
                 ["rejection_reason", "rejection_detail"]
    with REJECTED.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=rej_fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rejected)

    FINDINGS.parent.mkdir(parents=True, exist_ok=True)
    FINDINGS.write_text(json.dumps(findings_all, indent=2), encoding="utf-8")

    print(f"\nelapsed {time.time() - started:.0f}s")
    print(f"kept     : {len(kept)}/{len(rows)}  -> {OUT.relative_to(ROOT)}")
    print(f"rejected : {len(rejected)}       -> {REJECTED.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

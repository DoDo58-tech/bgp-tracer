#!/usr/bin/env python3
"""Re-compute `bgpt_actionable` based on the current verdict taxonomy.

Reads `per_alert_verdict.jsonl`, recomputes `bgpt_actionable` per alert using
the canonical NON_ACTION set, and rewrites `dangerous_alerts.csv`,
`skipped_alerts.csv`, `per_event_full.csv`, and `run_summary.json`.

This is used after a partial BGP Tracer run when we want to align the
"dangerous" filter with the paper's definition without re-running analysis.

Usage:
    python3 finalize_cf_alerts.py [--in-dir results/cloudflare_alerts]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IN_DIR = PROJECT_ROOT / "results" / "cloudflare_alerts"

NON_ACTION = {
    "normal", "unknown", "independent_coincidence",
    "traffic_anomaly_only", "silent_alert", "routing_only",
    "no_radar_data", "correlation_uncertain",
    "traffic_only", "no_clear_anomaly",
    "", None,
}

CSV_FIELDS = [
    "alert_id", "source", "asn", "asns",
    "start_time", "end_time",
    "severity_alert", "description",
    "linked_url", "quick_verdict", "quick_success",
    "traffic_anomaly_count", "routing_hijack_count", "routing_leak_count",
    "outage_score", "correlation_level", "traffic_signal_present",
    "elapsed_s", "status", "bgpt_actionable",
    "raw_leak_count", "raw_hijack_count",
]


def load_records(jsonl: Path) -> list:
    out = []
    if not jsonl.exists():
        return out
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def is_actionable(verdict) -> bool:
    if verdict is None or verdict == "":
        return False
    return verdict not in NON_ACTION


def classify(records: list) -> tuple:
    """Return (dangerous_rows, skipped_rows, action_count, real_count)."""
    dangerous = []
    skipped = []
    action = 0
    real = 0
    for r in records:
        verdict = r.get("quick_verdict")
        if verdict == "unknown" and r.get("status") in ("timeout", "subprocess_error", "error", "executor_error"):
            r["bgpt_actionable"] = False
            skipped.append(r)
            continue
        # Recompute bgpt_actionable based on the verdict
        r["bgpt_actionable"] = is_actionable(verdict)
        if is_actionable(verdict):
            action += 1
            if verdict not in NON_ACTION and verdict != "normal":
                real += 1
            dangerous.append(r)
        else:
            skipped.append(r)
    return dangerous, skipped, action, real


def write_csv(path: Path, rows: list, fields: list) -> int:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})
    return len(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in-dir", default=str(DEFAULT_IN_DIR))
    args = ap.parse_args()

    in_dir = Path(args.in_dir)
    jsonl = in_dir / "per_alert_verdict.jsonl"

    records = load_records(jsonl)
    if not records:
        print(f"ERROR: no records in {jsonl}", file=sys.stderr)
        return 1
    print(f"loaded {len(records)} records from {jsonl}")

    dangerous, skipped, action, real = classify(records)

    # Re-write the JSONL with corrected bgpt_actionable
    jsonl.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False, default=str) for r in records) + "\n",
        encoding="utf-8",
    )

    nd = write_csv(in_dir / "dangerous_alerts.csv", dangerous, CSV_FIELDS.copy())
    ns = write_csv(in_dir / "skipped_alerts.csv",   skipped,    CSV_FIELDS.copy())
    nf = write_csv(in_dir / "per_event_full.csv",   records,    CSV_FIELDS.copy())
    print(f"wrote: dangerous_alerts.csv ({nd} rows)")
    print(f"wrote: skipped_alerts.csv   ({ns} rows)")
    print(f"wrote: per_event_full.csv   ({nf} rows)")

    by_status, by_verdict, by_source = {}, {}, {}
    for r in records:
        s = r.get("status", "unknown")
        v = r.get("quick_verdict") or "unknown"
        src = r.get("source", "unknown")
        by_status[s] = by_status.get(s, 0) + 1
        by_verdict[v] = by_verdict.get(v, 0) + 1
        by_source[src] = by_source.get(src, 0) + 1

    summary = {
        "raw_alerts_total": len(records),
        "by_status": by_status,
        "by_verdict": by_verdict,
        "by_source_processed": by_source,
        "bgpt_actionable": action,
        "bgpt_real_incident": real,
        "reduction_to_actionable_pct": round(100 * action / max(len(records), 1), 2),
        "reduction_to_real_incident_pct": round(100 * real / max(len(records), 1), 2),
    }
    (in_dir / "run_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote: run_summary.json")

    print("\n" + "=" * 60)
    print("BGP TRACER ON CLOUDFLARE RADAR ALERT FEED")
    print("=" * 60)
    print(f"Total processed:       {len(records)}")
    for src in ["annotation", "hijack", "leak"]:
        cnt = by_source.get(src, 0)
        print(f"  {src:12} raw = {cnt}")
    print(f"\nActionable:            {action} ({summary['reduction_to_actionable_pct']}%)")
    print(f"Real incidents:        {real} ({summary['reduction_to_real_incident_pct']}%)")
    print(f"\nReduction ratio (actionable):   {len(records)/max(action,1):.1f}:1")
    print(f"Reduction ratio (real_incident): {len(records)/max(real,1):.1f}:1")
    return 0


if __name__ == "__main__":
    sys.exit(main())

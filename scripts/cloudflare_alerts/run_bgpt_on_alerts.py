#!/usr/bin/env python3
"""Run BGP Tracer on the Cloudflare alert feed and aggregate verdicts.

Pipeline:

  raw_alerts.json                       (from fetch_cloudflare_alerts.py)
        │
        ▼
  per-alert (asn, start, end) tuples   ◀── 这里决定要跑 BGP Tracer 的输入
        │
        ▼
  chief_agent.analyze_quick(...)        (per-alert, subprocess-isolated)
        │
        ▼
  per_alert_verdict.jsonl              (one record per alert: verdict, traffic,
                                         routing, correlation, ...)
        │
        ▼
  dangerous_alerts.csv                 (alerts BGP Tracer kept as "real incident")

Each alert is run in its own subprocess so that crashes (e.g. from pybgpstream
or bgpdump) cannot corrupt the shared process pool. A hard timeout kills
unresponsive workers.

Output structure:

    results/cloudflare_alerts/
        ├── raw/                          (input from fetch script)
        ├── per_alert_verdict.jsonl       (one line per alert)
        ├── dangerous_alerts.csv          (verdict = real_incident)
        ├── skipped_alerts.csv            (no ASN, no usable window, etc.)
        └── run_summary.json             (run statistics)
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=os.environ.get("BGPT_LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("bgpt_cf_alerts")

DEFAULT_RAW_DIR = PROJECT_ROOT / "results" / "cloudflare_alerts" / "raw"
DEFAULT_OUT_DIR = PROJECT_ROOT / "results" / "cloudflare_alerts"
DEFAULT_WINDOW_BEFORE_S = 60 * 60        # 1 hour before
DEFAULT_WINDOW_AFTER_S = 60 * 60        # 1 hour after
MAX_WINDOW_HOURS = 6

# Verdicts that BGP Tracer explicitly marks as "no real incident" — these do
# NOT count as actionable alerts because they are explicitly marked as silent
# / negative-control outputs by the chief_agent.
NON_ACTION = {
    # Verdicts that explicitly mark the alert as NOT a real incident
    "normal", "unknown", "independent_coincidence",
    "traffic_anomaly_only", "silent_alert", "routing_only",
    # "no_radar_data" — traffic agent had insufficient data for the window
    "no_radar_data",
    # "correlation_uncertain" — detected signal but couldn't confirm causality
    "correlation_uncertain",
    # BGP Tracer names for these categories
    "traffic_only", "no_clear_anomaly",
    "", None,
}


# ── Time window utilities ───────────────────────────────────────────────
def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip().rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def make_window(
    start_iso: Optional[str],
    end_iso: Optional[str],
    *,
    before_s: int = DEFAULT_WINDOW_BEFORE_S,
    after_s: int = DEFAULT_WINDOW_AFTER_S,
    max_hours: int = MAX_WINDOW_HOURS,
) -> Optional[Tuple[str, str]]:
    """Return ("YYYY-MM-DD HH:MM", "YYYY-MM-DD HH:MM") suitable for analyze_quick."""
    from datetime import timedelta as _td
    start_dt = _parse_iso(start_iso)
    end_dt = _parse_iso(end_iso)
    if start_dt and end_dt:
        anchor = start_dt + (end_dt - start_dt) / 2
    elif start_dt:
        anchor = start_dt
    elif end_dt:
        anchor = end_dt
    else:
        return None

    s = anchor - _td(seconds=before_s)
    e = anchor + _td(seconds=after_s)
    total_s = (e - s).total_seconds()
    if total_s > max_hours * 3600:
        half = max_hours * 3600 / 2
        s = anchor - _td(seconds=half)
        e = anchor + _td(seconds=half)

    # Cap window end to "now" (UTC) to avoid HTTP 400 from Cloudflare Radar API
    now_utc = datetime.now(timezone.utc)
    if e > now_utc:
        delta = e - now_utc
        e = now_utc
        s = s - delta
        min_start = anchor - _td(seconds=max_hours * 3600)
        if s < min_start:
            s = min_start

    return (
        s.strftime("%Y-%m-%d %H:%M"),
        e.strftime("%Y-%m-%d %H:%M"),
    )


# ── Alert normalization ────────────────────────────────────────────────
def alert_to_bgpl_payload(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert a normalized alert dict to the BGP Tracer input format.

    Returns None if the alert cannot be processed (no ASN, no time window, etc.)
    """
    asn = alert.get("asn")
    if not asn:
        return None

    # Try to get the event time from the alert
    start_iso = alert.get("start_time")
    end_iso = alert.get("end_time")

    window = make_window(start_iso, end_iso)
    if window is None:
        return None

    start, end = window

    source = alert.get("source", "unknown")
    alert_id = alert.get("alert_id", f"{source}:unknown")

    # Build a descriptive string for BGP Tracer
    desc = alert.get("description", "")
    description = f"Cloudflare {source} alert {alert_id}"
    if desc:
        description += f": {desc[:200]}"

    return {
        "event_id": alert_id,
        "asn": str(asn),
        "start": start,
        "end": end,
        "user_input": description,
        "source": source,
        "alert_id": alert_id,
    }


# ── Subprocess driver for a single alert ──────────────────────────────
_WORKER_TEMPLATE = '''
import sys, json, time, traceback
sys.path.insert(0, {project_root!r})

from chief_agent import analyze_quick

alert_path = {alert_path!r}
timeout_s = {timeout_s!r}

alert = json.loads(open(alert_path).read())
rec = {{
    "alert_id": alert.get("alert_id"),
    "asn": alert.get("asn"),
    "source": alert.get("source"),
}}

try:
    result = analyze_quick(
        asn=alert["asn"],
        start_time=alert["start_time"],
        end_time=alert["end_time"],
        user_input=alert.get("description", "")[:200],
        enable_mitm=False,
        event_id=alert.get("alert_id"),
    )
    rec["elapsed_s"] = round(result.get("elapsed_seconds", 0), 2)
    rec["quick_success"] = bool(result.get("success"))
    rec["quick_verdict"] = result.get("quick_verdict", "unknown")
    rec["warnings"] = result.get("warnings", [])
    summary = result.get("anomaly_summary", {{}}) or {{}}
    rec["traffic_anomaly_count"] = summary.get("traffic_anomaly_count", 0)
    rec["routing_hijack_count"] = summary.get("routing_hijack_count", 0)
    rec["routing_leak_count"] = summary.get("routing_leak_count", 0)
    rec["outage_score"] = summary.get("outage_score", 0.0)
    rec["correlation_level"] = summary.get("correlation_level", "none")
    rec["traffic_signal_present"] = result.get("traffic_signal_present", False)
    rec["status"] = "ok"
    verdict = rec.get("quick_verdict")
    rec["bgpt_actionable"] = verdict not in {non_action!r}
except Exception as e:
    rec["status"] = "error"
    rec["error"] = f"{{type(e).__name__}}: {{e}}"
    rec["elapsed_s"] = 0
    rec["quick_success"] = False
    rec["quick_verdict"] = None
    rec["bgpt_actionable"] = False

print(json.dumps(rec, ensure_ascii=False, default=str))
'''


def run_one_subprocess(alert: Dict[str, Any], timeout_s: int) -> Dict[str, Any]:
    """Run one alert through BGP Tracer in a fresh subprocess.

    Each alert runs in its own process with a hard timeout. This prevents any
    single crash from affecting other alerts or the main process.
    """
    tmp_input = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    try:
        tmp_input.write(json.dumps(alert, default=str))
        tmp_input.close()

        cmd = [
            sys.executable, "-c",
            _WORKER_TEMPLATE.format(
                project_root=str(PROJECT_ROOT),
                alert_path=tmp_input.name,
                timeout_s=timeout_s,
                non_action=list(NON_ACTION),
            ),
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 60,  # outer timeout is slightly longer
        )

        if proc.returncode == 0 and proc.stdout.strip():
            try:
                return json.loads(proc.stdout.strip())
            except json.JSONDecodeError:
                return {
                    "alert_id": alert.get("alert_id"),
                    "status": "json_decode_error",
                    "error": f"stdout={proc.stdout[:200]}",
                    "asn": alert.get("asn"),
                    "source": alert.get("source"),
                    "bgpt_actionable": False,
                }
        else:
            return {
                "alert_id": alert.get("alert_id"),
                "status": "subprocess_error",
                "error": f"exit={proc.returncode}, stderr={proc.stderr[:500]}",
                "asn": alert.get("asn"),
                "source": alert.get("source"),
                "bgpt_actionable": False,
            }
    except subprocess.TimeoutExpired:
        return {
            "alert_id": alert.get("alert_id"),
            "status": "timeout",
            "error": f"timeout after {timeout_s}s",
            "asn": alert.get("asn"),
            "source": alert.get("source"),
            "bgpt_actionable": False,
        }
    finally:
        os.unlink(tmp_input.name)


# ── CLI ─────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--raw-dir", default=str(DEFAULT_RAW_DIR),
                    help="Directory containing raw_alerts.json")
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR),
                    help="Directory for per_alert_verdict.jsonl etc.")
    ap.add_argument("--workers", type=int, default=4,
                    help="Number of parallel subprocess workers (default 4)")
    ap.add_argument("--timeout-s", type=int, default=300,
                    help="Timeout per alert in seconds (default 300 = 5 min)")
    ap.add_argument("--limit", type=int, default=0,
                    help="If >0, only process this many alerts (for testing)")
    ap.add_argument("--offset", type=int, default=0,
                    help="Skip this many alerts before processing")
    ap.add_argument("--sources-filter", default="annotation,leak,hijack",
                    help="Comma-separated alert sources to process")
    ap.add_argument("--shuffle", action="store_true",
                    help="Randomize alert order before processing")
    ap.add_argument("--resume", action="store_true", default=True,
                    help="Skip alerts already in per_alert_verdict.jsonl")
    ap.add_argument("--no-resume", dest="resume", action="store_false")
    return ap.parse_args()


# ── Main ─────────────────────────────────────────────────────────────────
def main() -> int:
    args = parse_args()
    raw_dir = Path(args.raw_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_alerts_path = raw_dir / "raw_alerts.json"
    if not raw_alerts_path.exists():
        log.error("raw_alerts.json not found at %s", raw_alerts_path)
        return 1

    all_alerts = json.loads(raw_alerts_path.read_text(encoding="utf-8"))
    log.info("loaded %d raw alerts from %s", len(all_alerts), raw_alerts_path)

    # Filter by source
    sources = {s.strip() for s in args.sources_filter.split(",") if s.strip()}
    alerts = [a for a in all_alerts if a.get("source", "") in sources]
    log.info("after source filter (%s): %d alerts", sources, len(alerts))

    # Shuffle
    if args.shuffle:
        import random
        random.seed(42)
        random.shuffle(alerts)

    # Skip / limit
    todo = alerts[args.offset:]
    if args.limit > 0:
        todo = todo[:args.limit]
    log.info("processing %d alerts (offset=%d, limit=%d)", len(todo), args.offset, args.limit)

    # Resume: skip already-processed alerts
    out_jsonl = out_dir / "per_alert_verdict.jsonl"
    done_ids: set[str] = set()
    if args.resume and out_jsonl.exists():
        for line in out_jsonl.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    done_ids.add(json.loads(line).get("alert_id", ""))
                except Exception:
                    pass
        skipped = sum(1 for a in todo if a.get("alert_id", "") in done_ids)
        todo = [a for a in todo if a.get("alert_id", "") not in done_ids]
        log.info("resume: skipped %d already-done alerts, %d remain", skipped, len(todo))

    if not todo:
        log.info("nothing to do — writing summary")
    else:
        completed = 0
        t_start = time.monotonic()
        records: List[Dict[str, Any]] = []
        records_lock = threading.Lock()

        def _process_one(i: int, alert: Dict[str, Any]) -> Dict[str, Any]:
            alert_id = alert.get("alert_id", f"unknown:{i}")
            log.info("--- alert %d/%d: %s (AS%s) starting ---",
                     i + 1, len(todo), alert_id, alert.get("asn", "?"))

            payload = alert_to_bgpl_payload(alert)
            if payload is None:
                rec = {
                    "alert_id": alert_id,
                    "asn": alert.get("asn"),
                    "source": alert.get("source"),
                    "status": "skipped_no_asn_or_window",
                    "bgpt_actionable": False,
                }
            else:
                run_alert = {**alert, **payload}
                rec = run_one_subprocess(run_alert, args.timeout_s)

            log.info("--- alert %d/%d: %s status=%s verdict=%s elapsed=%ss ---",
                     i + 1, len(todo), alert_id, rec.get("status"),
                     rec.get("quick_verdict"), rec.get("elapsed_s"))

            with records_lock:
                records.append(rec)
            with out_jsonl.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            return rec

        # Run alerts in parallel using ThreadPoolExecutor + subprocess.run
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.workers) as ex:
            futures = [ex.submit(_process_one, i, a) for i, a in enumerate(todo)]
            for fut in concurrent.futures.as_completed(futures):
                rec = fut.result()
                completed += 1
                if completed % 10 == 0 or completed == len(todo):
                    elapsed = time.monotonic() - t_start
                    rate = completed / max(elapsed, 1)
                    eta = (len(todo) - completed) / max(rate, 0.001)
                    log.info("progress %d/%d (%.2f/s, ETA %.0fs)",
                             completed, len(todo), rate, eta)

        log.info("done: %d records (elapsed %.1fs)", len(records),
                 time.monotonic() - t_start)

    # ── write summary ─────────────────────────────────────────────────────
    log.info("writing summary outputs")
    all_records = []
    for line in out_jsonl.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                all_records.append(json.loads(line))
            except Exception:
                pass

    by_status: Dict[str, int] = {}
    by_verdict: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    actionable = 0
    real_incident = 0
    dangerous_rows: List[Dict[str, Any]] = []
    skipped_rows: List[Dict[str, Any]] = []

    for r in all_records:
        by_status[r.get("status", "unknown")] = by_status.get(r.get("status", "unknown"), 0) + 1
        v = r.get("quick_verdict") or "unknown"
        by_verdict[v] = by_verdict.get(v, 0) + 1
        src = r.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1

        if r.get("bgpt_actionable"):
            actionable += 1
            v = r.get("quick_verdict", "")
            if v and v not in NON_ACTION and v != "normal":
                real_incident += 1
                dangerous_rows.append(r)
        else:
            skipped_rows.append(r)

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "raw_alerts_total": len(all_alerts),
        "processed_total": len(all_records),
        "by_status": by_status,
        "by_verdict": by_verdict,
        "by_source": by_source,
        "bgpt_actionable": actionable,
        "bgpt_real_incident": real_incident,
        "reduction_to_actionable_pct": round(100 * actionable / max(len(all_records), 1), 2),
        "reduction_to_real_incident_pct": round(100 * real_incident / max(len(all_records), 1), 2),
    }
    (out_dir / "run_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("summary: %s", summary)

    # Write CSVs
    fieldnames = ["alert_id", "source", "asn", "start_time", "end_time",
                  "quick_verdict", "quick_success", "traffic_anomaly_count",
                  "routing_hijack_count", "routing_leak_count",
                  "outage_score", "correlation_level", "traffic_signal_present",
                  "elapsed_s", "status", "bgpt_actionable", "description"]

    def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)

    write_csv(out_dir / "dangerous_alerts.csv", dangerous_rows)
    write_csv(out_dir / "skipped_alerts.csv", skipped_rows)

    # per-event full CSV (all records)
    write_csv(out_dir / "per_event_full.csv", all_records)

    log.info("outputs written to %s/", out_dir)
    log.info("  dangerous_alerts.csv: %d rows", len(dangerous_rows))
    log.info("  skipped_alerts.csv: %d rows", len(skipped_rows))
    log.info("  reduction: actionable=%d/%d (%.1f%%), real_incident=%d/%.1f%%)",
             actionable, len(all_records), summary["reduction_to_actionable_pct"],
             real_incident, summary["reduction_to_real_incident_pct"])

    return 0


if __name__ == "__main__":
    sys.exit(main())

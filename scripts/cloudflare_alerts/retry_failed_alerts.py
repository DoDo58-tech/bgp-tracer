#!/usr/bin/env python3
"""
Retry BGP Tracer on previously failed Cloudflare alerts.
Fixes:
  1. Increases subprocess timeout from 300s → 600s (hijacks have very large msg_counts)
  2. Increases memory limit (resource.setrlimit) to prevent SIGKILL/SIGABRT
  3. Adds retry logic: 3 attempts with exponential backoff
  4. Writes updated results to per_alert_verdict.jsonl (appends new records)

Usage:
  python3 scripts/cloudflare_alerts/retry_failed_alerts.py [--timeout-s 600]
"""
from __future__ import annotations

import concurrent.futures
import csv
import json
import os
import resource
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

# Load env for chief_agent
from dotenv import dotenv_values
_ = dotenv_values(PROJECT_ROOT / ".env")

OUT_DIR = PROJECT_ROOT / "results" / "cloudflare_alerts"
JSONL_PATH = OUT_DIR / "per_alert_verdict.jsonl"

TIMEOUT_S = 600   # 10 minutes — hijacks can be very slow
MAX_RETRIES = 3

NON_ACTION = {
    "normal", "unknown", "independent_coincidence",
    "traffic_anomaly_only", "silent_alert", "routing_only",
    "no_radar_data", "correlation_uncertain",
    "traffic_only", "no_clear_anomaly",
    "", None,
}

_WORKER_TEMPLATE = r'''
import resource, sys, json, time, traceback
# Increase memory limit to 12 GB (was causing SIGKILL at default)
try:
    resource.setrlimit(resource.RLIMIT_AS, (12 * 1024**3, resource.RLIM_INFINITY))
except Exception:
    pass

sys.path.insert(0, {project_root!r})
from chief_agent import analyze_quick

alert = json.loads(open({alert_path!r}).read())

# Build alert dict for BGP Tracer
start_iso = alert.get("start_time", "")
end_iso = alert.get("end_time", "")
asn = alert.get("asn", "")
event_id = alert.get("alert_id", "unknown")

try:
    result = analyze_quick(
        asn=asn,
        start_time=start_iso,
        end_time=end_iso,
        user_input=alert.get("description", "")[:200],
        enable_mitm=False,
        event_id=event_id,
    )
    elapsed = round(result.get("elapsed_seconds", 0), 2)
    success = bool(result.get("success"))
    verdict = result.get("quick_verdict", "unknown")
    summary = result.get("anomaly_summary", {{}}) or {{}}
    rec = {{
        "alert_id": alert.get("alert_id"),
        "asn": asn,
        "source": alert.get("source"),
        "elapsed_s": elapsed,
        "quick_success": success,
        "quick_verdict": verdict,
        "warnings": result.get("warnings", []),
        "traffic_anomaly_count": summary.get("traffic_anomaly_count", 0),
        "routing_hijack_count": summary.get("routing_hijack_count", 0),
        "routing_leak_count": summary.get("routing_leak_count", 0),
        "outage_score": summary.get("outage_score", 0.0),
        "correlation_level": summary.get("correlation_level", "none"),
        "traffic_signal_present": result.get("traffic_signal_present", False),
        "status": "ok",
        "retry": {retry!r},
    }}
except Exception as e:
    rec = {{
        "alert_id": alert.get("alert_id"),
        "asn": asn,
        "source": alert.get("source"),
        "status": "error",
        "error": f"{{type(e).__name__}}: {{e}}",
        "elapsed_s": 0,
        "quick_success": False,
        "quick_verdict": None,
        "retry": {retry!r},
    }}

rec["bgpt_actionable"] = rec.get("quick_verdict") not in {non_action!r}
print(json.dumps(rec, ensure_ascii=False, default=str))
'''


def run_one(alert: dict, timeout_s: int, retry: int) -> dict:
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    try:
        tmp.write(json.dumps(alert, default=str))
        tmp.close()

        cmd = [
            sys.executable, "-c",
            _WORKER_TEMPLATE.format(
                project_root=str(PROJECT_ROOT),
                alert_path=tmp.name,
                non_action=list(NON_ACTION),
                retry=retry,
            )
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 120,
        )

        if proc.returncode == 0 and proc.stdout.strip():
            try:
                return json.loads(proc.stdout.strip())
            except json.JSONDecodeError:
                return {
                    "alert_id": alert.get("alert_id"),
                    "status": "json_error",
                    "error": f"stdout={proc.stdout[:200]}",
                    "asn": alert.get("asn"),
                    "source": alert.get("source"),
                    "bgpt_actionable": False,
                    "retry": retry,
                }
        else:
            return {
                "alert_id": alert.get("alert_id"),
                "status": "subprocess_error",
                "error": f"exit={proc.returncode}, stderr={proc.stderr[:300]}",
                "asn": alert.get("asn"),
                "source": alert.get("source"),
                "bgpt_actionable": False,
                "retry": retry,
            }
    except subprocess.TimeoutExpired:
        return {
            "alert_id": alert.get("alert_id"),
            "status": "timeout",
            "error": f"timeout after {timeout_s}s",
            "asn": alert.get("asn"),
            "source": alert.get("source"),
            "bgpt_actionable": False,
            "retry": retry,
        }
    finally:
        os.unlink(tmp.name)


def load_failed_alerts() -> list[dict]:
    """Load the 46 failed alerts from per_alert_verdict.jsonl."""
    done_ids = set()
    records = []
    if JSONL_PATH.exists():
        for line in JSONL_PATH.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                records.append(r)
                done_ids.add(r.get("alert_id", ""))
            except Exception:
                pass

    # Return only the 46 failed alerts
    failed = [r for r in records if r.get("status") in ("timeout", "subprocess_error")]
    print(f"Found {len(failed)} previously failed alerts")
    return failed


def get_raw_alert(alert_id: str) -> dict | None:
    """Look up the raw alert from raw_alerts.json."""
    raw_path = OUT_DIR / "raw" / "raw_alerts.json"
    if not raw_path.exists():
        return None
    try:
        alerts = json.loads(raw_path.read_text())
        for a in alerts:
            if a.get("alert_id") == alert_id:
                return a
    except Exception:
        pass
    return None


def main():
    failed = load_failed_alerts()
    if not failed:
        print("No failed alerts to retry.")
        return 0

    print(f"Retrying {len(failed)} alerts with timeout={TIMEOUT_S}s, max_retries={MAX_RETRIES}")

    results_lock = threading.Lock()
    new_records = []
    final_records = []

    def process(alert_id: str, attempt: int):
        raw = get_raw_alert(alert_id)
        if not raw:
            print(f"  {alert_id}: raw alert not found — skipping")
            return

        # Build full alert dict
        alert_full = raw.copy()

        for retry in range(MAX_RETRIES):
            wait = 2 ** retry
            if retry > 0:
                print(f"  {alert_id}: retry {retry+1}/{MAX_RETRIES} (wait {wait}s)...")
                time.sleep(wait)

            rec = run_one(alert_full, TIMEOUT_S, retry)
            if rec.get("status") == "ok":
                print(f"  {alert_id}: SUCCESS after retry {retry+1} "
                      f"(elapsed={rec.get('elapsed_s')}s, verdict={rec.get('quick_verdict')})")
                break
            elif retry < MAX_RETRIES - 1:
                print(f"  {alert_id}: attempt {retry+1} failed ({rec.get('status')}) — retrying...")

        with results_lock:
            new_records.append(rec)
            # Append/update in jsonl
            with JSONL_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        return rec

    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(process, a.get("alert_id", ""), 0): a for a in failed}
        for i, fut in enumerate(concurrent.futures.as_completed(futures)):
            r = fut.result()
            final_records.append(r)
            elapsed = time.monotonic() - t0
            rate = (i+1) / max(elapsed, 1)
            print(f"  progress {i+1}/{len(failed)} ({rate:.2f}/s)")

    # Summary
    by_status = Counter(r.get("status") for r in final_records)
    ok_count = sum(1 for r in final_records if r.get("status") == "ok")
    print()
    print(f"Retry summary: {ok_count}/{len(failed)} recovered ({by_status})")
    print(f"Elapsed: {time.monotonic()-t0:.0f}s")

    # Write updated CSVs
    all_records = {}
    if JSONL_PATH.exists():
        for line in JSONL_PATH.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    r = json.loads(line)
                    all_records[r.get("alert_id", "")] = r
                except Exception:
                    pass

    records_list = list(all_records.values())

    fieldnames = ["alert_id", "source", "asn", "start_time", "end_time",
                  "quick_verdict", "quick_success", "traffic_anomaly_count",
                  "routing_hijack_count", "routing_leak_count",
                  "outage_score", "correlation_level", "traffic_signal_present",
                  "elapsed_s", "status", "bgpt_actionable", "description"]

    def write_csv(path, rows):
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)

    dangerous = [r for r in records_list
                 if r.get("bgpt_actionable") and r.get("quick_verdict") not in NON_ACTION
                 and r.get("quick_verdict") not in ("normal", "traffic_only", "no_clear_anomaly")]
    skipped = [r for r in records_list
               if not r.get("bgpt_actionable")]

    write_csv(OUT_DIR / "dangerous_alerts.csv", dangerous)
    write_csv(OUT_DIR / "skipped_alerts.csv", skipped)
    write_csv(OUT_DIR / "per_event_full.csv", records_list)

    print(f"Dangerous alerts: {len(dangerous)}")
    print(f"Skipped alerts: {len(skipped)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

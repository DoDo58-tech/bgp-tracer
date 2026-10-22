#!/usr/bin/env python3
"""
Full pipeline for Cloudflare alerts:
  1. Remove previously-failed records from per_alert_verdict.jsonl
  2. Add new high-confidence leak alerts (leak_count >= 10,000) to raw_alerts.json
  3. Run BGP Tracer on all unresolved alerts (failed + new leaks)
  4. Output summary

Usage:
  python3 scripts/cloudflare_alerts/full_pipeline.py 2>&1 | tee /data/bgp_tracer/results/cloudflare_alerts/pipeline.log
"""
import concurrent.futures
import csv
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

OUT_DIR = PROJECT_ROOT / "results" / "cloudflare_alerts"
RAW_DIR = OUT_DIR / "raw"
JSONL_PATH = OUT_DIR / "per_alert_verdict.jsonl"

TIMEOUT_S = 900   # 15 minutes per alert (leaks can be large)
MAX_WORKERS = 3   # be gentle on resources

NON_ACTION = {
    "normal", "unknown", "independent_coincidence",
    "traffic_anomaly_only", "silent_alert", "routing_only",
    "no_radar_data", "correlation_uncertain",
    "traffic_only", "no_clear_anomaly", "", None,
}

_WORKER_TEMPLATE = r'''
import resource, sys, json, traceback
try:
    resource.setrlimit(resource.RLIMIT_AS, (12 * 1024**3, resource.RLIM_INFINITY))
except Exception:
    pass

sys.path.insert(0, {project_root!r})
from chief_agent import analyze_quick

alert = json.loads(open({alert_path!r}).read())

try:
    result = analyze_quick(
        asn=alert.get("asn", ""),
        start_time=alert.get("start_time", ""),
        end_time=alert.get("end_time", ""),
        user_input=alert.get("description", "")[:300],
        enable_mitm=False,
        event_id=alert.get("alert_id", "unknown"),
    )
    elapsed = round(result.get("elapsed_seconds", 0), 2)
    verdict = result.get("quick_verdict", "unknown")
    summary = result.get("anomaly_summary", {{}}) or {{}}
    rec = {{
        "alert_id": alert.get("alert_id"),
        "asn": alert.get("asn", ""),
        "source": alert.get("source", ""),
        "elapsed_s": elapsed,
        "quick_success": bool(result.get("success")),
        "quick_verdict": verdict,
        "warnings": result.get("warnings", []),
        "traffic_anomaly_count": summary.get("traffic_anomaly_count", 0),
        "routing_hijack_count": summary.get("routing_hijack_count", 0),
        "routing_leak_count": summary.get("routing_leak_count", 0),
        "outage_score": summary.get("outage_score", 0.0),
        "correlation_level": summary.get("correlation_level", "none"),
        "traffic_signal_present": result.get("traffic_signal_present", False),
        "status": "ok",
    }}
except Exception as e:
    rec = {{
        "alert_id": alert.get("alert_id"),
        "asn": alert.get("asn", ""),
        "source": alert.get("source", ""),
        "status": "error",
        "error": f"{{type(e).__name__}}: {{e}}",
        "elapsed_s": 0,
        "quick_success": False,
        "quick_verdict": None,
    }}

v = rec.get("quick_verdict")
rec["bgpt_actionable"] = v not in {non_action!r}
print(json.dumps(rec, ensure_ascii=False, default=str))
'''


def run_one_subprocess(alert: dict, timeout_s: int) -> dict:
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    try:
        tmp.write(json.dumps(alert, default=str))
        tmp.close()
        cmd = [sys.executable, "-c",
               _WORKER_TEMPLATE.format(
                   project_root=str(PROJECT_ROOT),
                   alert_path=tmp.name,
                   non_action=list(NON_ACTION),
               )]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 120)
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                return json.loads(proc.stdout.strip())
            except json.JSONDecodeError:
                return {"alert_id": alert.get("alert_id"), "status": "json_error",
                        "error": proc.stdout[:200], "asn": alert.get("asn", ""),
                        "source": alert.get("source", ""), "bgpt_actionable": False}
        else:
            return {"alert_id": alert.get("alert_id"), "status": "subprocess_error",
                    "error": f"exit={proc.returncode}, stderr={proc.stderr[:300]}",
                    "asn": alert.get("asn", ""), "source": alert.get("source", ""),
                    "bgpt_actionable": False}
    except subprocess.TimeoutExpired:
        return {"alert_id": alert.get("alert_id"), "status": "timeout",
                "error": f"timeout after {timeout_s}s", "asn": alert.get("asn", ""),
                "source": alert.get("source", ""), "bgpt_actionable": False}
    finally:
        os.unlink(tmp.name)


def step1_remove_failed():
    """Remove failed records from jsonl so they can be retried."""
    print("\n=== Step 1: Remove failed records from jsonl ===")
    if not JSONL_PATH.exists():
        print("  No jsonl found, skipping.")
        return

    records = {}
    for line in JSONL_PATH.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            records[r.get("alert_id", "")] = r
        except Exception:
            pass

    failed_ids = [aid for aid, r in records.items() if r.get("status") in ("timeout", "subprocess_error")]
    # Keep only non-failed
    good = {aid: r for aid, r in records.items() if r.get("status") not in ("timeout", "subprocess_error")}
    # Rewrite jsonl with only good records
    with JSONL_PATH.open("w", encoding="utf-8") as f:
        for r in good.values():
            f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")

    print(f"  Removed {len(failed_ids)} failed records, kept {len(good)} good ones")
    print(f"  Failed IDs: {failed_ids}")
    return failed_ids


def step2_add_new_leaks():
    """Add new high-confidence leak alerts to raw_alerts.json."""
    print("\n=== Step 2: Add high-confidence leak alerts ===")
    raw_path = RAW_DIR / "raw_alerts.json"
    leak_raw_path = RAW_DIR / "raw_leaks.json"

    raw_alerts = json.loads(raw_path.read_text())
    leak_raw = json.loads(leak_raw_path.read_text())

    existing_ids = {r.get("alert_id") for r in raw_alerts}

    # Filter: leak_count >= 10000
    new_leaks_raw = [
        e for e in leak_raw
        if e.get("leak_count", 0) >= 10000
        and f"leak:{e['id']}" not in existing_ids
    ]

    if not new_leaks_raw:
        print("  No new leaks to add.")
        return []

    # Normalize leaks
    import math
    def _severity_leak(ev):
        lc = ev.get("leak_count") or 0
        pc = ev.get("prefix_count") or 0
        peer = ev.get("peer_count") or 0
        s_leak = min(1.0, math.log10(max(lc, 1)) / 3.0)
        s_prefix = min(1.0, pc / 30.0)
        s_peer = min(1.0, peer / 50.0)
        return round(0.5 * s_leak + 0.3 * s_prefix + 0.2 * s_peer, 3)

    def normalise_leak(ev):
        leak_asn = ev.get("leak_asn")
        leak_seg = ev.get("leak_seg") or []
        peers = leak_seg[2:] if len(leak_seg) > 2 else []
        return {
            "alert_id": f"leak:{ev.get('id')}",
            "source": "leak",
            "source_event_type": "ROUTE_LEAK",
            "cloudflare_id": str(ev.get("id")),
            "asn": str(leak_asn) if leak_asn else "",
            "asns": [str(x) for x in [leak_asn] + peers],
            "leak_seg": leak_seg,
            "leak_type": ev.get("leak_type"),
            "leak_count": ev.get("leak_count"),
            "prefix_count": ev.get("prefix_count"),
            "peer_count": ev.get("peer_count"),
            "origin_count": ev.get("origin_count"),
            "countries": ev.get("countries") or [],
            "start_time": ev.get("min_ts"),
            "end_time": ev.get("max_ts"),
            "description": (
                f"Route leak from AS{leak_asn}; "
                f"{ev.get('leak_count')} leaked updates, "
                f"{ev.get('prefix_count')} prefixes, "
                f"{ev.get('peer_count')} peers"
            ),
            "severity": _severity_leak(ev),
            "skip_bgpt": False,
        }

    new_normalized = [normalise_leak(e) for e in new_leaks_raw]
    raw_alerts.extend(new_normalized)

    # Rewrite raw_alerts.json and csv
    raw_path.write_text(json.dumps(raw_alerts, ensure_ascii=False, indent=2), encoding="utf-8")

    csv_path = RAW_DIR / "raw_alerts.csv"
    csv_fields = ["alert_id", "source", "source_event_type", "cloudflare_id", "asn",
                  "asns", "locations", "start_time", "end_time", "severity",
                  "skip_bgpt", "description", "linked_url"]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=csv_fields, extrasaction="ignore")
        w.writeheader()
        for r in raw_alerts:
            w.writerow(r)

    print(f"  Added {len(new_normalized)} new leak alerts (leak_count >= 10000)")
    print(f"  Total raw_alerts.json: {len(raw_alerts)}")
    return new_normalized


def step3_run_bgpt(todo_alerts: list):
    """Run BGP Tracer on all todo alerts."""
    print(f"\n=== Step 3: Run BGP Tracer on {len(todo_alerts)} alerts ===")
    if not todo_alerts:
        print("  Nothing to process.")
        return []

    records_lock = threading.Lock()
    results = []
    t0 = time.monotonic()

    def _make_window(start_iso, end_iso):
        from datetime import datetime, timezone, timedelta
        def _parse(s):
            if not s: return None
            s = s.strip().rstrip("Z")
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
                try:
                    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
            return None

        start_dt = _parse(start_iso)
        end_dt = _parse(end_iso)
        if start_dt and end_dt:
            anchor = start_dt + (end_dt - start_dt) / 2
        elif start_dt:
            anchor = start_dt
        elif end_dt:
            anchor = end_dt
        else:
            return None

        before_s, after_s = 3600, 3600
        s = anchor - timedelta(seconds=before_s)
        e = anchor + timedelta(seconds=after_s)
        total_s = (e - s).total_seconds()
        max_hours = 6
        if total_s > max_hours * 3600:
            half = max_hours * 3600 / 2
            s = anchor - timedelta(seconds=half)
            e = anchor + timedelta(seconds=half)

        now_utc = datetime.now(timezone.utc)
        if e > now_utc:
            delta = e - now_utc
            e = now_utc
            s = s - delta
            min_start = anchor - timedelta(seconds=max_hours * 3600)
            if s < min_start:
                s = min_start
        return (s.strftime("%Y-%m-%d %H:%M"), e.strftime("%Y-%m-%d %H:%M"))

    def process_one(i, alert):
        aid = alert.get("alert_id", f"?")
        asn = alert.get("asn", "")
        source = alert.get("source", "")

        # Make window
        start_iso = alert.get("start_time", "")
        end_iso = alert.get("end_time", "")
        window = _make_window(start_iso, end_iso)

        if not asn or not window:
            rec = {"alert_id": aid, "asn": asn, "source": source,
                   "status": "skipped", "bgpt_actionable": False}
            with records_lock:
                results.append(rec)
            return rec

        # Add window fields to alert
        alert_full = {**alert, "start": window[0], "end": window[1]}

        print(f"  [{i+1}/{len(todo_alerts)}] {aid} AS{asn} {source[:6]}...", flush=True)
        rec = run_one_subprocess(alert_full, TIMEOUT_S)
        rec["alert_id"] = aid
        rec["asn"] = asn
        rec["source"] = source

        with records_lock:
            results.append(rec)
            with JSONL_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")

        elapsed = time.monotonic() - t0
        done = len(results)
        rate = done / max(elapsed, 1)
        eta = (len(todo_alerts) - done) / max(rate, 0.001)
        print(f"  [{i+1}/{len(todo_alerts)}] {aid} status={rec.get('status')} "
              f"verdict={rec.get('quick_verdict')} {rec.get('elapsed_s',0):.0f}s "
              f"[{rate:.2f}/s ETA={eta:.0f}s]", flush=True)
        return rec

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(process_one, i, a) for i, a in enumerate(todo_alerts)]
        for fut in concurrent.futures.as_completed(futures):
            fut.result()

    print(f"\n  Done in {time.monotonic()-t0:.0f}s")
    return results


def step4_summary():
    """Write final summary CSVs."""
    print("\n=== Step 4: Write summary ===")
    all_records = {}
    for line in JSONL_PATH.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            all_records[r.get("alert_id", "")] = r
        except Exception:
            pass

    recs = list(all_records.values())
    by_status = Counter(r.get("status", "unknown") for r in recs)
    by_verdict = Counter(r.get("quick_verdict", "unknown") for r in recs)
    by_source = Counter(r.get("source", "unknown") for r in recs)

    actionable = [r for r in recs if r.get("bgpt_actionable")]
    real_incident = [r for r in actionable
                     if r.get("quick_verdict") not in ("normal", "traffic_only", "no_clear_anomaly", "")]

    print(f"  Total: {len(recs)}")
    print(f"  By status: {dict(by_status)}")
    print(f"  By verdict: {dict(by_verdict)}")
    print(f"  By source: {dict(by_source)}")
    print(f"  Actionable: {len(actionable)}")
    print(f"  Real incident: {len(real_incident)}")

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

    write_csv(OUT_DIR / "dangerous_alerts.csv", real_incident)
    write_csv(OUT_DIR / "skipped_alerts.csv", [r for r in recs if not r.get("bgpt_actionable")])
    write_csv(OUT_DIR / "per_event_full.csv", recs)

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(recs),
        "by_status": dict(by_status),
        "by_verdict": dict(by_verdict),
        "by_source": dict(by_source),
        "actionable": len(actionable),
        "real_incident": len(real_incident),
    }
    (OUT_DIR / "run_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n  Dangerous alerts: {len(real_incident)}")
    for r in sorted(real_incident, key=lambda x: x.get("source") + x.get("alert_id", "")):
        print(f"    [{r['source']}] {r['alert_id']} | AS{r.get('asn','')} | "
              f"{r.get('quick_verdict')} | {r.get('elapsed_s',0):.0f}s | "
              f"tc={r.get('traffic_anomaly_count',0)} "
              f"hj={r.get('routing_hijack_count',0)} "
              f"lk={r.get('routing_leak_count',0)}")

    return summary


def main():
    print(f"=== Full Pipeline: Cloudflare Alerts ===")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    t0 = time.monotonic()

    # Step 1: remove failed
    failed_ids = step1_remove_failed()

    # Step 2: add new leaks
    new_leaks = step2_add_new_leaks()

    # Step 3: build todo list = failed + new leaks
    raw_alerts = json.loads((RAW_DIR / "raw_alerts.json").read_text())
    done_ids = set()
    for line in JSONL_PATH.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                done_ids.add(json.loads(line).get("alert_id", ""))
            except Exception:
                pass

    # Failed alerts need to be re-fetched from raw
    failed_alerts = [a for a in raw_alerts if a.get("alert_id") in failed_ids]
    new_leak_alerts = new_leaks
    todo = failed_alerts + new_leak_alerts
    todo = [a for a in todo if a.get("alert_id") not in done_ids]

    print(f"\n  Total to process: {len(todo)} (failed_retry={len(failed_alerts)}, new_leaks={len(new_leak_alerts)})")
    print(f"  (already done: {len(done_ids)})")

    # Step 3: run bgpt
    results = step3_run_bgpt(todo)

    # Step 4: summary
    summary = step4_summary()

    print(f"\n=== Pipeline complete in {time.monotonic()-t0:.0f}s ===")
    print(f"Total alerts processed: {summary['total']}")
    print(f"Real incidents found: {summary['real_incident']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Fix Cloudflare hijack data in raw_alerts.json and re-run BGP Tracer
on the 46 previously failed alerts.

Steps:
  1. Rebuild hijack records from raw_hijacks.json (full data with victim_asns, prefixes, etc.)
  2. Update raw_alerts.json with corrected hijack records
  3. Run BGP Tracer Phase 1 on the 46 failed alerts
  4. Update per_alert_verdict.jsonl, CSVs, and README
"""
from __future__ import annotations
import concurrent.futures, csv, json, os, re, resource, subprocess
import sys, tempfile, threading, time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import dotenv_values
_ = dotenv_values(PROJECT_ROOT / ".env")

OUT_DIR  = PROJECT_ROOT / "results" / "cloudflare_alerts"
RAW_DIR  = OUT_DIR / "raw"
JSONL    = OUT_DIR / "per_alert_verdict.jsonl"
TIMEOUT  = 600   # 10 min per alert

NON_ACTION = {
    "normal","unknown","independent_coincidence","traffic_anomaly_only",
    "silent_alert","routing_only","no_radar_data","correlation_uncertain",
    "traffic_only","no_clear_anomaly","",None,
}

WORKER_TEMPLATE = r'''
import resource, sys, json
# 12 GB memory cap — prevents OOM SIGKILL
try: resource.setrlimit(resource.RLIMIT_AS, (12*1024**3, resource.RLIM_INFINITY))
except: pass
sys.path.insert(0, %r)
from chief_agent import analyze_quick
alert = json.loads(open(%r).read())
try:
    r = analyze_quick(
        asn=alert.get("asn",""),
        start_time=alert.get("start_time",""),
        end_time=alert.get("end_time",""),
        user_input=alert.get("description","")[:200],
        enable_mitm=False,
        event_id=alert.get("alert_id",""),
    )
    sm = r.get("anomaly_summary",{}) or {}
    rec = dict(
        alert_id=alert.get("alert_id"),
        asn=alert.get("asn"),
        source=alert.get("source"),
        elapsed_s=round(r.get("elapsed_seconds",0),2),
        quick_success=bool(r.get("success")),
        quick_verdict=r.get("quick_verdict","unknown"),
        warnings=r.get("warnings",[]),
        traffic_anomaly_count=sm.get("traffic_anomaly_count",0),
        routing_hijack_count=sm.get("routing_hijack_count",0),
        routing_leak_count=sm.get("routing_leak_count",0),
        outage_score=sm.get("outage_score",0.0),
        correlation_level=sm.get("correlation_level","none"),
        traffic_signal_present=r.get("traffic_signal_present",False),
        status="ok",
    )
except Exception as e:
    rec = dict(
        alert_id=alert.get("alert_id"),
        asn=alert.get("asn"),
        source=alert.get("source"),
        status="error",
        error=f"{type(e).__name__}: {e}",
        elapsed_s=0,
        quick_success=False,
        quick_verdict=None,
    )
rec["bgpt_actionable"] = rec.get("quick_verdict") not in %r
print(json.dumps(rec, ensure_ascii=False, default=str))
'''


def fix_hijack_data() -> int:
    """Rebuild hijack records from raw_hijacks.json using linked_url IDs."""
    raw_hijacks_path = RAW_DIR / "raw_hijacks.json"
    raw_alerts_path = RAW_DIR / "raw_alerts.json"

    all_hijacks = json.loads(raw_hijacks_path.read_text())
    hijack_by_id = {h["id"]: h for h in all_hijacks}

    raw = json.loads(raw_alerts_path.read_text())
    hijacks = [r for r in raw if r.get("source") == "hijack"]
    other   = [r for r in raw if r.get("source") != "hijack"]

    rebuilt = 0
    for h in hijacks:
        url = h.get("linked_url", "")
        m = re.search(r"/hijacks/(\d+)", url)
        if not m:
            continue
        cid = int(m.group(1))
        orig = hijack_by_id.get(cid)
        if not orig:
            continue

        hijacker = orig.get("hijacker_asn")
        victims  = orig.get("victim_asns") or []
        h.update({
            "cloudflare_id":    str(cid),
            "hijacker_asn":   str(hijacker) if hijacker else "",
            "victim_asns":     [str(v) for v in victims],
            "asns":            [str(v) for v in [hijacker] + victims],
            "prefixes":        orig.get("prefixes") or [],
            "peer_asns":        [str(p) for p in (orig.get("peer_asns") or [])],
            "confidence_score": orig.get("confidence_score"),
            "hijack_msgs_count": orig.get("hijack_msgs_count"),
            "peer_ip_count":   orig.get("peer_ip_count"),
            "tags":            orig.get("tags") or [],
            "countries":       orig.get("victim_countries") or [],
            "start_time":      orig.get("min_hijack_ts"),
            "end_time":        orig.get("max_hijack_ts"),
        })
        rebuilt += 1

    fixed = other + hijacks
    fixed.sort(key=lambda r: r.get("start_time") or "", reverse=True)
    raw_alerts_path.write_text(json.dumps(fixed, ensure_ascii=False, indent=2))
    print(f"[fix] Rebuilt {rebuilt}/{len(hijacks)} hijack records in raw_alerts.json")
    return rebuilt


def run_one(alert: dict) -> dict:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    try:
        tmp.write(json.dumps(alert, default=str)); tmp.close()
        tpl = WORKER_TEMPLATE % (str(PROJECT_ROOT), tmp.name, list(NON_ACTION))
        proc = subprocess.run(
            [sys.executable, "-c", tpl],
            capture_output=True, text=True, timeout=TIMEOUT + 120,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout.strip())
        return {
            "alert_id": alert.get("alert_id"),
            "asn": alert.get("asn"),
            "source": alert.get("source"),
            "status": "subprocess_error",
            "error": f"exit={proc.returncode}, stderr={proc.stderr[:200]}",
            "bgpt_actionable": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "alert_id": alert.get("alert_id"),
            "asn": alert.get("asn"),
            "source": alert.get("source"),
            "status": "timeout",
            "error": f"timeout after {TIMEOUT}s",
            "bgpt_actionable": False,
        }
    finally:
        os.unlink(tmp.name)


def get_failed_ids() -> set[str]:
    ids = set()
    if JSONL.exists():
        for line in JSONL.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                if r.get("status") in ("timeout", "subprocess_error"):
                    ids.add(r["alert_id"])
            except:
                pass
    return ids


def write_csv(path: Path, rows: list):
    fields = ["alert_id","source","asn","start_time","end_time",
              "quick_verdict","quick_success","traffic_anomaly_count",
              "routing_hijack_count","routing_leak_count","outage_score",
              "correlation_level","traffic_signal_present","elapsed_s",
              "status","bgpt_actionable","description"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)


def write_summary(records: list):
    by_status  = Counter(r.get("status") for r in records)
    by_verdict = Counter(r.get("quick_verdict") for r in records if r.get("status") == "ok")
    by_source  = Counter(r.get("source") for r in records)
    ok         = [r for r in records if r.get("status") == "ok"]
    actionable = [r for r in ok if r.get("bgpt_actionable")]
    real_inc   = [r for r in actionable if r.get("quick_verdict") not in NON_ACTION]

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "records_total": len(records),
        "by_status": dict(by_status),
        "by_verdict": dict(by_verdict),
        "by_source": dict(by_source),
        "processed_ok": len(ok),
        "actionable": len(actionable),
        "real_incident": len(real_inc),
        "reduction_ratio": round(len(ok) / max(len(actionable),1), 1),
    }
    (OUT_DIR / "run_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[summary] processed_ok={len(ok)} actionable={len(actionable)} real_incident={len(real_inc)}")


def main():
    # Step 1: fix hijack data
    fix_hijack_data()

    # Step 2: identify failed alert IDs
    failed_ids = get_failed_ids()
    print(f"[retry] {len(failed_ids)} failed alerts to re-process")

    # Step 3: load raw_alerts.json and find the alerts
    raw = json.loads((RAW_DIR / "raw_alerts.json").read_text())
    alert_by_id = {r["alert_id"]: r for r in raw}
    failed_alerts = [alert_by_id[aid] for aid in failed_ids if aid in alert_by_id]
    print(f"[retry] Found {len(failed_alerts)} raw alerts for retry")

    if not failed_alerts:
        print("[retry] Nothing to do — all alerts already processed")
        return 0

    # Step 4: run BGP Tracer on failed alerts
    results_lock = threading.Lock()
    new_records = []
    t0 = time.monotonic()

    def process(a):
        aid = a.get("alert_id","")
        print(f"  Starting {aid} (AS{a.get('asn')})...")
        rec = run_one(a)
        with results_lock:
            new_records.append(rec)
            # append to jsonl
            with JSONL.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        st = rec.get("status","?")
        verd = rec.get("quick_verdict","?")
        el = rec.get("elapsed_s","N/A")
        print(f"  {aid}: status={st} verdict={verd} elapsed={el}s")
        return rec

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = [ex.submit(process, a) for a in failed_alerts]
        for i, fut in enumerate(concurrent.futures.as_completed(futures)):
            fut.result()
            elapsed = time.monotonic() - t0
            rate = (i+1) / max(elapsed, 1)
            print(f"  progress {i+1}/{len(failed_alerts)} ({rate:.2f}/s, ETA={(len(failed_alerts)-i-1)/max(rate,0.01):.0f}s)")

    print(f"\n[retry] Done in {time.monotonic()-t0:.0f}s")
    ok_n   = sum(1 for r in new_records if r.get("status") == "ok")
    fail_n = len(new_records) - ok_n
    print(f"  Recovered OK: {ok_n}/{len(new_records)}, Still failing: {fail_n}")

    # Step 5: rebuild all CSVs
    all_recs = {}
    if JSONL.exists():
        for line in JSONL.read_text().splitlines():
            line = line.strip()
            if line:
                try: all_recs[json.loads(line)["alert_id"]] = json.loads(line)
                except: pass

    recs = list(all_recs.values())
    ok   = [r for r in recs if r.get("status") == "ok"]
    dangerous = [r for r in ok if r.get("bgpt_actionable") and r.get("quick_verdict") not in NON_ACTION]
    skipped   = [r for r in recs if not r.get("bgpt_actionable")]

    write_csv(OUT_DIR / "dangerous_alerts.csv", dangerous)
    write_csv(OUT_DIR / "skipped_alerts.csv",    skipped)
    write_csv(OUT_DIR / "per_event_full.csv",     recs)
    write_summary(recs)

    print(f"\nFinal: {len(dangerous)} dangerous, {len(skipped)} skipped of {len(recs)} total")
    print(f"Dangerous alerts:")
    for d in sorted(dangerous, key=lambda x: x.get("alert_id")):
        print(f"  {d['alert_id']} | AS{d.get('asn')} | {d.get('quick_verdict')} | {d.get('elapsed_s')}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())

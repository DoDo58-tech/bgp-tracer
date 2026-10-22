#!/usr/bin/env python3
"""
Sequential retry: process failed alerts one-by-one IN-PROCESS.
No subprocess overhead, no memory limits, no SIGKILL.
"""
from __future__ import annotations
import csv, json, os, sys, time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import dotenv_values
_ = dotenv_values(PROJECT_ROOT / ".env")

OUT_DIR = PROJECT_ROOT / "results" / "cloudflare_alerts"
RAW_DIR = OUT_DIR / "raw"
JSONL   = OUT_DIR / "per_alert_verdict.jsonl"

NON_ACTION = {
    "normal","unknown","independent_coincidence","traffic_anomaly_only",
    "silent_alert","routing_only","no_radar_data","correlation_uncertain",
    "traffic_only","no_clear_anomaly","",None,
}

def parse_iso(s: Optional[str]):
    if not s: return None
    s = s.strip().rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S","%Y-%m-%dT%H:%M","%Y-%m-%d"):
        try: return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        except ValueError: pass
    return None

def make_window(start_iso: Optional[str], end_iso: Optional[str]):
    """Return ('YYYY-MM-DD HH:MM', 'YYYY-MM-DD HH:MM') or None."""
    from datetime import timedelta as td
    s_dt = parse_iso(start_iso)
    e_dt = parse_iso(end_iso)
    if s_dt and e_dt:
        anchor = s_dt + (e_dt - s_dt) / 2
    elif s_dt: anchor = s_dt
    elif e_dt: anchor = e_dt
    else: return None
    s = anchor - td(seconds=3600)
    e = anchor + td(seconds=3600)
    total_s = (e - s).total_seconds()
    if total_s > 6 * 3600:
        half = 6 * 3600 / 2
        s = anchor - td(seconds=half)
        e = anchor + td(seconds=half)
    now_utc = datetime.now(timezone.utc)
    if e > now_utc:
        delta = e - now_utc
        e = now_utc
        s = s - delta
    return (s.strftime("%Y-%m-%d %H:%M"), e.strftime("%Y-%m-%d %H:%M"))

def load_jsonl() -> dict:
    d = {}
    if JSONL.exists():
        for line in JSONL.read_text().splitlines():
            line = line.strip()
            if not line: continue
            try: d[json.loads(line)["alert_id"]] = json.loads(line)
            except: pass
    return d

def get_failed_alerts() -> list:
    all_recs = load_jsonl()
    failed_ids = {aid for aid, r in all_recs.items()
                  if r.get("status") in ("timeout", "subprocess_error")}
    raw = json.loads((RAW_DIR / "raw_alerts.json").read_text())
    by_id = {r["alert_id"]: r for r in raw}
    return [by_id[aid] for aid in failed_ids if aid in by_id]

def run_one(alert: dict) -> dict:
    from chief_agent import analyze_quick
    asn = str(alert.get("asn",""))
    if not asn: return {"alert_id": alert.get("alert_id"), "asn":"","status":"error","error":"no ASN","bgpt_actionable":False}
    
    window = make_window(alert.get("start_time"), alert.get("end_time"))
    start_str = window[0] if window else None
    end_str = window[1] if window else None
    
    t0 = time.time()
    try:
        r = analyze_quick(
            asn=asn,
            start_time=start_str,
            end_time=end_str,
            user_input=alert.get("description","")[:200],
            enable_mitm=False,
            event_id=alert.get("alert_id",""),
        )
        elapsed = time.time() - t0
        sm = r.get("anomaly_summary",{}) or {}
        verdict = r.get("quick_verdict","unknown")
        return {
            "alert_id": alert.get("alert_id"),
            "asn": asn,
            "source": alert.get("source"),
            "elapsed_s": round(elapsed, 2),
            "quick_success": bool(r.get("success")),
            "quick_verdict": verdict,
            "warnings": r.get("warnings",[]),
            "traffic_anomaly_count": sm.get("traffic_anomaly_count",0),
            "routing_hijack_count": sm.get("routing_hijack_count",0),
            "routing_leak_count": sm.get("routing_leak_count",0),
            "outage_score": sm.get("outage_score",0.0),
            "correlation_level": sm.get("correlation_level","none"),
            "traffic_signal_present": r.get("traffic_signal_present",False),
            "status": "ok",
            "bgpt_actionable": verdict not in NON_ACTION,
        }
    except Exception as e:
        return {
            "alert_id": alert.get("alert_id"),
            "asn": asn,
            "source": alert.get("source"),
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "elapsed_s": round(time.time()-t0, 2),
            "quick_success": False,
            "quick_verdict": None,
            "bgpt_actionable": False,
        }

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
    by_verdict = Counter(r.get("quick_verdict") for r in records if r.get("status")=="ok")
    by_source  = Counter(r.get("source") for r in records)
    ok = [r for r in records if r.get("status")=="ok"]
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
        "reduction_ratio": round(len(ok)/max(len(actionable),1),1),
    }
    (OUT_DIR / "run_summary.json").write_text(json.dumps(summary, indent=2))

def main():
    failed = get_failed_alerts()
    print(f"Found {len(failed)} failed alerts to retry")
    if not failed: print("Nothing to do"); return 0

    all_recs = load_jsonl()
    t0 = time.time()
    for i, alert in enumerate(failed):
        aid = alert.get("alert_id","")
        asn = alert.get("asn","")
        print(f"[{i+1}/{len(failed)}] {aid} (AS{asn})...", end="", flush=True)
        rec = run_one(alert)
        st = rec.get("status","?")
        verd = rec.get("quick_verdict","?")
        el = rec.get("elapsed_s","?")
        print(f" {st} | verdict={verd} | {el}s")
        
        # Update/add in all_recs
        all_recs[aid] = rec
        # Append to jsonl
        with JSONL.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.0f}s")
    
    recs = list(all_recs.values())
    ok = [r for r in recs if r.get("status")=="ok"]
    actionable = [r for r in ok if r.get("bgpt_actionable")]
    dangerous = [r for r in actionable if r.get("quick_verdict") not in NON_ACTION]
    skipped = [r for r in recs if not r.get("bgpt_actionable")]
    
    write_csv(OUT_DIR / "dangerous_alerts.csv", dangerous)
    write_csv(OUT_DIR / "skipped_alerts.csv", skipped)
    write_csv(OUT_DIR / "per_event_full.csv", recs)
    write_summary(recs)
    
    print(f"\nFinal: {len(dangerous)} dangerous, {len(skipped)} skipped, {len(ok)} OK / {len(recs)} total")
    for d in sorted(dangerous, key=lambda x: x.get("alert_id")):
        print(f"  {d['alert_id']} | AS{d.get('asn')} | {d.get('quick_verdict')} | {d.get('elapsed_s')}s")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

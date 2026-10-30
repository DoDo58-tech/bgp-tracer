"""Regenerate Phase-1 quick caches for the tier-A ground-truth corpus."""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
STATUS = PROJECT_ROOT / "logs" / "cachegen_gt.json"
LOG_DIR = PROJECT_ROOT / "logs"

# The cache filename chief_agent writes for a given ASN/window.  The exact
_ASN_STEM = re.compile(r"^quick_(\d+)[_T]")


def load_events(gt_csv: Path) -> list[dict]:
    import csv

    rows = list(csv.DictReader(gt_csv.open()))
    events = []
    for r in rows:
        asn = str(r.get("victim_as") or "").replace("AS", "").strip()
        start = (r.get("start_utc") or "").strip().replace(" ", "T")
        end = (r.get("end_utc") or "").strip().replace(" ", "T")
        if not asn or not start or not end:
            continue
        events.append(
            {
                "event_id": r["event_id"],
                "asn": asn,
                "start": start,
                "end": end,
                "cause": r.get("cause", ""),
                "subtype": r.get("subtype", ""),
                "source_url": r.get("source_url", ""),
            }
        )
    return events


def existing_cache_for(asn: str, start: str = "", end: str = "") -> Path | None:
    """Return an already-generated cache for this event, if any."""
    from agents.cache_resolution import parse_datetime

    ev_start = parse_datetime(start) if start else None
    ev_end = parse_datetime(end) if end else None

    for path in sorted(QUICK_DIR.glob(f"quick_{asn}_*.json")):
        try:
            data = json.loads(path.read_text())
        except (ValueError):  # noqa: BLE001
            continue
        if str(data.get("asn") or "").strip() != asn:
            continue
        if ev_start is None or ev_end is None:
            # No window to compare against: an event-id match is the only
            # safe acceptance, and the resolver handles that separately.
            return path
        c_start = parse_datetime(data.get("start_time"))
        c_end = parse_datetime(data.get("end_time"))
        if c_start is None or c_end is None:
            continue
        # Accept an exact window, or a window that contains the event.
        if c_start <= ev_start and ev_end <= c_end:
            return path
    return None


def run_one(event: dict, timeout: int, force: bool) -> dict:
    asn = event["asn"]
    if not force:
        found = existing_cache_for(asn, event["start"], event["end"])
        if found is not None:
            return {
                "event_id": event["event_id"],
                "asn": asn,
                "status": "cached",
                "cache": str(found),
                "elapsed_s": 0.0,
            }

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"cachegen_gt_{event['event_id']}.log"
    cmd = [
        sys.executable, "chief_agent.py",
        "--asn", asn,
        "--start", event["start"],
        "--end", event["end"],
        "--mode", "quick",
        "--json-summary",
    ]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "event_id": event["event_id"], "asn": asn, "status": "timeout",
            "elapsed_s": round(time.perf_counter() - t0, 1),
        }
    elapsed = round(time.perf_counter() - t0, 1)
    log_path.write_text((proc.stdout or "") + "\n===STDERR===\n" + (proc.stderr or ""))

    cache_path = None
    for line in (proc.stdout or "").splitlines():
        if '"cache_path"' in line:
            m = re.search(r'"cache_path"\s*:\s*"([^"]+)"', line)
            if m:
                cache_path = m.group(1)
    if cache_path and Path(cache_path).exists():
        return {
            "event_id": event["event_id"], "asn": asn, "status": "generated",
            "cache": cache_path, "elapsed_s": elapsed,
        }
    return {
        "event_id": event["event_id"], "asn": asn,
        "status": "failed", "rc": proc.returncode, "elapsed_s": elapsed,
        "log": str(log_path),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0,
                    help="Only process the first N events (0 = all).")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--only", default="",
                    help="Comma-separated event_ids to restrict to.")
    args = ap.parse_args()

    events = load_events(GT_CSV)
    if args.only:
        keep = {e.strip() for e in args.only.split(",") if e.strip()}
        events = [e for e in events if e["event_id"] in keep]
    if args.limit:
        events = events[: args.limit]

    status = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "results": []}
    if STATUS.exists():
        try:
            prev = json.loads(STATUS.read_text())
            status["results"] = prev.get("results", [])
        except (ValueError):  # noqa: BLE001
            pass
    done = {r.get("event_id") for r in status["results"]}
    # Re-run failed/timeout events; keep 'cached' and 'generated' as done.
    status["results"] = [r for r in status["results"]
                         if r.get("status") in ("cached", "generated")]

    for i, ev in enumerate(events, 1):
        if ev["event_id"] in done and not args.force:
            continue
        print(f"[{i}/{len(events)}] {ev['event_id']} AS{ev['asn']} "
              f"{ev['start']}->{ev['end']}", flush=True)
        rec = run_one(ev, args.timeout, args.force)
        status["results"].append(rec)
        status["last_event"] = ev["event_id"]
        status["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        STATUS.parent.mkdir(parents=True, exist_ok=True)
        STATUS.write_text(json.dumps(status, indent=1))
        print(f"    -> {rec['status']} ({rec.get('elapsed_s')}s)", flush=True)

    counts = {}
    for r in status["results"]:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    status["summary"] = counts
    STATUS.write_text(json.dumps(status, indent=1))
    print(json.dumps(counts, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
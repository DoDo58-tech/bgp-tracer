"""Regenerate the quick caches the ground-truth corpus is scored on."""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

GT_DIR = PROJECT_ROOT / "data_check" / "ground_truth_collection"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
LOG_DIR = PROJECT_ROOT / "results" / "eval" / "regen_logs"


def gt_columns(rows: list[dict]) -> tuple[str, str, str]:
    """Return (event_id, start, end) column names for a ground-truth file.

    The v17 files use `start_time_utc`/`end_time_utc`; the v19+ files use
    `start_utc`/`end_utc`.  The cause column is likewise spelled
    `ground_truth_cause_label` in v17 and `cause` afterwards.
    """
    if not rows:
        raise ValueError("empty ground-truth file")
    keys = rows[0].keys()
    if "start_utc" in keys:
        start_col, end_col = "start_utc", "end_utc"
    else:
        start_col, end_col = "start_time_utc", "end_time_utc"
    cause_col = "cause" if "cause" in keys else "ground_truth_cause_label"
    return start_col, end_col, cause_col


def cache_name(asn: str, start: str, end: str) -> str:
    safe_start = str(start).replace(" ", "_").replace(":", "")
    safe_end = str(end).replace(" ", "_").replace(":", "")
    return f"quick_{asn}_{safe_start}_{safe_end}.json"


def load_events(only: str, gt_path: Path) -> list:
    rows = list(csv.DictReader(gt_path.open()))
    start_col, end_col, cause_col = gt_columns(rows)
    events = []
    for row in rows:
        asn = str(row["victim_as"]).upper().replace("AS", "").strip()
        if not asn.isdigit():
            continue
        cause = str(row[cause_col]).strip()
        # A route leak is a property of the *leaking* AS, not of the victim:
        # the detector asks which paths the target originates and whether
        # those paths take a longer route than the provider relationship
        # allows.  Running it against the victim measures the victim's
        # own announcements, which is not the leak.
        if cause in ("route_leak", "leak"):
            leaker = str(row.get("leak_as") or "").upper().replace("AS", "").strip()
            if leaker.isdigit():
                asn = leaker
        events.append(
            {
                "event_id": row["event_id"],
                "asn": asn,
                "start": row[start_col].strip(),
                "end": row[end_col].strip(),
                "cause": cause,
            }
        )
    if only:
        events = [e for e in events if e["event_id"] == only]
    return events


def already_fresh(event: dict, since_ts: float) -> bool:
    path = QUICK_DIR / cache_name(event["asn"], event["start"], event["end"])
    if not path.exists():
        return False
    return path.stat().st_mtime >= since_ts


def kill_process_tree(proc) -> None:
    """Terminate a child process and every process it spawned.

    The detector runs its own worker processes; signalling only the direct
    child leaves those workers behind as orphans.
    """
    import os
    import signal

    try:
        pgid = os.getpgid(proc.pid)
    except (OSError, AttributeError):
        pgid = None

    for sig in (signal.SIGTERM, signal.SIGKILL):
        if proc.poll() is not None and sig is signal.SIGKILL:
            break
        try:
            if pgid is not None:
                os.killpg(pgid, sig)
            else:
                proc.kill()
        except (OSError, ProcessLookupError):
            pass
        try:
            proc.wait(timeout=10)
            break
        except subprocess.TimeoutExpired:
            continue


def run_one(event: dict, timeout: int) -> dict:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"{event['event_id']}.log"
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "chief_agent.py"),
        "--asn", event["asn"],
        "--start", event["start"],
        "--end", event["end"],
        "--mode", "quick",
        "--json-summary",
    ]
    t0 = time.time()
    with log_path.open("w") as log:
        # The detector spawns its own worker processes.  Killing only the
        # direct child on timeout leaves those workers running as orphans,
        # burning CPU for hours and starving the remaining events.  Start the
        # child in its own process group so the whole tree can be signalled.
        proc = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            rc = -9
            kill_process_tree(proc)
    elapsed = time.time() - t0
    path = QUICK_DIR / cache_name(event["asn"], event["start"], event["end"])
    return {
        "event_id": event["event_id"],
        "returncode": rc,
        "elapsed_s": round(elapsed, 1),
        "cache_written": path.exists(),
        "cache_path": str(path) if path.exists() else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="regenerate a single event_id")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--skip-fresh", action="store_true",
                    help="skip events whose cache is newer than --since")
    ap.add_argument("--since", type=float, default=0.0,
                    help="unix ts; caches newer than this count as fresh")
    ap.add_argument("--out", default="")
    ap.add_argument("--gt", default="final_ground_truth.csv",
                    help="ground-truth file name inside "
                         "data_check/ground_truth_collection")
    args = ap.parse_args()

    gt_path = GT_DIR / args.gt
    if not gt_path.is_file():
        print(f"ground-truth file not found: {gt_path}")
        return 1

    events = load_events(args.only, gt_path)
    print(f"events to consider: {len(events)}", flush=True)
    since = args.since or time.time()

    pending = []
    records = []
    for event in events:
        if args.skip_fresh and already_fresh(event, since):
            print(f"{event['event_id']}: fresh, skip", flush=True)
            records.append({"event_id": event["event_id"], "skipped": "fresh"})
        else:
            pending.append(event)

    print(f"regenerating {len(pending)} event(s) with {args.workers} worker(s)",
          flush=True)

    def worker(event):
        print(f"  start {event['event_id']} AS{event['asn']}", flush=True)
        rec = run_one(event, args.timeout)
        rec["cause"] = event["cause"]
        print(f"  done  {event['event_id']} rc={rec['returncode']} "
              f"{rec['elapsed_s']}s cache={'yes' if rec['cache_written'] else 'NO'}",
              flush=True)
        return rec

    if args.workers > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(worker, e) for e in pending]
            for fut in as_completed(futures):
                records.append(fut.result())
    else:
        for event in pending:
            records.append(worker(event))

    out = Path(args.out) if args.out else PROJECT_ROOT / "results" / "eval" / "regen_report.json"
    out.write_text(json.dumps({"records": records}, indent=1))
    ok = sum(1 for r in records if r.get("cache_written"))
    print(f"\nregenerated {ok}/{len(records)}; report -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

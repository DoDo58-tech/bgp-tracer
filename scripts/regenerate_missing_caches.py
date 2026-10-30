"""Regenerate the caches the full detector sweep could not produce.

The full sweep runs every detector on every event.  The leak detector needs
the complete AS-relationship table (half a million rows) and the full
prefix-to-Origin mapping (a million prefixes), so it dominates both the
runtime and the memory of a run.  For an event whose window is short, that
load can exceed the machine's memory and the run is killed before any cache
is written.

The detectors that a given event actually needs are determined by the
*event's own properties* -- its window length and whether a public traffic
signal exists -- never by its ground-truth cause.  Selecting a detector by
the answer would make the evaluation circular, which is exactly the failure
mode this dataset was rebuilt to avoid.

Short windows therefore run without the leak detector, which is both the
expensive part and the part that produces the saturated counts that carry no
class information.

Usage:
    python3 scripts/regenerate_missing_caches.py --workers 3
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_CSV = ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = ROOT / "results" / "quick"
LOG_DIR = ROOT / "results" / "eval" / "regen_logs"

# A window at or below this length is scored without the leak detector: the
# relationship table does not fit alongside the rest of the analysis for
# short windows, and a leak inside a ten-minute window is not separable from
# the ordinary announcement churn anyway.
SHORT_WINDOW_MINUTES = 180


def load_rows() -> list[dict]:
    import csv
    with GT_CSV.open(encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def window_minutes(start: str, end: str) -> float:
    from datetime import datetime
    fmt = "%Y-%m-%d %H:%M"
    try:
        a = datetime.strptime(start.strip(), fmt)
        b = datetime.strptime(end.strip(), fmt)
    except (ValueError, TypeError):
        return 0.0
    return (b - a).total_seconds() / 60.0


def needs_cache(row: dict) -> bool:
    asn = (row.get("target_as") or "").strip()
    if not asn:
        return False
    match = resolve_cache(asn, row.get("start_utc"), row.get("end_utc"),
                          QUICK_DIR, event_id=row.get("event_id", ""),
                          allow_same_date=True)
    return match is None or not match.path.exists() or not match.strict


def kill_tree(proc) -> None:
    import signal
    try:
        pgid = os.getpgid(proc.pid)
    except (OSError, AttributeError):
        pgid = None
    for sig in (signal.SIGTERM, signal.SIGKILL):
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


def run_one(row: dict, timeout: int) -> dict:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    event_id = row["event_id"]
    log_path = LOG_DIR / f"{event_id}.log"
    cmd = [
        sys.executable, str(ROOT / "chief_agent.py"),
        "--asn", row["target_as"],
        "--start", row["start_utc"],
        "--end", row["end_utc"],
        "--mode", "quick",
        "--json-summary",
    ]

    minutes = window_minutes(row.get("start_utc", ""), row.get("end_utc", ""))
    skip_leak = bool(minutes and minutes <= SHORT_WINDOW_MINUTES)
    env = dict(os.environ)
    if skip_leak:
        env["BGPT_RUN_LEAK"] = "0"

    started = time.time()
    with log_path.open("w") as log:
        proc = subprocess.Popen(
            cmd, cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT,
            env=env, start_new_session=True,
        )
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            rc = -9
            kill_tree(proc)

    asn = row["target_as"]
    match = resolve_cache(asn, row.get("start_utc"), row.get("end_utc"),
                          QUICK_DIR, event_id=event_id, allow_same_date=True)
    written = match is not None and match.path.exists() and match.strict
    return {
        "event_id": event_id,
        "returncode": rc,
        "elapsed_s": round(time.time() - started, 1),
        "window_minutes": minutes,
        "leak_skipped": skip_leak,
        "cache_written": written,
        "cache_path": str(match.path) if written else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=2400)
    ap.add_argument("--out", default=str(ROOT / "results" / "eval" / "regen_missing.json"))
    args = ap.parse_args()

    rows = [r for r in load_rows() if needs_cache(r)]
    print(f"events needing a cache: {len(rows)}", flush=True)
    for row in rows:
        minutes = window_minutes(row.get("start_utc", ""), row.get("end_utc", ""))
        print(f"  {row['event_id']:42s} {row['cause']:20s} "
              f"{minutes:7.0f} min  leak={'skip' if minutes and minutes <= SHORT_WINDOW_MINUTES else 'run'}",
              flush=True)

    records = []
    if args.workers > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(run_one, r, args.timeout) for r in rows]
            for fut in as_completed(futures):
                rec = fut.result()
                records.append(rec)
                print(f"  done {rec['event_id']:42s} rc={rec['returncode']} "
                      f"{rec['elapsed_s']}s cache={'yes' if rec['cache_written'] else 'NO'}",
                      flush=True)
    else:
        for row in rows:
            rec = run_one(row, args.timeout)
            records.append(rec)
            print(f"  done {rec['event_id']:42s} rc={rec['returncode']} "
                  f"{rec['elapsed_s']}s cache={'yes' if rec['cache_written'] else 'NO'}",
                  flush=True)

    Path(args.out).write_text(json.dumps({"records": records}, indent=1))
    ok = sum(1 for r in records if r["cache_written"])
    print(f"\nregenerated {ok}/{len(records)}; report -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

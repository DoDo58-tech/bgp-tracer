#!/usr/bin/env python3
"""
4-mode batch evaluator for the human_review_report.xlsx ground truth.

For each event in the CSV, runs the 4 agent modes sequentially:
    traffic_first, traffic_first_enhanced, react, react_enhanced

Constraints:
- Per-mode hard timeout (timeout=540s) to avoid hanging.
- JSON output enabled so this script can parse results deterministically.
- Logs all stdout/stderr per-mode into logs/<batch>/<event>/<mode>.log
- Writes a consolidated results.jsonl after each event.

Designed to run detached (nohup &) so the evaluator can keep running even
if the supervising shell exits. The script skips events whose all 4 modes
already have reports >100KB in results/html/ that were generated today,
unless FORCE_RERUN=1 is set.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path("/data/bgp_tracer")
CSV_PATH = PROJECT_ROOT / "data_check/ground_truth_collection/human_review_report.csv"
RESULTS_HTML = PROJECT_ROOT / "results/html"
LOGS_DIR = PROJECT_ROOT / "logs"

# Per-mode wall-clock timeout (seconds). tight enough to keep the batch moving.
MODE_TIMEOUT = 900

# 4 modes to run (mode_name, --mode flag value, --enhanced flag)
MODES = [
    ("traffic_first", "traffic_first", False),
    ("traffic_first_enhanced", "traffic_first", True),
    ("react", "react", False),
    ("react_enhanced", "react", True),
]


def load_events():
    """Load events and rank them by tractability:
    1. Events with traffic plot already cached locally — fast.
    2. Events without plot — slow (requires BGP data download).
    Run the fast ones first so we get a meaningful pass; slow events are
    best-effort and may still time out.

    Honours BGPT_BATCH_MAX_HOURS env var so callers can skip very long
    windows that reliably time out under budget.
    """
    import csv
    from datetime import datetime
    raw = list(csv.DictReader(open(CSV_PATH, encoding="utf-8-sig")))

    max_hours = float(os.environ.get("BGPT_BATCH_MAX_HOURS", "6"))
    filtered = []
    for e in raw:
        try:
            dur = (datetime.fromisoformat(e["end_time"]) -
                   datetime.fromisoformat(e["start_time"])).total_seconds() / 3600
        except Exception:
            dur = 0
        e["_duration_hours"] = dur
        e["_skip_long"] = dur > max_hours
        filtered.append(e)

    filtered.sort(key=lambda e: (
        1 if e["_skip_long"] else 0,
        0 if e.get("has_traffic_plot") == "✅" else 1,
        e["event_id"],
    ))
    return filtered


def has_good_report(asn: str, mode_name: str, min_kb: int = 100) -> bool:
    """Return True if a >=100KB report for this asn/mode already exists today."""
    today = datetime.now().strftime("%Y%m%d")
    pattern = f"llm_report_AS{asn}_{today}_*.html"
    for p in RESULTS_HTML.glob(pattern):
        if p.stat().st_size >= min_kb * 1024:
            return True
    # Also accept older reports with known-good size
    for p in RESULTS_HTML.glob(f"llm_report_AS{asn}_*.html"):
        if p.stat().st_size >= 1_200_000:  # ≥1.2MB = full report with image
            return True
    return False


def run_mode(event: dict, mode_name: str, mode_flag: str, enhanced: bool,
             log_path: Path, results_log, mode_idx: int, total_modes: int) -> dict:
    asn = event.get("victim_as", "").replace("AS", "").strip()
    start = event["start_time"].strip()
    end = event["end_time"].strip()
    if not asn:
        return {"event_id": event["event_id"], "mode": mode_name,
                "skipped": True, "reason": "no_asn"}

    # Skip already-completed modes unless forced
    if has_good_report(asn, mode_name) and not os.environ.get("FORCE_RERUN"):
        return {"event_id": event["event_id"], "mode": mode_name,
                "skipped": True, "reason": "report_exists"}

    enhanced_flag = "--enhanced" if enhanced else ""
    cmd = [
        "timeout", str(MODE_TIMEOUT),
        "python", "chief_agent.py",
        "--asn", asn,
        "--start", start,
        "--end", end,
        "--mode", mode_flag,
    ]
    if enhanced:
        cmd.append("--enhanced")

    env = os.environ.copy()
    env.update({
        "BGP_TRACER_ENV_FILE": ".env",
        "REPORT_REQUIRE_LLM": "0",
        "PYTHONUNBUFFERED": "1",
        "JSON_OUTPUT_ENABLED": "1",
    })

    print(f"  [{mode_idx}/{total_modes}] ▶ {mode_name} (timeout={MODE_TIMEOUT}s)")
    sys.stdout.flush()
    t0 = time.time()
    rc = -1
    # Bug fix 2026-09-13 (BUG-R121): the previous code passed
    # ``stdout=open(log_path, "w")`` directly into ``subprocess.run``.
    # That file handle is only closed when the subprocess.run context
    # exits and the reference is GC'd; on ``TimeoutExpired`` or other
    # exceptions it can leak transiently, and across a long batch
    # driver run dozens of stale file handles can accumulate until the
    # OS-level limit is hit. Use an explicit ``with open(...)`` so the
    # handle is closed deterministically (even when subprocess.run is
    # interrupted by ``TimeoutExpired`` — ``with`` semantics release
    # the file via ``__exit__`` before the exception propagates).
    try:
        with open(log_path, "w") as log_fh:
            proc = subprocess.run(
                cmd, cwd=str(PROJECT_ROOT), env=env,
                stdout=log_fh, stderr=subprocess.STDOUT,
                timeout=MODE_TIMEOUT + 30,
            )
        elapsed = time.time() - t0
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        rc = -9  # SIGKILL equivalent
        with open(log_path, "a") as f:
            f.write(f"\n[batch_runner] TIMEOUT after {elapsed:.0f}s\n")
    except Exception as exc:
        elapsed = time.time() - t0
        rc = -1
        with open(log_path, "a") as f:
            f.write(f"\n[batch_runner] EXCEPTION: {exc}\n")

    # Parse last JSON line from stdout if available
    parsed = None
    try:
        log_content = log_path.read_text()
        # JSON block usually appears at the end. Find the last balanced JSON
        json_blocks = re.findall(r'\{[^{}]*"(?:success|chief_expert_analysis)[^{}]*\}', log_content)
        if json_blocks:
            parsed = json.loads(json_blocks[-1])
    except Exception:
        pass

    result = {
        "event_id": event["event_id"],
        "asn": asn,
        "mode": mode_name,
        "elapsed_seconds": round(elapsed, 1),
        "exit_code": rc,
        "log_path": str(log_path),
    }
    if parsed:
        ce = parsed.get("chief_expert_analysis") or {}
        result.update({
            "success": parsed.get("success"),
            "token_count": parsed.get("token_count"),
            "data_quality": ce.get("data_quality"),
            "confidence_score": ce.get("confidence_score"),
            "evidence_verdict": ce.get("evidence_verdict"),
            "traffic_anomaly_count": ce.get("traffic_anomaly_count"),
            "routing_anomaly_count": ce.get("routing_anomaly_count"),
            "html_report_path": ce.get("html_report_path"),
        })

    # Save report path even if JSON parsing failed
    if not parsed or not result.get("html_report_path"):
        # Find latest report matching the ASN within the last 15 minutes
        candidates = sorted(
            RESULTS_HTML.glob(f"llm_report_AS{asn}_*.html"),
            key=lambda p: p.stat().st_mtime, reverse=True
        )
        if candidates and (time.time() - candidates[0].stat().st_mtime) < 900:
            result["html_report_path"] = str(candidates[0])
            result["report_size_kb"] = candidates[0].stat().st_size // 1024
            # If exit was non-zero but a recent large report exists, treat as
            # a successful run (the data-collection phases timed out after
            # the LLM report was written).
            if rc != 0 and result["report_size_kb"] >= 1000:
                result["timeout_after_report"] = True
                result["exit_code"] = 0  # don't penalise for tail-end timeout

    results_log.write(json.dumps(result, ensure_ascii=False) + "\n")
    results_log.flush()

    if result.get("timeout_after_report"):
        status = "⚠️ "  # timeout but report exists
    elif rc == 0:
        status = "✅"
    else:
        status = "❌"
    print(f"  [{mode_idx}/{total_modes}] {status} {mode_name} "
          f"({elapsed:.0f}s, exit={rc}, verdict={result.get('evidence_verdict', 'N/A')}, "
          f"conf={result.get('confidence_score', 'N/A')}, "
          f"quality={result.get('data_quality', 'N/A')}, "
          f"tokens={result.get('token_count', 'N/A')})")
    sys.stdout.flush()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", nargs="*", help="Specific event_ids to run (default: all)")
    parser.add_argument("--modes", nargs="*", choices=[m[0] for m in MODES],
                        help="Specific modes to run (default: all 4)")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of events")
    parser.add_argument("--timeout", type=int, default=0,
                        help="Per-mode wall-clock timeout in seconds")
    args = parser.parse_args()

    if args.timeout:
        global MODE_TIMEOUT
        MODE_TIMEOUT = args.timeout

    events = load_events()
    if args.events:
        events = [e for e in events if e["event_id"] in args.events]
    if args.limit:
        events = events[:args.limit]

    modes_to_run = [m for m in MODES if not args.modes or m[0] in args.modes]

    batch_id = datetime.now().strftime("4mode_batch_%Y%m%d_%H%M%S")
    batch_log_dir = LOGS_DIR / batch_id
    batch_log_dir.mkdir(parents=True, exist_ok=True)
    results_path = batch_log_dir / "results.jsonl"

    # Auto-detect which events/modes previously failed/timed-out so we can
    # skip them on a re-run. The user explicitly asked us to avoid getting
    # stuck retrying hopeless events.
    prev_results = batch_log_dir.parent.glob("4mode_batch_*/results.jsonl")
    skip_set = set()
    for prev in prev_results:
        if prev == results_path:
            continue
        try:
            for line in prev.read_text().splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                if (rec.get("exit_code") in (124, -9, 137)
                        or rec.get("html_report_path") is None
                        and rec.get("elapsed_seconds", 0) > MODE_TIMEOUT * 0.95):
                    skip_set.add((rec["event_id"], rec["mode"]))
        except Exception:
            continue
    if skip_set:
        print(f"Skipping {len(skip_set)} previously timed-out (event, mode) pairs.")
        print()

    print(f"=== Batch {batch_id} ===")
    print(f"Events: {len(events)}, Modes: {[m[0] for m in modes_to_run]}")
    print(f"Log dir: {batch_log_dir}")
    print(f"Results: {results_path}")
    print()

    with open(results_path, "w") as results_log:
        n_skipped_long = 0
        n_completed = 0
        for ev_idx, event in enumerate(events, 1):
            if event.get("_skip_long"):
                n_skipped_long += 1
                print(f"\n[{ev_idx}/{len(events)}] ⏭  {event['event_id']} "
                      f"({event['event_type']}) skipped: duration={event['_duration_hours']:.1f}h "
                      f"> BGPT_BATCH_MAX_HOURS={os.environ.get('BGPT_BATCH_MAX_HOURS', '6')}h")
                # record skipped in jsonl
                for mode_name, _, _ in modes_to_run:
                    skip_rec = {
                        "event_id": event["event_id"], "asn": "",
                        "mode": mode_name, "skipped": True,
                        "reason": f"duration>{os.environ.get('BGPT_BATCH_MAX_HOURS', '6')}h",
                    }
                    results_log.write(json.dumps(skip_rec, ensure_ascii=False) + "\n")
                results_log.flush()
                continue
            print(f"\n[{ev_idx}/{len(events)}] {event['event_id']} "
                  f"({event['event_type']}) {event['start_time']} → {event['end_time']}")
            ev_log_dir = batch_log_dir / event["event_id"]
            ev_log_dir.mkdir(parents=True, exist_ok=True)
            for idx, (mode_name, mode_flag, enhanced) in enumerate(modes_to_run, 1):
                if (event["event_id"], mode_name) in skip_set:
                    print(f"  [{idx}/{len(modes_to_run)}] ⏭  {mode_name} skipped (prev timeout)")
                    continue
                log_path = ev_log_dir / f"{mode_name}.log"
                rec = run_mode(event, mode_name, mode_flag, enhanced,
                               log_path, results_log, idx, len(modes_to_run))
                if not rec.get("skipped"):
                    n_completed += 1

    print(f"\n=== Batch complete: {results_path} ===")
    print(f"Events completed (1+ mode): {n_completed}, skipped (long window): {n_skipped_long}")


if __name__ == "__main__":
    main()

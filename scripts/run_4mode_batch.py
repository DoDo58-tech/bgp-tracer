"""2-mode evaluation batch runner."""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detectors.input_validation import InputValidationError, validate_detection_request

DEFAULT_CSV = PROJECT_ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"

# (display_name, --mode value)
# traffic_first derives its routing window from the traffic anomaly cluster
# (plus buffer), so it scans a wider window than react.
MODES = [
    ("traffic_first", "traffic_first"),
    ("react",         "react"),
]

# Per-mode wall-clock timeout (seconds). Covers 8-25 min observed for
# AS12479 + worst-case (long events, large prefix tables).
MODE_TIMEOUT_S = int(os.environ.get("BGPT_MODE_TIMEOUT_S", "2400"))

# Inter-mode / inter-event pacing. The LLM gateway at api.sfkey.cn throttles
INTER_MODE_SLEEP_S = int(os.environ.get("BGPT_INTER_MODE_SLEEP_S", "5"))
INTER_EVENT_SLEEP_S = int(os.environ.get("BGPT_INTER_EVENT_SLEEP_S", "30"))

# 2026-10-08 (r18-token-budget): adaptive inter-event sleep based on
BUDGET_SHARED_FILE = os.environ.get("LLM_BUDGET_SHARED_FILE", "").strip()
BUDGET_MAX_CALLS = int(os.environ.get("LLM_BUDGET_MAX_CALLS", "950"))
BUDGET_WINDOW_S = int(os.environ.get("LLM_BUDGET_WINDOW_S", "18000"))
BUDGET_BACKOFF_S = int(os.environ.get("BGPT_BUDGET_BACKOFF_S", "60"))


def read_budget_used():
    """Read how many LLM calls have been recorded in the budget window.
    
    Returns 0 if the file is missing or unreadable (conservative: don't
    slow down the batch just because we can't read the budget)."""
    if not BUDGET_SHARED_FILE:
        return 0
    try:
        p = Path(BUDGET_SHARED_FILE)
        if not p.exists():
            return 0
        cutoff = time.time() - BUDGET_WINDOW_S
        used = 0
        with open(p, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ts = float(line)
                    if ts >= cutoff:
                        used += 1
                except ValueError:
                    pass
        return used
    except ValueError:
        return 0


def budget_window_oldest_ts():
    """Return the wall-clock timestamp of the oldest call in the budget window."""
    if not BUDGET_SHARED_FILE:
        return 0.0
    try:
        p = Path(BUDGET_SHARED_FILE)
        if not p.exists():
            return 0.0
        cutoff = time.time() - BUDGET_WINDOW_S
        oldest = 0.0
        with open(p, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ts = float(line)
                    if ts >= cutoff and (oldest == 0.0 or ts < oldest):
                        oldest = ts
                except ValueError:
                    pass
        return oldest
    except ValueError:
        return 0.0


def wait_for_budget_window():
    """If budget is critically full, actually wait for the rolling window
    to rotate rather than just sleeping 60s.
    
    When ``pct >= 0.95`` AND the oldest call is recent, we wait until that
    oldest call falls outside the rolling window. Otherwise we'd hit
    ``BudgetExhausted`` immediately on the next subprocess invocation."""
    used = read_budget_used()
    pct = used / BUDGET_MAX_CALLS if BUDGET_MAX_CALLS else 0
    if pct < 0.95:
        return
    oldest = budget_window_oldest_ts()
    if oldest == 0.0:
        return
    # Wait until the oldest call falls outside the rolling window
    wait_until = oldest + BUDGET_WINDOW_S + 5  # +5s safety margin
    wait_s = max(0, wait_until - time.time())
    if wait_s <= 0:
        return
    print(
        f"  ⏳ Budget critical ({pct*100:.0f}% used). "
        f"Waiting {wait_s:.0f}s for window rotation "
        f"(oldest call {oldest:.0f} + {BUDGET_WINDOW_S}s window)."
    )
    # Wait in 30s slices so the operator can see progress
    while wait_s > 0:
        chunk = min(30, wait_s)
        time.sleep(chunk)
        wait_s -= chunk
        # Re-check: maybe more calls have rolled out
        used2 = read_budget_used()
        if used2 < BUDGET_MAX_CALLS * 0.9:
            print(f"  ✓ Budget window has rotated. Resuming.")
            return


def adaptive_event_sleep(idx, total):
    """Sleep between events, scaling the duration by remaining budget."""
    if INTER_EVENT_SLEEP_S <= 0 and BUDGET_BACKOFF_S <= 0:
        return
    used = read_budget_used()
    if used == 0:
        # Fall back to fixed sleep when budget file isn't available
        if INTER_EVENT_SLEEP_S > 0:
            print(f"  [sleep {INTER_EVENT_SLEEP_S}s before next event]")
            time.sleep(INTER_EVENT_SLEEP_S)
        return
    pct = used / BUDGET_MAX_CALLS
    if pct < 0.5:
        sleep_s = INTER_EVENT_SLEEP_S
    elif pct < 0.8:
        sleep_s = INTER_EVENT_SLEEP_S * 2
    elif pct < 0.95:
        sleep_s = INTER_EVENT_SLEEP_S * 4
    else:
        sleep_s = max(BUDGET_BACKOFF_S, INTER_EVENT_SLEEP_S * 4)
    remaining = BUDGET_MAX_CALLS - used
    print(
        f"  [budget {used}/{BUDGET_MAX_CALLS} used ({pct*100:.0f}%); "
        f"{remaining} calls remaining; "
        f"sleeping {sleep_s}s before next event "
        f"({idx+1}/{total})]"
    )
    if pct >= 0.95:
        # When budget is critical, ACTUALLY wait for the rolling window
        wait_for_budget_window()
        return  # already slept
    time.sleep(sleep_s)

# Subprocess env — disables per-mode interactive banner pollution.
SUBPROCESS_ENV_EXTRA = {
    "BGP_TRACER_ENV_FILE": ".env",
    "REPORT_REQUIRE_LLM": "1",
    # Per-attempt timeout capped at 240s in agents/report_agent.py. With
    # the 5 inner retries the worst case per report is 240s * 5 = 20 min.
    "REPORT_LLM_TIMEOUT_S": "240",
    "BGP_TRACER_WORKFLOW_TIMEOUT_S": str(MODE_TIMEOUT_S - 60),
    "PYTHONUNBUFFERED": "1",
    "JSON_OUTPUT_ENABLED": "0",
}


def strip_asn(asn):
    """Strip leading 'AS' / 'as' for the --asn CLI argument."""
    s = (asn or "").strip()
    if s.upper().startswith("AS"):
        s = s[2:]
    return s


def load_events(csv_path: Path):
    rows: list[dict] = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    # Filter to events that are runnable AND have non-empty start/end times.
    def is_runnable(r):
        flag = (r.get("project_detector_runnable") or "").strip().lower()
        if flag in ("false", "0", "no"):
            return False
        if flag in ("true", "1", "yes"):
            return True
        # empty / unset → trust the row (v15 GT has no runnable column populated
        # for events that pass the manual quality bar).
        return True
    rows = [r for r in rows if is_runnable(r)]
    return rows


def find_latest_html(asn, since_ts):
    """Return the path of the most recent HTML report for this ASN."""
    html_dir = PROJECT_ROOT / "results/html"
    candidates = sorted(
        html_dir.glob(f"llm_report_AS{asn}_*.html"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    recent = [p for p in candidates if p.stat().st_mtime >= since_ts - 5]
    if recent:
        return str(recent[0])
    return None


def resolve_target_asn(event: dict):
    """Pick the AS to analyse, and say which field it came from.
    
    Returns (asn_digits, source_field)."""
    etype = (event.get("event_type") or "").strip().lower()
    label = (event.get("ground_truth_cause_label") or "").strip().lower()
    is_leak = etype in {"leak", "route_leak"} or label == "route_leak"

    if is_leak:
        order = ("leak_as", "attacker_as", "victim_as")
    else:
        order = ("victim_as", "attacker_as", "leak_as")

    for field in order:
        value = strip_asn(event.get(field) or "")
        if value:
            return value, field
    return "", ""


def run_one(event, mode_name, mode_flag, log_path):
    """Run chief_agent.py for one (event, mode) and capture result."""
    asn, asn_source = resolve_target_asn(event)
    if not asn:
        return {
            "event_id": event.get("event_id"),
            "mode": mode_name,
            "exit_code": 2,
            "elapsed_seconds": 0,
            "error": "no_target_asn",
            "html_report_path": None,
            "html_size_bytes": 0,
        }

    start = event["start_time_utc"]
    end = event["end_time_utc"]
    if not (start and start.strip()) or not (end and end.strip()):
        return {
            "event_id": event.get("event_id"),
            "mode": mode_name,
            "exit_code": 2,
            "elapsed_seconds": 0,
            "error": "empty_start_end_time",
            "html_report_path": None,
            "html_size_bytes": 0,
        }
    # chief_agent --start expects "YYYY-MM-DD HH:MM" (or ISO). Convert
    # "2024-01-03T14:45:00" → "2024-01-03 14:45" to be safe.
    start_arg = start.replace("T", " ")[:16]
    end_arg = end.replace("T", " ")[:16]

    # Reject an inverted window here rather than letting the subprocess scan
    # an empty range and report "no anomalies found". A dataset row with a
    # transposed window would otherwise score as a detector miss.
    try:
        _asn_chk, _s, _e = validate_detection_request(asn, start_arg, end_arg)
    except InputValidationError as exc:
        return {
            "event_id": event.get("event_id"),
            "mode": mode_name,
            "exit_code": 2,
            "elapsed_seconds": 0,
            "error": f"invalid_window: {exc}",
            "html_report_path": None,
            "html_size_bytes": 0,
            "target_asn": asn,
            "asn_source_field": asn_source,
        }

    cmd = [
        "timeout", str(MODE_TIMEOUT_S),
        sys.executable, "chief_agent.py",
        "--asn", asn,
        "--start", start_arg,
        "--end", end_arg,
        "--mode", mode_flag,
    ]

    env = os.environ.copy()
    env.update(SUBPROCESS_ENV_EXTRA)

    print(f"  ▶ {event['event_id']:42s} {mode_name:25s} ", end="", flush=True)
    t0 = time.time()
    with open(log_path, "w") as f:
        proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), env=env,
                              stdout=f, stderr=subprocess.STDOUT)
    elapsed = time.time() - t0

    html_path = find_latest_html(asn, t0)
    size = Path(html_path).stat().st_size if html_path and Path(html_path).exists() else 0

    # Verdict hierarchy:
    if proc.returncode == 0 and size > 1000:
        verdict = "PASS"
    elif proc.returncode in (124, 143) and size > 500_000:
        verdict = "PARTIAL"
    else:
        verdict = "FAIL"
    print(f"{verdict} exit={proc.returncode} elapsed={elapsed:.0f}s html={size//1024}KB")

    return {
        "event_id": event.get("event_id"),
        "event_type": event.get("event_type"),
        "asn": asn,
        "mode": mode_name,
        "exit_code": proc.returncode,
        "elapsed_seconds": round(elapsed, 1),
        "html_report_path": html_path,
        "html_size_bytes": size,
        "log_path": str(log_path),
        "verdict": verdict,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(DEFAULT_CSV),
                    help="Path to ground-truth CSV")
    ap.add_argument("--limit", type=int, default=0,
                    help="Run only the first N events (debug)")
    ap.add_argument("--event", action="append", default=[],
                    help="Filter to specific event_id(s); may repeat")
    ap.add_argument("--mode", action="append", default=[],
                    help="Filter to specific mode(s); may repeat")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"ERROR: CSV not found: {csv_path}", file=sys.stderr)
        return 2

    events = load_events(csv_path)
    print(f"Loaded {len(events)} events from {csv_path}")
    if args.event:
        events = [e for e in events if e["event_id"] in args.event]
        print(f"Filtered to {len(events)} event(s) by --event")
    if args.limit > 0:
        events = events[:args.limit]
        print(f"Limited to first {len(events)} event(s)")
    if not events:
        print("ERROR: no events to run", file=sys.stderr)
        return 2

    modes = MODES
    if args.mode:
        modes = [m for m in MODES if m[0] in args.mode]
        print(f"Filtered to modes: {[m[0] for m in modes]}")

    ts = time.strftime("%Y%m%d_%H%M%S")
    log_dir = PROJECT_ROOT / "logs" / f"4mode_batch_{ts}"
    log_dir.mkdir(parents=True, exist_ok=True)
    summary_path = log_dir / "summary.log"
    results_path = log_dir / "results.jsonl"
    print(f"\nLog dir: {log_dir}")
    print(f"Results: {results_path}")
    print(f"Modes per event: {[m[0] for m in modes]}")
    print(f"Per-mode timeout: {MODE_TIMEOUT_S}s")
    print(f"Total (event, mode) runs: {len(events) * len(modes)}")
    print()

    summary_lines: list[str] = []
    results: list[dict] = []
    total_t0 = time.time()

    for event in events:
        evt_dir = log_dir / event["event_id"]
        evt_dir.mkdir(exist_ok=True)
        print(f"━━━ Event {event['event_id']} ({event['event_type']}) AS={event.get('victim_as') or event.get('leak_as') or event.get('attacker_as')} ━━━")
        summary_lines.append(f"━━━ Event {event['event_id']} ({event['event_type']}) ━━━")
        for mode_name, mode_flag in modes:
            log_path = evt_dir / f"{mode_name}.log"
            result = run_one(event, mode_name, mode_flag, log_path)
            results.append(result)
            summary_lines.append(
                f"  {mode_name:25s} {result['verdict']:4s} "
                f"exit={result['exit_code']:3d} elapsed={result['elapsed_seconds']:.0f}s "
                f"html={result['html_size_bytes']//1024}KB"
            )
            # Inter-mode sleep: a single LLM-gateway call (report generation)
            if INTER_MODE_SLEEP_S > 0:
                time.sleep(INTER_MODE_SLEEP_S)
        # Inter-event sleep: longer pause between events to fully recover
        adaptive_event_sleep(events.index(event), len(events))

    total_elapsed = time.time() - total_t0

    # Summary
    passed = sum(1 for r in results if r["verdict"] == "PASS")
    failed = sum(1 for r in results if r["verdict"] == "FAIL")
    print(f"\n━━━ Summary ━━━")
    print(f"Total (event, mode) runs: {len(results)}")
    print(f"PASS: {passed}    FAIL: {failed}")
    print(f"Wall clock: {total_elapsed:.0f}s ({total_elapsed/3600:.2f}h)")

    # Write results.jsonl
    with open(results_path, "w") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    # Write summary.log
    with open(summary_path, "w") as f:
        f.write(f"4-mode batch: {len(events)} events × {len(modes)} modes\n")
        f.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Wall clock: {total_elapsed:.0f}s\n\n")
        for line in summary_lines:
            f.write(line + "\n")
        f.write(f"\nTotal runs: {len(results)}  PASS: {passed}  FAIL: {failed}\n")
    print(f"\nResults written to: {results_path}")
    print(f"Summary written to: {summary_path}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
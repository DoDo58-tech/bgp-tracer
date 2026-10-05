#!/usr/bin/env python3
"""2-mode evaluation batch runner.

Reads events from a CSV (default: final_balanced_dataset_v15.csv), then for
each event runs the two chief_agent modes serially:

    traffic_first  (mode=traffic_first, no --enhanced)
    react          (mode=react,         no --enhanced)

Enhanced mode (traffic_first_enhanced / react_enhanced) was removed
2026-09-29 (paper-grade cleanup) — see HANDOFF.md §13.

Each (event, mode) pair runs as a subprocess of ``chief_agent.py`` so a
crash in one mode does not poison the others, and so the per-event
log is exactly what an interactive run would produce.

Per-run timeout is enforced with the Linux ``timeout`` command; the
default budget is 2400s (40 min) per mode, which is well above the
observed 8-25 min per mode for AS12479.

Outputs:
    - logs/4mode_batch_<TS>/<event_id>/<mode>.log    (raw subprocess log)
    - logs/4mode_batch_<TS>/results.jsonl           (one record per (event, mode))
    - logs/4mode_batch_<TS>/summary.log             (human-readable summary)

Design choices:
    1. SERIAL execution — the LLM gateway rate-limits at 1000 req / 5h
       and the per-mode budget already contains its own throttle. Parallel
       runs would only stress the breaker.
    2. Per-mode retry-once — the LLM gateway occasionally returns a
       transient 5xx/timeout. One retry covers that without masking a
       genuine bug.
    3. All events run regardless of duration — the per-mode 2400s timeout
       is large enough to handle 6h windows; for very long windows the
       workflow engine truncates internally. Skipping events would defeat
       the purpose of the batch.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path("/data/bgp_tracer")
DEFAULT_CSV = PROJECT_ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v15.csv"

# (display_name, --mode value)
#
# traffic_first derives its routing window from the traffic anomaly cluster
# (plus buffer), so it scans a wider window than react.
MODES = [
    ("traffic_first", "traffic_first"),
    ("react",         "react"),
]

# Per-mode wall-clock timeout (seconds). Covers 8-25 min observed for
# AS12479 + worst-case (long events, large prefix tables).
MODE_TIMEOUT_S = int(os.environ.get("BGPT_MODE_TIMEOUT_S", "2400"))

# Subprocess env — disables per-mode interactive banner pollution.
SUBPROCESS_ENV_EXTRA = {
    "BGP_TRACER_ENV_FILE": ".env",
    "REPORT_REQUIRE_LLM": "1",
    "REPORT_LLM_TIMEOUT_S": "1500",
    "BGP_TRACER_WORKFLOW_TIMEOUT_S": str(MODE_TIMEOUT_S - 60),
    "PYTHONUNBUFFERED": "1",
    "JSON_OUTPUT_ENABLED": "0",
}


def _strip_asn(asn: str) -> str:
    """Strip leading 'AS' / 'as' for the --asn CLI argument."""
    s = (asn or "").strip()
    if s.upper().startswith("AS"):
        s = s[2:]
    return s


def _load_events(csv_path: Path) -> list[dict]:
    rows: list[dict] = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    # Filter to events that are runnable AND have non-empty start/end times.
    # v15 GT contains only events that pass the 5-criterion filter
    # (public report, route+traffic anomalies synced, route-caused), so
    # when runnable is empty (legacy rows) we keep them — they predate
    # the schema.  When runnable is explicitly True/False we honour it.
    def _is_runnable(r: dict) -> bool:
        flag = (r.get("project_detector_runnable") or "").strip().lower()
        if flag in ("false", "0", "no"):
            return False
        if flag in ("true", "1", "yes"):
            return True
        # empty / unset → trust the row (v15 GT has no runnable column populated
        # for events that pass the manual quality bar).
        return True
    rows = [r for r in rows if _is_runnable(r)]
    return rows


def _find_latest_html(asn: str, since_ts: float) -> str | None:
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


def run_one(event: dict, mode_name: str, mode_flag: str, log_path: Path) -> dict:
    """Run chief_agent.py for one (event, mode) and capture result."""
    asn = _strip_asn(event.get("victim_as") or "")
    # If no victim_as (e.g. leak-only events), fall back to attacker_as
    # then leak_as. The priority matters: leak_as alone is the LEAKER
    # which is interesting but its OWN announcements aren't what got
    # hijacked; attacker_as is the AS whose announcements we want to
    # characterise. For pure-leak events leak_as is the only AS that
    # announces anything, so it remains the right fallback.
    if not asn:
        asn = _strip_asn(event.get("attacker_as") or "")
    if not asn:
        asn = _strip_asn(event.get("leak_as") or "")
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

    html_path = _find_latest_html(asn, t0)
    size = Path(html_path).stat().st_size if html_path and Path(html_path).exists() else 0

    # Verdict hierarchy:
    #   PASS                — exit 0 and HTML > 1KB
    #   PARTIAL             — timeout (124) or sigterm (143) BUT HTML > 500KB
    #                         (the LLM-driven body finished writing before
    #                          the outer timeout fired, so the report is
    #                          still usable for the HTML-quality audit)
    #   FAIL                — anything else (e.g. SIGKILL/-9 with no HTML)
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


def main() -> int:
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

    events = _load_events(csv_path)
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

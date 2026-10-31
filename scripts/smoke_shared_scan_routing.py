"""End-to-end smoke test for the shared-scan routing path.

Runs the routing agent on one event and checks that every detector
produced a real result -- not a skipped placeholder.  This is a smoke
test, not an evaluation: it checks that the plumbing works and that
nothing silently returns "no data".
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

EVENT_ASN = "13335"
EVENT_START = "2025-07-14 00:00:00"
EVENT_END = "2025-07-14 02:00:00"


def main() -> int:
    from agents.impl.routing_impl import run_routing_agent_async

    print(f"[smoke] routing AS{EVENT_ASN} {EVENT_START} -> {EVENT_END}", flush=True)
    t0 = time.time()
    result = asyncio.run(run_routing_agent_async(
        asn=EVENT_ASN,
        start_time=EVENT_START,
        end_time=EVENT_END,
        use_llm=False,
        enable_mitm=False,
        skip_leak=False,
        skip_outage=False,
        skip_forge=True,
    ))
    elapsed = time.time() - t0
    print(f"[smoke] done in {elapsed:.1f}s")

    def count(key):
        v = result.get(key)
        return len(v) if isinstance(v, list) else (0 if v is None else v)

    leak = result.get("leak_analysis") or {}
    outage = result.get("outage_analysis") or {}

    summary = {
        "elapsed_seconds": round(elapsed, 1),
        "success": result.get("success"),
        "origin_hijacked": count("origin_hijacked"),
        "origin_hijacking": count("origin_hijacking"),
        "leak_count": result.get("leak_count"),
        "leak_total_detected": result.get("leak_count_total"),
        "leak_skipped": result.get("leak_analysis_skipped"),
        "leak_data_available": leak.get("data_available"),
        "outage_score": result.get("outage_score"),
        "outage_suspected": result.get("outage_suspected"),
        "outage_skipped": result.get("outage_analysis_skipped"),
        "outage_data_available": outage.get("data_available"),
        "outage_indicators": outage.get("indicators"),
        "outage_event_features": outage.get("event_features"),
    }
    print(json.dumps(summary, indent=2, default=str))

    # A detector that did not run must say so; one that ran must say it
    # had data.  A silent "success with zero findings" is the failure
    # mode this test exists to catch.
    problems = []
    if result.get("leak_analysis_skipped"):
        problems.append("leak was skipped")
    if not leak.get("data_available"):
        problems.append(f"leak reported no data ({leak.get('no_data_reason')!r})")
    if result.get("outage_analysis_skipped"):
        problems.append("outage was skipped")
    if not outage.get("data_available"):
        problems.append(f"outage reported no data ({outage.get('no_data_reason')!r})")
    if result.get("total_prefix_hijacks") is None:
        problems.append("hijack result missing")

    if problems:
        print("\n[smoke] PROBLEMS:")
        for p in problems:
            print(f"  - {p}")
        return 2

    print("\n[smoke] all three detectors produced measured results")
    dest = ROOT / "results" / "eval" / "smoke_shared_scan.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

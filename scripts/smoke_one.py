#!/usr/bin/env python3
"""Smoke-test one event end to end in a given mode.

Used to validate a mode before committing it to the full 4-mode batch, so a
broken mode is caught on a single event instead of after hours of runs.
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path("/data/bgp_tracer")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--asn", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--mode", required=True,
                    choices=["traffic_first", "react"])
    # --enhanced removed 2026-09-29 (paper-grade cleanup)
    ap.add_argument("--timeout", type=int, default=2400)
    args = ap.parse_args()

    import os
    env = os.environ.copy()
    env.update({
        "BGP_TRACER_ENV_FILE": ".env",
        "REPORT_REQUIRE_LLM": "1",
        "REPORT_LLM_TIMEOUT_S": "1500",
        "BGP_TRACER_WORKFLOW_TIMEOUT_S": str(args.timeout - 60),
        "PYTHONUNBUFFERED": "1",
        "JSON_OUTPUT_ENABLED": "0",
    })

    cmd = [
        "timeout", str(args.timeout),
        sys.executable, "chief_agent.py",
        "--asn", args.asn,
        "--start", args.start,
        "--end", args.end,
        "--mode", args.mode,
    ]
    # --enhanced flag removed 2026-09-29 (paper-grade cleanup)

    t0 = time.time()
    proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), env=env)
    print(f"\nexit={proc.returncode} elapsed={time.time() - t0:.0f}s")

    htmls = sorted(
        (PROJECT_ROOT / "results/html").glob(f"llm_report_AS{args.asn}_*.html"),
        key=lambda p: p.stat().st_mtime,
    )
    if htmls:
        latest = htmls[-1]
        print(f"html={latest} ({latest.stat().st_size // 1024}KB)")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())

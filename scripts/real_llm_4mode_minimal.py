#!/usr/bin/env python3
"""Minimal real-LLM 4-mode validation.

Runs all 4 modes against the real CSTCloud LLM for ONE small event (AS12479)
using cached traffic/routing data. Goal: prove the pipeline works end-to-end
for all 4 modes before launching the full batch.

Usage:
    cd /data/bgp_tracer
    python scripts/real_llm_4mode_minimal.py

Outputs:
    - logs/real_llm_minimal_{timestamp}/{mode}.log
    - results/html/real_minimal_{mode}_AS12479.html
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path("/data/bgp_tracer")
CACHE_PATH = PROJECT_ROOT / "results/quick/quick_12479_2024-01-03_1445_2024-01-03_1530.json"

# (display_name, --mode value, --enhanced)
MODES = [
    ("traffic_first",         "traffic_first", False),
    ("traffic_first_enhanced","traffic_first", True),
    ("react",                 "react",          False),
    ("react_enhanced",        "react",          True),
]

# Per-mode wall-clock timeout (seconds). S1-Base-Pro takes 8-25 min per mode
# (RIS download + LLM reasoning + report). Enhanced adds 5-15 min for debate
# + reactive probing + calibrator. 40 min accommodates the worst case observed
# in the 2026-09-16 batch (enhanced mode reached report generation at 39 min).
MODE_TIMEOUT = 2400


def run_mode(display_name: str, mode_flag: str, enhanced: bool, log_dir: Path) -> dict:
    """Run one mode end-to-end against the real LLM using precomputed cache."""
    asn = "12479"
    start = "2024-01-03T14:45:00Z"
    end = "2024-01-03T15:30:00Z"

    log_path = log_dir / f"{display_name}.log"

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
        "REPORT_REQUIRE_LLM": "1",
        "REPORT_LLM_TIMEOUT_S": str(MODE_TIMEOUT),
        "BGP_TRACER_WORKFLOW_TIMEOUT_S": str(MODE_TIMEOUT),
        "PYTHONUNBUFFERED": "1",
    })

    print(f"▶ {display_name} (timeout={MODE_TIMEOUT}s)", flush=True)
    t0 = time.time()
    with open(log_path, "w") as f:
        proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), env=env,
                              stdout=f, stderr=subprocess.STDOUT)
    elapsed = time.time() - t0

    # Find the HTML report (most recent one for this ASN).
    html_path = None
    candidates = sorted(
        PROJECT_ROOT.glob(f"results/html/llm_report_AS{asn}_*.html"),
        key=lambda p: p.stat().st_mtime, reverse=True,
    )
    if candidates:
        # Among reports created after this mode started.
        recent = [p for p in candidates if p.stat().st_mtime >= t0 - 5]
        if recent:
            html_path = str(recent[0])

    result = {
        "mode": display_name,
        "elapsed_seconds": round(elapsed, 1),
        "exit_code": proc.returncode,
        "log_path": str(log_path),
        "html_report_path": html_path,
        "html_size_bytes": Path(html_path).stat().st_size if html_path and Path(html_path).exists() else 0,
    }
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=MODE_TIMEOUT,
                    help="Per-mode timeout (seconds)")
    args = ap.parse_args()

    if not CACHE_PATH.exists():
        print(f"ERROR: precomputed cache not found: {CACHE_PATH}", file=sys.stderr)
        sys.exit(1)

    ts = time.strftime("%Y%m%d_%H%M%S")
    log_dir = PROJECT_ROOT / "logs" / f"real_llm_minimal_{ts}"
    log_dir.mkdir(parents=True, exist_ok=True)
    print(f"Real-LLM minimal validation starting")
    print(f"  Cache:  {CACHE_PATH}")
    print(f"  Logdir: {log_dir}")
    print(f"  Modes:  {[m[0] for m in MODES]}")
    print()

    results = []
    for display_name, mode_flag, enhanced in MODES:
        result = run_mode(display_name, mode_flag, enhanced, log_dir)
        results.append(result)
        hp = result["html_report_path"]
        size = result["html_size_bytes"]
        ok = "✅" if result["exit_code"] == 0 and hp and size > 1000 else "❌"
        print(f"  {ok} {display_name:30s} exit={result['exit_code']:3d} "
              f"elapsed={result['elapsed_seconds']:.0f}s size={size//1024}KB")
        print()

    # Validate reports
    print("=== REPORT CONTENT VALIDATION ===")
    for r in results:
        hp = r.get("html_report_path")
        if not hp or not Path(hp).exists():
            print(f"  ❌ {r['mode']:30s} no html report")
            continue
        with open(hp) as f:
            html = f.read()
        import re
        size_kb = len(html) // 1024
        doctype = html.lower().startswith("<!doctype")
        asn_in = "12479" in html
        placeholder = bool(re.search(r"\[([a-z_][\w.]+)\]", html))
        em_dash = html.count("—")
        sections = len(re.findall(r"<h2>", html))
        is_enhanced = "_enhanced" in r["mode"]
        has_enhanced_section = "Enhanced Analysis" in html
        verdict = ""
        if is_enhanced and not has_enhanced_section:
            verdict = "❌ enhanced missing Enhanced Analysis section"
        elif placeholder:
            verdict = "❌ has [field.path] placeholders"
        elif not doctype:
            verdict = "❌ missing DOCTYPE"
        elif not asn_in:
            verdict = "❌ missing target ASN"
        elif size_kb < 50:
            verdict = "❌ too small"
        else:
            verdict = "✅"
        print(f"  {verdict} {r['mode']:30s} {size_kb:5d}KB sections={sections} "
              f"em-dash={em_dash} doctype={doctype} enhanced_section={has_enhanced_section}")

    # Summary
    print()
    passed = sum(1 for r in results if r.get("html_size_bytes", 0) > 1000 and r["exit_code"] == 0)
    print(f"{passed}/{len(results)} modes passed minimal validation")
    if passed == 4:
        print("ALL 4 MODES PRODUCE VALID HTML ✅")
        sys.exit(0)
    else:
        print(f"SOME MODES FAILED — see logs at {log_dir} ❌")
        sys.exit(1)


if __name__ == "__main__":
    main()

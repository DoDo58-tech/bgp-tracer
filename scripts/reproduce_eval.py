#!/usr/bin/env python3
"""Reproduce paper §6 (Experiments / Evaluation) end-to-end.

Pipeline:
  1. Phase 1 (deterministic) — generate quick caches from ground truth
  2. Phase 2 (LLM narrative)  — generate HTML reports
  3. HCAF vs baselines        — JSONL ablation
  4. Per-event CSV            — table input
  5. Paper §6 figures         — fig7, fig8, fig9

Usage:
  python scripts/reproduce_eval.py                # full run
  python scripts/reproduce_eval.py --skip-phase1  # reuse existing quick caches
  python scripts/reproduce_eval.py --dry-run      # print commands without executing

Env requirements:
  - .env populated with OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL
  - CLOUDFLARE_API_TOKEN (for Cloudflare Radar traffic agent)
  - data/updates_rrc00/*.gz populated for the analysis dates
"""
from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GT = ROOT / "data_check/ground_truth_collection" / "final_balanced_dataset_v17.csv"


def announce(step: str) -> None:
    print(f"\n==> {step}")


def run(cmd: list[str], dry: bool) -> None:
    pretty = " ".join(cmd)
    print(f"   $ {pretty}")
    if not dry:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"   !! command failed (exit={e.returncode}): {pretty}", file=sys.stderr)


def phase1(gt_rows: list[dict], skip: bool, dry: bool) -> None:
    announce("Step 1: Phase 1 (deterministic quick caches)")
    if skip:
        print("    (skipped — reusing existing results/quick/*.json)")
        return
    quick_dir = ROOT / "results" / "quick"
    quick_dir.mkdir(parents=True, exist_ok=True)
    for r in gt_rows:
        # Choose the AS to analyse: victim for hijacks, leaker for leaks, victim for outages.
        asn = r.get("victim_as") or r.get("leak_as") or r.get("attacker_as") or ""
        asn_num = asn.lstrip("AS").strip()
        start = r["start_time_utc"]
        end = r["end_time_utc"]
        if not asn_num:
            print(f"   skip event_id={r['event_id']}: no AS available")
            continue
        # Reuse any existing cache for this AS (multiple naming variants exist on disk)
        existing = list(quick_dir.glob(f"quick_AS{asn_num}_*.json")) + list(quick_dir.glob(f"quick_{asn}_*.json"))
        if existing:
            print(f"   cache exists for AS{asn_num}: {existing[0].name}")
            continue
        cmd = ["python3", str(ROOT / "chief_agent.py"),
               "--asn", asn_num, "--start", start, "--end", end, "--mode", "quick"]
        run(cmd, dry)


def phase2(dry: bool) -> None:
    announce("Step 2: Phase 2 (LLM narrative HTML reports)")
    run(["bash", str(ROOT / "scripts" / "launch_4mode_eval.sh")], dry)


def phase3(dry: bool) -> None:
    announce("Step 3: HCAF vs baselines ablation")
    out = ROOT / "results" / "eval" / "hcaf_vs_baselines_v36.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["python3", str(ROOT / "scripts" / "eval_hcaf_vs_baselines.py"),
           "--csv", str(GT),
           "--quick-dir", str(ROOT / "results" / "quick"),
           "--out", str(out)]
    run(cmd, dry)


def phase4(dry: bool) -> None:
    announce("Step 4: Build per-event CSV")
    run(["python3", str(ROOT / "scripts" / "build_per_event_csv.py")], dry)


def phase5(dry: bool) -> None:
    announce("Step 5: Generate paper §6 figures + supplementary artifacts")
    run(["python3", str(ROOT / "scripts" / "render_paper_figs.py")], dry)
    run(["python3", str(ROOT / "scripts" / "render_paper_figs_p1.py")], dry)
    run(["python3", str(ROOT / "scripts" / "render_paper_figs_p2.py")], dry)
    run(["python3", str(ROOT / "scripts" / "render_case_study.py")], dry)
    run(["python3", str(ROOT / "scripts" / "build_real_subset_csv.py")], dry)
    run(["python3", str(ROOT / "scripts" / "build_sensitivity.py")], dry)
    run(["python3", str(ROOT / "scripts" / "build_threshold_sensitivity.py")], dry)
    run(["python3", str(ROOT / "scripts" / "build_delta_sensitivity.py")], dry)
    run(["python3", str(ROOT / "scripts" / "benchmark_timing.py")], dry)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skip-phase1", action="store_true",
                    help="reuse existing results/quick/*.json")
    ap.add_argument("--dry-run", action="store_true",
                    help="print commands without executing")
    args = ap.parse_args()

    if not GT.exists():
        print(f"FATAL: ground truth not found at {GT}", file=sys.stderr)
        return 1

    with GT.open() as f:
        gt_rows = list(csv.DictReader(f))
    print(f"Loaded {len(gt_rows)} ground-truth events from {GT.name}")

    phase1(gt_rows, args.skip_phase1, args.dry_run)
    phase2(args.dry_run)
    phase3(args.dry_run)
    phase4(args.dry_run)
    phase5(args.dry_run)

    print("\n==> Done. Key outputs:")
    for p in [
        ROOT / "results" / "eval" / "hcaf_vs_baselines_v36.jsonl",
        ROOT / "results" / "eval" / "per_event_v36.csv",
        ROOT / "docs" / "paper" / "figs" / "fig7_eval_overview.pdf",
        ROOT / "docs" / "paper" / "figs" / "fig8_per_cause.pdf",
        ROOT / "docs" / "paper" / "figs" / "fig9_event_direction_heatmap.pdf",
    ]:
        if p.exists():
            size = p.stat().st_size
            print(f"    ✓ {p.relative_to(ROOT)}  ({size:,} bytes)")
        else:
            print(f"    ✗ {p.relative_to(ROOT)}  (not produced)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Audit the 2026-10-02 4-mode batch runs against the ground-truth dataset.

Answers the questions that matter for the 10.2 run, focusing on NON-HTML
issues (the HTML pipeline is being reworked separately):

  * did every ground-truth event actually run?
  * how did each (event, mode) end — pass, timeout, crash, silent?
  * did any run produce a JSON artifact / HTML, and was the HTML a fallback?
  * for the runs that DID produce results, does the diagnosis agree with the
    ground-truth cause label?

Usage::

    python scripts/audit_1002_run.py [run_tag ...]
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GT_CSV = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v13.csv"
RUNS = {
    "095908": ROOT / "logs" / "4mode_batch_20261002_095908",
    "100558": ROOT / "logs" / "4mode_batch_20261002_100558",
}
EVAL_DIRS = {
    "095908": ROOT / "logs" / "20261002_095908_eval4mode",
    "100558": ROOT / "logs" / "20261002_100558_eval4mode",
}
RESULT_RE = re.compile(
    r"▶\s+(?P<event>\S+)\s+(?P<mode>\S+)\s+(?P<status>PASS|FAIL)\s+"
    r"exit=(?P<code>-?\d+)\s+elapsed=(?P<elapsed>\d+)s\s+html=(?P<kb>\d+)KB"
)
EVENT_RE = re.compile(r"Event\s+(?P<event>\S+)\s+\((?P<etype>[^)]*)\)\s+AS=(?P<asn>\S+)")


def load_gt() -> dict:
    rows = list(csv.DictReader(GT_CSV.open(encoding="utf-8")))
    return {r["event_id"]: r for r in rows}


def parse_log(tag: str) -> tuple:
    log = EVAL_DIRS[tag] / "launcher.log"
    if not log.exists():
        return {}, []
    text = log.read_text(errors="replace")
    announced = []
    for m in EVENT_RE.finditer(text):
        announced.append((m.group("event"), m.group("etype"), m.group("asn")))
    results = []
    for m in RESULT_RE.finditer(text):
        results.append({
            "event": m.group("event"),
            "mode": m.group("mode"),
            "status": m.group("status"),
            "code": int(m.group("code")),
            "elapsed": int(m.group("elapsed")),
            "html_kb": int(m.group("kb")),
        })
    return {e: r for e, r in load_gt().items()}, results, announced


def exit_meaning(code: int) -> str:
    return {
        0: "clean exit",
        1: "python exception",
        2: "argparse / bad CLI input",
        124: "TIMEOUT (killed by `timeout`)",
        -9: "SIGKILL — likely OOM-killed",
    }.get(code, f"unknown exit {code}")


def main() -> int:
    gt = load_gt()
    print(f"Ground truth: {len(gt)} events in {GT_CSV.name}\n")

    summary_rows = []
    for tag, rundir in RUNS.items():
        log = EVAL_DIRS[tag] / "launcher.log"
        if not log.exists():
            print(f"[{tag}] no launcher.log")
            continue
        text = log.read_text(errors="replace")
        announced = [(m.group("event"), m.group("etype"))
                     for m in EVENT_RE.finditer(text)]
        results = [
            {
                "event": m.group("event"), "mode": m.group("mode"),
                "status": m.group("status"), "code": int(m.group("code")),
                "elapsed": int(m.group("elapsed")), "html_kb": int(m.group("kb")),
            }
            for m in RESULT_RE.finditer(text)
        ]

        print("=" * 78)
        print(f"RUN {tag}   dir={rundir.name}")
        print("=" * 78)
        declared = 29 * 2
        print(f"events announced : {len(announced)} / 29")
        print(f"(event,mode) runs declared : {declared}")
        print(f"(event,mode) runs reported : {len(results)}   "
              f"=> {declared - len(results)} never reported (batch died mid-run)")
        print(f"results.jsonl written      : "
              f"{'YES' if (rundir / 'results.jsonl').exists() else 'NO  <-- no machine-readable record'}")

        by_code = Counter()
        for r in results:
            key = "PASS" if r["status"] == "PASS" else f"exit={r['code']}"
            by_code[key] += 1
        print("\noutcome breakdown:")
        for key, n in by_code.most_common():
            label = "" if key == "PASS" else f"  ({exit_meaning(int(key.split('=')[1]))})"
            print(f"   {key:>10}: {n:>3}{label}")
        html_ok = sum(1 for r in results if r["html_kb"] > 0)
        print(f"\nHTML produced: {html_ok} / {len(results)} reported runs")
        summary_rows.append((tag, len(results), by_code, html_ok))
        print()

    # ── Per-event coverage across both runs ───────────────────────────────
    print("=" * 78)
    print("PER-EVENT COVERAGE (union of both runs)")
    print("=" * 78)
    seen = defaultdict(list)
    for tag in RUNS:
        log = EVAL_DIRS[tag] / "launcher.log"
        if not log.exists():
            continue
        for m in RESULT_RE.finditer(log.read_text(errors="replace")):
            seen[m.group("event")].append((tag, m.group("mode"), m.group("status"),
                                           int(m.group("code")), int(m.group("kb"))))

    never = [e for e in gt if e not in seen]
    print(f"ground-truth events attempted : {len(seen)} / {len(gt)}")
    print(f"never attempted at all        : {len(never)}")
    for e in never:
        print(f"   - {e}  ({gt[e]['event_type']}, AS{gt[e]['victim_as']})")

    print(f"\n{'event':<42}{'gt_type':<12}{'runs':>5}  detail")
    print("-" * 110)
    for eid, row in gt.items():
        runs = seen.get(eid, [])
        if not runs:
            print(f"{eid:<42}{row['event_type']:<12}{0:>5}  NEVER RAN")
            continue
        detail = "  ".join(
            f"{t[:6]}/{m[:4]}:{'OK' if s=='PASS' else code}{'+'+str(kb)+'KB' if kb else ''}"
            for t, m, s, code, kb in runs
        )
        print(f"{eid:<42}{row['event_type']:<12}{len(runs):>5}  {detail}")

    # ── Ground-truth agreement for runs that produced artifacts ───────────
    print()
    print("=" * 78)
    print("DIAGNOSIS vs GROUND TRUTH (JSON artifacts only)")
    print("=" * 78)
    js = ROOT / "results" / "json"
    agree = Counter()
    rows_out = []
    for f in sorted(js.glob("traffic_outage_analysis_*.json")):
        if f.stat().st_size < 1000:
            continue
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict) or not doc.get("reasoning_result"):
            continue
        asn = str((doc.get("reasoning_result") or {}).get("asn") or "")
        llm_cls = ((doc.get("reasoning_result") or {}).get("llm_classification") or {})
        verdict = ((doc.get("chief_expert_analysis") or {}).get("evidence_verdict") or "")
        inc = llm_cls.get("incident_type") or ""
        # Match ground truth by ASN + date fragment in the filename.
        cand = [r for r in gt.values() if r["victim_as"] == asn]
        if not cand:
            continue
        gt_label = cand[0]["ground_truth_cause_label"]
        rows_out.append((f.name[:44], asn, gt_label, inc, verdict))
        agree[(gt_label, inc or verdict or "(none)")] += 1

    if not rows_out:
        print("no analysable JSON artifacts matched a ground-truth ASN")
    else:
        print(f"{'artifact':<46}{'asn':<8}{'gt_label':<26}{'llm_incident':<26}{'verdict'}")
        print("-" * 130)
        for name, asn, g, inc, verdict in rows_out:
            print(f"{name:<46}{asn:<8}{g:<26}{inc:<26}{verdict}")
        print("\nlabel distribution (gt -> predicted):")
        for (g, p), n in agree.most_common():
            print(f"   {g:<28} -> {p:<28} x{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

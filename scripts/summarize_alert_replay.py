#!/usr/bin/env python3
"""
Summarise the 150-alert Cloudflare Radar replay (2026-10-20 run).

Why this script exists
----------------------
The paper's five-month deployment section originally claimed an
"18.8:1 reduction" from a 150-alert replay. This script recomputes
that claim from the completed run and reports it *together with*
the two confounders that the earlier version omitted:

  1. Coverage. 130/150 alerts were processed; 33 timed out and
     13 hit a subprocess error (64.6% success). Any reduction
     ratio computed over the 150-alert denominator implicitly
     counts timeouts as "correctly suppressed", which is not a
     measurement of the arbitration -- it is a measurement of
     the harness running out of time.

  2. Source confound. All 5 actionable verdicts came from
     source=annotation (curated Cloudflare post-mortems, i.e.
     known-real incidents by construction). The 80 hijack-source
     alerts -- the ones where the question "is this a real
     incident?" is actually open -- produced 0 actionable
     verdicts. Reporting a pooled 18.8:1 hides this entirely.

Both numbers are computed here so the paper can cite the honest
version.

Outputs:
  results/cloudflare_alerts/replay_summary.json

Usage:
  python3 scripts/summarize_alert_replay.py
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS = PROJECT_ROOT / "results" / "cloudflare_alerts"
PER_ALERT = RESULTS / "per_alert_verdict.jsonl"


def wilson_ci(correct: int, n: int, z: float = 1.96):
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 1.0)
    p = correct / n
    denom = 1 + z ** 2 / n
    center = (p + z ** 2 / (2 * n)) / denom
    half = (z / denom) * ((p * (1 - p) / n + z ** 2 / (4 * n ** 2)) ** 0.5)
    return (max(0.0, center - half), min(1.0, center + half))


def main() -> None:
    rows = [json.loads(line) for line in PER_ALERT.open() if line.strip()]

    total = len(rows)
    by_status = Counter(r.get("status") for r in rows)
    by_source = Counter(r.get("source") for r in rows)
    by_verdict = Counter(r.get("quick_verdict") for r in rows)

    processed = [r for r in rows if r.get("status") == "ok"]
    actionable = [r for r in rows if r.get("bgpt_actionable")]

    # --- Per-source breakdown (this is where the confound shows) ---
    per_source = {}
    for src in sorted(by_source):
        src_rows = [r for r in rows if r.get("source") == src]
        src_ok = [r for r in src_rows if r.get("status") == "ok"]
        src_act = [r for r in src_rows if r.get("bgpt_actionable")]
        per_source[src] = {
            "alerts": len(src_rows),
            "processed_ok": len(src_ok),
            "processed_rate": round(len(src_ok) / len(src_rows), 4)
            if src_rows else None,
            "actionable": len(src_act),
            "actionable_rate_of_all": round(len(src_act) / len(src_rows), 4)
            if src_rows else None,
            "actionable_rate_of_processed": round(len(src_act) / len(src_ok), 4)
            if src_ok else None,
            "actionable_asns": sorted({str(r.get("asn")) for r in src_act}),
        }

    # --- Timing ---
    elapsed = sorted(r["elapsed_s"] for r in rows if r.get("elapsed_s"))

    payload = {
        "run_completed": "2026-10-20T07:41:42Z",
        "raw_alerts_enqueued": 150,
        "alerts_written": total,
        "by_status": dict(by_status),
        "by_source": dict(by_source),
        "by_verdict": dict(by_verdict),
        "per_source": per_source,
        "processed_ok": len(processed),
        "coverage_rate": round(len(processed) / total, 4),
        "actionable_total": len(actionable),
        "actionable_rate_of_written": round(len(actionable) / total, 4),
        "actionable_rate_of_processed": round(len(actionable) / len(processed), 4),
        "actionable_wilson_ci95": [
            round(v, 4) for v in wilson_ci(len(actionable), total)
        ],
        "reduction_ratio_raw_to_actionable": round(total / len(actionable), 1)
        if actionable else None,
        "reduction_ratio_processed_to_actionable": round(
            len(processed) / len(actionable), 1) if actionable else None,
        "elapsed_s": {
            "min": elapsed[0] if elapsed else None,
            "median": elapsed[len(elapsed) // 2] if elapsed else None,
            "max": elapsed[-1] if elapsed else None,
        },
        "interpretation": (
            "This replay does NOT support a pooled alert-reduction "
            "claim, and the paper quotes none. Three confounders: "
            "(1) coverage is "
            f"{len(processed)}/{total} = "
            f"{100*len(processed)/total:.1f}%; the timeouts and "
            "subprocess errors are harness failures, not suppressions, "
            "so a raw-alert denominator overstates the arbitration. "
            "(2) actionable verdicts from source=annotation are real "
            "by construction; the hijack-source alerts, where the "
            "incident question is genuinely open, are the "
            "informative ones. (3) the per-record counts the routing "
            "detectors emit are truncated per-event observations, not "
            "operator-facing alarms. The reportable result is a "
            "precision result over the alerts actually adjudicated."
        ),
    }

    out = RESULTS / "replay_summary.json"
    out.write_text(json.dumps(payload, indent=2))

    print(f"alerts written        : {total}")
    print(f"processed ok          : {len(processed)} "
          f"({100*len(processed)/total:.1f}%)")
    print(f"actionable            : {len(actionable)}")
    for src, d in per_source.items():
        print(f"  {src:<11} alerts={d['alerts']:>3} "
              f"ok={d['processed_ok']:>3} "
              f"({100*(d['processed_rate'] or 0):.1f}%) "
              f"actionable={d['actionable']:>2} "
              f"asns={d['actionable_asns']}")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
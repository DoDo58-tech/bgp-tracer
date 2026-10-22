#!/usr/bin/env python3
"""Summarise the Cloudflare Radar alert replay from ``per_alert_verdict.jsonl``.

Why this script exists
----------------------
Earlier versions of this summary hard-coded the size of the replay
(150 enqueued, 130 written, 84 processed, 5 actionable) while the
per-alert verdict log it was supposed to summarise had since grown to
192 submitted records.  A summary that disagrees with its own source
file is worse than no summary, so every count below is now derived from
the JSONL at run time.

The three confounders that any alert-reduction claim must disclose:

  1. Coverage.  Only records with ``status == "ok"`` were actually
     adjudicated.  Timeouts and subprocess errors are *harness
     failures*, not suppressed alerts, so a raw-submitted denominator
     silently counts them as correct suppressions.

  2. Source confound.  Alerts drawn from curated post-mortems
     (``source == "annotation"``) are known-real incidents by
     construction; the hijack/leak alerts are the ones where the
     incident question is genuinely open.  Pooled and per-source rates
     are both reported.

  3. Precision, not reduction, is the reportable quantity: we report
     "of the alerts actually adjudicated, how many were real
     incidents", with a Wilson interval, and give the reduction ratio
     only alongside the denominator it uses.

Outputs:
  results/cloudflare_alerts/replay_summary.json
"""
from __future__ import annotations

import json
import statistics
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
    failed = [r for r in rows if r.get("status") != "ok"]
    actionable = [r for r in rows if r.get("bgpt_actionable")]
    real_incidents = [r for r in rows if r.get("quick_verdict") == "real_incident"]

    # --- Per-source breakdown (this is where the confound shows) ---
    per_source = {}
    for src in sorted(by_source):
        src_rows = [r for r in rows if r.get("source") == src]
        src_ok = [r for r in src_rows if r.get("status") == "ok"]
        src_act = [r for r in src_rows if r.get("bgpt_actionable")]
        per_source[src] = {
            "alerts": len(src_rows),
            "processed_ok": len(src_ok),
            "failed": len(src_rows) - len(src_ok),
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

    def _pct(values, q):
        if not values:
            return None
        idx = min(len(values) - 1, max(0, int(round(q * (len(values) - 1)))))
        return values[idx]

    payload = {
        # Derived from the source file, never hard-coded.  `alerts_written`
        # and `raw_alerts_enqueued` are retained as aliases so older scripts
        # reading this file keep working.
        "alerts_submitted": total,
        "alerts_written": total,
        "raw_alerts_enqueued": total,
        "completed": len(processed),
        "failed": len(failed),
        "processed_ok": len(processed),
        "by_status": dict(by_status),
        "by_source": dict(by_source),
        "by_verdict": dict(by_verdict),
        "per_source": per_source,
        "coverage_rate": round(len(processed) / total, 4) if total else None,
        "actionable_total": len(actionable),
        "real_incident_verdicts": len(real_incidents),
        # Precision over what was actually adjudicated (reportable), and the
        # conservative lower bound that counts every harness failure as a miss.
        "precision_of_completed": round(len(actionable) / len(processed), 4)
        if processed else None,
        "precision_of_completed_wilson_ci95": [
            round(v, 4) for v in wilson_ci(len(actionable), len(processed))
        ],
        "actionable_rate_of_written": round(len(actionable) / total, 4)
        if total else None,
        "actionable_rate_of_processed": round(len(actionable) / len(processed), 4)
        if processed else None,
        "reduction_ratio_submitted_to_actionable": round(total / len(actionable), 1)
        if actionable else None,
        "reduction_ratio_completed_to_actionable": round(
            len(processed) / len(actionable), 1) if actionable else None,
        "elapsed_s": {
            "min": elapsed[0] if elapsed else None,
            "median": round(statistics.median(elapsed), 2) if elapsed else None,
            "p95": _pct(elapsed, 0.95),
            "max": elapsed[-1] if elapsed else None,
            "n": len(elapsed),
        },
        "interpretation": (
            "Coverage is "
            f"{len(processed)}/{total} = {100*len(processed)/total:.1f}%: "
            f"{len(failed)} records are harness failures (timeout / "
            "subprocess error), not suppressed alerts, so any reduction "
            "ratio over the submitted denominator must say so. The "
            "reportable quantity is precision over the adjudicated set "
            f"({len(actionable)}/{len(processed)} = "
            f"{100*len(actionable)/max(len(processed), 1):.1f}%). "
            "Alerts from source=annotation are known-real by construction; "
            "the hijack/leak alerts are the ones where the incident "
            "question is genuinely open, and are reported separately above."
        ),
    }

    out = RESULTS / "replay_summary.json"
    out.write_text(json.dumps(payload, indent=2))

    print(f"alerts submitted      : {total}")
    print(f"completed / failed    : {len(processed)} / {len(failed)} "
          f"({100*len(processed)/total:.1f}% coverage)")
    print(f"actionable            : {len(actionable)}")
    if processed:
        lo, hi = wilson_ci(len(actionable), len(processed))
        print(f"precision (completed) : {len(actionable)}/{len(processed)} = "
              f"{100*len(actionable)/len(processed):.1f}% "
              f"[{100*lo:.1f}, {100*hi:.1f}]")
    for src, d in per_source.items():
        print(f"  {src:<11} alerts={d['alerts']:>3} "
              f"ok={d['processed_ok']:>3} "
              f"({100*(d['processed_rate'] or 0):.1f}%) "
              f"actionable={d['actionable']:>2} "
              f"asns={d['actionable_asns']}")
    print(f"elapsed median / p95  : {payload['elapsed_s']['median']} / "
          f"{payload['elapsed_s']['p95']} s")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
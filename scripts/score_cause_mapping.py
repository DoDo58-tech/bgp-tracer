#!/usr/bin/env python3
"""Score the deterministic cause mapping on the ground-truth corpus.

The agent arm costs ~45 s per event because it runs the LLM stages.  The
*cause* mapping that the evidence chain applies is deterministic, so it
can be scored on the whole corpus in seconds.  This script does that,
and it is the honest way to check a mapping change before paying for
an agent run.

It reports:
  * accuracy of the cause mapping, overall and per true class;
  * the confusion matrix over the corpus's four cause labels;
  * the same for the "traffic signal present" feature, so the value of
    the traffic feature can be seen on its own.

No ground-truth label is ever fed back into the mapping; the mapping
sees only detector output.

Usage:
    python scripts/score_cause_mapping.py
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402
from detectors.evidence_chain_builder import EvidenceChainBuilder  # noqa: E402

GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "cause_mapping_scores.json"


def load_gt():
    rows = list(csv.DictReader(GT_CSV.open()))
    out = []
    for r in rows:
        out.append(
            {
                "event_id": r["event_id"],
                "asn": str(r.get("victim_as") or "").replace("AS", "").strip(),
                "start": (r.get("start_utc") or "").strip(),
                "end": (r.get("end_utc") or "").strip(),
                "gt_cause": (r.get("cause") or "").strip(),
            }
        )
    return out


def main():
    builder = EvidenceChainBuilder()
    records = []
    for ev in load_gt():
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=ev["event_id"], allow_same_date=False,
        )
        if match is None:
            records.append({**ev, "resolved": False})
            continue
        quick = json.loads(match.path.read_text())
        traffic = quick.get("traffic") or {}
        routing = quick.get("routing") or {}
        chain = builder.build(traffic, routing, None, None)
        records.append(
            {
                **ev,
                "resolved": True,
                "pred_cause": chain.cause,
                "verdict": chain.verdict,
                "correct": chain.cause == ev["gt_cause"],
                "traffic_signal": bool(
                    traffic.get("traffic_signal_present")
                    or (traffic.get("anomaly_count") or 0) > 0
                ),
            }
        )

    resolved = [r for r in records if r.get("resolved")]
    correct = [r for r in resolved if r["correct"]]

    confusion: dict[str, Counter] = {}
    for r in resolved:
        confusion.setdefault(r["gt_cause"], Counter())[r["pred_cause"]] += 1

    per_class = {}
    for cls in sorted({r["gt_cause"] for r in resolved}):
        rows = [r for r in resolved if r["gt_cause"] == cls]
        hit = sum(1 for r in rows if r["correct"])
        per_class[cls] = {
            "n": len(rows),
            "correct": hit,
            "accuracy": round(hit / len(rows), 4),
        }

    # How informative is the traffic signal on its own?
    traffic_only = {}
    for cls in sorted({r["gt_cause"] for r in resolved}):
        rows = [r for r in resolved if r["gt_cause"] == cls]
        with_sig = sum(1 for r in rows if r["traffic_signal"])
        traffic_only[cls] = {
            "n": len(rows),
            "with_traffic_signal": with_sig,
            "rate": round(with_sig / len(rows), 4),
        }

    out = {
        "corpus_total": len(records),
        "resolved": len(resolved),
        "accuracy": round(len(correct) / len(resolved), 4) if resolved else None,
        "per_class": per_class,
        "confusion": {k: dict(v) for k, v in confusion.items()},
        "traffic_signal_by_class": traffic_only,
        "records": records,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1))

    print(f"resolved {len(resolved)}/{len(records)}")
    print(f"cause-mapping accuracy: {out['accuracy']}")
    for cls, st in per_class.items():
        print(f"  {cls:24s} {st['correct']}/{st['n']}  ({st['accuracy']})")
    print("\ntraffic-signal presence by class:")
    for cls, st in traffic_only.items():
        print(f"  {cls:24s} {st['with_traffic_signal']}/{st['n']}  ({st['rate']})")
    print("\nconfusion (rows = truth, cols = predicted):")
    for cls, row in confusion.items():
        print(f"  {cls:24s} {dict(row)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

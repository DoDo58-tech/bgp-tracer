"""AEA coverage on the archived quick caches (labels not needed).

Every cache is one measurement window, so this sweep answers a question the
labelled corpus cannot: on real windows, *where* does the estimator stop?
The reason tally is the point of the artefact -- an abstention rate of 1.0 with
``not_exclusive`` at the top says something different from the same rate with
``empty_routing_buckets`` at the top, and only the tally distinguishes them.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.edge_ownership import (  # noqa: E402
    AEA_PROTOCOL,
    UNKNOWN,
    attribute,
    protocol_hash,
)
from scripts.fit_coverage_on_caches import series_for  # noqa: E402


def measure(caches: List[Path], repair: str,
            alpha: float | None = None) -> Dict[str, Any]:
    reasons: Counter = Counter()
    vetoes: Counter = Counter()
    offsets: Counter = Counter()
    committed = 0
    scored = 0
    buckets: List[int] = []
    examples: List[Dict[str, Any]] = []
    protocol_override = {"alpha": alpha} if alpha is not None else None

    for cache in caches:
        r, t, pre_reason, offset = series_for(cache, repair)
        if offset:
            offsets[offset] += 1
        if pre_reason:
            reasons[pre_reason] += 1
            continue
        scored += 1
        buckets.append(int(min(len(r), len(t))))
        v = attribute(r, t, protocol=protocol_override)
        reasons[v.reason] += 1
        for name, state in v.vetoes.items():
            vetoes[f"{name}:{state}"] += 1
        if v.direction != UNKNOWN:
            committed += 1
            if len(examples) < 10:
                examples.append({
                    "cache": cache.name,
                    "direction": v.direction,
                    "lag": v.lag,
                    "p_value": v.p_value,
                    "n_buckets": int(min(len(r), len(t))),
                    "offset_hours": offset,
                })

    return {
        "repair": repair,
        "n_series_built": scored,
        "n_committed": committed,
        "coverage": round(committed / scored, 4) if scored else 0.0,
        "reasons": dict(reasons.most_common()),
        "vetoes": dict(vetoes.most_common()),
        "offsets_applied": {str(k): v for k, v in offsets.most_common()},
        "n_buckets": {
            "min": int(min(buckets)) if buckets else None,
            "median": float(np.median(buckets)) if buckets else None,
            "max": int(max(buckets)) if buckets else None,
        },
        "committed_examples": examples,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick-dir", default=str(ROOT / "results/quick"))
    ap.add_argument("--out", default=str(ROOT / "results/eval/aea_coverage_caches.json"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--alpha", type=float, default=None,
                    help="Override the V2 level to test whether abstention is a "
                         "threshold artefact rather than a data limit.")
    args = ap.parse_args()

    quick = Path(args.quick_dir)
    caches = sorted(quick.glob("quick_*.json"))
    if args.limit:
        caches = caches[: args.limit]

    runs = [measure(caches, "none", args.alpha),
            measure(caches, "auto", args.alpha)]
    out = {"estimator": "AEA", "protocol": AEA_PROTOCOL,
           "protocol_hash": protocol_hash(),
           "alpha_override": args.alpha,
           "n_caches": len(caches), "runs": runs}
    primary = runs[-1] if runs else {}
    n_two = int(primary.get("n_series_built") or 0)
    n_commit = int(primary.get("n_committed") or 0)
    out["coverage_summary"] = {
        "n_caches": len(caches),
        "n_two_series": n_two,
        "n_without_two_series": len(caches) - n_two,
        "n_committed": n_commit,
        "n_stopped_at_first_veto": n_two - n_commit,
        "repair": primary.get("repair"),
        "reasons": primary.get("reasons"),
        "vetoes": primary.get("vetoes"),
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")

    print(f"caches: {len(caches)}   protocol {out['protocol_hash']}")
    for run in runs:
        print(f"\n[repair={run['repair']}]  series built: "
              f"{run['n_series_built']}   committed: {run['n_committed']}")
        if run["n_buckets"]["min"] is not None:
            print(f"  buckets: min={run['n_buckets']['min']} "
                  f"median={run['n_buckets']['median']:.0f} "
                  f"max={run['n_buckets']['max']}")
        if run["offsets_applied"]:
            print(f"  offsets applied (hours -> caches): {run['offsets_applied']}")
        for reason, count in run["reasons"].items():
            print(f"  {reason:<26}{count:>5}")
        for veto, count in run["vetoes"].items():
            print(f"    {veto:<24}{count:>5}")
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

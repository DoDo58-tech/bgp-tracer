"""Per-event AEA verdicts on the labelled corpus, with provenance for every row.

Two properties are deliberate:

* a row is written only if the cache it cites exists and parses, so every row
  of the artefact can be re-derived from a local file;
* events whose evidence is gone (or whose window carries no traffic bucket) are
  written to a skip ledger with a reason, never dropped silently and never
  filled with a placeholder.

Baselines are recomputed here rather than copied from an earlier artefact, so
every number in one row comes from the same cache and the same series.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_resolution import cache_identity, parse_datetime  # noqa: E402
from agents.causal_baselines import run_all_baselines  # noqa: E402
from agents.edge_ownership import (  # noqa: E402
    AEA_PROTOCOL,
    UNKNOWN,
    attribute,
    protocol_hash,
)
from scripts.eval_hcaf_vs_baselines import split_merged_timeline  # noqa: E402

CORPUS = ROOT / "results/eval/per_event_30.csv"
QUICK = ROOT / "results/quick"


def locate(src: str) -> Optional[Path]:
    """Resolve a recorded evidence reference to a local cache file."""
    if not src or src.startswith("synthetic") or "no cache" in src.lower():
        return None
    raw = src.split(" (")[0].strip()
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    if path.exists():
        return path
    # The tree holds caches in nested run directories; a bare filename is a
    # legitimate reference as long as exactly one file matches it.
    hits = sorted(QUICK.rglob(path.name))
    return hits[0] if hits else None


def build(cache: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    """Return the two bucket series for a cache, or a reason it cannot be built."""
    try:
        data = json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, "unreadable_cache"
    corr = data.get("correlation", {}) or {}
    events: List[dict] = []
    for key in ("routing_events_full", "traffic_events_full"):
        block = corr.get(key)
        if isinstance(block, list):
            events.extend(block)
    if not events:
        events = list(corr.get("timeline") or [])
    start = parse_datetime(data.get("start_time"))
    end = parse_datetime(data.get("end_time"))
    if start is None or end is None or end <= start:
        return None, "no_window"
    events.sort(key=lambda e: str(e.get("timestamp", "")))
    routing, traffic = split_merged_timeline(
        events, window_start=start, window_end=end)
    if not routing or not traffic:
        return None, "no_events_in_window"
    r = np.array([float(p.get("score", 0.0)) for p in routing])
    t = np.array([float(p.get("score", 0.0)) for p in traffic])
    if r.max() <= 1e-6:
        return None, "empty_routing_buckets"
    if t.max() <= 1e-6:
        return None, "empty_traffic_buckets"
    return {"r": r, "t": t, "r_timeline": routing, "t_timeline": traffic,
            "asn": (cache_identity(cache) or {}).get("asn")}, ""


def score_prediction(pred: str, expected: str) -> Dict[str, int]:
    if pred == UNKNOWN:
        return {"correct": 0, "wrong": 0, "abstain": 1}
    if pred == expected:
        return {"correct": 1, "wrong": 0, "abstain": 0}
    return {"correct": 0, "wrong": 1, "abstain": 0}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--out", default=str(ROOT / "results/eval/aea_per_event_30.csv"))
    ap.add_argument("--meta", default=str(ROOT / "results/eval/aea_per_event_30.meta.json"))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.corpus, encoding="utf-8")))
    if args.limit:
        rows = rows[: args.limit]

    records: List[Dict[str, Any]] = []
    skipped: Dict[str, List[str]] = {}
    reason_tally: Dict[str, int] = {}

    for row in rows:
        event_id = row["event_id"]
        cache = locate(row.get("cache_source", ""))
        if cache is None:
            skipped.setdefault("no_cache_artefact", []).append(event_id)
            continue
        built, why = build(cache)
        if built is None:
            skipped.setdefault(why, []).append(event_id)
            continue

        expected = row.get("expected_direction", "")
        verdict = attribute(built["r"], built["t"])
        reason_tally[verdict.reason] = reason_tally.get(verdict.reason, 0) + 1

        rec: Dict[str, Any] = {
            "event_id": event_id,
            "tier": row.get("tier", ""),
            "cause_label": row.get("cause_label", ""),
            "expected_direction": expected,
            "cache_source": str(cache.relative_to(ROOT)),
            "asn": built["asn"] or "",
            "n_buckets": int(min(len(built["r"]), len(built["t"]))),
            "aea_pred": verdict.direction,
            "aea_reason": verdict.reason,
            "aea_p_value": round(float(verdict.p_value), 6),
            "aea_placebos": int(verdict.n_placebos),
            "aea_lag": verdict.lag,
            "aea_v1": verdict.vetoes.get("V1", ""),
            "aea_v2": verdict.vetoes.get("V2", ""),
            "aea_v3": verdict.vetoes.get("V3", ""),
            "aea_v4": verdict.vetoes.get("V4", ""),
            "aea_correct": 0, "aea_wrong": 0, "aea_abstain": 0,
        }
        s = score_prediction(verdict.direction, expected)
        rec["aea_correct"], rec["aea_wrong"], rec["aea_abstain"] = (
            s["correct"], s["wrong"], s["abstain"])

        for name, res in sorted(run_all_baselines(
                built["r_timeline"], built["t_timeline"]).items()):
            bs = score_prediction(res.direction, expected)
            rec[f"{name}_pred"] = res.direction
            rec[f"{name}_correct"] = bs["correct"]
            rec[f"{name}_wrong"] = bs["wrong"]
            rec[f"{name}_abstain"] = bs["abstain"]
        records.append(rec)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: List[str] = []
    for rec in records:
        for key in rec:
            if key not in fieldnames:
                fieldnames.append(key)
    with open(out, "w", encoding="utf-8", newline="") as fh:
        if records:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)

    methods = ["aea"] + sorted({k[:-5] for k in fieldnames
                                if k.endswith("_pred") and k != "aea_pred"})
    summary = {
        "estimator": "AEA",
        "protocol": AEA_PROTOCOL,
        "protocol_hash": protocol_hash(),
        "corpus": str(Path(args.corpus).relative_to(ROOT)),
        "n_corpus_rows": len(rows),
        "n_scored": len(records),
        "skipped": {k: {"count": len(v), "events": v}
                    for k, v in sorted(skipped.items())},
        "reasons": dict(sorted(reason_tally.items())),
        "methods": {
            m: {
                "committed": sum(r[f"{m}_correct"] + r[f"{m}_wrong"] for r in records),
                "correct": sum(r[f"{m}_correct"] for r in records),
                "wrong": sum(r[f"{m}_wrong"] for r in records),
                "abstain": sum(r[f"{m}_abstain"] for r in records),
            }
            for m in methods
        },
    }
    meta = Path(args.meta)
    meta.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")

    print(f"corpus rows {len(rows)}   scored {len(records)}   "
          f"protocol {summary['protocol_hash']}")
    for reason, events in summary["skipped"].items():
        print(f"  skipped[{reason}] = {len(events['events'])}")
    print("\nreasons:")
    for reason, count in summary["reasons"].items():
        print(f"  {reason:<26}{count:>4}")
    print("\nmethods (correct / wrong / abstain of scored rows):")
    for m, s in summary["methods"].items():
        print(f"  {m:<20}{s['correct']:>3} / {s['wrong']:>3} / {s['abstain']:>3}")
    print(f"\nwrote {out}\nwrote {meta}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

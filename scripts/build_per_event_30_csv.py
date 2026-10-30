"""Build the canonical per-event CSV from hcaf_vs_baselines_30.jsonl."""
from __future__ import annotations
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "results" / "eval" / "hcaf_vs_baselines_30.jsonl"
OUT_CSV = ROOT / "results" / "eval" / "per_event_30.csv"

METHODS = [
    ("hcaf", "hcaf_direction"),
    ("css", "css_direction"),
    ("pearson", "pearson_direction"),
    ("granger", "granger_direction"),
    ("ts_distance", "ts_distance_direction"),
    ("transfer_entropy", "transfer_entropy_direction"),
]


def is_strict_correct(pred, expected):
    """Strict metric: only an exact direction match counts. Abstain != correct."""
    return pred == expected


def is_abstain(pred):
    return pred in ("unknown", "insufficient")


def is_wrong(pred, expected):
    """A committed direction that does not match is wrong; abstention is neither."""
    return not is_abstain(pred) and not is_strict_correct(pred, expected)


def main():
    EXCLUDE_CAUSES = {"origin_hijack_attacker"}

    rows = []
    with SRC.open() as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("ground_truth_cause_label") in EXCLUDE_CAUSES:
                continue
            expected = rec.get("expected_direction")
            row = {
                "event_id": rec["event_id"],
                "tier": rec["tier"],
                "cause_label": rec["ground_truth_cause_label"],
                "expected_direction": expected,
                "cache_source": Path(rec["cache_source"]).name if rec.get("cache_source") else "synthetic",
                "hcaf_confidence": round(rec.get("hcaf_confidence", 0.0) or 0.0, 4),
                "css_is_causal": rec.get("css_is_causal", False),
                "css_p_value": rec.get("css_p_value", 1.0),
                "post_r2t": round((rec.get("posterior") or {}).get("routing_to_traffic", 0.0), 4),
                "post_t2r": round((rec.get("posterior") or {}).get("traffic_to_routing", 0.0), 4),
                "post_indep": round((rec.get("posterior") or {}).get("independent", 0.0), 4),
            }
            for short, key in METHODS:
                pred = rec.get(key, "unknown") or "unknown"
                row[f"{short}_pred"] = pred
                row[f"{short}_correct"] = int(is_strict_correct(pred, expected))
                row[f"{short}_wrong"] = int(is_wrong(pred, expected))
                row[f"{short}_abstain"] = int(is_abstain(pred))
            rows.append(row)

    if not rows:
        raise SystemExit(f"No records found in {SRC}")

    fieldnames = list(rows[0].keys())
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"Wrote {len(rows)} rows → {OUT_CSV.relative_to(ROOT)}")
    print()
    n = len(rows)
    def is_real(r):
        src = (r.get("cache_source") or "").lower()
        return "synthetic" not in src and not src.startswith("no data")

    real = [r for r in rows if is_real(r)]
    nodata = [r for r in rows if (r.get("cache_source") or "").lower().startswith("no data")]
    print(f"Real-cache events: {len(real)}/{n}"
          + (f"  (no-data rows excluded from every denominator: {len(nodata)})" if nodata else ""))
    print()
    print("Strict directional scoring: an abstention is a cost, never a correct answer.")
    print(f"{'Method':<20} {'corr':>5} {'wrong':>6} {'abs':>5} {'cov':>6} {'sel':>6}  "
          f"{'real corr':>9} {'real wrong':>10} {'real abs':>8}")
    print("-" * 86)
    for short, _ in METHODS:
        c = sum(r[f"{short}_correct"] for r in rows)
        w = sum(r[f"{short}_wrong"] for r in rows)
        a = sum(r[f"{short}_abstain"] for r in rows)
        cov = (c + w) / n if n else 0.0
        sel = c / (c + w) if (c + w) else 0.0
        n_real = len(real)
        cr = sum(r[f"{short}_correct"] for r in real)
        wr = sum(r[f"{short}_wrong"] for r in real)
        ar = sum(r[f"{short}_abstain"] for r in real)
        print(f"{short:<20} {c:>5} {w:>6} {a:>5} {cov:>6.3f} {sel:>6.3f}  "
              f"{cr:>9} {wr:>10} {ar:>8}"
              + (f"   (n={n_real})" if short == METHODS[0][0] else ""))


if __name__ == "__main__":
    main()
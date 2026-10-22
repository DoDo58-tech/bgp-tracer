#!/usr/bin/env python3
"""
V22 Multi-Dimensional Evaluation Framework.

Implements the 8-tier metric dashboard described in
``docs/V22_EVAL_DESIGN.md``. Replaces the v20 evaluation's
opaque "strict-precision" and "macro-F1" with named,
diagnostic metrics.

Usage:
  python scripts/v22_evaluate.py --gt v22
  python scripts/v22_evaluate.py --gt all
"""
from __future__ import annotations
import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import importlib
import agents.report_agent as ra
importlib.reload(ra)
compute_top_cause = ra.compute_top_cause
_normalize_routing = ra._normalize_routing
_normalize_traffic = ra._normalize_traffic
_normalize_correlation = ra._normalize_correlation

EVAL_DIR = ROOT / "results" / "eval_v22"
EVAL_DIR.mkdir(parents=True, exist_ok=True)
QUICK_DIR = ROOT / "results" / "quick"
FIGS_DIR = EVAL_DIR / "figures"
FIGS_DIR.mkdir(parents=True, exist_ok=True)
GT_FILES = {
    "v17": ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v17.csv",
    "v18": ROOT / "data_check/ground_truth_collection/final_balanced_v18_30.csv",
    "v19": ROOT / "data_check/ground_truth_collection/final_balanced_v19_40.csv",
    "v20": ROOT / "data_check/ground_truth_collection/final_balanced_v20.csv",
    "v21": ROOT / "data_check/ground_truth_collection/final_balanced_v21.csv",
    "v22": ROOT / "data_check/ground_truth_collection/final_balanced_v22.csv",
}

# Negative controls are events that should NOT trigger any
# detector — a normal day for the AS, no traffic anomaly, no
# routing event. We don't have any such events in our GT (every
# GT event has both a traffic and a routing signal). To test
# the negative-control path, we synthesize a small set of
# negative controls from the v22 GT by selecting events that
# have a *weak* traffic signal (count < 5) — the system should
# still get them right because the routing signal is strong,
# so this is not a true negative control.
#
# Conclusion: NEG_CONTROLS is empty for v22. We retain the
# infrastructure for future use.
NEG_CONTROLS: set = set()

# Canonical cause classes
CAUSE_CLASSES = ["outage", "route_leak", "origin_hijack_victim", "roa_misconfig", "no_clear_anomaly", "traffic_anomaly_only", "origin_hijack_attacker", "independent_coincidence"]


def load_gt(gt_name):
    p = GT_FILES[gt_name]
    if not p.exists():
        raise FileNotFoundError(f"GT file not found: {p}")
    return p, list(csv.DictReader(open(p)))


def _resolve_target_as(row):
    """Resolve the cache's target AS (victim for hijack, leaker for leak)."""
    etype = (row.get("event_type") or "").strip().lower()
    label = (row.get("ground_truth_cause_label") or row.get("cause") or "").strip().lower()
    is_leak = etype in {"leak", "route_leak"} or label in ("route_leak", "leak")
    order = ("leak_as", "attacker_as", "victim_as") if is_leak else (
        "victim_as", "attacker_as", "leak_as")
    for field in order:
        v = (row.get(field) or "").replace("AS", "").strip()
        if v:
            return v
    return ""


def _find_quick(event_id, asn, date):
    """Find the quick cache with the most routing signal for the date."""
    import re
    candidates = list(QUICK_DIR.glob(f"quick_{asn}_*.json"))
    if not candidates:
        return None
    # Filter by date
    matching = []
    for c in candidates:
        m = re.match(r"quick_\d+_(\d{4}-\d{2}-\d{2})", c.name)
        if m and m.group(1) == date:
            matching.append(c)
    if not matching:
        return None
    # Pick the one with the strongest signal
    def _score(p):
        try:
            c = json.load(open(p))
        except Exception:
            return 0
        r = c.get("routing") or {}
        # Count unique signal types
        sigs = 0
        if r.get("origin_hijacked") or r.get("forge_hijacked"):
            sigs += 1
        if r.get("origin_hijacking") or r.get("forge_hijacking"):
            sigs += 1
        if r.get("route_leaks"):
            sigs += 1
        if r.get("outage_suspected") or (r.get("outage_score") or 0) >= 0.2:
            sigs += 1
        return (
            sigs * 10000
            + len(r.get("origin_hijacked") or [])
            + len(r.get("origin_hijacking") or [])
            + len(r.get("forge_hijacked") or [])
            + len(r.get("forge_hijacking") or [])
            + len(r.get("route_leaks") or [])
        )
    matching.sort(key=_score, reverse=True)
    return matching[0]


def evaluate_event(row, has_cache):
    """Run v22 evaluation on one event. Returns dict of per-event metrics."""
    eid = row["event_id"]
    gt_cause = row.get("ground_truth_cause_label") or row.get("cause", "")
    gt_subtype = row.get("ground_truth_root_cause_subtype") or row.get("subtype", "")
    asn = _resolve_target_as(row)
    date = row["date"]
    is_nc = eid in NEG_CONTROLS

    out = {
        "event_id": eid,
        "gt_cause": gt_cause,
        "gt_subtype": gt_subtype,
        "is_negative_control": is_nc,
        "has_cache": has_cache,
    }

    if not has_cache:
        out.update({
            "predicted_cause": "no_cache",
            "predicted_confidence": 0.0,
            "top3_causes": [],
            "cause_correct": None,
            "cause_top3_hit": None,
            "rank_of_gt": None,
            "hijack_count": 0, "hijacking_count": 0, "leak_count": 0,
            "leak_well_evidenced": 0, "outage_suspected": False, "outage_score": 0.0,
            "traffic_anomaly_count": 0, "traffic_success": False,
        })
        return out

    cache_file = _find_quick(eid, asn, date)
    if cache_file is None:
        out.update({
            "predicted_cause": "no_cache_found",
            "predicted_confidence": 0.0,
            "cause_correct": None,
            "cause_top3_hit": None,
            "rank_of_gt": None,
        })
        return out

    cache = json.load(open(cache_file))
    routing_raw = cache.get("routing") or {}
    traffic_raw = cache.get("traffic") or {}
    correlation_raw = cache.get("correlation") or {}
    hcaf_dir = routing_raw.get("hcaf_direction", "") if isinstance(routing_raw, dict) else ""

    routing_norm = ra._normalize_routing(routing_raw) if routing_raw else {}
    traffic_norm = ra._normalize_traffic(traffic_raw) if traffic_raw else {}
    correlation_norm = ra._normalize_correlation(correlation_raw, hcaf_attribution={"direction": hcaf_dir} if hcaf_dir else None) if correlation_raw else {"temporal_proximity": "none", "confidence": 0.0}

    try:
        verdict = ra.compute_top_cause(
            routing_norm, traffic_norm, correlation_norm,
            target_as=asn,
            hcaf_direction=hcaf_dir,
        )
        pred_cause = verdict.get("cause", "unknown")
        pred_conf = float(verdict.get("confidence", 0.0) or 0.0)
        top3_raw = verdict.get("ranked", [])
        if top3_raw and isinstance(top3_raw[0], dict):
            top3 = [(c["cause"], c["confidence"]) for c in top3_raw]
        elif top3_raw and isinstance(top3_raw[0], (list, tuple)):
            top3 = [(c[0], c[2]) for c in top3_raw]
        else:
            top3 = []
    except Exception as e:
        pred_cause = "error"
        pred_conf = 0.0
        top3 = []
        out["verdict_error"] = str(e)[:200]

    # Cause attribution
    if is_nc:
        cause_correct = pred_cause in ("no_clear_anomaly", "traffic_anomaly_only")
    else:
        cause_correct = (pred_cause == gt_cause)
    cause_top3_hit = gt_cause in [c[0] for c in top3] if top3 else None
    rank_of_gt = None
    for i, (c, _) in enumerate(top3):
        if c == gt_cause:
            rank_of_gt = i + 1
            break

    # Detector counts
    hijack_count = sum(len(routing_norm.get(k, []) or []) for k in ("origin_hijacked", "forge_hijacked"))
    hijacking_count = sum(len(routing_norm.get(k, []) or []) for k in ("origin_hijacking", "forge_hijacking"))
    leak_count_raw = int(routing_norm.get("leak_count") or 0)
    # Compute well-evidenced leak count
    leak_list = routing_norm.get("route_leaks") or []
    leak_well = _count_well_evidenced(leak_list)
    outage_suspected = bool(routing_norm.get("outage_suspected"))
    outage_score = float(routing_norm.get("outage_score") or 0.0)
    traffic_anomaly_count = int(traffic_norm.get("anomaly_count") or 0)
    traffic_success = bool(traffic_norm.get("success"))

    out.update({
        "cache_file": str(cache_file),
        "predicted_cause": pred_cause,
        "predicted_confidence": pred_conf,
        "top3_causes": [c[0] for c in top3],
        "cause_correct": cause_correct,
        "cause_top3_hit": cause_top3_hit,
        "rank_of_gt": rank_of_gt,
        "hijack_count": hijack_count,
        "hijacking_count": hijacking_count,
        "leak_count": leak_count_raw,
        "leak_well_evidenced": leak_well,
        "outage_suspected": outage_suspected,
        "outage_score": outage_score,
        "traffic_anomaly_count": traffic_anomaly_count,
        "traffic_success": traffic_success,
    })
    return out


def _count_well_evidenced(leak_list):
    """Count leak events with real evidence (prefix + AS-path)."""
    if not leak_list:
        return 0
    if isinstance(leak_list[0], str):
        return sum(
            1 for s in leak_list
            if isinstance(s, str)
            and not (
                "affected_prefixes=[]" in s
                and "affected_asns=[]" in s
                and "claimed_as=None" in s
                and "victim_as=None" in s
            )
        )
    elif isinstance(leak_list[0], dict):
        return sum(
            1 for e in leak_list
            if e.get("prefix") or e.get("origin-as") or e.get("origin_as")
            or e.get("as-path") or e.get("as_path")
            or e.get("affected_prefixes") or e.get("affected_asns")
            or e.get("claimed_as") or e.get("victim_as")
        )
    return 0


# ============================================================================
# Tier 1: Cause Attribution
# ============================================================================
def tier1_cause(results):
    """Returns dict of cause-attribution metrics."""
    evaluable = [r for r in results if r["cause_correct"] is not None]
    n = len(evaluable)
    if n == 0:
        return {"n": 0, "metrics": {}}

    # Top-1
    n_correct = sum(1 for r in evaluable if r["cause_correct"])
    top1 = n_correct / n

    # Top-3
    n_top3 = sum(1 for r in evaluable if r["cause_top3_hit"])
    top3 = n_top3 / n

    # Per-class precision, recall, F1
    per_class = {}
    for cls in CAUSE_CLASSES:
        tp = sum(1 for r in evaluable if r["gt_cause"] == cls and r["predicted_cause"] == cls)
        fp = sum(1 for r in evaluable if r["gt_cause"] != cls and r["predicted_cause"] == cls)
        fn = sum(1 for r in evaluable if r["gt_cause"] == cls and r["predicted_cause"] != cls)
        support = sum(1 for r in evaluable if r["gt_cause"] == cls)
        p = tp / max(1, tp + fp)
        rc = tp / max(1, support)
        f1 = 2 * p * rc / max(1e-9, p + rc)
        per_class[cls] = {"precision": p, "recall": rc, "f1": f1, "support": support, "tp": tp, "fp": fp, "fn": fn}

    macro_f1 = sum(per_class[c]["f1"] for c in CAUSE_CLASSES if per_class[c]["support"] > 0) / max(1, sum(1 for c in CAUSE_CLASSES if per_class[c]["support"] > 0))

    # Balanced accuracy: per-class accuracy, averaged
    class_accuracies = []
    for cls in CAUSE_CLASSES:
        if per_class[cls]["support"] == 0:
            continue
        cls_correct = sum(1 for r in evaluable if r["gt_cause"] == cls and r["predicted_cause"] == cls)
        class_accuracies.append(cls_correct / per_class[cls]["support"])
    balanced_acc = sum(class_accuracies) / max(1, len(class_accuracies))

    # Confusion pairs
    confusion = Counter()
    for r in evaluable:
        if r["gt_cause"] != r["predicted_cause"]:
            confusion[(r["gt_cause"], r["predicted_cause"])] += 1

    return {
        "n": n,
        "top1_accuracy": top1,
        "top3_hit_rate": top3,
        "macro_f1": macro_f1,
        "balanced_accuracy": balanced_acc,
        "per_class": {c: per_class[c] for c in CAUSE_CLASSES if per_class[c]["support"] > 0},
        "top_confusion_pairs": [
            {"true": k[0], "pred": k[1], "count": v}
            for k, v in confusion.most_common(10)
        ],
    }


# ============================================================================
# Tier 2: Detection Coverage
# ============================================================================
def tier2_detection(results):
    """Returns dict of detector coverage metrics."""
    evaluable = [r for r in results if r["has_cache"]]

    # Recall per GT cause
    det_outage_recall = 0.0
    det_leak_recall = 0.0
    det_hijack_recall = 0.0
    n_outage_gt = sum(1 for r in evaluable if r["gt_cause"] == "outage")
    n_leak_gt = sum(1 for r in evaluable if r["gt_cause"] == "route_leak")
    n_hijack_gt = sum(1 for r in evaluable if r["gt_cause"] == "origin_hijack_victim")

    if n_outage_gt > 0:
        det_outage_recall = sum(
            1 for r in evaluable
            if r["gt_cause"] == "outage" and (r["outage_suspected"] or r["outage_score"] >= 0.2)
        ) / n_outage_gt
    if n_leak_gt > 0:
        det_leak_recall = sum(
            1 for r in evaluable
            if r["gt_cause"] == "route_leak" and r["leak_well_evidenced"] >= 1
        ) / n_leak_gt
    if n_hijack_gt > 0:
        det_hijack_recall = sum(
            1 for r in evaluable
            if r["gt_cause"] == "origin_hijack_victim" and r["hijack_count"] >= 1
        ) / n_hijack_gt

    # Global traffic recall
    n_total = len(evaluable)
    n_traffic = sum(1 for r in evaluable if r["traffic_anomaly_count"] >= 1 and r["traffic_success"])
    traffic_recall = n_traffic / max(1, n_total)

    # Detector precision: among events where detector fires, fraction with matching GT
    leak_fired = [r for r in evaluable if r["leak_well_evidenced"] >= 10]
    hijack_fired = [r for r in evaluable if r["hijack_count"] >= 10]
    leak_precision = sum(1 for r in leak_fired if r["gt_cause"] == "route_leak") / max(1, len(leak_fired))
    hijack_precision = sum(1 for r in hijack_fired if r["gt_cause"] == "origin_hijack_victim") / max(1, len(hijack_fired))

    return {
        "n_total": n_total,
        "outage_recall": det_outage_recall,
        "leak_recall": det_leak_recall,
        "hijack_recall": det_hijack_recall,
        "traffic_recall": traffic_recall,
        "leak_precision": leak_precision,
        "hijack_precision": hijack_precision,
        "n_outage_gt": n_outage_gt,
        "n_leak_gt": n_leak_gt,
        "n_hijack_gt": n_hijack_gt,
        "n_leak_fired": len(leak_fired),
        "n_hijack_fired": len(hijack_fired),
    }


# ============================================================================
# Tier 3: Hypothesis Ranking Quality
# ============================================================================
def tier3_ranking(results):
    """Returns dict of ranking quality metrics."""
    evaluable = [r for r in results if r["rank_of_gt"] is not None]
    n = len(evaluable)
    if n == 0:
        return {"n": 0, "ndcg_at_3": 0.0, "mrr": 0.0}

    # NDCG@3
    dcg = 0.0
    idcg = 0.0
    mrr_sum = 0.0
    for r in evaluable:
        rank = r["rank_of_gt"]
        rel = 1.0 if rank == 1 else (0.5 if rank <= 3 else 0.0)
        dcg += rel / math.log2(rank + 1)
        idcg += 1.0 / math.log2(2)  # ideal: rank 1
        mrr_sum += 1.0 / rank
    ndcg = dcg / max(1e-9, idcg)
    mrr = mrr_sum / n
    return {"n": n, "ndcg_at_3": ndcg, "mrr": mrr}


# ============================================================================
# Tier 4: Severity / Confidence Calibration
# ============================================================================
def tier4_calibration(results):
    """Returns dict of calibration metrics."""
    evaluable = [r for r in results if r["cause_correct"] is not None]
    n = len(evaluable)
    if n == 0:
        return {"n": 0, "ece": 0.0, "brier": 0.0, "overconf_rate": 0.0}

    # ECE: bin predictions by confidence, compute accuracy per bin
    bins = [(0.0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.01)]
    ece = 0.0
    brier = 0.0
    overconf = 0
    for r in evaluable:
        conf = r["predicted_confidence"]
        is_correct = 1.0 if r["cause_correct"] else 0.0
        # Brier
        brier += (conf - is_correct) ** 2
        # Over-confident wrong
        if conf > 0.85 and not r["cause_correct"]:
            overconf += 1
    brier /= n
    overconf_rate = overconf / n

    # ECE
    for lo, hi in bins:
        bin_rows = [r for r in evaluable if lo <= r["predicted_confidence"] < hi]
        if not bin_rows:
            continue
        bin_acc = sum(1 for r in bin_rows if r["cause_correct"]) / len(bin_rows)
        bin_conf = sum(r["predicted_confidence"] for r in bin_rows) / len(bin_rows)
        ece += (len(bin_rows) / n) * abs(bin_acc - bin_conf)
    return {
        "n": n, "ece": ece, "brier": brier, "overconf_rate": overconf_rate,
    }


# ============================================================================
# Tier 5: Robustness
# ============================================================================
def tier5_robustness(results):
    """Returns dict of robustness metrics across hard cases."""
    no_traffic = [r for r in results if r["has_cache"] and (not r["traffic_success"] or r["traffic_anomaly_count"] == 0)]
    with_traffic = [r for r in results if r["has_cache"] and r["traffic_success"] and r["traffic_anomaly_count"] >= 1]
    withdrawal = [r for r in results if r["has_cache"] and r["leak_count"] >= 1000]
    hijack_dom = [r for r in results if r["has_cache"] and r["hijack_count"] >= 100 and r["hijack_count"] > r["leak_well_evidenced"]]
    neg_ctrl = [r for r in results if r["is_negative_control"] and r["cause_correct"] is not None]

    def acc(rs):
        if not rs:
            return None
        n = len(rs)
        nc = sum(1 for r in rs if r["cause_correct"])
        return nc / n

    return {
        "no_traffic": {"n": len(no_traffic), "accuracy": acc(no_traffic)},
        "with_traffic": {"n": len(with_traffic), "accuracy": acc(with_traffic)},
        "withdrawal_storm": {"n": len(withdrawal), "accuracy": acc(withdrawal)},
        "hijack_dominant": {"n": len(hijack_dom), "accuracy": acc(hijack_dom)},
        "negative_control": {"n": len(neg_ctrl), "accuracy": acc(neg_ctrl)},
    }


# ============================================================================
# Tier 6: Operational Cost
# ============================================================================
def tier6_cost(results):
    """Returns dict of operational cost metrics."""
    evaluable = [r for r in results if r["has_cache"]]
    if not evaluable:
        return {"n": 0, "detectors_fired_avg": 0.0}
    detectors = []
    for r in evaluable:
        n = 0
        if r["hijack_count"] > 0 or r["hijacking_count"] > 0 or r["leak_well_evidenced"] > 0 or r["outage_suspected"]:
            n += 1
        if r["traffic_success"] and r["traffic_anomaly_count"] > 0:
            n += 1
        # HCAF is not always in cache
        detectors.append(n)
    return {
        "n": len(evaluable),
        "detectors_fired_avg": sum(detectors) / len(detectors),
    }


# ============================================================================
# Composite Score
# ============================================================================
def composite(t1, t2, t3, t4, t5):
    """Weighted combination of key metrics. Weights documented in eval design."""
    brier_norm = max(0.0, 1.0 - t4.get("brier", 0.0))  # 0 brier → 1, 1 brier → 0
    return (
        0.30 * t1.get("balanced_accuracy", 0.0)
        + 0.20 * t1.get("macro_f1", 0.0)
        + 0.20 * brier_norm
        + 0.15 * t2.get("traffic_recall", 0.0)
        + 0.10 * t2.get("hijack_recall", 0.0)
        + 0.05 * (t5.get("negative_control", {}).get("accuracy") or 0.0)
    )


# ============================================================================
# Markdown Audit Report
# ============================================================================
def render_audit_md(gt_name, t1, t2, t3, t4, t5, t6, comp):
    md = []
    md.append(f"# V22 Evaluation — {gt_name}\n")
    md.append(f"## Tier 1: Cause Attribution\n")
    md.append(f"- **Top-1 Accuracy:** {t1['top1_accuracy']:.3f}")
    md.append(f"- **Top-3 Hit Rate:** {t1['top3_hit_rate']:.3f}")
    md.append(f"- **Macro-F1:** {t1['macro_f1']:.3f}")
    md.append(f"- **Balanced Accuracy:** {t1['balanced_accuracy']:.3f}\n")
    md.append(f"| Class | Precision | Recall | F1 | Support |")
    md.append(f"|---|---|---|---|---|")
    for cls, m in sorted(t1["per_class"].items(), key=lambda x: -x[1]["support"]):
        md.append(f"| {cls} | {m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} | {m['support']} |")
    md.append("")
    if t1["top_confusion_pairs"]:
        md.append(f"**Top confusion pairs:**\n")
        for p in t1["top_confusion_pairs"][:5]:
            md.append(f"- {p['true']} → {p['pred']}: {p['count']} events")
        md.append("")

    md.append(f"## Tier 2: Detection Coverage\n")
    md.append(f"- **Outage Detector Recall:** {t2['outage_recall']:.3f} ({t2['n_outage_gt']} GT events)")
    md.append(f"- **Leak Detector Recall:** {t2['leak_recall']:.3f} ({t2['n_leak_gt']} GT events)")
    md.append(f"- **Hijack Detector Recall:** {t2['hijack_recall']:.3f} ({t2['n_hijack_gt']} GT events)")
    md.append(f"- **Traffic Detector Recall:** {t2['traffic_recall']:.3f} ({t2['n_total']} events)")
    md.append(f"- **Leak Precision:** {t2['leak_precision']:.3f} ({t2['n_leak_fired']} events where leak fired)")
    md.append(f"- **Hijack Precision:** {t2['hijack_precision']:.3f} ({t2['n_hijack_fired']} events where hijack fired)\n")

    md.append(f"## Tier 3: Hypothesis Ranking Quality\n")
    md.append(f"- **NDCG@3:** {t3['ndcg_at_3']:.3f}")
    md.append(f"- **MRR:** {t3['mrr']:.3f}\n")

    md.append(f"## Tier 4: Calibration\n")
    md.append(f"- **ECE:** {t4['ece']:.3f} (lower is better)")
    md.append(f"- **Brier Score:** {t4['brier']:.3f} (lower is better)")
    md.append(f"- **Over-confident Wrong Rate:** {t4['overconf_rate']:.3f} (lower is better)\n")

    md.append(f"## Tier 5: Robustness\n")
    for k, v in t5.items():
        if v["n"] > 0:
            md.append(f"- **{k}**: n={v['n']}, acc={v['accuracy']:.3f}")
    md.append("")

    md.append(f"## Tier 6: Operational Cost\n")
    md.append(f"- **Detectors fired per event:** {t6['detectors_fired_avg']:.2f}\n")

    md.append(f"## Composite Score: **{comp:.3f}**\n")
    return "\n".join(md)


# ============================================================================
# Main
# ============================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default="v22", choices=list(GT_FILES.keys()) + ["all"])
    args = ap.parse_args()
    if args.gt == "all":
        for gt_name in ["v19", "v20", "v21", "v22"]:
            print()
            print("#" * 70)
            print(f"### Evaluating {gt_name} ###")
            print("#" * 70)
            args.gt = gt_name
            _run_eval(args)
        return
    _run_eval(args)


def _run_eval(args):
    gt_path, events = load_gt(args.gt)
    print(f"GT: {gt_path} ({len(events)} events)")

    results = []
    for e in events:
        eid = e["event_id"]
        asn = _resolve_target_as(e)
        date = e["date"]
        cache = _find_quick(eid, asn, date)
        r = evaluate_event(e, has_cache=cache is not None)
        results.append(r)

    # Compute tiers
    t1 = tier1_cause(results)
    t2 = tier2_detection(results)
    t3 = tier3_ranking(results)
    t4 = tier4_calibration(results)
    t5 = tier5_robustness(results)
    t6 = tier6_cost(results)
    comp = composite(t1, t2, t3, t4, t5)

    # Write per-event CSV
    csv_path = EVAL_DIR / f"per_event_{args.gt}.csv"
    if results:
        keys = []
        for r in results:
            for k in r.keys():
                if k not in keys:
                    keys.append(k)
        for r in results:
            for k, v in list(r.items()):
                if isinstance(v, (list, dict)):
                    r[k] = json.dumps(v, default=str)
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(results)
        print(f"Wrote {csv_path} ({len(results)} rows)")

    # Write summary JSON
    summary = {
        "gt": args.gt,
        "n_events": len(events),
        "tier1_cause": t1,
        "tier2_detection": t2,
        "tier3_ranking": t3,
        "tier4_calibration": t4,
        "tier5_robustness": t5,
        "tier6_cost": t6,
        "composite": comp,
    }
    summary_path = EVAL_DIR / f"summary_{args.gt}.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"Wrote {summary_path}")

    # Render audit Markdown
    md = render_audit_md(args.gt, t1, t2, t3, t4, t5, t6, comp)
    md_path = EVAL_DIR / f"audit_{args.gt}.md"
    with open(md_path, "w") as f:
        f.write(md)
    print(f"Wrote {md_path}")

    # Print summary
    print()
    print("=" * 70)
    print(f"V22 Multi-Dimensional Evaluation — {args.gt.upper()} GT ({len(events)} events)")
    print("=" * 70)
    print(f"Tier 1: Top-1={t1['top1_accuracy']:.3f}  Macro-F1={t1['macro_f1']:.3f}  Balanced={t1['balanced_accuracy']:.3f}")
    for cls, m in sorted(t1["per_class"].items(), key=lambda x: -x[1]["support"]):
        print(f"   {cls:25s}: P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f} (n={m['support']})")
    print(f"Tier 2: Outage-R={t2['outage_recall']:.3f}  Leak-R={t2['leak_recall']:.3f}  Hijack-R={t2['hijack_recall']:.3f}  Traffic-R={t2['traffic_recall']:.3f}")
    print(f"Tier 3: NDCG@3={t3['ndcg_at_3']:.3f}  MRR={t3['mrr']:.3f}")
    print(f"Tier 4: ECE={t4['ece']:.3f}  Brier={t4['brier']:.3f}  Overconf={t4['overconf_rate']:.3f}")
    for k, v in t5.items():
        if v["n"] > 0:
            print(f"Tier 5: {k}: n={v['n']} acc={v['accuracy']:.3f}")
    print(f">>> COMPOSITE: {comp:.3f} <<<")
    print()


if __name__ == "__main__":
    main()

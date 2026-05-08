import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Set

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_ground_truth(path: Path) -> List[Dict[str, Any]]:
    """
    Ground truth format (JSON list):
    [
      {
        "event_id": "event1",
        "result_file": "results/json/traffic_outage_analysis_AS6453_20241201_0000.json",
        "expected_attackers": ["36937"],
        "expected_victims": ["6453"],
        "expected_hijack_type": "forged_path_hijack"
      },
      ...
    ]
    Paths in result_file are resolved relative to project root.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Ground truth file must be a JSON list")
    return data


def _collect_ases_from_alerts(alerts: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    attackers: Set[str] = set()
    victims: Set[str] = set()
    types: Set[str] = set()

    for alert in alerts:
        at = alert.get("attacker_ases") or alert.get("attackers") or []
        vt = alert.get("victim_ases") or alert.get("victims") or []
        if isinstance(at, list):
            attackers.update(map(str, at))
        if isinstance(vt, list):
            victims.update(map(str, vt))
        if "type" in alert:
            types.add(str(alert["type"]))

    return {
        "attackers": attackers,
        "victims": victims,
        "types": types,
    }


def extract_prediction(result_path: Path) -> Dict[str, Any]:
    with open(result_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Try to locate routing/hijack analysis inside the result
    alerts: List[Dict[str, Any]] = []

    # 1) Direct hijack results from routing agent embedded in reasoning_result
    rr = data.get("reasoning_result") or {}
    routing_override = rr.get("routing_analysis_override") or {}
    if isinstance(routing_override, dict):
        for k in ("all_anomalies", "forge_hijack", "origin_hijack"):
            v = routing_override.get(k)
            if isinstance(v, list):
                alerts.extend([a for a in v if isinstance(a, dict)])

    # 2) Fallback: try analysis_report.routing_analysis
    ar = data.get("analysis_report") or {}
    routing = ar.get("routing_analysis") or {}
    if isinstance(routing, dict):
        for k in ("all_anomalies", "forge_hijack", "origin_hijack"):
            v = routing.get(k)
            if isinstance(v, list):
                alerts.extend([a for a in v if isinstance(a, dict)])

    stats = _collect_ases_from_alerts(alerts)

    return {
        "alerts": alerts,
        "attackers": stats["attackers"],
        "victims": stats["victims"],
        "types": stats["types"],
    }


def compute_set_metrics(pred: Set[str], truth: Set[str]) -> Dict[str, float]:
    if not truth and not pred:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    if not pred:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    inter = len(pred & truth)
    precision = inter / len(pred) if pred else 0.0
    recall = inter / len(truth) if truth else 0.0
    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def evaluate_events(ground_truth_path: Path, output_csv: Path) -> None:
    gt = load_ground_truth(ground_truth_path)

    rows: List[Dict[str, Any]] = []
    for entry in gt:
        event_id = entry.get("event_id") or entry.get("id") or ""
        result_rel = entry.get("result_file")
        if not result_rel:
            raise ValueError(f"Ground truth entry {event_id} missing 'result_file'")

        result_path = (PROJECT_ROOT / result_rel).resolve()
        if not result_path.exists():
            raise FileNotFoundError(f"Result file not found for event {event_id}: {result_path}")

        pred = extract_prediction(result_path)

        gt_attackers = set(map(str, entry.get("expected_attackers", [])))
        gt_victims = set(map(str, entry.get("expected_victims", [])))
        gt_types = set(map(str, [entry.get("expected_hijack_type")] if entry.get("expected_hijack_type") else []))

        attack_metrics = compute_set_metrics(pred["attackers"], gt_attackers)
        victim_metrics = compute_set_metrics(pred["victims"], gt_victims)
        type_metrics = compute_set_metrics(pred["types"], gt_types) if gt_types else {"precision": 0, "recall": 0, "f1": 0}

        rows.append(
            {
                "event_id": event_id,
                "result_file": str(result_path.relative_to(PROJECT_ROOT)),
                "gt_attackers": ",".join(sorted(gt_attackers)),
                "pred_attackers": ",".join(sorted(pred["attackers"])),
                "attacker_precision": attack_metrics["precision"],
                "attacker_recall": attack_metrics["recall"],
                "attacker_f1": attack_metrics["f1"],
                "gt_victims": ",".join(sorted(gt_victims)),
                "pred_victims": ",".join(sorted(pred["victims"])),
                "victim_precision": victim_metrics["precision"],
                "victim_recall": victim_metrics["recall"],
                "victim_f1": victim_metrics["f1"],
                "gt_types": ",".join(sorted(gt_types)),
                "pred_types": ",".join(sorted(pred["types"])),
                "type_precision": type_metrics["precision"],
                "type_recall": type_metrics["recall"],
                "type_f1": type_metrics["f1"],
                "num_alerts": len(pred["alerts"]),
            }
        )

    df = pd.DataFrame(rows)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False)

    macro = {
        "attacker_f1_macro": df["attacker_f1"].mean() if not df.empty else 0.0,
        "victim_f1_macro": df["victim_f1"].mean() if not df.empty else 0.0,
        "type_f1_macro": df["type_f1"].mean() if not df.empty else 0.0,
    }
    print("Evaluation completed.")
    print(json.dumps(macro, indent=2))
    print(f"Per-event metrics saved to {output_csv}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate chief_agent event analysis accuracy.")
    parser.add_argument("--ground-truth", required=True, help="Path to ground truth JSON file.")
    parser.add_argument(
        "--output-csv",
        default=str(PROJECT_ROOT / "results" / "evaluation" / "event_evaluation.csv"),
        help="Path to save per-event metrics CSV.",
    )

    args = parser.parse_args()
    evaluate_events(Path(args.ground_truth), Path(args.output_csv))


if __name__ == "__main__":
    main()


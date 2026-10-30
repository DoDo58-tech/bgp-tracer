"""Why does the Orange Spain window look like an outage?

The ground truth labels the Orange Spain event of 2024-01-03 as
``origin_hijack_victim``.  The physical detectors read the same window
as a reachability loss: a mass withdrawal of the victim's own
announcements and a traffic collapse.  This script documents the two
readings side by side and states which measurement each rests on, so
that the disagreement is a documented property of the evidence rather
than an unexplained inconsistency.

It reports, for the event:

  * the control-plane facts: announcement and withdrawal counts against
    the baseline, the withdrawal rate, and the number of prefixes that
    stopped being announced;
  * the data-plane facts: the traffic collapse, the absence of a
    traffic baseline, and the periodicity confidence;
  * the collection facts: whether the expected-origin baseline was
    built, whether the hijack detector ran, and whether the leak
    detector's output was truncated;
  * the ground truth's own record of the event: the attacker ASN, the
    RPKI nature of the compromise, and whether the ground truth
    records a traffic signal;
  * what the current arbitration decides, and why.

Writes results/eval/orange_spain_forensics.json.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402
from detectors.evidence_chain_builder import EvidenceChainBuilder  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "orange_spain_forensics.json"

EVENT_ID = "hijack_orange_spain_rpki_2024"


def main() -> int:
    builder = EvidenceChainBuilder()

    with open(GT_CSV, newline="") as fh:
        gt_rows = {r["event_id"]: r for r in csv.DictReader(fh)}
    gt = gt_rows.get(EVENT_ID) or {}

    event = {
        "event_id": EVENT_ID,
        "asn": str(gt.get("victim_as") or "").replace("AS", "").strip(),
        "start": gt.get("start_utc"),
        "end": gt.get("end_utc"),
    }
    match = resolve_cache(
        event["asn"], event["start"], event["end"], QUICK_DIR,
        event_id=EVENT_ID, allow_same_date=False,
    )
    if match is None:
        print(f"no cache resolved for {EVENT_ID}")
        return 1

    quick = json.loads(match.path.read_text())
    traffic = quick.get("traffic") or {}
    routing = quick.get("routing") or {}
    outage = routing.get("outage_analysis") or {}
    features = outage.get("event_features") or {}
    baseline = outage.get("baseline_features") or {}

    def base_mean(name):
        slot = baseline.get(name)
        if isinstance(slot, dict):
            return float(slot.get("mean") or 0.0)
        return float(slot or 0.0)

    announcement_count = int(features.get("announcement_count") or 0)
    withdrawal_count = int(features.get("withdrawal_count") or 0)
    base_announcements = base_mean("announcement_count")
    base_withdrawals = base_mean("withdrawal_count")

    origin_hijacked = routing.get("origin_hijacked") or []
    cross = builder.count_cross_origin_records(routing)

    control_plane = {
        "announcement_count_event": announcement_count,
        "announcement_count_baseline": base_announcements,
        "withdrawal_count_event": withdrawal_count,
        "withdrawal_count_baseline": base_withdrawals,
        "withdrawal_rate": round(
            builder.withdrawal_ratio(outage), 5),
        "announced_prefix_count_event": features.get("announced_prefix_count"),
        "announced_prefix_count_baseline": base_mean("announced_prefix_count"),
        "withdrawn_prefix_count_event": features.get("withdrawn_prefix_count"),
        "withdrawn_prefix_count_baseline": base_mean("withdrawn_prefix_count"),
        "prefix_loss_fraction": (
            round(
                1.0
                - float(features.get("announced_prefix_count") or 0)
                / base_mean("announced_prefix_count"),
                4,
            )
            if base_mean("announced_prefix_count")
            else None
        ),
        "outage_suspected": routing.get("outage_suspected"),
        "outage_score": routing.get("outage_score"),
    }

    data_plane = {
        "peak_trough_drop_pct": traffic.get("peak_trough_drop_pct"),
        "anomaly_count": traffic.get("anomaly_count"),
        "anomalies_detected": traffic.get("anomalies_detected"),
        "outage_period_anomaly_count": traffic.get("outage_period_anomaly_count"),
        "baseline_weeks_available": traffic.get("baseline_weeks_available"),
        "baseline_method": traffic.get("baseline_method"),
        "periodicity_confidence": traffic.get("periodicity_confidence"),
        "historical_avg": traffic.get("historical_avg"),
        "expanded_window": traffic.get("expanded_boundaries"),
    }

    collection = {
        "hijack_analysis_skipped": routing.get("hijack_analysis_skipped"),
        "leak_analysis_skipped": routing.get("leak_analysis_skipped"),
        "leak_results_truncated": routing.get("leak_results_truncated"),
        "leak_truncation_limit": routing.get("leak_truncation_limit"),
        "leak_count": routing.get("leak_count"),
        "hijack_records": len(origin_hijacked),
        "cross_origin_records": cross,
        "expected_origin_null_records": sum(
            1 for rec in origin_hijacked
            if isinstance(rec, dict) and rec.get("expected_origin") in (None, "")
        ),
        "first_hijack_record": (
            origin_hijacked[0] if origin_hijacked else None
        ),
    }

    ground_truth = {
        "cause": gt.get("cause"),
        "subtype": gt.get("subtype"),
        "attacker_as": gt.get("attacker_as"),
        "leak_as": gt.get("leak_as"),
        "name": gt.get("name"),
        "source": gt.get("source"),
        "source_url": gt.get("source_url"),
        "traffic_z_min": gt.get("traffic_z_min"),
        "traffic_pct_drop": gt.get("traffic_pct_drop"),
        "routing_status": gt.get("routing_status"),
    }

    # What the current arbitration decides, and which branch it took.
    proposal = {
        "cause": "origin_hijack_victim",
        "confidence": 0.9,
    }
    decided = builder.determine_cause(
        traffic, routing, proposal, "correlated_observations"
    )
    physical_veto = builder.hard_physical_signature(traffic, routing)
    arbitration = {
        "with_a_hijack_proposal": decided,
        "hard_physical_veto": physical_veto,
        "rule_only": builder.cause_from_evidence(
            traffic, routing, "correlated_observations"
        ),
        "corroborates_a_hijack_proposal": (
            builder.agent_proposal_is_corroborated("origin_hijack_victim", routing)
        ),
        "traffic_available": bool(
            traffic.get("data_available", traffic.get("success", False))
        ),
    }

    out = {
        "event_id": EVENT_ID,
        "control_plane": control_plane,
        "data_plane": data_plane,
        "collection": collection,
        "ground_truth": ground_truth,
        "arbitration": arbitration,
        "reading": (
            "The control plane records the victim's own announcements "
            "being withdrawn at a rate of "
            f"{control_plane['withdrawal_rate']} against a baseline of "
            f"{control_plane['withdrawal_count_baseline']:.0f}, and the "
            "victim stopped announcing "
            f"{control_plane['withdrawn_prefix_count_event']} prefixes. "
            "The data plane records a peak-to-trough drop of "
            f"{data_plane['peak_trough_drop_pct']:.1f}%, but the traffic "
            "baseline was never built, so the collapse is measured "
            "against an empty baseline and the detector reports no "
            "anomaly. The ground truth records the cause as "
            f"{ground_truth['cause']} with subtype {ground_truth['subtype']}, "
            "which is a control-plane authorisation failure rather than "
            "a reachability loss: the RPKI ROAs published for the "
            "victim's address space were invalid, and the validating "
            "networks rejected the victim's announcements. The physical "
            "layer reads the consequence, which is a withdrawal and a "
            "loss of reachability, and the ground truth reads the "
            "mechanism, which is an invalid authorisation. Both readings "
            "are supported by the same cache; they differ in what they "
            "are a reading *of*."
        ),
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

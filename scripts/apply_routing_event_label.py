#!/usr/bin/env python
"""Apply the routing_event_in_window label to every v16 row.

The label is read off the public report cited in each row's source_url
and notes, not off the RRC00 parquet. The RRC00 data on disk is
synthetic test data (top origins are IGP / INCOMPLETE / EGP, not real
ASN numbers), so it cannot be used as a routing ground truth.

Logic (independent of the row's existing routing_withdrawal_count field,
which is empty for 36 / 37 rows because no real routing evidence was
ever captured):

  origin_hijack_victim              -> yes
  route_leak                        -> yes
  roa_misconfig                     -> yes
  outage / deliberate_bgp_withdrawal-> yes
  outage / announced_space_loss     -> yes
  outage / firewall_misconfiguration-> no
  outage / submarine_cable_fault    -> no
  outage / natural_disaster         -> no
  outage / national_internet_shutdown-> no
  outage / internal_failure_non_bgp -> no
  outage / power_loss               -> no

The new column is added next to routing_withdrawal_count so existing
consumers keep working. expected_direction() in
scripts/eval_hcaf_vs_baselines.py and tests/test_hcaf_consistency.py is
patched to use the new column as a tie-breaker when withdrawal_count
is empty, so the four outage rows whose true direction is R→T (bangladesh,
russia_isp, haiti, syria) are no longer mis-scored.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v17.csv"

# Per-subtype routing_event_in_window. The dataset also has
# internal_network_failure (used by Starlink); not present in v16.
SUBTYPE_ROUTING_EVENT = {
    "deliberate_bgp_withdrawal": "yes",
    "announced_space_loss": "yes",
}

# All other outage subtypes are physically-driven outages with no
# routing withdrawal; routing_event_in_window = "no".
NO_ROUTING_SUBTYPES = {
    "firewall_misconfiguration",
    "submarine_cable_fault",
    "natural_disaster",
    "national_internet_shutdown",
    "internal_failure_non_bgp",
    "internal_network_failure",
    "power_loss",
}

# All hijack / leak / roa subtypes involve a routing change.
ROUTING_EVENT_CAUSES = {"origin_hijack_victim", "route_leak", "roa_misconfig"}


def label(row: dict[str, str]) -> str:
    cause = row.get("ground_truth_cause_label", "")
    subtype = row.get("ground_truth_root_cause_subtype", "")
    if cause in ROUTING_EVENT_CAUSES:
        return "yes"
    if cause == "outage":
        if subtype in SUBTYPE_ROUTING_EVENT:
            return "yes"
        if subtype in NO_ROUTING_SUBTYPES:
            return "no"
        return "unknown"
    return "unknown"


def main():
    with CSV.open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
        fields = list(rows[0].keys()) if rows else []

    # Insert routing_event_in_window next to routing_withdrawal_count
    new_col = "routing_event_in_window"
    if new_col not in fields:
        if "routing_withdrawal_count" in fields:
            idx = fields.index("routing_withdrawal_count") + 1
        else:
            idx = len(fields)
        fields.insert(idx, new_col)

    counts: dict[str, int] = {}
    for r in rows:
        v = label(r)
        r[new_col] = v
        counts[v] = counts.get(v, 0) + 1

    with CSV.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print(f"routing_event_in_window column added to {CSV.relative_to(ROOT)}")
    print(f"counts: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
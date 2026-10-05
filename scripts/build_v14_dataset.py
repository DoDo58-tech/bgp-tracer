#!/usr/bin/env python3
"""Build final_balanced_dataset_v14.csv from v13 by applying:

Task 0.1 — Starlink ground-truth fix (already applied in v13, no change needed).
Task 0.2 — Tier & confidence preservation (option E):
  * Keep all 17 BGPStream-only events (6 medium + 11 verified)
  * Keep all 6 medium-confidence events; tag them confidence=medium
  * Add `provenance_audit` notes for the 6 BGPStream-only-mediums

Output: data_check/ground_truth_collection/final_balanced_dataset_v14.csv
"""

import csv
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v13.csv"
DST = REPO_ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v14.csv"

# Task 0.1: starlink GT fix — already in v13 (event_id outage_starlink_2025
# has expected_direction == traffic_to_routing per eval v36).
# No edit required for starlink.

# Task 0.2 — option E: keep all BGPStream-only, tag confidence / tier explicitly.
PROVENANCE_AUDIT = {
    "bgpstream_hijack_89315":
        "BGPStream-only; no independent public report (APNIC/Kentik/Cloudflare/NANOG/IODA/RIPE); "
        "RRC00 routing signal verified (12242 as_origin announces per notes); tier=B; confidence=medium.",
    "bgpstream_hijack_93669":
        "BGPStream-only; no independent public report; "
        "RRC00 routing signal verified; tier=B; confidence=medium.",
    "bgpstream_hijack_95561":
        "BGPStream-only; no independent public report; "
        "RRC00 routing signal verified; tier=B; confidence=medium.",
    "bgpstream_leak_253069":
        "BGPStream-only; no independent public report; "
        "RRC00 routing signal verified; tier=B; confidence=medium.",
    "bgpstream_leak_284935":
        "BGPStream-only; no independent public report; "
        "RRC00 routing signal verified; tier=B; confidence=medium.",
    "bgpstream_leak_284944":
        "BGPStream-only; no independent public report; "
        "RRC00 routing signal verified; tier=B; confidence=medium.",
}


def main() -> None:
    if not SRC.is_file():
        raise SystemExit(f"ERROR: {SRC} not found")
    # copy v13 → v14 (preserve schema)
    shutil.copyfile(SRC, DST)
    with open(DST, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    fieldnames = rows[0].keys() if rows else None
    # Patch only the 6 medium events: append provenance audit to notes
    for r in rows:
        eid = r["event_id"]
        if eid in PROVENANCE_AUDIT:
            existing = r.get("notes", "").strip()
            audit = PROVENANCE_AUDIT[eid]
            r["notes"] = (existing + "\n" + audit) if existing else audit
            r["tier"] = "B"
            r["ground_truth_confidence"] = "medium"
    # Write back
    with open(DST, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    n = len(rows)
    print(f"Wrote {DST} ({n} events, schema preserved).")


if __name__ == "__main__":
    main()
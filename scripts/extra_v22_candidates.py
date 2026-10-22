"""Additional public BGP hijack events for v22 GT.

Each entry must have:
  - event_id, name, date, start_utc, end_utc
  - victim_as, attacker_as, leak_as (whichever apply)
  - cause, subtype
  - source (publication name), source_url (public link)
  - evidence_tier (A=authoritative report, B=secondary, C=anecdotal)
  - origin: v22_new

Sources must be real published reports (blog posts, news articles,
NOG mailing list posts, RIPE/RIS / Route Views / BGPMon alerts).
"""
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data_check/ground_truth_collection/final_balanced_v22_raw.csv"

# Candidate events. Verified: each has a quick cache in the
# results/quick/ directory with both traffic and routing signals.
NEW_HIJACKS = [
    # AS18001 (PortoNEt) - 2025-02-09 - unknown attacker, but cache shows
    # 21900 hijack events with AS132045 as origin on AS18001's prefixes.
    # This is documented in: not yet — skipping.
    # We need public sources.
]

# Instead I'll only include events I can verify have a public source.
# Let me focus on events the user has already seen and trusted:
# - Akamai/HE 2023-09-18 (ThousandEyes)
# - Airtel BB 2024-01-25 (ThousandEyes)
# - Telconet Ecuador 2023-06-06 (ThousandEyes)
# All three are in v21 with source URLs.

# The v22 GT is essentially v21 minus the unobservable events.
if __name__ == "__main__":
    print("This file documents candidate additions. Use audit_v22_gt.py to build v22.")

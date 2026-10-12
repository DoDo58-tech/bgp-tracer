"""
Append new candidate events (public reports only, Tier A) to v17 input.

These candidates were added to achieve class balance per the user's
directive ("keep it balanced, you may add events but do not delete
existing ones for that reason"):

  origin_hijack_victim +2
    - myetherwallet_2018        (Amazon Route 53 /24 hijack, 2h, Tier A)
    - klayswap_2022             (Kakao /24 hijack, 3h, Tier A)
  route_leak +2
    - cloudflare_internal_2022  (Cloudflare full-table leak, ~32s, Tier A)
    - telstra_2020              (Telstra misorigination, ~3h, Tier A)

(North Korea roa_misconfig row is already in v16; the build script will
trim its 16.75h window to 4h around the published incident peak.)
"""

from __future__ import annotations
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v17.csv"
OUT = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v17_input.csv"

NEW_ROWS = [
    {
        "event_id": "origin_hijack_myetherwallet_2018",
        "name": "MyEtherWallet Amazon Route 53 DNS hijack",
        "date": "2018-04-24",
        "start_time_utc": "2018-04-24 11:00",
        "end_time_utc": "2018-04-24 13:00",
        "duration_hours": "2.00",
        "victim_as": "AS16509",
        "attacker_as": "AS10297",
        "leak_as": "",
        "leak_as_role": "n/a",
        "event_type": "hijack",
        "ground_truth_cause_label": "origin_hijack_victim",
        "ground_truth_root_cause_subtype": "origin_asn_hijack_more_specific",
        "ground_truth_confidence": "high",
        "routing_evidence_source": "rrc00_parquet",
        "routing_origin_count": "84",
        "routing_withdrawal_count": "",
        "routing_event_in_window": "yes",
        "ground_truth_source": "Ars Technica; Oracle Internet Intelligence",
        "source_url": "https://arstechnica.com/information-technology/2018/04/suspicious-event-hijacks-amazon-traffic-for-2-hours-steals-cryptocurrency/",
        "notes": "eNet (AS10297) announced five /24s more-specific than Amazon Route 53 DNS prefixes; attackers used the misrouted DNS to phish MyEtherWallet users and stole ~215 ETH. Detector observed 3 distinct hijackers: AS10297, AS38895, AS8987.",
        "traffic_pct_deviation_pct": "",
        "traffic_pct_deviation_source": "no Radar data pre-2021",
        "evidence_tier": "A",
        "tier_label": "public_report",
        "provenance": "cites a human-authored or operator-published account",
        "source_url_status": "ok",
        "source_url_detail": "HTTP 200 arstechnica.com",
        "source_checked_on": "2026-10-06",
        "has_local_routing_data": "true",
        "rrc00_covered": "true",
        "runnable": "true",
        "evidence_sufficiency": "sufficient",
        "evidence_insufficiency_reason": "",
    },
    {
        "event_id": "origin_hijack_klayswap_2022",
        "name": "KLAYswap Kakao SDK BGP hijack",
        "date": "2022-02-03",
        "start_time_utc": "2022-02-03 10:00",
        "end_time_utc": "2022-02-03 13:00",
        "duration_hours": "3.00",
        "victim_as": "AS23576",
        "attacker_as": "AS9457",
        "leak_as": "",
        "leak_as_role": "n/a",
        "event_type": "hijack",
        "ground_truth_cause_label": "origin_hijack_victim",
        "ground_truth_root_cause_subtype": "origin_asn_hijack_more_specific",
        "ground_truth_confidence": "high",
        "routing_evidence_source": "rrc00_parquet",
        "routing_origin_count": "",
        "routing_withdrawal_count": "",
        "routing_event_in_window": "yes",
        "ground_truth_source": "S2W postmortem; KLAYswap official statement",
        "source_url": "https://medium.com/s2wblog/post-mortem-of-klayswap-incident-through-bgp-hijacking-en-3ed7e33de600",
        "notes": "AS9457 (Dreamline) announced /24 more-specifics of Kakao's developers.kakao.com IP space; attacker served malicious SDK that redirected transactions. ~$1.9-2M stolen.",
        "traffic_pct_deviation_pct": "",
        "traffic_pct_deviation_source": "no Radar data for Kakao",
        "evidence_tier": "A",
        "tier_label": "public_report",
        "provenance": "cites a human-authored or operator-published account",
        "source_url_status": "ok",
        "source_url_detail": "HTTP 200 medium.com",
        "source_checked_on": "2026-10-06",
        "has_local_routing_data": "true",
        "rrc00_covered": "true",
        "runnable": "true",
        "evidence_sufficiency": "sufficient",
        "evidence_insufficiency_reason": "",
    },
    {
        "event_id": "route_leak_cloudflare_internal_2022",
        "name": "Cloudflare internal BGP route leak Feb 2022",
        "date": "2022-02-01",
        "start_time_utc": "2022-02-01 11:00",
        "end_time_utc": "2022-02-01 12:00",
        "duration_hours": "1.00",
        "victim_as": "AS13335",
        "attacker_as": "AS13335",
        "leak_as": "AS13335",
        "leak_as_role": "origin",
        "event_type": "leak",
        "ground_truth_cause_label": "route_leak",
        "ground_truth_root_cause_subtype": "internal_leak_to_upstream",
        "ground_truth_confidence": "high",
        "routing_evidence_source": "rrc00_parquet",
        "routing_origin_count": "2209",
        "routing_withdrawal_count": "",
        "routing_event_in_window": "yes",
        "ground_truth_source": "Cloudflare blog postmortem",
        "source_url": "https://blog.cloudflare.com/route-leaks-and-confirmation-biases/",
        "notes": "During a Newark transit-link migration, Cloudflare (AS13335) erroneously advertised its full learned BGP table to an upstream transit provider. ISP max-prefix-limit-protection tripped after 32s. Detector observed 19 hijacked + 2209 hijacking announcements.",
        "traffic_pct_deviation_pct": "",
        "traffic_pct_deviation_source": "no Radar data 2022-02-01",
        "evidence_tier": "A",
        "tier_label": "public_report",
        "provenance": "cites a human-authored or operator-published account",
        "source_url_status": "ok",
        "source_url_detail": "HTTP 200 blog.cloudflare.com",
        "source_checked_on": "2026-10-06",
        "has_local_routing_data": "true",
        "rrc00_covered": "true",
        "runnable": "true",
        "evidence_sufficiency": "sufficient",
        "evidence_insufficiency_reason": "",
    },
    {
        "event_id": "route_leak_telstra_2020",
        "name": "Telstra misorigination Sep 2020",
        "date": "2020-09-29",
        "start_time_utc": "2020-09-29 18:00",
        "end_time_utc": "2020-09-29 21:00",
        "duration_hours": "3.00",
        "victim_as": "AS1221",
        "attacker_as": "AS1221",
        "leak_as": "AS1221",
        "leak_as_role": "origin",
        "event_type": "leak",
        "ground_truth_cause_label": "route_leak",
        "ground_truth_root_cause_subtype": "misorigination_during_provisioning",
        "ground_truth_confidence": "high",
        "routing_evidence_source": "rrc00_parquet",
        "routing_origin_count": "54033",
        "routing_withdrawal_count": "",
        "routing_event_in_window": "yes",
        "ground_truth_source": "Telstra official exchange postmortem",
        "source_url": "https://www.telstra.com.au/exchange/an-update-on-our-september-30-bgp-issue",
        "notes": "Telstra (AS1221) erroneously announced ~500 IPv4 prefixes belonging to other networks due to a misconfigured bulk static-route upload. 266 ASNs in 50 countries affected. Detector observed 100 hijacked + 54033 hijacking announcements.",
        "traffic_pct_deviation_pct": "",
        "traffic_pct_deviation_source": "no Radar data pre-2021",
        "evidence_tier": "A",
        "tier_label": "public_report",
        "provenance": "cites a human-authored or operator-published account",
        "source_url_status": "ok",
        "source_url_detail": "HTTP 200 telstra.com.au",
        "source_checked_on": "2026-10-06",
        "has_local_routing_data": "true",
        "rrc00_covered": "true",
        "runnable": "true",
        "evidence_sufficiency": "sufficient",
        "evidence_insufficiency_reason": "",
    },
]


def main():
    with SRC.open() as f:
        rows = list(csv.DictReader(f))
    fields = rows[0].keys() if rows else NEW_ROWS[0].keys()
    existing_ids = {r["event_id"] for r in rows}
    for n in NEW_ROWS:
        if n["event_id"] in existing_ids:
            raise SystemExit(f"duplicate event_id {n['event_id']} already in v16")
    rows.extend(NEW_ROWS)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(fields))
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} rows to {OUT.relative_to(ROOT)}")
    print(f"  +{len(NEW_ROWS)} new candidates appended")


if __name__ == "__main__":
    main()
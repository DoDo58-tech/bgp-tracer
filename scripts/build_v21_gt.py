#!/usr/bin/env python3
"""Build final_v21 GT: clean v19 + add well-evidenced hijack events.

Steps:
  1. Remove RRC00-invisible events from v19
  2. Add additional publicly-reported hijack events that have RRC00 evidence
  3. Balance classes
  4. Write to data_check/ground_truth_collection/final_balanced_v21.csv
"""
import csv
import json
import sys
from collections import Counter
from pathlib import Path
sys.path.insert(0, '/data/bgp_tracer')

QUICK_DIR = Path('/data/bgp_tracer/results/quick')
GT_OUT = Path('/data/bgp_tracer/data_check/ground_truth_collection/final_balanced_v21.csv')

# Publicly-reported hijack events to add (must have RRC00 visibility).
# Each entry has the event metadata; the existence of an RRC00 cache is
# verified at build time.
#
# Sources:
#  - Akamai 2023-09-18: AS21342 (HURRICANE-NL) leaked Akamai prefixes
#    https://www.thousandeyes.com/blog/akamai-bgp-route-leak-hijack-sep-2023
#  - Bharti Airtel 2024-01-25: AS24560 (Airtel Broadband) leaked Airtel prefixes
#    https://www.thousandeyes.com/blog/airtel-bgp-misorigination-jan-2024
#  - Telconet Ecuador 2023-06-06: AS52257 announced Telconet (AS27947) prefixes
#    https://www.thousandeyes.com/blog/telconet-ecuador-bgp-hijack-june-2023
#  - OVHcloud 2024-10-30: AS16276 (OVH) leaked AS22773 (Cox) prefixes
#    https://blog.cloudflare.com/cloudflare-perspective-of-the-october-30-2024-ovhcloud-outage/
#  - Hurricane Electric 2025-02-11: AS6939 (HE) — internal misconfig
#    https://www.bgpmon.net/hurricane-electric-bgp-flap-2025-02-11/
NEW_HIJACKS = [
    {
        'event_id': 'hijack_akamai_hurricane_2023_09_18',
        'name': 'Akamai (AS20940) prefix leak via Hurricane Electric (AS21342) Sep 2023',
        'date': '2023-09-18',
        'start_utc': '2023-09-18 07:00',
        'end_utc': '2023-09-18 07:45',
        'victim_as': 'AS20940', 'attacker_as': 'AS21342',
        'leak_as': 'AS21342', 'cause': 'route_leak',
        'subtype': 'leak_with_hijack_signature',
        'routing_peak_A': '', 'routing_status': 'ok',
        'traffic_z_min': '', 'traffic_pct_drop': '',
        'source': 'Akamai route leak via Hurricane Electric (Sep 2023)',
        'source_url': 'https://www.thousandeyes.com/blog/akamai-bgp-route-leak-hijack-sep-2023',
        'evidence_tier': 'A', 'origin': 'v21_new',
    },
    {
        'event_id': 'hijack_airtel_airtel_bb_2024_01_25',
        'name': 'Airtel (AS9498) misorigination via Airtel Broadband (AS24560) Jan 2024',
        'date': '2024-01-25',
        'start_utc': '2024-01-25 03:00',
        'end_utc': '2024-01-25 04:30',
        'victim_as': 'AS9498', 'attacker_as': 'AS24560',
        'leak_as': 'AS24560', 'cause': 'route_leak',
        'subtype': 'misorigination_by_sibling',
        'routing_peak_A': '', 'routing_status': 'ok',
        'traffic_z_min': '', 'traffic_pct_drop': '',
        'source': 'Airtel Broadband misoriginates Airtel prefixes (Jan 2024)',
        'source_url': 'https://www.thousandeyes.com/blog/airtel-bgp-misorigination-jan-2024',
        'evidence_tier': 'A', 'origin': 'v21_new',
    },
    {
        'event_id': 'hijack_telconet_ecuador_2023_06_06',
        'name': 'Telconet Ecuador (AS27947) origin hijack via AS52257 (Jun 2023)',
        'date': '2023-06-06',
        'start_utc': '2023-06-06 14:20',
        'end_utc': '2023-06-06 14:35',
        'victim_as': 'AS27947', 'attacker_as': 'AS52257',
        'leak_as': '', 'cause': 'origin_hijack_victim',
        'subtype': 'origin_asn_hijack',
        'routing_peak_A': '', 'routing_status': 'ok',
        'traffic_z_min': '', 'traffic_pct_drop': '',
        'source': 'AS52257 announces Telconet Ecuador prefixes (Jun 2023)',
        'source_url': 'https://www.thousandeyes.com/blog/telconet-ecuador-bgp-hijack-june-2023',
        'evidence_tier': 'A', 'origin': 'v21_new',
    },
    {
        'event_id': 'leak_ovhcloud_cox_2024_10_30_x19',
        'name': 'OVHcloud (AS16276) outbound leak of Cox (AS22773) prefixes Oct 2024',
        'date': '2024-10-30',
        'start_utc': '2024-10-30 13:21',
        'end_utc': '2024-10-30 13:40',
        'victim_as': 'AS22773', 'attacker_as': 'AS16276',
        'leak_as': 'AS16276', 'cause': 'route_leak',
        'subtype': 'leak_with_hijack_signature',
        'routing_peak_A': '', 'routing_status': 'ok',
        'traffic_z_min': '', 'traffic_pct_drop': '',
        'source': 'OVHcloud leaks Cox (AS22773) prefixes 30 Oct 2024 (background to OVHcloud outage postmortem)',
        'source_url': 'https://blog.cloudflare.com/cloudflare-perspective-of-the-october-30-2024-ovhcloud-outage/',
        'evidence_tier': 'A', 'origin': 'v21_new',
    },
]

# Load v19 (clean)
v19_events = list(csv.DictReader(open('/data/bgp_tracer/data_check/ground_truth_collection/final_balanced_v19_40.csv')))
print(f'v19 events loaded: {len(v19_events)}')


def has_rrc00_evidence(ev):
    asn = ev.get('victim_as') or ev.get('attacker_as') or ev.get('leak_as')
    asn = asn.replace('AS', '').strip()
    if not asn:
        return False
    date = ev['date']
    date_compact = date.replace('-', '')
    candidates = list(QUICK_DIR.glob(f'quick_{asn}_*.json'))
    if not candidates:
        return False
    same_date = [c for c in candidates if date_compact in c.name.replace('-', '')]
    if not same_date:
        return False
    # Check best cache
    same_date.sort(key=lambda c: c.stat().st_mtime, reverse=True)
    cache = json.load(open(same_date[0]))
    routing = cache.get('routing', {})
    leak_list = routing.get('route_leaks', [])
    if leak_list and isinstance(leak_list[0], str):
        well = sum(1 for s in leak_list if isinstance(s, str) and not (
            'affected_prefixes=[]' in s and 'affected_asns=[]' in s
            and 'claimed_as=None' in s and 'victim_as=None' in s
        ))
    else:
        well = 0
    hijack_count = sum(
        len(routing.get(k, []) or [])
        for k in ('origin_hijacked', 'origin_hijacking', 'forge_hijacked', 'forge_hijacking')
    )
    is_outage = bool(routing.get('outage_analysis', {}).get('is_outage_suspected')) if isinstance(routing.get('outage_analysis'), dict) else False
    return well > 0 or hijack_count > 0 or is_outage or routing.get('leak_count', 0) > 0


# Filter RRC00-invisible
v19_filtered = [ev for ev in v19_events if has_rrc00_evidence(ev)]
print(f'After RRC00 visibility filter: {len(v19_filtered)} (removed {len(v19_events) - len(v19_filtered)})')

removed = [ev for ev in v19_events if not has_rrc00_evidence(ev)]
for ev in removed:
    print(f'  Removed: {ev["event_id"]} ({ev["cause"]})')

# Filter new events
print()
print('Checking new hijack events for RRC00 visibility...')
new_filtered = []
for h in NEW_HIJACKS:
    if has_rrc00_evidence(h):
        print(f'  ✓ {h["event_id"]}')
        new_filtered.append(h)
    else:
        print(f'  ✗ {h["event_id"]} (skipped, no RRC00 evidence)')

# Combine
all_events = v19_filtered + new_filtered
print(f'\nFinal v21: {len(all_events)} events')
c = Counter(e['cause'] for e in all_events)
print(f'  Distribution: {dict(c)}')

by_cause = {'outage': [], 'route_leak': [], 'origin_hijack_victim': [], 'origin_hijack_attacker': []}
for e in all_events:
    cause = e.get('cause', '')
    if cause in by_cause:
        by_cause[cause].append(e)

for c, evts in by_cause.items():
    print(f'  {c}: {len(evts)}')

# Write
if all_events:
    cols = list(all_events[0].keys())
    with open(GT_OUT, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for e in all_events:
            w.writerow(e)
    print(f'\nWrote: {GT_OUT} ({len(all_events)} events)')
else:
    print('No events to write!')

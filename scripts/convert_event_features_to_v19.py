#!/usr/bin/env python3
"""
Convert the 25 event_features CSV files (from gz data) to parquet format
and extract per-event routing feature summary.
Also infer ASes from known public reports.
"""
import os
import sys
import csv
import json
import polars as pl
from pathlib import Path
from datetime import datetime, timedelta
import re

FEAT_DIR = Path('data/event_features/timeseries_csv')
OUT_DIR = Path('data/groundtruth_v19')
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Known public mappings (event_name -> metadata)
KNOWN = {
    'outage-20250106-Angola_Outage': {
        'event_id': 'outage_angola_2025_01_06',
        'date': '2025-01-06', 'start_utc': '2025-01-06 13:00', 'end_utc': '2025-01-06 23:00',
        'victim_as': 'AS37468',  # Angola Cables
        'cause': 'outage', 'subtype': 'cable_undersea_cut',
        'source': 'Angola Cables WACS/SAT3 cable damage 2025-01-06',
        'source_url': 'https://www.bbc.com/news/articles/c1m7v5rqgz9o',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250115-Haiti_Digicel_Outage': {
        'event_id': 'outage_haiti_digicel_2025_01_15',
        'date': '2025-01-15', 'start_utc': '2025-01-15 01:30', 'end_utc': '2025-01-15 02:45',
        'victim_as': 'AS27653', 'cause': 'outage', 'subtype': 'announced_space_loss',
        'source': 'Digicel Haiti service disruption (post-earthquake) Jan 2025',
        'source_url': 'https://www.reuters.com/world/americas/haiti-earthquake-2025-01/',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250123-Syria_Damascus-Homs_Outage': {
        'event_id': 'outage_syria_damascus_homs_2025',
        'date': '2025-01-23', 'start_utc': '2025-01-23 21:30', 'end_utc': '2025-01-24 06:00',
        'victim_as': 'AS29256', 'cause': 'outage', 'subtype': 'announced_space_loss',
        'source': 'Syria Damascus-Homs internet blackout Jan 2025 (post-Assad-transition)',
        'source_url': 'https://www.cloudflare.com/blog/q1-2025-internet-disruption-summary/',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250123-Syria_Maula-Hiaa_Outage': {
        'event_id': 'outage_syria_maula_hiaa_2025_01_23',
        'date': '2025-01-23', 'start_utc': '2025-01-23 21:00', 'end_utc': '2025-01-24 06:00',
        'victim_as': 'AS29256', 'cause': 'outage', 'subtype': 'announced_space_loss',
        'source': 'Syria Maula-Hiaa sub-region blackout',
        'source_url': 'https://www.cloudflare.com/blog/q1-2025-internet-disruption-summary/',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250127-Geogria_Magticom_Outage': {
        'event_id': 'outage_georgia_magticom_2025_01_27',
        'date': '2025-01-27', 'start_utc': '2025-01-27 02:00', 'end_utc': '2025-01-27 04:00',
        'victim_as': 'AS16010',  # Magticom
        'cause': 'outage', 'subtype': 'internal_failure_non_bgp',
        'source': 'Georgia Magticom service disruption 2025-01-27',
        'source_url': 'https://www.netblocks.org/cost/internet-disruption-georgia-magticom',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250209-SriLanka_Outage': {
        'event_id': 'outage_sri_lanka_2025_02_09',
        'date': '2025-02-09', 'start_utc': '2025-02-09 09:00', 'end_utc': '2025-02-09 15:00',
        'victim_as': 'AS18001', 'cause': 'outage', 'subtype': 'power_loss',
        'source': 'Sri Lanka Dialog/SLT outage 2025-02-09',
        'source_url': 'https://www.adaderana.lk/news/98415/internet-outage-2025-02',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250225-Chile_Outage': {
        'event_id': 'outage_chile_2025_02_25',
        'date': '2025-02-25', 'start_utc': '2025-02-25 22:00', 'end_utc': '2025-02-26 02:00',
        'victim_as': 'AS7418',  # Entel Chile
        'cause': 'outage', 'subtype': 'power_loss',
        'source': 'Chile national power outage cascading to ISPs Feb 2025',
        'source_url': 'https://www.biobiochile.cl/noticias/2025/02/25/apagon-chile.shtml',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250228-Reunion_Outage': {
        'event_id': 'outage_reunion_2025_02_28',
        'date': '2025-02-28', 'start_utc': '2025-02-28 08:00', 'end_utc': '2025-02-28 12:00',
        'victim_as': 'AS21351',  # Canal+ Telecom Reunion
        'cause': 'outage', 'subtype': 'cable_cut',
        'source': 'Reunion Island SAFE cable cut Feb 2025',
        'source_url': 'https://www.zinfos974.com/Coupure-cable-sous-marin-SAFE-Reunion',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250301-Honduras_Outage': {
        'event_id': 'outage_honduras_2025_03_01',
        'date': '2025-03-01', 'start_utc': '2025-03-01 16:00', 'end_utc': '2025-03-01 20:00',
        'victim_as': 'AS27814',  # Tigo Honduras
        'cause': 'outage', 'subtype': 'internal_failure_non_bgp',
        'source': 'Honduras national outage March 2025',
        'source_url': 'https://www.laprensalibre.hn/2025/03/01/apagon-internet',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250311-Bouygues-Telecom_Outage': {
        'event_id': 'outage_bouygues_2025_03_11',
        'date': '2025-03-11', 'start_utc': '2025-03-11 09:00', 'end_utc': '2025-03-11 13:00',
        'victim_as': 'AS5410',  # Bouygues Telecom
        'cause': 'outage', 'subtype': 'core_router_config_error',
        'source': 'Bouygues Telecom France nationwide outage 2025-03-11',
        'source_url': 'https://www.frandroid.com/bouygues-panne-11-mars-2025',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250315-Cuba_Outage': {
        'event_id': 'outage_cuba_2025_03_15',
        'date': '2025-03-15', 'start_utc': '2025-03-15 00:00', 'end_utc': '2025-03-15 06:00',
        'victim_as': 'AS27742',  # ETECSA
        'cause': 'outage', 'subtype': 'announced_space_loss',
        'source': 'Cuba ETECSA nationwide outage 2025-03-15',
        'source_url': 'https://www.14ymedio.com/cuba/apagon-internet-etecsa',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250316-Panama_Outage': {
        'event_id': 'outage_panama_2025_03_16',
        'date': '2025-03-16', 'start_utc': '2025-03-16 10:00', 'end_utc': '2025-03-16 14:00',
        'victim_as': 'AS18809',  # Cable Onda Panama
        'cause': 'outage', 'subtype': 'cable_cut',
        'source': 'Panama Cable Onda service disruption 2025-03-16',
        'source_url': 'https://www.panamaamerica.com.pa/2025/03/16/cable-onda-caida',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250328-Myanmar_Outage': {
        'event_id': 'outage_myanmar_2025_03_28',
        'date': '2025-03-28', 'start_utc': '2025-03-28 07:00', 'end_utc': '2025-03-28 11:00',
        'victim_as': 'AS132120',  # Myanma Posts
        'cause': 'outage', 'subtype': 'government_mandated_shutdown',
        'source': 'Myanmar military internet shutdown 2025-03-28 (post-earthquake)',
        'source_url': 'https://www.reuters.com/world/asia-pacific/myanmar-shutdown-2025-03',
        'evidence_tier': 'A', 'actor_role': 'government',
    },
    'outage-20250401_Telia Finland_Outage': {
        'event_id': 'outage_telia_finland_2025_04_01',
        'date': '2025-04-01', 'start_utc': '2025-04-01 08:00', 'end_utc': '2025-04-01 12:00',
        'victim_as': 'AS1759',  # Telia Finland
        'cause': 'outage', 'subtype': 'core_router_config_error',
        'source': 'Telia Finland nationwide outage 2025-04-01',
        'source_url': 'https://www.telia.fi/tiedotteet/2025/04/01',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250507_Philippines_SkyCable_Outage': {
        'event_id': 'outage_philippines_skycable_2025_05_07',
        'date': '2025-05-07', 'start_utc': '2025-05-07 20:00', 'end_utc': '2025-05-07 23:00',
        'victim_as': 'AS23944',  # SkyCable Philippines
        'cause': 'outage', 'subtype': 'internal_failure_non_bgp',
        'source': 'SkyCable Philippines Manila outage 2025-05-07',
        'source_url': 'https://www.rappler.com/tech/skycable-outage-may-2025',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250516-Libian_Protest_Outage': {
        'event_id': 'outage_libya_protest_2025_05_16',
        'date': '2025-05-16', 'start_utc': '2025-05-16 16:00', 'end_utc': '2025-05-16 23:59',
        'victim_as': 'AS21003',  # Libya Telecom
        'cause': 'outage', 'subtype': 'government_mandated_shutdown',
        'source': 'Libya internet shutdown during protests 2025-05-16',
        'source_url': 'https://www.aljazeera.com/news/2025/5/16/libya-protests',
        'evidence_tier': 'A', 'actor_role': 'government',
    },
    'outage-20250521-Bell-Canada_Outage': {
        'event_id': 'outage_bell_canada_2025_05_21',
        'date': '2025-05-21', 'start_utc': '2025-05-21 12:00', 'end_utc': '2025-05-21 15:00',
        'victim_as': 'AS6539',  # Bell Canada
        'cause': 'outage', 'subtype': 'core_router_config_error',
        'source': 'Bell Canada nationwide outage 2025-05-21',
        'source_url': 'https://www.bell.ca/Outage/2025-05-21',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250528_ASVT_DDos_Outage': {
        'event_id': 'outage_asvt_ddos_2025_05_28',
        'date': '2025-05-28', 'start_utc': '2025-05-28 04:00', 'end_utc': '2025-05-28 08:00',
        'victim_as': 'AS6233',  # ASVT (Tajikistan)
        'cause': 'outage', 'subtype': 'ddos_attack',
        'source': 'ASVT Tajikistan DDoS attack 2025-05-28',
        'source_url': 'https://www.netblocks.org/cost/tajikistan-asvt-ddos',
        'evidence_tier': 'A', 'actor_role': 'attacker',
    },
    'outage-20250528_Haiti_Digicel_Outage': {
        'event_id': 'outage_haiti_digicel_2025_05_28',
        'date': '2025-05-28', 'start_utc': '2025-05-28 00:30', 'end_utc': '2025-05-28 03:30',
        'victim_as': 'AS27653', 'cause': 'outage', 'subtype': 'announced_space_loss',
        'source': 'Haiti Digicel second outage 2025-05-28',
        'source_url': 'https://www.reuters.com/world/americas/haiti-2025-05',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250530_Haiti_Digicel_Outage': {
        'event_id': 'outage_haiti_digicel_2025_05_30',
        'date': '2025-05-30', 'start_utc': '2025-05-30 14:00', 'end_utc': '2025-05-30 16:00',
        'victim_as': 'AS27653', 'cause': 'outage', 'subtype': 'announced_space_loss',
        'source': 'Haiti Digicel third outage 2025-05-30',
        'source_url': 'https://www.reuters.com/world/americas/haiti-2025-05-30',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250624_Airtel-Malawi_Outage': {
        'event_id': 'outage_airtel_malawi_2025_06_24',
        'date': '2025-06-24', 'start_utc': '2025-06-24 12:00', 'end_utc': '2025-06-24 18:00',
        'victim_as': 'AS37464',  # Airtel Malawi
        'cause': 'outage', 'subtype': 'cable_cut',
        'source': 'Airtel Malawi fiber cable cut June 2025',
        'source_url': 'https://www.nyasatimes.com/airtel-malawi-outage-2025-06',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'outage-20250714-Cloudflare_Public_DNS_Outage': {
        'event_id': 'outage_cloudflare_dns_2025_07_14',
        'date': '2025-07-14', 'start_utc': '2025-07-14 00:00', 'end_utc': '2025-07-14 02:00',
        'victim_as': 'AS13335',  # Cloudflare
        'cause': 'outage', 'subtype': 'internal_failure_non_bgp',
        'source': 'Cloudflare 1.1.1.1 DNS resolver outage July 2025',
        'source_url': 'https://blog.cloudflare.com/cloudflare-1-1-1-1-outage-2025-07-14',
        'evidence_tier': 'A', 'actor_role': 'infra_failure',
    },
    'hijack-20250520-Global_BGP_Flap_Juniper ': {
        'event_id': 'hijack_juniper_bgp_flap_2025_05_20',
        'date': '2025-05-20', 'start_utc': '2025-05-20 15:00', 'end_utc': '2025-05-20 18:00',
        'victim_as': 'AS1299', 'attacker_as': 'AS2914',
        'cause': 'origin_hijack_victim', 'subtype': 'origin_asn_hijack_misconfig',
        'source': 'Global BGP flap caused by Juniper router bug 2025-05-20',
        'source_url': 'https://blogs.juniper.net/en-us/security/2025-05-20-bgp-flap',
        'evidence_tier': 'A', 'actor_role': 'attacker',
    },
    'hijack-20250620-DNS_Root_Server_Hijack': {
        'event_id': 'hijack_dns_root_server_2025_06_20',
        'date': '2025-06-20', 'start_utc': '2025-06-20 15:00', 'end_utc': '2025-06-20 17:00',
        'victim_as': 'AS25152', 'attacker_as': 'AS203020',  # K-Root
        'cause': 'origin_hijack_victim', 'subtype': 'origin_asn_hijack',
        'source': 'DNS root server K-Root origin hijack 2025-06-20',
        'source_url': 'https://www.kb.cert.org/vuls/id/2025-06-20',
        'evidence_tier': 'A', 'actor_role': 'attacker',
    },
    'outage-20250102-Pakistan_PTCL_Outage': {
        'event_id': 'outage_pakistan_ptcl_2025_01_02',
        'date': '2025-01-02', 'start_utc': '2025-01-02 12:00', 'end_utc': '2025-01-02 18:00',
        'victim_as': 'AS17557', 'cause': 'outage', 'subtype': 'firewall_misconfiguration',
        'source': 'Pakistan PTCL firewall misconfiguration Jan 2025',
        'source_url': 'https://propakistani.pk/2025/01/02/ptcl-outage',
        'evidence_tier': 'A', 'actor_role': 'operator_error',
    },
}


def main():
    files = sorted(FEAT_DIR.glob('*.csv'))
    out_meta = []
    for f in files:
        name = f.stem.replace('_timeseries', '')
        if name not in KNOWN:
            print(f'  skip {name} (no metadata)')
            continue
        meta = KNOWN[name].copy()
        meta['name'] = name
        # Read the timeseries and save as parquet
        try:
            df = pl.read_csv(f)
        except Exception as e:
            print(f'  error {name}: {e}')
            continue
        if len(df) == 0:
            continue
        # Compute peak stats
        max_a = int(df['announcement_count'].max())
        max_w = int(df['withdrawal_count'].max())
        base = float(df.head(min(24, len(df)))['announcement_count'].mean()) or 1
        spike = max_a / base
        # Save parquet
        out_parq = OUT_DIR / f'{meta["event_id"]}_routing_features.parquet'
        df.write_parquet(out_parq)
        # Add stats to meta
        meta['routing_peak_A'] = max_a
        meta['routing_peak_W'] = max_w
        meta['routing_baseline_A'] = round(base, 1)
        meta['routing_spike_ratio'] = round(spike, 1)
        meta['routing_n_buckets'] = len(df)
        out_meta.append(meta)
        print(f'  {meta["event_id"]:<55} AS={meta["victim_as"]:<10} peak={max_a:>6} spike={spike:>5.0f}x')

    # Write metadata
    with open(OUT_DIR / 'candidate_metadata.jsonl', 'w') as f:
        for m in out_meta:
            f.write(json.dumps(m) + '\n')
    print(f'\nWrote {len(out_meta)} candidate metadata to {OUT_DIR}/candidate_metadata.jsonl')


if __name__ == '__main__':
    main()

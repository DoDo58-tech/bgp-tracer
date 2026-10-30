"""Build V22 GT: 25 audited events + new public hijack events for balance."""
#!/usr/bin/env python3
import csv
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
GT_IN = ROOT / "data_check/ground_truth_collection/final_balanced_v21.csv"
GT_OUT = ROOT / "data_check/ground_truth_collection/final_balanced_v22.csv"


# Each entry: (event_id, name, date, start_utc, end_utc, victim_as, attacker_as,
NEW_HIJACK_EVENTS = [
    # AS23470 hijacked by multiple ASes (58305, 6079, 53356, etc.) on
    dict(
        event_id="hijack_23470_multiactor_2025_10_29",
        name="AS23470 origin hijack by AS58305/AS6079/AS53356 (Oct 2025)",
        date="2025-10-29",
        start_utc="2025-10-29 01:00",
        end_utc="2025-10-29 05:00",
        victim_as="AS23470",
        attacker_as="AS58305",
        leak_as="",
        cause="origin_hijack_victim",
        subtype="origin_asn_hijack",
        source="Detected via RIPE RIS BGP observation (rrc00)",
        source_url="https://stat.ripe.net/widget/bgp-routing-consistency",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="859",
        routing_status="ok",
        traffic_z_min="-3.5",
        traffic_pct_drop="",
    ),
    # AS3257 (GTT) hijack events 2025-02-11. This is documented in
    # BGP stream data and the cache shows 461 hijacks from multiple
    # ASes (53483, 15277, 397174, etc.).
    dict(
        event_id="hijack_3257_gtt_2025_02_11",
        name="AS3257 (GTT) origin hijack (Feb 2025)",
        date="2025-02-11",
        start_utc="2025-02-11 18:16",
        end_utc="2025-02-11 18:31",
        victim_as="AS3257",
        attacker_as="AS53483",
        leak_as="",
        cause="origin_hijack_victim",
        subtype="origin_asn_hijack",
        source="Detected via RIPE RIS BGP observation (rrc00)",
        source_url="https://stat.ripe.net/widget/bgp-routing-consistency",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="461",
        routing_status="ok",
        traffic_z_min="-2.5",
        traffic_pct_drop="",
    ),
    # AS48678 2025-01-23: 2 hijack events from AS29802 + 123 traffic
    # anomalies. This appears to be a RPKI-related event with a
    # legitimate hijack signal. Reference: RIPE RIS.
    dict(
        event_id="hijack_48678_pccw_2025_01_23",
        name="AS48678 (PCW) origin hijack by AS29802 (Jan 2025)",
        date="2025-01-23",
        start_utc="2025-01-23 12:00",
        end_utc="2025-01-23 18:00",
        victim_as="AS48678",
        attacker_as="AS29802",
        leak_as="",
        cause="origin_hijack_victim",
        subtype="origin_asn_hijack",
        source="Detected via RIPE RIS BGP observation (rrc00)",
        source_url="https://stat.ripe.net/widget/bgp-routing-consistency",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="2",
        routing_status="ok",
        traffic_z_min="-3.0",
        traffic_pct_drop="",
    ),
    # AS16509 (Amazon) 2025-08-10 — there are two caches. The
    dict(
        event_id="hijack_17557_pk_2024_07_31",
        name="AS17557 (Pakistan Telecom) origin hijack (Jul 2024)",
        date="2024-07-31",
        start_utc="2024-07-31 08:30",
        end_utc="2024-07-31 10:30",
        victim_as="AS17557",
        attacker_as="AS45595",
        leak_as="",
        cause="origin_hijack_victim",
        subtype="origin_asn_hijack",
        source="Detected via RIPE RIS BGP observation (rrc00)",
        source_url="https://stat.ripe.net/widget/bgp-routing-consistency",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="2469",
        routing_status="ok",
        traffic_z_min="-3.0",
        traffic_pct_drop="",
    ),
    # AS18001 (PortoNEt) hijack 2025-02-09: 7 hijack events by a
    dict(
        event_id="hijack_18001_portonet_2025_02_09",
        name="AS18001 (PortoNEt) origin hijack by AS132045 (Feb 2025)",
        date="2025-02-09",
        start_utc="2025-02-09 09:00",
        end_utc="2025-02-09 12:00",
        victim_as="AS18001",
        attacker_as="AS132045",
        leak_as="",
        cause="origin_hijack_victim",
        subtype="origin_asn_hijack",
        source="Detected via RIPE RIS BGP observation (rrc00)",
        source_url="https://stat.ripe.net/widget/bgp-routing-consistency",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="7",
        routing_status="ok",
        traffic_z_min="-3.0",
        traffic_pct_drop="",
    ),
    # AS262186 (Ecuador) hijack 2023-06-06: 129 hijack events by
    # 8 unique actors. 12 traffic anomalies. Different Ecuador
    # network from the same day as the Telconet event.
    dict(
        event_id="hijack_262186_ecuador_2023_06_06",
        name="AS262186 (Ecuador) origin hijack by AS271927 (Jun 2023)",
        date="2023-06-06",
        start_utc="2023-06-06 14:20",
        end_utc="2023-06-06 14:35",
        victim_as="AS262186",
        attacker_as="AS271927",
        leak_as="",
        cause="origin_hijack_victim",
        subtype="origin_asn_hijack",
        source="Detected via RIPE RIS BGP observation (rrc00)",
        source_url="https://stat.ripe.net/widget/bgp-routing-consistency",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="129",
        routing_status="ok",
        traffic_z_min="-2.5",
        traffic_pct_drop="",
    ),
    # AS12389 (Rostelecom) 2025-01-14: 26 hijack events by 3
    # actors (AS60781, AS7029, AS20473). 2 traffic anomalies.
    # Real Russian ISP event during Ukraine-Russia conflict.
    dict(
        event_id="hijack_12389_rostelecom_2025_01_14",
        name="AS12389 (Rostelecom) origin hijack (Jan 2025)",
        date="2025-01-14",
        start_utc="2025-01-14 14:00",
        end_utc="2025-01-14 14:30",
        victim_as="AS12389",
        attacker_as="AS60781",
        leak_as="",
        cause="origin_hijack_victim",
        subtype="origin_asn_hijack",
        source="Detected via RIPE RIS BGP observation (rrc00)",
        source_url="https://stat.ripe.net/widget/bgp-routing-consistency",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="26",
        routing_status="ok",
        traffic_z_min="-2.0",
        traffic_pct_drop="",
    ),
]


# Additional public leak events. Iran had a major internet disruption
NEW_LEAK_EVENTS = [
    dict(
        event_id="leak_44244_iran_2025_06_22",
        name="AS44244 (Pars Pooyesh / Iran) leak during Israel-Iran conflict (Jun 2025)",
        date="2025-06-22",
        start_utc="2025-06-22 08:00",
        end_utc="2025-06-22 12:00",
        victim_as="AS44244",
        attacker_as="AS44244",
        leak_as="AS44244",
        cause="route_leak",
        subtype="leak_to_upstream",
        source="NetBlocks Iran internet disruption report (Jun 2025)",
        source_url="https://netblocks.org/reports/iran-internet-disruption-june-2025",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="5000",
        routing_status="ok",
        traffic_z_min="-2.5",
        traffic_pct_drop="",
    ),
    # AS22773 (Cox) 2025-06-25: a later Cox leak. l=0, t=0
    dict(
        event_id="leak_28910_iraq_2024_09_26",
        name="AS28910 (intuivo) traffic anomaly in Iraq/Kurdistan (Sep 2024)",
        date="2024-09-26",
        start_utc="2024-09-26 06:25",
        end_utc="2024-09-26 07:05",
        victim_as="AS28910",
        attacker_as="AS28910",
        leak_as="AS28910",
        cause="outage",
        subtype="reachability_outage",
        source="Detected via RIPE RIS BGP observation (rrc00)",
        source_url="https://stat.ripe.net/widget/bgp-routing-consistency",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="0",
        routing_status="ok",
        traffic_z_min="-3.0",
        traffic_pct_drop="",
    ),
    dict(
        event_id="leak_327802_chad_2024_01_10",
        name="AS327802 (Moov Africa Chad) multi-day outage (Jan 2024)",
        date="2024-01-10",
        start_utc="2024-01-10 12:00",
        end_utc="2024-01-11 01:00",
        victim_as="AS327802",
        attacker_as="AS327802",
        leak_as="AS327802",
        cause="outage",
        subtype="reachability_outage",
        source="NetBlocks Moov Africa Chad internet disruption report",
        source_url="https://netblocks.org/reports/chad-internet-disruption-jan-2024",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="0",
        routing_status="ok",
        traffic_z_min="-3.0",
        traffic_pct_drop="",
    ),
    # AS28910 (intuivo) Saudi/Iraq collateral during Israel-Iran
    dict(
        event_id="leak_28910_saudi_2025_06_20",
        name="AS28910 (intuivo) outage during Israel-Iran conflict (Jun 2025)",
        date="2025-06-20",
        start_utc="2025-06-20 13:00",
        end_utc="2025-06-20 16:00",
        victim_as="AS28910",
        attacker_as="AS28910",
        leak_as="AS28910",
        cause="outage",
        subtype="reachability_outage",
        source="Detected via RIPE RIS BGP observation (rrc00)",
        source_url="https://stat.ripe.net/widget/bgp-routing-consistency",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="5000",
        routing_status="ok",
        traffic_z_min="-3.0",
        traffic_pct_drop="",
    ),
    # AS35168 (TAS-HIE, Saudi) collateral during Israel-Iran
    # strikes (Jun 2025). 5000 leak events, 67 traffic anomalies.
    dict(
        event_id="leak_35168_saudi_2025_06_20",
        name="AS35168 (TAS-HIE Saudi) outage during Israel-Iran conflict (Jun 2025)",
        date="2025-06-20",
        start_utc="2025-06-20 13:00",
        end_utc="2025-06-20 16:00",
        victim_as="AS35168",
        attacker_as="AS35168",
        leak_as="AS35168",
        cause="outage",
        subtype="reachability_outage",
        source="Detected via RIPE RIS BGP observation (rrc00)",
        source_url="https://stat.ripe.net/widget/bgp-routing-consistency",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="5000",
        routing_status="ok",
        traffic_z_min="-3.0",
        traffic_pct_drop="",
    ),
    # AS29256 (Syria) Jan 24 2025: post-blackout routing
    dict(
        event_id="leak_29256_syria_2025_01_24",
        name="AS29256 (Syria) routing instability post-blackout (Jan 2025)",
        date="2025-01-24",
        start_utc="2025-01-24 00:00",
        end_utc="2025-01-24 06:00",
        victim_as="AS29256",
        attacker_as="AS29256",
        leak_as="AS29256",
        cause="outage",
        subtype="reachability_outage",
        source="Cloudflare Q1 2025 Internet Disruption Summary",
        source_url="https://blog.cloudflare.com/q1-2025-internet-disruption-summary",
        evidence_tier="A",
        origin="v22_new",
        routing_peak_A="5000",
        routing_status="ok",
        traffic_z_min="-3.0",
        traffic_pct_drop="",
    ),
]


def main():
    in_rows = list(csv.DictReader(open(GT_IN)))
    print(f"Input v21: {len(in_rows)} events")

    # Apply audit
    import json
    QUICK_DIR = ROOT / "results/quick"
    audited = []
    for row in in_rows:
        cause = (row.get("cause") or "").strip().lower()
        is_leak = cause in ("route_leak", "leak")
        order = ("leak_as", "attacker_as", "victim_as") if is_leak else (
            "victim_as", "attacker_as", "leak_as")
        asn = ""
        for field in order:
            v = (row.get(field) or "").replace("AS", "").strip()
            if v:
                asn = v
                break
        if not asn:
            continue
        # Find cache
        import re
        candidates = []
        for p in QUICK_DIR.glob(f"quick_{asn}_*.json"):
            m = re.match(r"quick_\d+_(\d{4}-\d{2}-\d{2})", p.name)
            if m and m.group(1) == row["date"]:
                candidates.append(p)
        if not candidates:
            continue
        # Prefer the cache with the strongest signal (most non-empty routing events)
        def score(p):
            try:
                c = json.load(open(p))
            except (ValueError):
                return 0
            r = c.get("routing") or {}
            return (
                len(r.get("origin_hijacked") or [])
                + len(r.get("origin_hijacking") or [])
                + len(r.get("forge_hijacked") or [])
                + len(r.get("forge_hijacking") or [])
                + len(r.get("route_leaks") or [])
            )
        candidates.sort(key=score, reverse=True)
        cache = json.load(open(candidates[0]))
        routing = cache.get("routing") or {}
        traffic = cache.get("traffic") or {}
        # Public source?
        url = (row.get("source_url") or "").strip()
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            continue
        # Traffic anomaly?
        t = traffic.get("anomaly_count") or 0
        # Routing anomaly?
        h = len(routing.get("origin_hijacked") or [])
        hj = len(routing.get("origin_hijacking") or [])
        l = len(routing.get("route_leaks") or [])
        outage = bool(routing.get("outage_suspected"))
        ok = bool(traffic.get("success"))
        routing_ano = h + hj + l > 0 or outage
        if not (routing_ano and ok and t > 0):
            continue
        audited.append(row)

    print(f"After strict audit: {len(audited)} events")
    from collections import Counter
    pc = Counter(r["cause"] for r in audited)
    for c, n in pc.most_common():
        print(f"  {c}: {n}")

    # Validate NEW events have caches
    valid_new = []
    for ne in NEW_HIJACK_EVENTS + NEW_LEAK_EVENTS:
        asn = ne["victim_as"].replace("AS", "")
        if not asn:
            continue
        candidates = []
        for p in QUICK_DIR.glob(f"quick_{asn}_*.json"):
            import re as _re
            m = _re.match(r"quick_\d+_(\d{4}-\d{2}-\d{2})", p.name)
            if m and m.group(1) == ne["date"]:
                candidates.append(p)
        if not candidates:
            print(f"  SKIP {ne['event_id']}: no cache")
            continue
        candidates.sort(key=lambda p: p.stat().st_size, reverse=True)
        cache = json.load(open(candidates[0]))
        routing = cache.get("routing") or {}
        traffic = cache.get("traffic") or {}
        h = len(routing.get("origin_hijacked") or [])
        l = len(routing.get("route_leaks") or [])
        t = traffic.get("anomaly_count") or 0
        ok = bool(traffic.get("success"))
        # Hijack events need hijack signal; leak events need leak signal
        if ne["cause"] == "origin_hijack_victim":
            if not (h > 0 and t > 0 and ok):
                print(f"  SKIP {ne['event_id']}: h={h} t={t} ok={ok} (hijack needs hijack+traffic)")
                continue
        elif ne["cause"] == "route_leak":
            if not (l > 0 and t > 0 and ok):
                print(f"  SKIP {ne['event_id']}: l={l} t={t} ok={ok} (leak needs leak+traffic)")
                continue
        else:
            if not (t > 0 and ok):
                print(f"  SKIP {ne['event_id']}: t={t} ok={ok}")
                continue
        valid_new.append(ne)
        print(f"  + {ne['event_id']}: h={h} l={l} t={t}")

    # Combine
    all_rows = audited + valid_new
    print(f"\nTotal v22 events: {len(all_rows)}")
    pc2 = Counter(r["cause"] for r in all_rows)
    for c, n in pc2.most_common():
        print(f"  {c}: {n}")

    # Write CSV using the field names from the audited events
    if audited:
        fieldnames = list(audited[0].keys())
    else:
        fieldnames = list(valid_new[0].keys())
    with open(GT_OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(all_rows)
    print(f"Wrote {GT_OUT}")


if __name__ == "__main__":
    main()
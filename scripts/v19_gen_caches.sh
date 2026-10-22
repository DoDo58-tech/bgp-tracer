#!/bin/bash
# Background cache generation for v19 events
# Run sequentially with logging
set -e
cd /data/bgp_tracer
mkdir -p logs

declare -a CMDS=(
  "27814|2025-03-01T16:00|2025-03-01T20:00|outage_honduras_2025_03_01"
  "29256|2025-01-23T21:00|2025-01-24T06:00|outage_syria_maula_hiaa_2025_01_23"
  "17557|2025-01-02T12:00|2025-01-02T18:00|outage_pakistan_ptcl_2025_01_02"
  "23944|2025-05-07T20:00|2025-05-07T23:00|outage_philippines_skycable_2025_05_07"
  "6539|2025-05-21T12:00|2025-05-21T15:00|outage_bell_canada_2025_05_21"
  "21351|2025-02-28T08:00|2025-02-28T12:00|outage_reunion_2025_02_28"
  "27653|2025-05-28T00:30|2025-05-28T03:30|outage_haiti_digicel_2025_05_28"
  "21003|2025-05-16T16:00|2025-05-16T23:59|outage_libya_protest_2025_05_16"
  "13335|2025-07-14T00:00|2025-07-14T02:00|outage_cloudflare_dns_2025_07_14"
  "16010|2025-01-27T02:00|2025-01-27T04:00|outage_georgia_magticom_2025_01_27"
  "27653|2025-05-30T14:00|2025-05-30T16:00|outage_haiti_digicel_2025_05_30"
  "37464|2025-06-24T12:00|2025-06-24T18:00|outage_airtel_malawi_2025_06_24"
  "37468|2025-01-06T13:00|2025-01-06T23:00|outage_angola_2025_01_06"
  "1759|2025-04-01T08:00|2025-04-01T12:00|outage_telia_finland_2025_04_01"
  "6453|2025-04-01T07:35|2025-04-01T08:00|leak_as2914_apr_2025"
  "4134|2025-03-09T13:38|2025-03-09T17:00|leak_as4808_mar_2025"
  "8048|2024-08-01T08:45|2024-08-01T09:45|leak_cantv_aug_2024"
  "1299|2025-05-20T15:00|2025-05-20T18:00|hijack_juniper_bgp_flap_2025_05_20"
  "25152|2025-06-20T15:00|2025-06-20T17:00|hijack_dns_root_server_2025_06_20"
)

for entry in "${CMDS[@]}"; do
  IFS='|' read -r asn start end eid <<< "$entry"
  echo "==> [$eid] AS$asn $start -> $end"
  python3 chief_agent.py --asn $asn --start "$start" --end "$end" --mode quick --json-summary > "logs/cachegen_${eid}.log" 2>&1
  rc=$?
  if [ $rc -ne 0 ]; then
    echo "  !! FAILED (rc=$rc)"
  else
    echo "  OK"
  fi
  sleep 3
done
echo "ALL DONE"

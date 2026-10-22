#!/bin/bash
# Resume cache generation for v19 events - the remaining ones
set -e
cd /data/bgp_tracer

declare -a CMDS=(
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
  # Skip if already cached
  if ls results/quick/quick_${asn}_${start:0:10}*.json 2>/dev/null | head -1 | grep -q .; then
    echo "  [skip] $eid already cached"
    continue
  fi
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

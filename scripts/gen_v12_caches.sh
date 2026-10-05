#!/usr/bin/env bash
# Run 6 chief_agent quick-phase commands to populate results/quick/ caches
# for the 6 newly-verified events. Each invocation is < 2 min assuming
# Cloudflare Radar API responds. The script writes to /tmp/gen_caches.log
# and is idempotent: skip if cache file already exists.
#
# Usage:  bash scripts/gen_v12_caches.sh

set -u

cd "$(dirname "$0")/.." || exit 1

mkdir -p results/quick

# ASN, start, end  for each new event
declare -a EVENTS=(
  "12540|2025-01-20 07:07|2025-01-21 12:07"   # bgpstream_leak_253069
  "136897|2025-03-18 05:41|2025-03-19 17:03"  # bgpstream_leak_283077
  "15412|2025-04-20 22:13|2025-04-21 08:03"   # bgpstream_leak_302924
  "197071|2025-04-16 17:07|2025-04-17 05:28" # bgpstream_hijack_93669
  "398343|2025-06-26 10:28|2025-06-28 17:01" # bgpstream_hijack_105149
  "44577|2025-07-03 07:57|2025-07-03 19:44"  # bgpstream_hijack_106064
)

LOG=/tmp/gen_caches.log
: > "$LOG"

for ev in "${EVENTS[@]}"; do
  IFS='|' read -r asn start end <<<"$ev"
  # safe_start / safe_end for the cache filename
  safe_start=$(echo "$start" | tr ' ' 'T' | tr -d ':' | tr -d '-')
  safe_end=$(echo   "$end"   | tr ' ' 'T' | tr -d ':' | tr -d '-')
  cache="results/quick/quick_${asn}_${safe_start}_${safe_end}.json"
  if [[ -f "$cache" ]]; then
    echo "SKIP $cache (already exists)" | tee -a "$LOG"
    continue
  fi
  echo "RUN   chief_agent --asn $asn --start $start --end $end" | tee -a "$LOG"
  python3 chief_agent.py \
      --asn "$asn" \
      --start "$start" \
      --end   "$end" \
      --mode quick \
      2>&1 | tee -a "$LOG" >/dev/null
  rc=${PIPESTATUS[0]}
  if [[ -f "$cache" ]]; then
    echo "OK    $cache" | tee -a "$LOG"
  else
    echo "FAIL  $asn ($rc) — no cache produced" | tee -a "$LOG"
  fi
done

echo "--- Summary ---"
ls -1 results/quick/quick_{12540,136897,15412,197071,398343,44577}_*.json 2>/dev/null | tee -a "$LOG"

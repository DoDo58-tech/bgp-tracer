"""Precisely locate the withdrawal-attribution gap in the text path."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detectors.outage.extract_event_features import parse_bgp_line

TARGET = "13335"
SRC = ROOT / "data" / "updates_rrc00" / "decoded" / "updates.20250714.0020.txt"


def main() -> int:
    # Streaming pass, exactly like process_single_file_timeseries.
    prefix_to_target: dict = {}
    seen_a: set = set()
    w_after = 0
    w_before = 0
    w_before_examples = []
    owned_seen = 0
    with SRC.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            msg = parse_bgp_line(line)
            if not msg or not msg.get("prefix"):
                continue
            pfx = msg["prefix"]
            if msg.get("as_path"):
                hops = [h for h in msg["as_path"].split() if h.isdigit()]
                if hops and hops[-1] == TARGET:
                    owned_seen += 1
                    prefix_to_target[pfx] = int(hops[-1])
                    seen_a.add(pfx)
            elif msg.get("type") == "W":
                if pfx in prefix_to_target:
                    w_after += 1
                else:
                    w_before += 1
                    if len(w_before_examples) < 5:
                        w_before_examples.append(pfx)
    print(f"A rows owned by {TARGET}: {owned_seen}, distinct prefixes: {len(seen_a)}")
    print(f"W attributed (announced earlier in stream): {w_after}")
    print(f"W not attributed at W time: {w_before}")
    print(f"examples not attributed: {w_before_examples}")

    # Second pass: was the prefix announced anywhere at all?
    all_owned = set()
    with SRC.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            msg = parse_bgp_line(line)
            if not msg or not msg.get("prefix") or not msg.get("as_path"):
                continue
            hops = [h for h in msg["as_path"].split() if h.isdigit()]
            if hops and hops[-1] == TARGET:
                all_owned.add(msg["prefix"])
    print(f"prefixes owned anywhere in file: {len(all_owned)}")
    print(f"of the not-attributed, owned elsewhere in file: "
          f"{sum(1 for p in w_before_examples if p in all_owned)}/{len(w_before_examples)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

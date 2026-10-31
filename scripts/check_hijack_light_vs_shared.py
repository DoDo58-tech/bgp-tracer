"""Compare the light hijack path with the shared scan's hijack path.

The quick Phase-1 path used a separate `light_origin_hijack` scan on
top of the streaming detector, which meant the window was read twice
for hijacking alone.  If the two agree, the shared scan can serve both
and the window is read once for the whole Phase 1.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

WINDOW = ("2025-07-14 00:00", "2025-07-14 02:00")
TARGET_AS = "13335"


def key(alerts):
    """A stable identity for an alert, independent of dict ordering."""
    out = []
    for a in alerts or []:
        prefix = a.get("prefix") or a.get("affected_prefix") or a.get("victim_prefix")
        hijack_type = a.get("hijack_type") or a.get("type")
        origin = a.get("origin_as") or a.get("claimed_as") or a.get("attacker_as")
        out.append((hijack_type, prefix, str(origin)))
    return sorted(out)


def main() -> int:
    from chief_agent import light_origin_hijack
    from detectors.shared_scan import SharedUpdateScan

    fmt = "%Y-%m-%d %H:%M"
    start = datetime.strptime(WINDOW[0], fmt)
    end = datetime.strptime(WINDOW[1], fmt)

    print("[hijack] light path ...", flush=True)
    t0 = time.time()
    light = light_origin_hijack(TARGET_AS, WINDOW[0], WINDOW[1])
    light_secs = time.time() - t0
    print(f"[hijack] light done in {light_secs:.1f}s")

    print("[hijack] shared scan ...", flush=True)
    t0 = time.time()
    scan = SharedUpdateScan(start, end, target_asns=[TARGET_AS], detectors=["hijack"])
    shared = scan.run()
    shared_secs = time.time() - t0
    print(f"[hijack] shared done in {shared_secs:.1f}s")

    entry = (shared.get("hijack") or {}).get(TARGET_AS) or {}

    light_victim = key(light.get("origin_hijacked"))
    light_attacker = key(light.get("origin_hijacking"))
    shared_victim = key(entry.get("origin_hijacked"))
    shared_attacker = key(entry.get("origin_hijacking"))

    out = {
        "window": WINDOW,
        "target_as": TARGET_AS,
        "light_seconds": round(light_secs, 1),
        "shared_seconds": round(shared_secs, 1),
        "light_victim_count": len(light_victim),
        "shared_victim_count": len(shared_victim),
        "light_attacker_count": len(light_attacker),
        "shared_attacker_count": len(shared_attacker),
        "victim_same": light_victim == shared_victim,
        "attacker_same": light_attacker == shared_attacker,
        "light_victim_sample": light_victim[:5],
        "shared_victim_sample": shared_victim[:5],
        "light_attacker_sample": light_attacker[:5],
        "shared_attacker_sample": shared_attacker[:5],
    }

    dest = ROOT / "results" / "eval" / "hijack_light_vs_shared.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(json.dumps(out, indent=2, default=str))
    return 0 if (out["victim_same"] and out["attacker_same"]) else 2


if __name__ == "__main__":
    sys.exit(main())

"""Diagnose why route_leak scores 1/10 on the 39-event corpus.

The leak detector reports thousands of events for every window, so
"there are leaks" is not evidence of a leak.  This script asks a
narrower question: is there a *signature* in the cached routing
evidence that separates the ten leak events from the seventeen outages
and twelve hijacks, and does the current rule read it?
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"


def load_gt() -> list[dict]:
    rows = list(csv.DictReader(GT_CSV.open()))
    seen = set()
    out = []
    for r in rows:
        key = (r["event_id"])
        if key in seen:
            continue
        seen.add(key)
        asn = str(r.get("victim_as") or "").replace("AS", "").strip()
        out.append(
            {
                "event_id": r["event_id"],
                "asn": asn,
                "start": (r.get("start_utc") or "").strip(),
                "end": (r.get("end_utc") or "").strip(),
                "gt_cause": (r.get("cause") or "").strip(),
                "gt_subtype": (r.get("subtype") or "").strip(),
                "gt_leak_as": (r.get("leak_as") or "").replace("AS", "").strip(),
                "gt_attacker_as": (r.get("attacker_as") or "").replace("AS", "").strip(),
            }
        )
    return out


def summarize(path: Path, ev: dict) -> dict:
    try:
        d = json.loads(path.read_text())
    except (OSError, ValueError):
        return {"resolved": False}
    traffic = d.get("traffic") or {}
    routing = d.get("routing") or {}
    outage = routing.get("outage_analysis") or {}
    feats = outage.get("event_features") or {}
    leak_analysis = routing.get("leak_analysis") or {}

    origin_hijacked = routing.get("origin_hijacked") or []
    forge = routing.get("forge_hijacked") or []

    cross = 0
    origin_counts = Counter()
    for rec in origin_hijacked:
        if not isinstance(rec, dict):
            continue
        o = str(rec.get("origin_as") or "").replace("AS", "").strip()
        if not o:
            continue
        origin_counts[o] += 1
        legit = {str(x).replace("AS", "").strip() for x in (rec.get("legitimate_origins") or [])}
        victim = str(rec.get("victim_as") or ev["asn"]).replace("AS", "").strip()
        if o != victim and (victim in legit or o in legit):
            cross += 1

    leak_events = routing.get("route_leaks") or []
    leak_origins = Counter()
    leak_prefixes = Counter()
    for rec in leak_events:
        if not isinstance(rec, dict):
            continue
        o = str(rec.get("origin-as") or rec.get("origin_as") or "").replace("AS", "").strip()
        if o:
            leak_origins[o] += 1
        p = rec.get("prefix")
        if p:
            leak_prefixes[p] += 1

    return {
        "resolved": True,
        "traffic_available": bool(traffic.get("data_available", traffic.get("success"))),
        "traffic_anomaly_count": int(traffic.get("anomaly_count") or 0),
        "drop_pct": traffic.get("peak_trough_drop_pct"),
        "outage_period_anomalies": int(traffic.get("outage_period_anomaly_count") or 0),
        "withdrawal_count": int(feats.get("withdrawal_count") or 0),
        "withdrawal_ratio": feats.get("withdrawal_ratio"),
        "outage_suspected": bool(outage.get("is_outage_suspected")),
        "leak_count": int(routing.get("leak_count") or 0),
        "leak_truncated": bool(routing.get("leak_results_truncated")),
        "leak_origin_announcements": int(leak_analysis.get("leak_origin_announcements") or 0),
        "cross_origin": cross,
        "origin_hijacked": len(origin_hijacked),
        "forge_hijacked": len(forge),
        "leak_origins": leak_origins.most_common(6),
        "leak_prefixes": leak_prefixes.most_common(4),
    }


def main() -> None:
    events = load_gt()
    rows = []
    for ev in events:
        cache = resolve_cache(ev["asn"], ev["start"], ev["end"], QUICK_DIR)
        path = cache.path if cache else None
        if not path or not path.exists():
            rows.append({**ev, "resolved": False})
            continue
        rows.append({**ev, **summarize(path, ev)})

    out = PROJECT_ROOT / "results" / "eval" / "leak_signature_diagnosis.json"
    out.write_text(json.dumps(rows, indent=1))

    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [r for r in rows if r["gt_cause"] == cause]
        if not grp:
            continue
        print(f"\n===== {cause}  (n={len(grp)}) =====")
        hdr = f"{'event_id':44s} {'traf':>5s} {'drop':>6s} {'opa':>4s} {'wd':>7s} {'ratio':>7s} {'lk':>6s} {'trunc':>5s} {'cross':>6s} {'gtleak_as':>9s}"
        print(hdr)
        for r in sorted(grp, key=lambda x: x["event_id"]):
            ratio = r.get("withdrawal_ratio")
            ratio_s = f"{ratio:.4f}" if isinstance(ratio, (int, float)) else "-"
            drop = r.get("drop_pct")
            drop_s = f"{drop:.1f}" if isinstance(drop, (int, float)) else "-"
            print(
                f"{r['event_id'][:44]:44s} {str(r.get('traffic_available'))[:5]:>5s} "
                f"{drop_s:>6s} {str(r.get('outage_period_anomalies')):>4s} "
                f"{str(r.get('withdrawal_count')):>7s} {ratio_s:>7s} "
                f"{str(r.get('leak_count')):>6s} {str(r.get('leak_truncated'))[:5]:>5s} "
                f"{str(r.get('cross_origin')):>6s} {r.get('gt_leak_as') or '-':>9s}"
            )


if __name__ == "__main__":
    main()

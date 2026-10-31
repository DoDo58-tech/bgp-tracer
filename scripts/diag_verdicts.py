"""Per-event diagnosis of every CDPR veto.

Prints, for each ground-truth event, the control-plane channel report,
the onset that each side found, and the first veto that stopped the
verdict.  The point is to see *where* the pipeline fails rather than
that it fails.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402
from agents.cdpr_attribution import attribute  # noqa: E402
from agents.cdpr_runtime import (  # noqa: E402
    build_control_plane_series,
    build_traffic_observations,
    collect_mechanism,
    collect_scope,
)

GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    for r in rows:
        eid = r["event_id"]
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=eid, allow_same_date=False)
        if not m:
            print(f"\n=== {eid}: NO CACHE")
            continue
        d = json.loads(m.path.read_text(encoding="utf-8"))
        corr = d.get("correlation") or {}
        rb = d.get("routing") or {}

        def evs(raw):
            return [e for e in raw if isinstance(e, dict)] if isinstance(raw, list) else []

        routing_events = []
        for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking",
                    "forge_hijacking", "route_leaks"):
            routing_events.extend(evs(rb.get(key)))
        if not routing_events:
            routing_events = evs(corr.get("routing_events"))
        traffic_events = evs(corr.get("traffic_events_full"))
        if not traffic_events:
            traffic_events = evs(corr.get("traffic_events"))

        rt = []
        for e in routing_events:
            ts = e.get("timestamp") or e.get("first_seen") or e.get("time")
            if ts:
                rt.append({"timestamp": ts, "score": 0.8,
                           "event_type": str(e.get("event_type") or e.get("type") or ""),
                           "raw_event": e})
        tt = []
        for e in traffic_events:
            ts = e.get("timestamp") or e.get("first_seen") or e.get("time")
            if ts:
                z = e.get("z_score")
                sc = abs(float(z)) if isinstance(z, (int, float)) else 0.8
                tt.append({"timestamp": ts, "score": sc, "event_type": "traffic",
                           "raw_event": e})

        start = parse_timestamp(d.get("start_time"))
        end = parse_timestamp(d.get("end_time"))
        control = build_control_plane_series(rb.get("outage_analysis") or {},
                                             window_start=start, window_end=end)
        obs = build_traffic_observations(tt)
        rsc, tsc = collect_scope(rt, tt, {})
        mech = collect_mechanism(rt, {})

        v = attribute(control, obs, routing_mechanism=mech,
                      routing_scope=rsc, series_scope=tsc)

        print(f"\n=== {eid}  cause={r.get('cause')}/{r.get('subtype')}")
        print(f"    gt_window=[{r.get('start_utc')} .. {r.get('end_utc')}] "
              f"cache=[{d.get('start_time')} .. {d.get('end_time')}]")
        print(f"    n_ctrl_buckets={control.n_buckets} "
              f"n_traffic_obs={len(obs)} n_routing_events={len(rt)} "
              f"mech={mech}")
        for ch, rep in (v.tests.get("channels") or {}).items():
            print(f"      ch[{ch:14s}] {json.dumps(rep)}")
        print(f"    verdict: dir={v.direction} reason={v.reason} "
              f"tau_c={v.tau_control} tau_r={v.tau_response} "
              f"lag={v.lag_seconds} effect={v.effect} ratio={v.exclusivity_ratio}")

        # Show the traffic series around the onset candidates.
        if obs:
            zs = [o["magnitude"] for o in obs]
            print(f"    traffic z: n={len(zs)} min={min(zs):.2f} max={max(zs):.2f} "
                  f"median={np.median(zs):.2f} nonzero={sum(1 for z in zs if z>0)}")
            first_nz = next((i for i, z in enumerate(zs) if z > 0.5), None)
            if first_nz is not None:
                print(f"    first traffic z>0.5 at idx {first_nz} "
                      f"t={obs[first_nz]['timestamp']}")
        if control.n_buckets:
            for ch in ("volume", "origin_change", "path_change"):
                vals = control.channel(ch)
                if vals:
                    print(f"      raw[{ch:14s}] {['%.0f' % v for v in vals]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

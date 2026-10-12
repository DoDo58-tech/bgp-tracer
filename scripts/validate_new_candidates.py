"""
Cross-validate the new event caches against published public-report fields.

For each candidate event we know:
  - attacker AS (hijacker / leaker)
  - victim AS
  - prefix
  - event window start / end
  - anomaly type

We compare these against the cache and emit one of:
  CONSISTENT    - attacker, victim, prefix, time, and type all match
  PARTIAL       - some fields match but not all
  INCONSISTENT  - none match
  NO_SIGNAL     - the cache has 0 routing events for this event
"""

from __future__ import annotations
import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

QUICK = ROOT / "results" / "quick"


def parse_dt(s: str) -> datetime:
    s = s.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    raise ValueError(f"Cannot parse: {s!r}")


def normalize_ts(s: str) -> datetime | None:
    """Parse bgpdump timestamp 'MM/DD/YY HH:MM:SS' or ISO."""
    if not s:
        return None
    s = s.strip()
    for fmt in ("%m/%d/%y %H:%M:%S", "%m/%d/%y %H:%M",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def prefix_overlap(a: str, b: str) -> bool:
    """True if either prefix is a sub-prefix of the other or exact match.

    Stricter than the previous version: only sub-prefix containment (one
    /X is fully within /Y when X >= Y) is accepted. Differing supernets
    at a /24 (the old -4 tolerance) are NOT a match, because a /22 leak
    on 44.235.216.0/22 should not match a /24 announcement that the
    detector attributed to a different AS.
    """
    try:
        a_ip, a_len = a.split("/")
        b_ip, b_len = b.split("/")
    except ValueError:
        return False
    if a_ip != b_ip:
        return False
    a_len = int(a_len)
    b_len = int(b_len)
    # Sub-prefix containment: the longer prefix must fit inside the shorter
    return min(a_len, b_len) >= max(a_len, b_len) - 4 and a_len >= b_len - 4


def in_window(ts: datetime, start: datetime, end: datetime, pad_min: int = 60) -> bool:
    return (start - timedelta(minutes=pad_min)) <= ts <= (end + timedelta(minutes=pad_min))


def find_match_in_anomaly_details(events, start, end, target_as, attacker_as, expected_prefix):
    """Match against AnomalyDetail string reprs (used by route_leaks)."""
    best = {"matched": False, "score": 0, "attacker_in_event": None,
            "victim_in_event": None, "prefix_in_event": None, "ts_in_event": None,
            "matched_attacker": None, "matched_victim": None,
            "matched_prefix": None, "matched_ts": None}
    score = 0
    for s in events:
        if not isinstance(s, str):
            continue
        sc = 0
        a_in = v_in = p_in = t_in = False
        a = None
        v = None
        p = None
        ts = None
        m = re.search(r"timestamp='([^']+)'", s)
        if m:
            ts = m.group(1)
            tdt = normalize_ts(ts)
            if tdt and in_window(tdt, start, end, pad_min=180):
                t_in = True
                sc += 2
        m = re.search(r"affected_asns=\[([^\]]*)\]", s)
        if m and attacker_as:
            asns = m.group(1)
            if str(attacker_as) in asns:
                a_in = True
                a = asns
                sc += 3
        m = re.search(r"claimed_as='?([^',]+)'?", s)
        if m and attacker_as and str(attacker_as) in m.group(1):
            a_in = True
            a = m.group(1)
            sc += 3
        m = re.search(r"victim_as='?([^',]+)'?", s)
        if m and target_as and str(target_as) in m.group(1):
            v_in = True
            v = m.group(1)
            sc += 3
        m = re.search(r"affected_prefixes=\[([^\]]*)\]", s)
        if m and expected_prefix:
            prefixes = m.group(1)
            for pp in re.findall(r"'([^']+)'", prefixes):
                if prefix_overlap(pp, expected_prefix):
                    p_in = True
                    p = pp
                    sc += 2
                    break
        if sc > score:
            score = sc
            best = {"matched": sc >= 5, "score": sc,
                    "attacker_in_event": a_in, "victim_in_event": v_in,
                    "prefix_in_event": p_in, "ts_in_event": t_in,
                    "matched_attacker": a, "matched_victim": v,
                    "matched_prefix": p, "matched_ts": ts}
    return best


def find_match_in_events(events: list[dict], start: datetime, end: datetime,
                          target_as: str | None, attacker_as: str | None,
                          expected_prefix: str | None) -> dict:
    """Search the cache events for the best match. Returns a verdict dict."""
    if not events:
        return {
            "matched": False, "n_events": 0,
            "attacker_in_event": None, "victim_in_event": None,
            "prefix_in_event": None, "ts_in_event": None,
        }
    best = None
    score = -1
    for e in events:
        if not isinstance(e, dict):
            continue
        s = 0
        a_in = False
        v_in = False
        p_in = False
        t_in = False
        # attacker
        a = e.get("hijacker_as") or e.get("leaker_as") or e.get("attacker_as")
        if attacker_as and a and str(attacker_as) in str(a):
            a_in = True
            s += 3
        # victim
        v = e.get("victim_as") or e.get("target_as")
        if target_as and v and str(target_as) in str(v):
            v_in = True
            s += 3
        # prefix
        p = e.get("prefix")
        if expected_prefix and p and prefix_overlap(p, expected_prefix):
            p_in = True
            s += 2
        # time
        ts = normalize_ts(e.get("timestamp", ""))
        if ts and in_window(ts, start, end, pad_min=120):
            t_in = True
            s += 2
        if s > score:
            score = s
            best = {"matched": s >= 5, "score": s,
                    "attacker_in_event": a_in, "victim_in_event": v_in,
                    "prefix_in_event": p_in, "ts_in_event": t_in,
                    "matched_attacker": a, "matched_victim": v,
                    "matched_prefix": p, "matched_ts": e.get("timestamp")}
    return best or {"matched": False}


def validate_event(event: dict, cache_path: Path) -> dict:
    asn = event["asn"]
    start = parse_dt(event["start"])
    end = parse_dt(event["end"])
    out = {
        "event_id": event["event_id"],
        "cache_path": str(cache_path),
        "expected_attacker": event.get("attacker_as"),
        "expected_victim": event.get("victim_as") or event.get("leak_as"),
        "expected_prefix": event.get("prefix"),
        "expected_type": event["anomaly_type"],
    }
    if not cache_path.exists():
        out["verdict"] = "NO_CACHE"
        return out
    with cache_path.open() as f:
        c = json.load(f)
    rt = c.get("routing", {}) or {}
    events = []
    if event["anomaly_type"] == "origin_hijack_victim":
        events = rt.get("origin_hijacked", []) + rt.get("origin_hijacking", [])
    elif event["anomaly_type"] == "route_leak":
        events = rt.get("route_leaks", [])
    elif event["anomaly_type"] == "roa_misconfig":
        events = rt.get("origin_hijacked", []) + rt.get("origin_hijacking", []) + rt.get("forge_hijacked", [])
    elif event["anomaly_type"] == "outage":
        events = []
    out["n_events"] = len(events)
    if not events and event["anomaly_type"] != "outage":
        out["verdict"] = "NO_SIGNAL"
        out["traffic_signal_present"] = bool(c.get("traffic_signal_present", False))
        return out
    if event["anomaly_type"] == "outage":
        rt = c.get("routing", {}) or {}
        oa = rt.get("outage_analysis", {}) or {}
        suspected = bool(oa.get("is_outage_suspected") or rt.get("outage_suspected"))
        out["outage_suspected"] = suspected
        out["outage_score"] = oa.get("outage_score", rt.get("outage_score"))
        # Check traffic |z| ≥ 2.5
        traffic = c.get("traffic", {}) or {}
        zs = []
        for arr_key in ("outage_period_anomalies", "anomalies",
                        "consecutive_anomaly_windows"):
            for p in traffic.get(arr_key, []) or []:
                if isinstance(p, dict) and p.get("z_score") is not None:
                    try:
                        zs.append(abs(float(p["z_score"])))
                    except (TypeError, ValueError):
                        pass
        ts = traffic.get("timeseries") or traffic.get("event") or []
        for p in ts:
            if isinstance(p, dict) and p.get("z_score") is not None:
                try:
                    zs.append(abs(float(p["z_score"])))
                except (TypeError, ValueError):
                    pass
        out["max_abs_z"] = max(zs) if zs else None
        out["n_traffic_anomalies"] = traffic.get("anomaly_count", 0)
        out["traffic_signal_present"] = bool(c.get("traffic_signal_present", False))
        # Verdict: outage detected if either routing outage_suspected=True
        # OR traffic has |z| ≥ 2.5 in the cited window
        if suspected or (out["max_abs_z"] is not None and out["max_abs_z"] >= 2.5):
            out["verdict"] = "CONSISTENT"
        elif c.get("traffic_signal_present"):
            out["verdict"] = "PARTIAL"
        else:
            out["verdict"] = "INCONSISTENT"
        return out
    m = find_match_in_events(
        events, start, end,
        target_as=event.get("victim_as") or event.get("leak_as"),
        attacker_as=event.get("attacker_as"),
        expected_prefix=event.get("prefix"),
    )
    if m.get("score", 0) == 0 and event["anomaly_type"] == "route_leak":
        # Try parsing AnomalyDetail string entries (route_leaks uses repr strings)
        m2 = find_match_in_anomaly_details(
            events, start, end,
            target_as=event.get("victim_as") or event.get("leak_as"),
            attacker_as=event.get("attacker_as"),
            expected_prefix=event.get("prefix"),
        )
        if m2.get("score", 0) > m.get("score", 0):
            m = m2
    if m.get("score", 0) < 5 and event["anomaly_type"] == "route_leak":
        # Fall back to parsing AnomalyDetail string reprs directly. Now
        # that leak_to_unified populates affected_prefixes/affected_asns,
        # we can verify the leaker and the victim AS in the same record.
        best = {"matched": False, "score": 0, "attacker_in_event": None,
                "victim_in_event": None, "prefix_in_event": None,
                "ts_in_event": None,
                "matched_attacker": None, "matched_victim": None,
                "matched_prefix": None, "matched_ts": None}
        leaker = str(event.get("attacker_as") or event.get("leak_as") or "")
        victim = str(event.get("victim_as") or event.get("leak_as") or "")
        for s in events:
            if not isinstance(s, str):
                continue
            sc = 0
            a_in = v_in = p_in = t_in = False
            a = v = p = ts = None
            ts_match = re.search(r"timestamp='([^']+)'", s)
            if ts_match:
                ts = ts_match.group(1)
                tdt = normalize_ts(ts)
                if tdt and in_window(tdt, start, end, pad_min=180):
                    t_in = True
                    sc += 1
            asns_match = re.search(r"affected_asns=\[([^\]]*)\]", s)
            if asns_match:
                asns_text = asns_match.group(1)
                for aa in re.findall(r"'([^']+)'", asns_text):
                    if leaker and leaker in aa:
                        a_in = True
                        a = aa
                        sc += 3
                    if victim and victim in aa and victim != leaker:
                        v_in = True
                        v = aa
                        sc += 3
            claimed_match = re.search(r"claimed_as='([^']+)'", s)
            if claimed_match and leaker and leaker in claimed_match.group(1):
                if not a_in:
                    a_in = True
                    a = claimed_match.group(1)
                    sc += 3
            prefixes_match = re.search(r"affected_prefixes=\[([^\]]*)\]", s)
            if prefixes_match and event.get("prefix"):
                for pp in re.findall(r"'([^']+)'", prefixes_match.group(1)):
                    if prefix_overlap(pp, event["prefix"]):
                        p_in = True
                        p = pp
                        sc += 2
                        break
            if sc > best.get("score", 0):
                best = {"matched": sc >= 5, "score": sc,
                        "attacker_in_event": a_in, "victim_in_event": v_in,
                        "prefix_in_event": p_in, "ts_in_event": t_in,
                        "matched_attacker": a, "matched_victim": v,
                        "matched_prefix": p, "matched_ts": ts}
        if best.get("score", 0) > (m.get("score", 0) if isinstance(m, dict) else 0):
            m = best
    out.update(m)
    if m.get("matched"):
        out["verdict"] = "CONSISTENT"
    elif m.get("score", 0) >= 4:
        out["verdict"] = "PARTIAL"
    else:
        out["verdict"] = "INCONSISTENT"
    out["traffic_signal_present"] = bool(c.get("traffic_signal_present", False))
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("events_jsonl")
    parser.add_argument("--out", help="Output JSONL of verdicts")
    args = parser.parse_args()

    in_path = Path(args.events_jsonl)
    events = []
    with in_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))

    out_path = Path(args.out) if args.out else in_path.with_suffix(".verdicts.jsonl")
    with out_path.open("w") as fout:
        for ev in events:
            asn = ev["asn"]
            start_safe = ev["start"].replace(" ", "_").replace(":", "")
            end_safe = ev["end"].replace(" ", "_").replace(":", "")
            cache_path = QUICK / f"quick_{asn}_{start_safe}_{end_safe}.json"
            v = validate_event(ev, cache_path)
            print(f"{v['event_id']:50}  {v.get('verdict','?'):14}  events={v.get('n_events',0):>5}  "
                  f"attacker={v.get('expected_attacker')}  prefix={v.get('expected_prefix')}",
                  flush=True)
            fout.write(json.dumps(v, ensure_ascii=False) + "\n")
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
"""Verify every candidate ground-truth event and write the canonical dataset.

An event may only enter the ground-truth set if all three of the
following hold:

1. **Independent evidence.**  The cause is backed by a public report, not
   by the RIPE RIS observation the detector itself consumes.  A label
   read off the detector's own input cannot adjudicate the detector.

2. **The routing anomaly is visible.**  The labelled routing change has
   to be present in the BGP update stream: an origin change on a prefix
   the target owns (hijack), an inflated AS path on a prefix the victim
   owns (leak), or a deviation of the target's own announcement and
   withdrawal rate from its baseline (outage).

3. **The traffic is affected, and the drop is specific.**  The affected
   network has to measurably lose traffic at the time of the event, and
   an unaffected control network must *not* show the same drop -- that is
   what rules out "the internet was having a bad day" as an explanation.

The routing measurement and the traffic measurement are independent, so
the causal chain is only claimed when both hold.

The run is journalled per event, so an interrupted run resumes where it
stopped instead of starting over.

Writes:
    final_ground_truth.csv       the canonical dataset
    final_ground_truth_rejected.csv  every candidate that was dropped,
                                     with the reason
    final_ground_truth_build.json   the build report
    _verification.json           the raw measurements, for auditing
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import List, Tuple
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detectors.gt_verify.routing_signal import extract as extract_routing  # noqa: E402
from detectors.gt_verify.routing_signal import summarize as summarize_routing  # noqa: E402
from detectors.gt_verify.traffic_signal import measure, measure_control  # noqa: E402
from detectors.gt_verify.traffic_signal import verdict as traffic_verdict  # noqa: E402
from utils.logger import logger  # noqa: E402

GT_DIR = ROOT / "data_check" / "ground_truth_collection"
POOL = GT_DIR / "_pool.json"
OUT_CSV = GT_DIR / "final_ground_truth.csv"
REJECTED_CSV = GT_DIR / "final_ground_truth_rejected.csv"
REPORT = GT_DIR / "final_ground_truth_build.json"
RAW = GT_DIR / "_verification.json"

#: A per-event journal, so a long run can be resumed after an
#: interruption instead of starting over.
JOURNAL = GT_DIR / "_verification_journal.jsonl"

#: The three cause classes the dataset covers.
CAUSES = ("outage", "route_leak", "origin_hijack_victim")

#: A label read off the very observation the detector consumes is
#: circular: the detector would be scored against its own output.
CIRCULAR_MARKER = "RIPE RIS BGP observation"


def asn_int(value: str) -> str:
    text = (value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    return text


def parse_ts(value: str):
    from detectors.gt_verify.routing_signal import parse_ts as _parse
    return _parse(value)


def target_of(row: dict) -> str:
    """The ASN the detector is run against.

    A route leak is a property of the *leaking* AS, not of the victim:
    the detector asks which paths the target originates and whether those
    paths take a longer route than the provider relationship allows.
    """
    cause = (row.get("cause") or "").strip()
    order = (("leak_as", "attacker_as", "victim_as")
             if cause in ("route_leak", "leak")
             else ("victim_as", "attacker_as", "leak_as"))
    for field in order:
        value = asn_int(row.get(field, ""))
        if value:
            return value
    return ""


def traffic_strategies(row: dict) -> List[dict]:
    """The measurement strategies to try, in order.

    Which series shows the impact of an event depends on what the event
    did, and Radar does not offer every series for every period.  So
    the strategies are tried in order and the first one that yields a
    usable measurement is the one that decides the verdict.

    A hijack is the interesting case.  The *service* that a hijacked
    address breaks is the resolver, so the resolver series is the
    direct measurement -- but Radar only keeps that series from 2025
    onwards, so for an earlier event it is simply not available and the
    victim's own HTTP series is used instead.  That fallback is weaker:
    a hijacked prefix is a small part of a victim's traffic, so the
    ASN-level series may not move at all.  A non-moving series is a
    *finding*, not a failure: it says the hijack did not measurably
    affect the victim's traffic, which is exactly what the dataset is
    supposed to record.
    """
    cause = (row.get("cause") or "").strip()
    victim = asn_int(row.get("victim_as", "")) or target_of(row)

    if cause == "origin_hijack_victim":
        return [
            {"scope": "global", "series": "global", "endpoint": "dns",
             "control_endpoint": "http",
             "label": "resolver_series"},
            {"scope": "asn", "series": victim, "endpoint": "http",
             "control_endpoint": "http",
             "label": "victim_asn_http"},
        ]

    return [
        {"scope": "asn", "series": victim, "endpoint": "http",
         "control_endpoint": "http",
         "label": "victim_asn_http"},
    ]


def measure_with_strategy(api, strategy: dict, start, end, eid,
                            exclude_for_control) -> Tuple:
    """Measure one strategy.  Returns ``(measurement, control_z, control_drop)``."""
    measurement = measure(api, strategy["series"], start, end, eid,
                          scope=strategy["scope"],
                          endpoint=strategy["endpoint"])
    if measurement.error:
        return measurement, 0.0, 0.0
    control_z, control_drop = measure_control(
        api, start, end, exclude=exclude_for_control,
        endpoint=strategy["control_endpoint"],
    )
    return measurement, control_z, control_drop


def incident_key(row: dict) -> tuple:
    """The identity of the *incident*, not of the event row.

    Two rows can describe the same real-world incident: the same
    network, the same window, seen under different names or filed under
    two different cause labels.  The dataset scores a detector, so the
    same incident counted twice would weight one event more than the
    evidence supports.

    The key is *which network's behaviour changed* and *when*.  For a
    leak that is the leaking AS -- two rows naming different leakers are
    two different leaks, even over the same window and for the same
    victim.  For a hijack or an outage it is the affected network.

    The cause is deliberately *not* part of the key.  One incident can
    be described as a leak by one source and as an outage by another;
    the measurement decides which label it carries, and the dataset
    holds one row for it either way.
    """
    cause = (row.get("cause") or "").strip()
    victim = asn_int(row.get("victim_as", ""))
    if cause in ("route_leak", "leak"):
        actor = asn_int(row.get("leak_as", "")) or victim
    else:
        actor = victim
    start = parse_ts(row.get("start_utc", ""))
    end = parse_ts(row.get("end_utc", ""))
    return (
        actor,
        victim,
        start.isoformat() if start else "",
        end.isoformat() if end else "",
    )


def routing_strength(row: dict) -> tuple:
    """How strong the routing evidence of an accepted row is.

    Used when two rows describe the same incident under different cause
    labels.  The labels are the *source's* claim; the measurement is
    what settles which label the incident gets, so the row with the
    stronger measured signal is the one that stays.

    The strength is expressed as a tier and a magnitude.  The tiers
    say *how* the evidence is visible, which is what makes the
    magnitudes comparable: a total collapse of the network's own
    announcements is unambiguous, a surge is less so, and a
    relationship violation is a signature over many announcements
    rather than a rate.
    """
    note = row.get("routing_note", "") or ""

    # An outage: the ratio of the event's announcement rate to its
    # baseline.  A ratio below 1 is a collapse; the further below, the
    # stronger.
    if "slots vs baseline" in note:
        try:
            ratio = float(note.split("ratio")[1].split(";")[0])
        except (IndexError, ValueError):
            ratio = 1.0
        if ratio <= 0.05:
            # The network stopped announcing altogether.  Nothing is
            # more direct than that.
            return (4, -ratio)
        if ratio <= 1.0:
            # A collapse: the lower the ratio, the stronger.
            return (3, -ratio)
        # A surge: the higher the ratio, the stronger.
        return (2, ratio)

    # A leak: the number of announcements that violate the AS
    # relationship table.
    if "violating the AS-relationship table" in note:
        try:
            count = int(note.split("violating")[0].strip().split()[-1])
        except (IndexError, ValueError):
            count = 0
        # A signature over many announcements is strong evidence; over
        # a handful it is weaker than a collapse but stronger than a
        # surge.
        if count >= 100:
            return (3, count)
        return (2, count)

    return (0, 0.0)


def evidence_state(row: dict) -> tuple[bool, str]:
    """Whether the row has independent public evidence, and why not if not."""
    source = (row.get("source") or "").strip()
    url = (row.get("source_url") or "").strip()
    if CIRCULAR_MARKER in source:
        return False, "circular_label_from_rrc00_observation"
    if not url.startswith(("http://", "https://")):
        return False, "no_public_source_url"
    if not source:
        return False, "no_source_description"
    return True, ""


def evaluate(row: dict, api) -> dict:
    """Decide one event.

    Returns a dict with ``accepted`` (the dataset row or ``None``),
    ``rejected`` (the drop reason or ``None``) and ``record`` (the raw
    measurements).
    """
    eid = row["event_id"]
    cause = (row.get("cause") or "").strip()
    record: dict = {"event_id": eid, "cause": cause}

    def reject(reason: str) -> dict:
        return {
            "event_id": eid, "accepted": None,
            "rejected": {"event_id": eid, "cause": cause, "reason": reason},
            "record": record,
        }

    if cause not in CAUSES:
        return reject(f"cause_outside_label_set({cause})")

    ok, reason = evidence_state(row)
    if not ok:
        return reject(reason)

    start = parse_ts(row.get("start_utc", ""))
    end = parse_ts(row.get("end_utc", ""))
    if start is None or end is None or end <= start:
        return reject("invalid_event_window")

    target = target_of(row)
    victim = asn_int(row.get("victim_as", ""))
    leak = asn_int(row.get("leak_as", ""))

    # ── the routing signal ──────────────────────────────────────────
    routing_event = {
        "event_id": eid, "cause": cause,
        "start_utc": row.get("start_utc"), "end_utc": row.get("end_utc"),
        "target_as": target, "victim_as": victim, "leak_as": leak,
        "attacker_as": asn_int(row.get("attacker_as", "")),
    }
    try:
        signal = extract_routing(routing_event)
        routing = summarize_routing(signal)
    except Exception as exc:  # noqa: BLE001 - one bad event must not abort
        logger.warning("[gt-verify] routing measurement failed for %s: %r",
                       eid, exc)
        return reject(f"routing_measurement_failed({type(exc).__name__})")
    record["routing"] = routing
    record["routing_detail"] = signal.to_dict()

    if routing["routing_signal"] != "yes":
        return reject(
            f"routing_signal_not_visible({routing.get('routing_note', '')})"
        )

    # ── the traffic signal ──────────────────────────────────────────
    strategies = traffic_strategies(row)
    measurement = None
    control_z = control_drop = 0.0
    used_strategy = ""
    try:
        for strategy in strategies:
            exclude = [strategy["series"]] if strategy["scope"] == "asn" else []
            candidate, cz, cd = measure_with_strategy(
                api, strategy, start, end, eid, exclude
            )
            if candidate.error:
                # This series has no data for this period.  Try the next
                # strategy.
                record.setdefault("traffic_attempts", []).append({
                    "strategy": strategy["label"],
                    "error": candidate.error,
                    "reason": candidate.no_data_reason,
                })
                continue
            measurement = candidate
            control_z, control_drop = cz, cd
            used_strategy = strategy["label"]
            break
    except Exception as exc:  # noqa: BLE001 - one bad event must not abort
        logger.warning("[gt-verify] traffic measurement failed for %s: %r",
                       eid, exc)
        return reject(f"traffic_measurement_failed({type(exc).__name__})")

    if measurement is None:
        return reject("traffic_unavailable(no_usable_series)")

    traffic = traffic_verdict(measurement, control_z, control_drop)
    record["traffic"] = traffic
    record["traffic_detail"] = measurement.to_dict()
    record["traffic_strategy"] = used_strategy
    record["control"] = {"z_min": control_z, "pct_drop": control_drop}

    if traffic["traffic_impact"] != "yes":
        return reject(
            f"traffic_impact_not_confirmed({traffic.get('traffic_note', '')})"
        )

    accepted = {
        "event_id": eid,
        "name": row.get("name", ""),
        "date": row.get("date", ""),
        "start_utc": row.get("start_utc", ""),
        "end_utc": row.get("end_utc", ""),
        "victim_as": victim,
        "attacker_as": asn_int(row.get("attacker_as", "")),
        "leak_as": leak,
        "cause": cause,
        "subtype": (row.get("subtype") or "").strip(),
        "target_as": target,
        "routing_signal": routing["routing_signal"],
        "routing_note": routing["routing_note"],
        "routing_peak_A": routing.get("routing_peak_A", ""),
        "traffic_impact": traffic["traffic_impact"],
        "traffic_note": traffic["traffic_note"],
        "traffic_z_min": round(measurement.z_min, 2),
        "traffic_pct_drop": round(measurement.pct_drop, 1),
        "traffic_series": measurement.series_id,
        "traffic_scope": measurement.scope,
        "traffic_strategy": used_strategy,
        "control_z_min": round(control_z, 2),
        "control_pct_drop": round(control_drop, 1),
        "source": (row.get("source") or "").strip(),
        "source_url": (row.get("source_url") or "").strip(),
        "evidence_tier": (row.get("evidence_tier") or "A").strip(),
        "versions": ",".join(row.get("versions", [])),
    }
    return {"event_id": eid, "accepted": accepted, "rejected": None,
            "record": record}


def main() -> int:
    pool = json.loads(POOL.read_text(encoding="utf-8"))
    from detectors.traffic.traffic_detector import CloudflareRadarAPI
    api = CloudflareRadarAPI()

    # Resume: the journal holds the verdict of every event that has
    # already been decided, so a long run survives an interruption.
    done: dict[str, dict] = {}
    if JOURNAL.is_file():
        for line in JOURNAL.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("event_id"):
                done[entry["event_id"]] = entry
        if done:
            print(f"resuming: {len(done)} events already decided")

    accepted: list[dict] = []
    rejected: list[dict] = []
    raw: list[dict] = []

    # The incidents already in the dataset.  A second row describing the
    # same incident is dropped: the dataset scores a detector, and
    # counting one incident twice would weight it more than the
    # evidence supports.
    #
    # The key maps to the row that holds the incident.  When two rows
    # describe the same incident under different cause labels, the one
    # whose routing evidence is stronger is the one that stays: the
    # labels disagree, and the measurement is what settles it.
    seen_incidents: dict[tuple, dict] = {}

    journal = JOURNAL.open("a", encoding="utf-8")

    for index, row in enumerate(sorted(pool, key=lambda r: r["event_id"]), 1):
        eid = row["event_id"]
        print(f"[{index:2d}/{len(pool)}] {eid}", flush=True)

        entry = done.get(eid)
        if entry is None:
            try:
                entry = evaluate(row, api)
            except Exception as exc:  # noqa: BLE001 - never abort the build
                logger.warning("[gt-verify] evaluation failed for %s: %r",
                               eid, exc)
                entry = {
                    "event_id": eid, "accepted": None,
                    "rejected": {"event_id": eid,
                                 "cause": (row.get("cause") or "").strip(),
                                 "reason": f"evaluation_failed({type(exc).__name__})"},
                    "record": {},
                }
            journal.write(json.dumps(entry, default=str) + "\n")
            journal.flush()

        if entry.get("accepted"):
            candidate = entry["accepted"]
            key = incident_key(row)
            held = seen_incidents.get(key)

            if held is None:
                seen_incidents[key] = candidate
                accepted.append(candidate)
                continue

            # The same incident is already in the dataset.  If the two
            # rows carry the same cause, the later one is simply a
            # duplicate.  If they carry different causes, the labels
            # disagree about one incident, and the routing evidence
            # decides which label it gets.
            if candidate["cause"] != held["cause"]:
                if routing_strength(candidate) > routing_strength(held):
                    # The new row's routing evidence is stronger, so it
                    # replaces the held one.  The held row is the one
                    # that leaves the dataset, and the new row stays --
                    # so exactly one rejection is recorded, for the row
                    # that was dropped.
                    accepted[accepted.index(held)] = candidate
                    seen_incidents[key] = candidate
                    rejected.append({
                        "event_id": held["event_id"],
                        "cause": held["cause"],
                        "reason": (
                            f"superseded_by_stronger_routing_evidence"
                            f"({candidate['event_id']})"
                        ),
                    })
                    continue
                rejected.append({
                    "event_id": eid,
                    "cause": candidate["cause"],
                    "reason": f"superseded_by_stronger_routing_evidence"
                              f"({held['event_id']})",
                })
                continue

            rejected.append({
                "event_id": eid,
                "cause": candidate["cause"],
                "reason": f"duplicate_incident_of({held['event_id']})",
            })
            continue
        elif entry.get("rejected"):
            rejected.append(entry["rejected"])
        if entry.get("record"):
            raw.append(entry["record"])

    journal.close()

    accepted.sort(key=lambda r: (CAUSES.index(r["cause"]), r["event_id"]))

    fields = list(accepted[0].keys()) if accepted else []
    with OUT_CSV.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(accepted)

    with REJECTED_CSV.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["event_id", "cause", "reason"])
        writer.writeheader()
        writer.writerows(sorted(rejected, key=lambda r: (r["reason"], r["event_id"])))

    RAW.write_text(json.dumps(raw, indent=2, default=str), encoding="utf-8")

    per_class = Counter(r["cause"] for r in accepted)
    report = {
        "dataset": str(OUT_CSV.relative_to(ROOT)),
        "n_pool": len(pool),
        "n_accepted": len(accepted),
        "n_rejected": len(rejected),
        "per_class": dict(per_class),
        "rejection_reasons": dict(Counter(
            r["reason"].split("(")[0] for r in rejected
        )),
        "rule": ("independent public source + routing anomaly visible in "
                 "RRC00 + measurable traffic impact that a control network "
                 "does not show"),
    }
    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\npool={len(pool)} accepted={len(accepted)} rejected={len(rejected)}")
    print(f"per_class={dict(per_class)}")
    print(f"reasons={report['rejection_reasons']}")
    print(f"-> {OUT_CSV}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

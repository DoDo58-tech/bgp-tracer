"""
Three-card joint evidence analysis
=================================

Combines routing + traffic signals through three independent "cards":
  1. Temporal alignment — ΔT between first routing event and first traffic anomaly
  2. Blast radius         — affected prefix count + magnitude of traffic deviation
  3. Falsification tree   — alternative explanations (CDN reroute, scheduled maintenance, DDoS)

Returns a tier C1/C2/C3 (C3 = strongest joint evidence) plus an average score
and a list of evidence cards for the report renderer.

This is a deliberately simple, explainable scorer — no ML, no opaque weighting.
Each card produces a 0–1 score, and the tier is derived from the average.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional


# ── Tier thresholds ────────────────────────────────────────────────────────────
# C3 = strong joint evidence (avg ≥ 0.66), C2 = moderate (≥ 0.40), C1 = weak
_TIER_THRESHOLDS = (0.66, 0.40)


def _parse_ts(value: Any) -> Optional[datetime]:
    """Parse a timestamp value (str, datetime, or None) into datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y%m%d.%H%M"):
            try:
                return datetime.strptime(value.replace("Z", ""), fmt)
            except (ValueError, AttributeError):
                continue
    return None


def _card_temporal_alignment(
    routing_events: List[Dict],
    traffic_anomalies: List[Dict],
    traffic_anomaly_window: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Card 1: How closely do routing events and traffic anomalies overlap in time?

    Score 1.0 when both have explicit timestamps and they are within 30 minutes
    of each other. Falls off linearly to 0.5 at 4h, 0.0 at 24h+.
    """
    routing_ts = []
    for ev in routing_events or []:
        ts = _parse_ts(ev.get("timestamp") or ev.get("first_seen"))
        if ts:
            routing_ts.append(ts)

    traffic_ts = []
    for an in traffic_anomalies or []:
        if isinstance(an, dict):
            ts = _parse_ts(an.get("timestamp") or an.get("time"))
            if ts:
                traffic_ts.append(ts)

    # Fall back to soft window from the traffic detector
    if not traffic_ts and isinstance(traffic_anomaly_window, dict):
        start = _parse_ts(traffic_anomaly_window.get("start") or traffic_anomaly_window.get("detected_start"))
        end = _parse_ts(traffic_anomaly_window.get("end") or traffic_anomaly_window.get("detected_end"))
        if start:
            traffic_ts = [start]
        if end:
            traffic_ts.append(end)

    if not routing_ts or not traffic_ts:
        return {
            "name": "temporal_alignment",
            "available": False,
            "score": 0.0,
            "reason": (
                "missing timestamps"
                if not routing_ts and not traffic_ts
                else "missing traffic timestamps" if not traffic_ts
                else "missing routing timestamps"
            ),
        }

    delta_min = abs((min(routing_ts) - min(traffic_ts)).total_seconds() / 60.0)
    if delta_min <= 30:
        score = 1.0
    elif delta_min <= 240:  # 4h
        score = 0.5 + 0.5 * (240 - delta_min) / 210.0
    elif delta_min <= 1440:  # 24h
        score = 0.5 * (1440 - delta_min) / 1200.0
    else:
        score = 0.0

    return {
        "name": "temporal_alignment",
        "available": True,
        "score": round(score, 3),
        "delta_minutes": round(delta_min, 1),
        "routing_first": min(routing_ts).isoformat() if routing_ts else None,
        "traffic_first": min(traffic_ts).isoformat() if traffic_ts else None,
        "reason": f"ΔT = {delta_min:.0f} min between first routing event and first traffic anomaly",
    }


def _card_blast_radius(
    routing_events: List[Dict],
    traffic_anomalies: List[Dict],
    prefix_traffic: Optional[Dict] = None,
    victim_traffic: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Card 2: How wide is the impact (affected prefixes × traffic deviation)?

    Combines:
      - count of distinct affected prefixes from routing events
      - max |percent_change| or |drop_ratio| from traffic anomalies
      - (optional) per-prefix traffic drop magnitude
    """
    prefixes = set()
    severities = []
    for ev in routing_events or []:
        p = ev.get("prefix") or ev.get("affected_prefix")
        if isinstance(p, str):
            prefixes.add(p)
        elif isinstance(p, list):
            prefixes.update(str(x) for x in p if x)
        sev = ev.get("severity") or ev.get("outage_score") or 1.0
        try:
            severities.append(float(sev))
        except (TypeError, ValueError):
            severities.append(1.0)

    pct_changes = []
    drop_ratios = []
    for an in traffic_anomalies or []:
        if not isinstance(an, dict):
            continue
        for key in ("percent_change", "pct_change", "percent_drop"):
            v = an.get(key)
            if isinstance(v, (int, float)):
                pct_changes.append(abs(float(v)))
        for key in ("drop_ratio", "traffic_drop_ratio"):
            v = an.get(key)
            if isinstance(v, (int, float)):
                drop_ratios.append(abs(float(v)))

    if not prefixes and not pct_changes and not drop_ratios:
        return {
            "name": "blast_radius",
            "available": False,
            "score": 0.0,
            "reason": "no blast-radius data (no affected prefixes, no traffic deviation)",
        }

    # Components: prefix breadth, severity depth, traffic magnitude
    prefix_score = min(1.0, len(prefixes) / 5.0)
    severity_score = (max(severities) / 100.0) if severities and max(severities) > 1.0 else 0.0
    if not severity_score and severities:
        severity_score = min(1.0, max(severities))
    traffic_score = 0.0
    if pct_changes:
        traffic_score = max(traffic_score, min(1.0, max(pct_changes) / 50.0))
    if drop_ratios:
        traffic_score = max(traffic_score, min(1.0, max(drop_ratios)))

    score = 0.4 * prefix_score + 0.2 * severity_score + 0.4 * traffic_score

    details = {
        "affected_prefix_count": len(prefixes),
        "max_severity": round(max(severities), 2) if severities else 0,
        "max_percent_change": round(max(pct_changes), 2) if pct_changes else None,
        "max_drop_ratio": round(max(drop_ratios), 4) if drop_ratios else None,
    }
    return {
        "name": "blast_radius",
        "available": True,
        "score": round(score, 3),
        **details,
        "reason": (
            f"{len(prefixes)} prefix(es), max |Δ%|="
            f"{max(pct_changes):.1f}" if pct_changes else
            f"{len(prefixes)} prefix(es)"
        ),
    }


def _card_falsification(
    routing_events: List[Dict],
    traffic_anomalies: List[Dict],
    confounders: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Card 3: Are there credible alternative explanations?

    Looks for evidence the change could be CDN reroute, scheduled maintenance,
    DDoS, etc. Each alternative explanation weakens the joint evidence score.
    """
    confounders = confounders or {}

    # Heuristics for known confounders
    notes: List[str] = []
    penalty = 0.0

    # CDN reroute — multiple distinct ASes with simultaneous traffic change
    asns_in_events = {
        ev.get("hijacker_as") or ev.get("attacker_as") or ev.get("victim_as") or ev.get("asn")
        for ev in (routing_events or []) if isinstance(ev, dict)
    }
    asns_in_events.discard(None)
    if len(asns_in_events) > 3:
        penalty += 0.1
        notes.append(f"{len(asns_in_events)} ASes involved — could be multi-AS CDN reroute")

    # DDoS — high magnitude traffic drop with no routing counterpart
    if not routing_events and traffic_anomalies:
        penalty += 0.2
        notes.append("traffic-only anomaly with no routing events — DDoS / misconfiguration plausible")

    # Scheduled maintenance — usually announced in advance, baseline hint
    if isinstance(confounders, dict) and confounders.get("scheduled_maintenance"):
        penalty += 0.3
        notes.append("scheduled-maintenance hint provided")

    if not notes:
        notes.append("no alternative explanations identified")

    score = max(0.0, 1.0 - penalty)
    return {
        "name": "falsification",
        "available": True,
        "score": round(score, 3),
        "alternative_explanations": notes,
        "reason": notes[0],
    }


def _tier_from_score(avg_score: float) -> str:
    """Map an average 0–1 score to a tier label."""
    if avg_score >= _TIER_THRESHOLDS[0]:
        return "C3"
    if avg_score >= _TIER_THRESHOLDS[1]:
        return "C2"
    return "C1"


def analyse_joint_evidence(
    routing_events: Optional[Iterable[Dict]] = None,
    traffic_anomalies: Optional[Iterable[Dict]] = None,
    *,
    traffic_anomaly_window: Optional[Dict] = None,
    prefix_traffic: Optional[Dict] = None,
    victim_traffic: Optional[Dict] = None,
    confounders: Optional[Dict] = None,
    causal_evidence: Optional[Dict] = None,
    routing_available: bool = True,
    traffic_available: bool = True,
) -> Dict[str, Any]:
    """Run the three-card joint evidence analysis.

    Returns:
        Dict with tier, average_score, evidence_cards (list of 3 card dicts),
        rationale (list of human-readable strings), and availability flags.
    """
    routing_events = list(routing_events or [])
    traffic_anomalies = list(traffic_anomalies or [])

    cards = [
        _card_temporal_alignment(routing_events, traffic_anomalies, traffic_anomaly_window),
        _card_blast_radius(routing_events, traffic_anomalies, prefix_traffic, victim_traffic),
        _card_falsification(routing_events, traffic_anomalies, confounders),
    ]

    available_scores = [c["score"] for c in cards if c["available"]]
    average_score = sum(available_scores) / len(available_scores) if available_scores else 0.0
    tier = _tier_from_score(average_score)

    rationale = [
        f"Card '{c['name']}': {c.get('reason', 'no reason')}"
        for c in cards
    ]
    if not routing_available:
        rationale.append("Routing data unavailable — joint evidence limited to traffic-side signals")
    if not traffic_available:
        rationale.append("Traffic data unavailable — joint evidence limited to routing-side signals")

    return {
        "tier": tier,
        "average_score": round(average_score, 3),
        "evidence_cards": cards,
        "rationale": rationale,
        "routing_available": routing_available,
        "traffic_available": traffic_available,
    }


__all__ = ["analyse_joint_evidence"]

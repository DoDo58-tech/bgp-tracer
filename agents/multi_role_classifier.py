"""
Multi-Role Classification Engine
================================

Resolves the core classification challenge: most ASes don't have a single role —
they have MULTIPLE roles simultaneously. Turk Telekom (AS9121) was annotated as
"leaker" but also shows 500 origin_hijacking + 500 origin_hijacked events.

This engine classifies an AS into ALL applicable roles simultaneously, with
confidence scores and evidence chains for each role.

Role taxonomy (multi-label):
  ATTACKER:
    - origin_hijacking:   announcing prefixes it doesn't own
    - forge_hijacking:    impersonating another AS's origin
    - path_manipulation:  inserting itself into paths it shouldn't be in
    - route_leak (active): leaking customer/provider routes to peers it shouldn't

  VICTIM:
    - origin_hijacked:    someone else announced this AS's prefixes
    - outage:             this AS's prefixes disappeared from routing table
    - traffic_hijacked:  traffic was redirected (correlates with origin_hijacked)

  LEAKER:
    - route_leak (passive): this AS received leaked routes from neighbor
    - path_leak:            route passed through AS that shouldn't carry it

  NEUTRAL / INTERNAL FAULT:
    - routing anomaly caused by internal misconfiguration (no external attacker)
    - Starlink/AWS internal faults that look like BGP issues

  CONDUIT:
    - AS was inserted into path but was neither attacker nor victim
    - (typically downstream provider unaware of customer's hijack)

Usage:
    classifier = MultiRoleClassifier()
    result = classifier.classify(routing_data, traffic_data, asn_info)
    # result.roles gives {attacker: {score, evidence, events}, victim: {...}, ...}
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from utils.logger import logger


# ── Role Definitions ───────────────────────────────────────────────────────────

@dataclass
class RoleEvidence:
    """Evidence supporting a specific role classification."""
    count: int = 0
    events: list[dict] = field(default_factory=list)
    prefixes: list[str] = field(default_factory=list)
    asns_involved: list[str] = field(default_factory=list)
    timestamps: list[str] = field(default_factory=list)
    severity: str = "unknown"  # critical / high / medium / low / none
    confidence: float = 0.0  # 0.0 - 1.0

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "events": self.events[:20],  # cap for LLM context
            "prefix_count": len(set(self.prefixes)),
            "unique_asns": list(set(self.asns_involved))[:20],
            "timestamp_range": (
                f"{min(self.timestamps)} to {max(self.timestamps)}"
                if self.timestamps else "N/A"
            ),
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
        }


@dataclass
class RoleClassification:
    """Classification result for a single role."""
    role: str
    is_active: bool  # True if this role applies, False otherwise
    score: float  # 0.0 - 1.0 overall role confidence
    evidence: RoleEvidence
    narrative: str  # Human-readable explanation
    sub_types: list[str] = field(default_factory=list)  # e.g. ["origin_hijacking", "forge_hijacking"]

    def to_dict(self) -> dict:
        return {
            "role": self.role,
            "is_active": self.is_active,
            "score": round(self.score, 3),
            "sub_types": self.sub_types,
            "evidence": self.evidence.to_dict(),
            "narrative": self.narrative,
        }


@dataclass
class MultiRoleResult:
    """Full multi-role classification result for one AS."""
    asn: str
    primary_role: str  # dominant role for simple classification
    primary_score: float
    roles: dict[str, RoleClassification]
    composite_narrative: str  # Full explanation combining all roles
    complexity_level: str  # simple / dual_role / multi_role / ambiguous
    recommended_analysis_depth: str  # quick / standard / deep
    cross_references: dict[str, Any] = field(default_factory=dict)
    # Special cross-reference insights
    self_hijack: Optional[dict] = None  # AS attacked its own prefixes
    victim_becomes_attacker: Optional[dict] = None  # AS was hijacked then hijacked others
    attacker_becomes_victim: Optional[dict] = None  # AS hijacked then got hijacked
    detection_gap: bool = False  # routing says "clean" but annotation says otherwise

    def to_dict(self) -> dict:
        return {
            "asn": self.asn,
            "primary_role": self.primary_role,
            "primary_score": round(self.primary_score, 3),
            "roles": {k: v.to_dict() for k, v in self.roles.items()},
            "complexity_level": self.complexity_level,
            "recommended_analysis_depth": self.recommended_analysis_depth,
            "composite_narrative": self.composite_narrative,
            "cross_references": self.cross_references,
            "self_hijack": self.self_hijack,
            "victim_becomes_attacker": self.victim_becomes_attacker,
            "attacker_becomes_victim": self.attacker_becomes_victim,
            "detection_gap": self.detection_gap,
        }

    def get_active_roles(self) -> list[str]:
        return [r for r, c in self.roles.items() if c.is_active]

    def get_summary(self) -> str:
        """One-line summary for LLM context."""
        active = self.get_active_roles()
        if not active:
            return f"AS{self.asn}: No anomalous role detected (clean)"
        return (
            f"AS{self.asn}: "
            + " | ".join(
                f"{r} (conf={c.score:.2f})"
                for r, c in self.roles.items()
                if c.is_active
            )
            + f" [complexity: {self.complexity_level}]"
        )


# ── Helper Functions ───────────────────────────────────────────────────────────

def score_by_count(count: int, thresholds: dict[str, int]) -> tuple[float, str]:
    """Map event count to confidence score and severity."""
    if count == 0:
        return 0.0, "none"
    if count >= thresholds.get("critical", 100):
        return 0.95, "critical"
    if count >= thresholds.get("high", 50):
        return 0.85, "high"
    if count >= thresholds.get("medium", 10):
        return 0.7, "medium"
    if count >= thresholds.get("low", 1):
        return 0.5, "low"
    return 0.3, "low"


def extract_events(data: list[dict], key: str = "prefix") -> tuple[list[str], list[str], list[str]]:
    """Extract prefixes, asns, timestamps from event list."""
    prefixes, asns, times = [], [], []
    for ev in data:
        p = ev.get(key, ev.get("prefix", ""))
        if p:
            prefixes.append(str(p))
        # Extract ASNs from various fields
        for asn_field in ["origin_asn", "hijacker_asn", "victim_asn", "asn", "peer_asn"]:
            v = ev.get(asn_field, "")
            if v:
                asns.append(str(v).lstrip("AS"))
        t = ev.get("timestamp", ev.get("time", ""))
        if t:
            times.append(str(t))
    return prefixes, asns, times


def check_temporal_overlap(
    events_a: list[dict], events_b: list[dict], time_window_hours: float = 2.0
) -> bool:
    """Check if two sets of events overlap temporally (within time_window_hours)."""
    if not events_a or not events_b:
        return False

    def parse_ts(ev: dict) -> Optional[datetime]:
        for f in ["timestamp", "time", "start_time", "date"]:
            v = ev.get(f, "")
            if v:
                try:
                    # Handle formats like "07/14/23 11:02:23" or ISO
                    v = str(v).strip()
                    for fmt in ["%m/%d/%y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"]:
                        try:
                            return datetime.strptime(v, fmt)
                        except ValueError:
                            continue
                except Exception:
                    pass
        return None

    for ev_a in events_a:
        ts_a = parse_ts(ev_a)
        if not ts_a:
            continue
        for ev_b in events_b:
            ts_b = parse_ts(ev_b)
            if not ts_b:
                continue
            diff = abs((ts_a - ts_b).total_seconds()) / 3600
            if diff <= time_window_hours:
                return True
    return False


# ── Main Classifier ────────────────────────────────────────────────────────────

class MultiRoleClassifier:
    """
    Classifies an AS into all applicable roles based on routing evidence.

    Key insight: The same AS can simultaneously be attacker, victim, and leaker.
    We classify ALL roles, then determine:
      - Primary role (dominant by score)
      - Complexity level (simple/dual/multi/ambiguous)
      - Cross-reference patterns (self-hijack, victim→attacker, etc.)
    """

    # Thresholds for severity scoring
    ORIGIN_HIJACK_THRESHOLDS = {
        "critical": 50, "high": 20, "medium": 5, "low": 1
    }
    LEAK_THRESHOLDS = {
        "critical": 500, "high": 100, "medium": 20, "low": 1
    }
    OUTAGE_THRESHOLDS = {
        "critical": 0.8, "high": 0.5, "medium": 0.3, "low": 0.1
    }

    def classify(
        self,
        routing_data: dict,
        traffic_data: Optional[dict] = None,
        asn_info: Optional[dict] = None,
    ) -> MultiRoleResult:
        """
        Classify all applicable roles for an AS.

        Args:
            routing_data: from RoutingAgent (contains hijack, leak, outage)
            traffic_data: optional from TrafficAgent (for traffic correlation)
            asn_info: optional AS organization info

        Returns:
            MultiRoleResult with all roles classified
        """
        asn = routing_data.get("asn", "unknown")
        logger.info(f"[multi_role] Classifying AS{asn}")

        # Extract evidence from routing data
        hijack = routing_data.get("hijack", {}) or {}
        leak = routing_data.get("leak", {}) or {}
        outage = routing_data.get("outage", {}) or {}

        origin_hijacking = hijack.get("origin_hijacking", []) or []
        origin_hijacked = hijack.get("origin_hijacked", []) or []
        forge_hijacking = hijack.get("forge_hijacking", []) or []
        forge_hijacked = hijack.get("forge_hijacked", []) or []
        path_manipulation = hijack.get("path_manipulation", []) or []
        route_leaks = leak.get("route_leaks", []) or []
        path_leaks = leak.get("path_leaks", []) or []
        outage_score = outage.get("outage_score", 0.0) or 0.0
        is_outage = outage.get("is_outage_suspected", False)

        # Detect detection gaps: success=True but zero events
        detection_gap = (
            routing_data.get("hijack", {}).get("success") is True
            and routing_data.get("leak", {}).get("success") is True
            and all([
                len(origin_hijacking) == 0,
                len(origin_hijacked) == 0,
                len(forge_hijacking) == 0,
                len(route_leaks) == 0,
                len(path_leaks) == 0,
                not is_outage,
            ])
        )

        # Classify each role
        attacker_role = self.classify_attacker(
            origin_hijacking, forge_hijacking, path_manipulation, route_leaks
        )
        victim_role = self.classify_victim(
            origin_hijacked, forge_hijacked, outage_score, is_outage, traffic_data
        )
        leaker_role = self.classify_leaker(route_leaks, path_leaks)
        conduit_role = self.classify_conduit(path_manipulation, origin_hijacking)
        internal_fault_role = self.classify_internal_fault(
            routing_data, attacker_role, victim_role, leaker_role
        )

        roles = {
            "attacker": attacker_role,
            "victim": victim_role,
            "leaker": leaker_role,
            "conduit": conduit_role,
            "internal_fault": internal_fault_role,
        }

        # Detect "clean" but suspicious (detection gap)
        active_roles = [(r, c) for r, c in roles.items() if c.is_active]
        if detection_gap:
            primary_role = "detection_gap"
            primary_score = 0.5
        elif not active_roles:
            primary_role = "clean"
            primary_score = 1.0
        else:
            primary_role, primary_score = max(active_roles, key=lambda x: x[1].score)

        # ── Detect cross-reference patterns ──────────────────────────────────
        self_hijack = self.detect_self_hijack(origin_hijacking, origin_hijacked)
        victim_becomes_attacker = self.detect_victim_becomes_attacker(
            origin_hijacked, origin_hijacking
        )
        attacker_becomes_victim = self.detect_attacker_becomes_victim(
            origin_hijacking, origin_hijacked
        )

        # ── Determine complexity level ────────────────────────────────────────
        complexity = self.assess_complexity(
            active_roles, self_hijack, victim_becomes_attacker, attacker_becomes_victim
        )

        # ── Recommended analysis depth ───────────────────────────────────────
        depth = self.recommended_depth(
            complexity, primary_score, roles, routing_data, traffic_data
        )

        # ── Build composite narrative ─────────────────────────────────────────
        composite = self.build_composite_narrative(
            asn, roles, primary_role, complexity,
            self_hijack, victim_becomes_attacker, attacker_becomes_victim, detection_gap
        )

        return MultiRoleResult(
            asn=asn,
            primary_role=primary_role,
            primary_score=primary_score,
            roles=roles,
            composite_narrative=composite,
            complexity_level=complexity,
            recommended_analysis_depth=depth,
            self_hijack=self_hijack,
            victim_becomes_attacker=victim_becomes_attacker,
            attacker_becomes_victim=attacker_becomes_victim,
            detection_gap=detection_gap,
        )

    # ── Individual Role Classifiers ────────────────────────────────────────────

    def classify_attacker(
        self,
        origin_hijacking: list,
        forge_hijacking: list,
        path_manipulation: list,
        route_leaks: list,
    ) -> RoleClassification:
        """Classify if this AS acted as an attacker."""
        sub_types = []
        evidence = RoleEvidence()
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        max_severity = "none"

        # Origin hijacking
        if origin_hijacking:
            sub_types.append("origin_hijacking")
            score, sev = score_by_count(len(origin_hijacking), self.ORIGIN_HIJACK_THRESHOLDS)
            evidence.count += len(origin_hijacking)
            pfx, asns, times = extract_events(origin_hijacking)
            evidence.prefixes.extend(pfx)
            evidence.asns_involved.extend(asns)
            evidence.timestamps.extend(times)
            evidence.events.extend(origin_hijacking[:50])
            if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                max_severity = sev

        # Forge hijacking
        if forge_hijacking:
            sub_types.append("forge_hijacking")
            score, sev = score_by_count(len(forge_hijacking), self.ORIGIN_HIJACK_THRESHOLDS)
            evidence.count += len(forge_hijacking)
            pfx, asns, times = extract_events(forge_hijacking)
            evidence.prefixes.extend(pfx)
            evidence.asns_involved.extend(asns)
            evidence.timestamps.extend(times)
            evidence.events.extend(forge_hijacking[:50])
            if sev == "critical":
                sev = "high"  # downgrade forge (rare and often ambiguous)
            if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                max_severity = sev

        # Path manipulation
        if path_manipulation:
            sub_types.append("path_manipulation")
            score, sev = score_by_count(len(path_manipulation), self.ORIGIN_HIJACK_THRESHOLDS)
            evidence.count += len(path_manipulation)
            pfx, asns, times = extract_events(path_manipulation)
            evidence.prefixes.extend(pfx)
            evidence.asns_involved.extend(asns)
            evidence.timestamps.extend(times)
            evidence.events.extend(path_manipulation[:50])
            if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                max_severity = sev

        # Active route leaking
        if route_leaks:
            sub_types.append("route_leak_active")
            score, sev = score_by_count(len(route_leaks), self.LEAK_THRESHOLDS)
            evidence.count += len(route_leaks)
            pfx, asns, times = extract_events(route_leaks)
            evidence.prefixes.extend(pfx)
            evidence.asns_involved.extend(asns)
            evidence.timestamps.extend(times)
            evidence.events.extend(route_leaks[:100])
            if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                max_severity = sev

        if not sub_types:
            return RoleClassification(
                role="attacker",
                is_active=False,
                score=0.0,
                evidence=evidence,
                narrative="No evidence of this AS acting as an attacker.",
                sub_types=[],
            )

        evidence.severity = max_severity

        # Score based on count and diversity of sub-types
        type_bonus = len(sub_types) * 0.05
        total_count = evidence.count
        if total_count >= 100:
            score = 0.95
        elif total_count >= 50:
            score = 0.9
        elif total_count >= 10:
            score = 0.8
        else:
            score = 0.6
        score = min(score + type_bonus, 0.98)
        evidence.confidence = score

        # Narrative
        severity = evidence.severity
        if len(sub_types) == 1:
            narrative = (
                f"This AS was an active attacker using {sub_types[0]} technique. "
                f"Evidence: {total_count} event(s), "
                f"affecting {len(set(evidence.prefixes))} unique prefix(es), "
                f"involving {len(set(evidence.asns_involved))} other AS(es). "
                f"Severity: {severity}."
            )
        else:
            narrative = (
                f"This AS was an active attacker using {len(sub_types)} attack techniques: "
                f"{', '.join(sub_types)}. "
                f"Total: {total_count} attack event(s), "
                f"affecting {len(set(evidence.prefixes))} prefix(es), "
                f"{len(set(evidence.asns_involved))} other AS(es). "
                f"Severity: {severity}."
            )

        return RoleClassification(
            role="attacker",
            is_active=True,
            score=score,
            evidence=evidence,
            narrative=narrative,
            sub_types=sub_types,
        )

    def classify_victim(
        self,
        origin_hijacked: list,
        forge_hijacked: list,
        outage_score: float,
        is_outage: bool,
        traffic_data: Optional[dict],
    ) -> RoleClassification:
        """Classify if this AS was a victim."""
        sub_types = []
        evidence = RoleEvidence()

        # Origin hijacked
        if origin_hijacked:
            sub_types.append("origin_hijacked")
            score, sev = score_by_count(len(origin_hijacked), self.ORIGIN_HIJACK_THRESHOLDS)
            evidence.count += len(origin_hijacked)
            pfx, asns, times = extract_events(origin_hijacked)
            evidence.prefixes.extend(pfx)
            evidence.asns_involved.extend(asns)
            evidence.timestamps.extend(times)
            evidence.events.extend(origin_hijacked[:50])

        # Forge hijacked (MITM)
        if forge_hijacked:
            sub_types.append("forge_hijacked")
            evidence.count += len(forge_hijacked)
            pfx, asns, times = extract_events(forge_hijacked)
            evidence.prefixes.extend(pfx)
            evidence.asns_involved.extend(asns)
            evidence.timestamps.extend(times)
            evidence.events.extend(forge_hijacked[:50])

        # Outage
        if is_outage or outage_score > 0.3:
            sub_types.append("route_outage")
            evidence.count += 1
            evidence.events.append({
                "type": "outage",
                "score": outage_score,
                "is_suspected": is_outage,
            })

        # Traffic drop correlation
        traffic_drop = False
        if traffic_data:
            direction = traffic_data.get("direction", "")
            pct = abs(traffic_data.get("percent_change", 0.0) or 0.0)
            if direction == "decrease" and pct > 20:
                sub_types.append("traffic_drop")
                traffic_drop = True
                evidence.events.append({
                    "type": "traffic_drop",
                    "percent": pct,
                })

        if not sub_types:
            return RoleClassification(
                role="victim",
                is_active=False,
                score=0.0,
                evidence=evidence,
                narrative="No evidence this AS was a victim.",
                sub_types=[],
            )

        # Severity assessment
        severity = "low"
        if is_outage and outage_score >= 0.5:
            severity = "critical"
        elif evidence.count >= 20 or (traffic_drop and len(origin_hijacked) > 0):
            severity = "high"
        elif evidence.count >= 5:
            severity = "medium"
        evidence.severity = severity

        # Score
        score = 0.0
        if is_outage and outage_score >= 0.5:
            score = 0.9
        elif evidence.count >= 20:
            score = 0.85
        elif evidence.count >= 5:
            score = 0.75
        elif evidence.count >= 1:
            score = 0.65
        if traffic_drop:
            score = min(score + 0.1, 0.95)
        evidence.confidence = score

        narrative = (
            f"This AS was a victim. "
            f"Evidence types: {', '.join(sub_types)}. "
            f"Total {evidence.count} victimization event(s), "
            f"affecting {len(set(evidence.prefixes))} prefix(es), "
            f"attacked by {len(set(evidence.asns_involved))} AS(es). "
            f"Severity: {severity}."
        )

        return RoleClassification(
            role="victim",
            is_active=True,
            score=score,
            evidence=evidence,
            narrative=narrative,
            sub_types=sub_types,
        )

    def classify_leaker(
        self,
        route_leaks: list,
        path_leaks: list,
    ) -> RoleClassification:
        """Classify if this AS was a route leaker (passive recipient of leaked routes)."""
        sub_types = []
        evidence = RoleEvidence()

        if route_leaks:
            sub_types.append("route_leak")
            score, sev = score_by_count(len(route_leaks), self.LEAK_THRESHOLDS)
            evidence.count = len(route_leaks)
            pfx, asns, times = extract_events(route_leaks)
            evidence.prefixes.extend(pfx)
            evidence.asns_involved.extend(asns)
            evidence.timestamps.extend(times)
            evidence.events.extend(route_leaks[:100])
            evidence.severity = sev
            evidence.confidence = score

        if path_leaks:
            sub_types.append("path_leak")
            evidence.count += len(path_leaks)
            pfx, asns, times = extract_events(path_leaks)
            evidence.prefixes.extend(pfx)
            evidence.asns_involved.extend(asns)
            evidence.events.extend(path_leaks[:50])

        if not sub_types:
            return RoleClassification(
                role="leaker",
                is_active=False,
                score=0.0,
                evidence=evidence,
                narrative="No evidence of route leaking.",
                sub_types=[],
            )

        narrative = (
            f"This AS was involved in route leaking ({sub_types[0]}). "
            f"{evidence.count} leak event(s), "
            f"{len(set(evidence.prefixes))} unique prefix(es), "
            f"{len(set(evidence.asns_involved))} AS(es). "
            f"Severity: {evidence.severity}."
        )

        return RoleClassification(
            role="leaker",
            is_active=True,
            score=evidence.confidence,
            evidence=evidence,
            narrative=narrative,
            sub_types=sub_types,
        )

    def classify_conduit(
        self,
        path_manipulation: list,
        origin_hijacking: list,
    ) -> RoleClassification:
        """Classify if this AS was a conduit (inserted in path but not attacker/victim)."""
        # Conduit: AS appears in path_manipulation but wasn't the hijacker
        # (This is a specialized detection — simplified here)
        evidence = RoleEvidence()
        evidence.events = path_manipulation[:20]
        evidence.count = len(path_manipulation)

        return RoleClassification(
            role="conduit",
            is_active=len(path_manipulation) > 0,
            score=0.3 if path_manipulation else 0.0,
            evidence=evidence,
            narrative="AS appeared in path manipulation events.",
            sub_types=["path_manipulation"] if path_manipulation else [],
        )

    def classify_internal_fault(
        self,
        routing_data: dict,
        attacker: RoleClassification,
        victim: RoleClassification,
        leaker: RoleClassification,
    ) -> RoleClassification:
        """
        Classify if the AS had internal faults (misconfiguration, software bugs)
        that LOOK like BGP attacks but are actually internal issues.

        Examples:
          - Starlink: BGP routes mostly intact, but internal service failed
          - AWS Virginia: BGP withdrawal but internal datacenter issue
          - Orange España: RPKI misconfiguration by attacker (not internal)
        """
        evidence = RoleEvidence()
        sub_types = []

        # Check for outage with no external attacker
        outage = routing_data.get("outage", {}) or {}
        is_outage = outage.get("is_outage_suspected", False)
        outage_score = outage.get("outage_score", 0.0) or 0.0

        # Internal fault indicators:
        # 1. Outage but no origin_hijacked events (wasn't externally attacked)
        # 2. BGP announcements dropped but no one else announced those prefixes
        # 3. Starlink-like pattern: announced space dropped but routes still there

        if is_outage:
            origin_hijacked = routing_data.get("hijack", {}).get("origin_hijacked", []) or []
            # If outage but nobody hijacked our prefixes → internal fault
            if not origin_hijacked and outage_score < 0.9:
                sub_types.append("internal_outage")
                evidence.count += 1
                evidence.events.append({
                    "type": "internal_outage",
                    "score": outage_score,
                    "reason": "outage detected but no external hijack",
                })

        # Check for "BGP looks normal but traffic dropped" pattern
        # This is internal fault, not external attack
        # (Handled by traffic correlation in victim classifier)

        if not sub_types:
            return RoleClassification(
                role="internal_fault",
                is_active=False,
                score=0.0,
                evidence=evidence,
                narrative="No evidence of internal fault (non-BGP issue).",
                sub_types=[],
            )

        narrative = (
            f"This AS shows signs of internal fault (not external BGP attack). "
            f"Pattern: {sub_types[0]}. "
            f"The routing anomaly appears to be caused by internal misconfiguration or "
            f"non-BGP infrastructure issues rather than external malicious activity."
        )

        return RoleClassification(
            role="internal_fault",
            is_active=True,
            score=0.6,
            evidence=evidence,
            narrative=narrative,
            sub_types=sub_types,
        )

    # ── Cross-Reference Pattern Detectors ────────────────────────────────────

    def detect_self_hijack(
        self,
        origin_hijacking: list,
        origin_hijacked: list,
    ) -> Optional[dict]:
        """
        Detect self-hijack: AS announces its own prefixes as a different AS
        (or vice versa: AS's prefixes were announced by itself as a different origin).

        This is a specific attack pattern where AS X announces prefixes that
        AS X legitimately owns, but with a different AS number.
        """
        if not origin_hijacking or not origin_hijacked:
            return None

        # Check if same prefixes appear in both lists (at similar times)
        hijacking_prefixes = set(e.get("prefix", "") for e in origin_hijacking)
        hijacked_prefixes = set(e.get("prefix", "") for e in origin_hijacked)
        overlap = hijacking_prefixes & hijacked_prefixes

        if overlap:
            return {
                "detected": True,
                "overlap_count": len(overlap),
                "overlap_prefixes": list(overlap)[:10],
                "interpretation": (
                    "This AS both hijacked and was hijacked for the SAME prefixes. "
                    "This could indicate: (1) a misconfiguration where the AS accidentally "
                    "changed its own origin AS, or (2) a sophisticated attack where the AS "
                    "first hijacked its own prefixes then reverted."
                ),
            }

        # Also check: hijacker_asn == target AS
        # (If origin_hijacking lists the victim AS as the target)
        asn = origin_hijacking[0].get("asn", "") if origin_hijacking else ""
        for ev in origin_hijacked:
            if ev.get("hijacker_asn", "").lstrip("AS") == asn.lstrip("AS"):
                return {
                    "detected": True,
                    "overlap_count": 1,
                    "overlap_prefixes": [ev.get("prefix", "")],
                    "interpretation": (
                        "The AS that was hijacked appears to also be the hijacker "
                        "(same AS number in both roles). This strongly suggests "
                        "a self-hijack or origin AS change misconfiguration."
                    ),
                }

        return None

    def detect_victim_becomes_attacker(
        self,
        origin_hijacked: list,
        origin_hijacking: list,
    ) -> Optional[dict]:
        """
        Detect temporal pattern: AS was FIRST hijacked, then LATER became a hijacker.
        This is the "compromised account" pattern (e.g., AS49581 Orange España RPKI case).

        Interpretation: Attackers first compromised this AS's routing infrastructure,
        used it to hijack others' prefixes, and possibly later the AS reverted.
        """
        if not origin_hijacked or not origin_hijacking:
            return None

        # Check temporal ordering
        hijacked_times = []
        hijacking_times = []

        for ev in origin_hijacked:
            for f in ["timestamp", "time"]:
                v = ev.get(f, "")
                if v:
                    try:
                        for fmt in ["%m/%d/%y %H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                            hijacked_times.append(datetime.strptime(str(v), fmt))
                            break
                    except Exception:
                        pass

        for ev in origin_hijacking:
            for f in ["timestamp", "time"]:
                v = ev.get(f, "")
                if v:
                    try:
                        for fmt in ["%m/%d/%y %H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                            hijacking_times.append(datetime.strptime(str(v), fmt))
                            break
                    except Exception:
                        pass

        if not hijacked_times or not hijacking_times:
            return None

        first_hijacked = min(hijacked_times)
        first_hijacking = min(hijacking_times)

        # Victim→Attacker: hijacked BEFORE becoming attacker
        if first_hijacked < first_hijacking:
            delta = (first_hijacking - first_hijacked).total_seconds() / 3600
            return {
                "detected": True,
                "pattern": "victim_then_attacker",
                "first_hijacked": first_hijacked.isoformat(),
                "first_hijacking": first_hijacking.isoformat(),
                "gap_hours": round(delta, 1),
                "hijacked_count": len(origin_hijacked),
                "hijacking_count": len(origin_hijacking),
                "interpretation": (
                    f"This AS was FIRST a victim (hijacked at {first_hijacked.strftime('%Y-%m-%d %H:%M')}) "
                    f"then became an attacker {delta:.1f} hours later "
                    f"(hijacking others from {first_hijacking.strftime('%Y-%m-%d %H:%M')}). "
                    f"This is the classic 'compromised account' pattern: "
                    f"attackers first compromised the AS's routing infrastructure (e.g., RPKI password, "
                    f"router access), used it to hijack, then the AS either reverted or attackers left."
                ),
            }

        return None

    def detect_attacker_becomes_victim(
        self,
        origin_hijacking: list,
        origin_hijacked: list,
    ) -> Optional[dict]:
        """
        Detect temporal pattern: AS was FIRST a hijacker, then LATER got hijacked.
        This is the "revenge" or "collateral damage" pattern.
        """
        if not origin_hijacking or not origin_hijacked:
            return None

        hijacked_times, hijacking_times = [], []

        for ev in origin_hijacked:
            for f in ["timestamp", "time"]:
                v = ev.get(f, "")
                if v:
                    try:
                        for fmt in ["%m/%d/%y %H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                            hijacked_times.append(datetime.strptime(str(v), fmt))
                            break
                    except Exception:
                        pass

        for ev in origin_hijacking:
            for f in ["timestamp", "time"]:
                v = ev.get(f, "")
                if v:
                    try:
                        for fmt in ["%m/%d/%y %H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                            hijacking_times.append(datetime.strptime(str(v), fmt))
                            break
                    except Exception:
                        pass

        if not hijacked_times or not hijacking_times:
            return None

        first_hijacking = min(hijacking_times)
        first_hijacked = min(hijacked_times)

        if first_hijacking < first_hijacked:
            delta = (first_hijacked - first_hijacking).total_seconds() / 3600
            return {
                "detected": True,
                "pattern": "attacker_then_victim",
                "first_hijacking": first_hijacking.isoformat(),
                "first_hijacked": first_hijacked.isoformat(),
                "gap_hours": round(delta, 1),
                "hijacking_count": len(origin_hijacking),
                "hijacked_count": len(origin_hijacked),
                "interpretation": (
                    f"This AS was FIRST an attacker (hijacking others at {first_hijacking.strftime('%Y-%m-%d %H:%M')}), "
                    f"then became a victim {delta:.1f} hours later "
                    f"(hijacked by others at {first_hijacked.strftime('%Y-%m-%d %H:%M')}). "
                    f"This could indicate: (1) 'collateral damage' where another attacker targeted "
                    f"this AS's prefixes, or (2) the AS's own attack triggered a response/retaliation."
                ),
            }

        return None

    # ── Complexity & Depth Assessment ────────────────────────────────────────

    def assess_complexity(
        self,
        active_roles: list[tuple[str, RoleClassification]],
        self_hijack: Optional[dict],
        victim_becomes_attacker: Optional[dict],
        attacker_becomes_victim: Optional[dict],
    ) -> str:
        """Assess how complex this AS's role picture is."""
        role_count = len(active_roles)

        # Cross-reference patterns make it more complex
        cross_refs = sum([
            1 if self_hijack else 0,
            1 if victim_becomes_attacker else 0,
            1 if attacker_becomes_victim else 0,
        ])

        if cross_refs >= 2:
            return "very_complex"  # e.g., self-hijack + temporal pattern
        if cross_refs == 1:
            if victim_becomes_attacker:
                return "complex"  # compromised account pattern
            return "complex"  # some temporal pattern

        if role_count == 0:
            return "clean"
        if role_count == 1:
            return "simple"
        if role_count == 2:
            return "dual_role"
        return "multi_role"

    def recommended_depth(
        self,
        complexity: str,
        primary_score: float,
        roles: dict[str, RoleClassification],
        routing_data: dict,
        traffic_data: Optional[dict],
    ) -> str:
        """Recommend how deep the analysis should go."""
        if complexity == "clean":
            return "quick"

        if complexity in ("very_complex", "multi_role"):
            return "deep"

        if complexity in ("complex", "dual_role"):
            return "standard"

        if primary_score < 0.6:
            return "deep"  # low confidence needs more evidence

        return "standard"

    # ── Narrative Builder ──────────────────────────────────────────────────────

    def build_composite_narrative(
        self,
        asn: str,
        roles: dict[str, RoleClassification],
        primary_role: str,
        complexity: str,
        self_hijack: Optional[dict],
        victim_becomes_attacker: Optional[dict],
        attacker_becomes_victim: Optional[dict],
        detection_gap: bool = False,
    ) -> str:
        """Build a comprehensive narrative explaining all roles and patterns."""
        lines = [f"Multi-Role Analysis for AS{asn}:"]

        if detection_gap:
            lines.append(
                "\n⚠️ DETECTION GAP: No anomalous events were detected in routing data, "
                "but the annotation indicates this AS was involved in an event. "
                "This may indicate: (1) event was too short to appear in MRT data (e.g., <5 min), "
                "(2) event was outside the RouteViews/RIPE RIS monitoring window, "
                "(3) internal fault rather than BGP-level event."
            )
            lines.append(f"Complexity Level: detection_gap")
            lines.append(f"Recommended Analysis Depth: standard")
            return "\n".join(lines)

        active = [(r, c) for r, c in roles.items() if c.is_active]
        if not active:
            return f"AS{asn}: No anomalous roles detected. Routing appears normal."

        lines.append(f"\nActive Roles ({len(active)}):")
        for role, classification in active:
            lines.append(f"\n  [{role.upper()}] Score={classification.score:.2f}")
            lines.append(f"    {classification.narrative}")

        if self_hijack:
            lines.append(f"\n  [SELF-HIJACK PATTERN DETECTED]")
            lines.append(f"    {self_hijack['interpretation']}")

        if victim_becomes_attacker:
            lines.append(f"\n  [VICTIM→ATTACKER PATTERN DETECTED: Compromised Account]")
            lines.append(f"    {victim_becomes_attacker['interpretation']}")

        if attacker_becomes_victim:
            lines.append(f"\n  [ATTACKER→VICTIM PATTERN DETECTED]")
            lines.append(f"    {attacker_becomes_victim['interpretation']}")

        lines.append(f"\nComplexity Level: {complexity}")
        lines.append(f"Recommended Analysis Depth: {self.recommended_depth(complexity, 0.5, roles, {}, None)}")

        return "\n".join(lines)


# ── Convenience Function ───────────────────────────────────────────────────────

def classify_as_roles(
    routing_data: dict,
    traffic_data: Optional[dict] = None,
    asn_info: Optional[dict] = None,
) -> dict:
    """
    One-shot multi-role classification.

    Usage in ReasoningAgent or Supervisor:
        from agents.multi_role_classifier import classify_as_roles
        result = classify_as_roles(routing_data, traffic_data)
        print(result.get_summary())
        print(result.composite_narrative)
    """
    classifier = MultiRoleClassifier()
    result = classifier.classify(routing_data, traffic_data, asn_info)
    return result

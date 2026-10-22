"""

Unified Detection Result Schema

: 
1. (hijack/leak/outage/traffic)
2. 
3. 

Author: BGP Tracer Team
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum
import json


class DetectionType(Enum):
    """"""
    HIJACK = "hijack"
    LEAK = "leak"
    OUTAGE = "outage"
    TRAFFIC = "traffic"
    UNKNOWN = "unknown"


class AnomalySeverity(Enum):
    """"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AnomalyDetail:
    """"""
    # 
    type: str                          # 
    subtype: Optional[str] = None       # 
    
    # 
    timestamp: Optional[str] = None     # ISO 
    duration_seconds: Optional[int] = None
    
    # 
    affected_prefixes: List[str] = field(default_factory=list)
    affected_asns: List[str] = field(default_factory=list)
    event_count: int = 0

    # （ origin_hijacking / forge_hijacking ）
    claimed_as: Optional[str] = None
    victim_as: Optional[str] = None

    # 
    evidence: Dict[str, Any] = field(default_factory=dict)

    # 
    confidence: float = 0.5
    
    # 
    severity: Optional[str] = None
    
    def to_dict(self):
        return {
            'type': self.type,
            'subtype': self.subtype,
            'timestamp': self.timestamp,
            'duration_seconds': self.duration_seconds,
            'affected_prefixes': self.affected_prefixes,
            'affected_asns': self.affected_asns,
            'event_count': self.event_count,
            'claimed_as': self.claimed_as,
            'victim_as': self.victim_as,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'severity': self.severity,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            type=data.get('type', 'unknown'),
            subtype=data.get('subtype'),
            timestamp=data.get('timestamp'),
            duration_seconds=data.get('duration_seconds'),
            affected_prefixes=data.get('affected_prefixes', []),
            affected_asns=data.get('affected_asns', []),
            claimed_as=data.get('claimed_as'),
            victim_as=data.get('victim_as'),
            event_count=data.get('event_count', 0),
            evidence=data.get('evidence', {}),
            confidence=data.get('confidence', 0.5),
            severity=data.get('severity'),
        )


@dataclass
class DetectionMetadata:
    """"""
    # 
    analysis_start: str = ""           # ISO 
    analysis_end: str = ""
    analysis_duration_ms: float = 0.0
    
    # 
    data_sources: List[str] = field(default_factory=list)
    
    # 
    data_quality_score: float = 1.0   # 0-1
    coverage_percent: float = 100.0    # 
    
    # API 
    api_calls_made: int = 0
    api_calls_failed: int = 0
    
    # 
    detection_threshold: float = 0.5
    sensitivity: str = "normal"
    
    def to_dict(self):
        return {
            'analysis_start': self.analysis_start,
            'analysis_end': self.analysis_end,
            'analysis_duration_ms': self.analysis_duration_ms,
            'data_sources': self.data_sources,
            'data_quality_score': self.data_quality_score,
            'coverage_percent': self.coverage_percent,
            'api_calls_made': self.api_calls_made,
            'api_calls_failed': self.api_calls_failed,
            'detection_threshold': self.detection_threshold,
            'sensitivity': self.sensitivity,
        }


@dataclass
class ConfidenceAssessment:
    """"""
    # 
    raw_confidence: float = 0.5
    
    # 
    calibrated_confidence: float = 0.5
    
    # 
    calibration_level: str = "unknown"
    
    # 
    evidence_sufficiency: float = 0.0
    evidence_consistency: float = 0.0
    evidence_diversity: float = 0.0
    
    # 
    uncertainty_lower: float = 0.0
    uncertainty_upper: float = 1.0
    
    # 
    reasoning_chain: List[str] = field(default_factory=list)
    
    # 
    alternative_hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self):
        return {
            'raw_confidence': self.raw_confidence,
            'calibrated_confidence': self.calibrated_confidence,
            'calibration_level': self.calibration_level,
            'evidence_quality': {
                'sufficiency': self.evidence_sufficiency,
                'consistency': self.evidence_consistency,
                'diversity': self.evidence_diversity,
            },
            'uncertainty_range': [self.uncertainty_lower, self.uncertainty_upper],
            'reasoning_chain': self.reasoning_chain,
            'alternative_hypotheses': self.alternative_hypotheses,
        }


@dataclass
class UnifiedDetectionResult:
    """
 

 (hijack/leak/outage/traffic)
 """
    # 
    success: bool = True
    error: Optional[str] = None
    error_code: Optional[str] = None

    # （： anomalies_detected ）
    data_available: bool = True
    no_data_reason: str = ""            # "" / "api_error" / "out_of_range" / "asn_unsupported" / "rate_limited"

    # 
    asn: str = ""
    target_asn: str = ""  # ， asn 
    detection_type: str = DetectionType.UNKNOWN.value

    # 
    analysis_start: str = ""
    analysis_end: str = ""

    # 
    anomalies_detected: bool = False
    anomaly_count: int = 0
    anomalies: List[AnomalyDetail] = field(default_factory=list)
    
    # （）
    @property
    def detected_anomalies(self) -> List[AnomalyDetail]:
        """detected_anomalies """
        return self.anomalies
    
    @property
    def origin_hijacked(self) -> List[AnomalyDetail]:
        """origin_hijacked ()"""
        return [a for a in self.anomalies
                if (a.subtype and 'origin_hijacked' in a.subtype) or a.type == 'origin_hijack']

    @property
    def forge_hijacked(self) -> List[AnomalyDetail]:
        """forge_hijacked ()"""
        return [a for a in self.anomalies
                if (a.subtype and 'forge_hijacked' in a.subtype) or a.type == 'forge_hijack']

    @property
    def route_leaks(self) -> List[AnomalyDetail]:
        """route_leaks ()"""
        return [a for a in self.anomalies if a.type == 'leak']
    
    # 
    confidence: ConfidenceAssessment = field(default_factory=ConfidenceAssessment)
    
    # 
    metadata: DetectionMetadata = field(default_factory=DetectionMetadata)
    
    # （）
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        """"""
        # Build base dict from standard fields
        result = {
            'success': self.success,
            'error': self.error,
            'error_code': self.error_code,
            'data_available': self.data_available,
            'no_data_reason': self.no_data_reason,
            'asn': self.asn or self.target_asn,
            'target_asn': self.target_asn or self.asn,
            'detection_type': self.detection_type,
            'analysis_start': self.analysis_start,
            'analysis_end': self.analysis_end,
            'anomalies_detected': self.anomalies_detected,
            'anomaly_count': self.anomaly_count,
            'anomalies': [a.to_dict() for a in self.anomalies],
            'confidence': self.confidence.to_dict(),
            'metadata': self.metadata.to_dict(),
            # 
            'origin_hijacked': self.origin_hijacked,
            'forge_hijacked': self.forge_hijacked,
            'route_leaks': self.route_leaks,
        }
        # Preserve any extra fields the caller passed to wrap() (e.g. leak_count,
        if self.raw_data:
            for _k, _v in self.raw_data.items():
                if _k not in result:
                    result[_k] = _v
        return result
    
    def to_legacy_dict(self):
        """
 ()

 
 """
        result = {
            'success': self.success,
            'asn': self.asn or self.target_asn,
            'analysis_period': f"{self.analysis_start} to {self.analysis_end}",
            'data_available': self.data_available,
            'no_data_reason': self.no_data_reason,
        }

        # 
        for anomaly in self.anomalies:
            item = anomaly.to_dict() if not isinstance(anomaly, dict) else anomaly
            ev_type = item.get('type', 'unknown')
            if ev_type == 'origin_hijack' and item.get('subtype') == 'origin_hijacked':
                result.setdefault('origin_hijacked', []).append(item)
            elif ev_type == 'origin_hijack' and item.get('subtype') in ('origin_hijacking', 'origin_hijacking'):
                result.setdefault('origin_hijacking', []).append(item)
            elif ev_type == 'forge_hijack' and item.get('subtype') == 'forge_hijacked':
                result.setdefault('forge_hijacked', []).append(item)
            elif ev_type == 'forge_hijack' and item.get('subtype') in ('forge_hijacking', 'forge_hijacking'):
                result.setdefault('forge_hijacking', []).append(item)
            elif ev_type in ('leak', 'route_leak'):
                result.setdefault('route_leaks', []).append(item)

        # 
        result.update({
            'anomaly_count': self.anomaly_count,
            'confidence': self.confidence.calibrated_confidence,
            'error': self.error,
        })

        return result

    @classmethod
    def from_dict(cls, data):
        """"""
        # 
        # Parse anomalies
        anomalies = []
        for key in ['origin_hijacked', 'forge_hijacked', 'route_leaks', 'anomalies']:
            if key in data:
                items = data[key]
                if isinstance(items, list):
                    # Determine the correct type for items that don't carry one.
                    if key == 'origin_hijacked':
                        default_type = 'origin_hijack'
                    elif key == 'forge_hijacked':
                        default_type = 'forge_hijack'
                    elif key == 'route_leaks':
                        default_type = 'leak'
                    else:
                        default_type = 'unknown'
                    # Normalise legacy / alias type names so the property
                    _TYPE_ALIASES = {
                        "route_leak": "leak",
                        "leak": "leak",
                        "origin_hijack": "origin_hijack",
                        "origin_hijacking": "origin_hijack",
                        "origin_hijacked": "origin_hijack",
                        "forge_hijack": "forge_hijack",
                        "forge_hijacking": "forge_hijack",
                        "forge_hijacked": "forge_hijack",
                    }
                    for item in items:
                        if isinstance(item, dict):
                            type_value = item.get('type')
                            if not type_value:
                                item = {**item, 'type': default_type}
                            elif type_value in _TYPE_ALIASES:
                                # Rewrite legacy aliases so downstream
                                if type_value != _TYPE_ALIASES[type_value]:
                                    item = {**item, 'type': _TYPE_ALIASES[type_value]}
                            anomalies.append(AnomalyDetail.from_dict(item))

        # 
        conf_data = data.get('confidence', {})
        if isinstance(conf_data, dict):
            evidence_q = conf_data.get('evidence_quality', {}) or {}
            unc_range = conf_data.get('uncertainty_range', [0.0, 1.0]) or [0.0, 1.0]
            confidence = ConfidenceAssessment(
                raw_confidence=conf_data.get('raw_confidence', 0.5),
                calibrated_confidence=conf_data.get('calibrated_confidence', 0.5),
                calibration_level=conf_data.get('calibration_level', 'unknown'),
                evidence_sufficiency=float(evidence_q.get('sufficiency', 0.0)),
                evidence_consistency=float(evidence_q.get('consistency', 0.0)),
                evidence_diversity=float(evidence_q.get('diversity', 0.0)),
                uncertainty_lower=float(unc_range[0]) if len(unc_range) > 0 else 0.0,
                uncertainty_upper=float(unc_range[1]) if len(unc_range) > 1 else 1.0,
                reasoning_chain=list(conf_data.get('reasoning_chain', []) or []),
                alternative_hypotheses=list(conf_data.get('alternative_hypotheses', []) or []),
            )
        else:
            confidence = ConfidenceAssessment(
                raw_confidence=float(conf_data) if conf_data else 0.5,
                calibrated_confidence=float(conf_data) if conf_data else 0.5,
            )

        # 
        meta_data = data.get('metadata', {})
        metadata = DetectionMetadata(
            analysis_start=meta_data.get('analysis_start', ''),
            analysis_end=meta_data.get('analysis_end', ''),
            analysis_duration_ms=meta_data.get('analysis_duration_ms', 0.0),
            data_sources=meta_data.get('data_sources', []) or list(data.get('data_sources', []) or []),
            data_quality_score=meta_data.get('data_quality_score', data.get('data_quality_score', 1.0)),
            coverage_percent=meta_data.get('coverage_percent', data.get('coverage_percent', 100.0)),
            api_calls_made=meta_data.get('api_calls_made', data.get('api_calls_made', 0)),
            api_calls_failed=meta_data.get('api_calls_failed', data.get('api_calls_failed', 0)),
            detection_threshold=meta_data.get('detection_threshold', data.get('detection_threshold', 0.5)),
            sensitivity=meta_data.get('sensitivity', data.get('sensitivity', 'normal')),
        )

        return cls(
            success=data.get('success', True),
            error=data.get('error'),
            asn=data.get('asn', data.get('target_asn', '')),
            target_asn=data.get('target_asn', data.get('asn', '')),
            detection_type=data.get('detection_type', DetectionType.UNKNOWN.value),
            analysis_start=data.get('analysis_start', ''),
            analysis_end=data.get('analysis_end', ''),
            anomalies_detected=data.get('anomalies_detected', len(anomalies) > 0),
            anomaly_count=data.get('anomaly_count', len(anomalies)),
            anomalies=anomalies,
            confidence=confidence,
            metadata=metadata,
            raw_data=data,
            data_available=data.get('data_available', True),
            no_data_reason=data.get('no_data_reason', ''),
        )

    def to_json(self):
        """ JSON """
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def summary(self):
        """"""
        if not self.success:
            return f"[ERROR] {self.error or 'Unknown error'}"

        if not self.data_available:
            reason = self.no_data_reason or "no_data"
            return f"[NO_DATA] ASN {self.asn}: data unavailable ({reason})"

        if not self.anomalies_detected:
            return f"[CLEAN] ASN {self.asn}: No anomalies detected"

        summary_parts = [f"[ALERT] ASN {self.asn}:"]

        for anomaly in self.anomalies[:3]:  # 3
            summary_parts.append(
                f"  - {anomaly.type}: {anomaly.event_count} events, "
                f"confidence={anomaly.confidence:.2f}"
            )

        if self.anomaly_count > 3:
            summary_parts.append(f"  ... and {self.anomaly_count - 3} more")

        return "\n".join(summary_parts)


class DetectionResultConverter:
    """
 
 
 
 """
    
    @staticmethod
    def hijack_to_unified(payload):
        """ hijack """
        hijack_result = payload
        anomalies = []
        
        # Origin hijacked ( AS )
        for item in hijack_result.get('origin_hijacked', []):
            anomalies.append(AnomalyDetail(
                type='origin_hijack',
                subtype='origin_hijacked',
                timestamp=item.get('timestamp'),
                affected_prefixes=item.get('affected_prefixes', []),
                affected_asns=item.get('affected_asns', []),
                event_count=item.get('event_count', 0),
                claimed_as=item.get('claimed_as') or item.get('hijacker_as') or item.get('attacker_as'),
                victim_as=item.get('victim_as') or item.get('origin_as') or item.get('legitimate_origin'),
                evidence=item.get('evidence', {}),
                confidence=item.get('confidence', 0.5),
            ))

        # Origin hijacking ( AS )
        for item in hijack_result.get('origin_hijacking', []):
            anomalies.append(AnomalyDetail(
                type='origin_hijack',
                subtype='origin_hijacking',
                timestamp=item.get('timestamp'),
                affected_prefixes=item.get('affected_prefixes', []),
                affected_asns=item.get('affected_asns', []),
                event_count=item.get('event_count', 0),
                claimed_as=item.get('claimed_as') or item.get('hijacker_as') or item.get('attacker_as') or item.get('asn'),
                victim_as=item.get('victim_as') or item.get('legitimate_origin'),
                evidence=item.get('evidence', {}),
                confidence=item.get('confidence', 0.5),
            ))

        # Forge hijacked (MITM )
        for item in hijack_result.get('forge_hijacked', []):
            anomalies.append(AnomalyDetail(
                type='forge_hijack',
                subtype='forge_hijacked',
                timestamp=item.get('timestamp'),
                affected_prefixes=item.get('affected_prefixes', []),
                affected_asns=item.get('affected_asns', []),
                event_count=item.get('event_count', 0),
                claimed_as=item.get('claimed_as') or item.get('hijacker_as') or item.get('attacker_as'),
                victim_as=item.get('victim_as') or item.get('legitimate_origin'),
                evidence=item.get('evidence', {}),
                confidence=item.get('confidence', 0.5),
            ))

        # Forge hijacking (MITM )
        for item in hijack_result.get('forge_hijacking', []):
            anomalies.append(AnomalyDetail(
                type='forge_hijack',
                subtype='forge_hijacking',
                timestamp=item.get('timestamp'),
                affected_prefixes=item.get('affected_prefixes', []),
                affected_asns=item.get('affected_asns', []),
                event_count=item.get('event_count', 0),
                claimed_as=item.get('claimed_as') or item.get('hijacker_as') or item.get('attacker_as') or item.get('asn'),
                victim_as=item.get('victim_as') or item.get('legitimate_origin'),
                evidence=item.get('evidence', {}),
                confidence=item.get('confidence', 0.5),
            ))

        return UnifiedDetectionResult(
            success=hijack_result.get('success', True),
            error=hijack_result.get('error'),
            asn=hijack_result.get('asn', ''),
            detection_type=DetectionType.HIJACK.value,
            analysis_start=hijack_result.get('analysis_start', ''),
            analysis_end=hijack_result.get('analysis_end', ''),
            anomalies_detected=len(anomalies) > 0,
            anomaly_count=len(anomalies),
            anomalies=anomalies,
            # BGP data from RIPE RIS
            # available; flag as data_available = True.
            data_available=hijack_result.get('data_available', True),
            no_data_reason=hijack_result.get('no_data_reason', ''),
        )

    @staticmethod
    def leak_to_unified(payload):
        """ leak """
        leak_result = payload
        anomalies = []

        for item in leak_result.get('route_leaks', []):
            anomalies.append(AnomalyDetail(
                type='leak',
                subtype='route_leak',
                timestamp=item.get('timestamp'),
                affected_prefixes=item.get('affected_prefixes', []),
                affected_asns=item.get('affected_asns', []),
                event_count=item.get('event_count', 0),
                evidence=item.get('evidence', {}),
                confidence=item.get('confidence', 0.5),
            ))

        return UnifiedDetectionResult(
            success=leak_result.get('success', True),
            error=leak_result.get('error'),
            asn=leak_result.get('asn', ''),
            detection_type=DetectionType.LEAK.value,
            analysis_start=leak_result.get('analysis_start', ''),
            analysis_end=leak_result.get('analysis_end', ''),
            anomalies_detected=len(anomalies) > 0,
            anomaly_count=len(anomalies),
            anomalies=anomalies,
            data_available=leak_result.get('data_available', True),
            no_data_reason=leak_result.get('no_data_reason', ''),
        )

    @staticmethod
    def outage_to_unified(payload):
        """ outage """
        outage_result = payload
        anomalies = []

        if outage_result.get('is_outage_suspected'):
            anomalies.append(AnomalyDetail(
                type='outage',
                subtype='route_outage',
                event_count=outage_result.get('anomaly_count', 0),
                confidence=outage_result.get('outage_score', 0.5),
                evidence=outage_result.get('evidence', {}),
            ))

        return UnifiedDetectionResult(
            success=outage_result.get('success', True),
            error=outage_result.get('error'),
            asn=outage_result.get('asn', ''),
            detection_type=DetectionType.OUTAGE.value,
            analysis_start=outage_result.get('analysis_start', ''),
            analysis_end=outage_result.get('analysis_end', ''),
            anomalies_detected=outage_result.get('is_outage_suspected', False),
            anomaly_count=outage_result.get('anomaly_count', 0),
            anomalies=anomalies,
            data_available=outage_result.get('data_available', True),
            no_data_reason=outage_result.get('no_data_reason', ''),
        )

    @staticmethod
    def traffic_to_unified(payload):
        """ traffic """
        traffic_result = payload
        anomalies = []

        for item in traffic_result.get('anomalies', []):
            anomalies.append(AnomalyDetail(
                type='traffic',
                subtype=item.get('anomaly_type', 'unknown'),
                timestamp=item.get('timestamp'),
                duration_seconds=item.get('duration_seconds'),
                evidence=item.get('evidence', {}),
                confidence=item.get('confidence', 0.5),
            ))

        # Traffic detector (Cloudflare Radar API token missing or
        # ASN with data_points=0). Flag as not data_available.
        return UnifiedDetectionResult(
            success=traffic_result.get('success', True),
            error=traffic_result.get('error'),
            asn=traffic_result.get('asn', ''),
            detection_type=DetectionType.TRAFFIC.value,
            analysis_start=traffic_result.get('analysis_start', ''),
            analysis_end=traffic_result.get('analysis_end', ''),
            anomalies_detected=traffic_result.get('anomalies_detected', len(anomalies) > 0),
            anomaly_count=traffic_result.get('anomaly_count', len(anomalies)),
            anomalies=anomalies,
            data_available=traffic_result.get(
                'data_available',
                # Default: detector didn't set data_available; treat as
                # success=True only when data_points>0.
                bool(traffic_result.get('data_points', 0)) and traffic_result.get('success', True),
            ),
            no_data_reason=traffic_result.get('no_data_reason', ''),
        )


def merge_detection_results(results: List[UnifiedDetectionResult]):
    """
 
 
 hijack + leak + outage + traffic 
 """
    if not results:
        return UnifiedDetectionResult()
    
    # 
    all_anomalies = []
    for result in results:
        all_anomalies.extend(result.anomalies)
    
    # 
    start_times = [r.analysis_start for r in results if r.analysis_start]
    end_times = [r.analysis_end for r in results if r.analysis_end]
    
    # （）
    confidences = [r.confidence.calibrated_confidence for r in results if r.confidence]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5
    
    return UnifiedDetectionResult(
        success=all(r.success for r in results),
        asn=results[0].asn or results[0].target_asn,
        target_asn=results[0].target_asn or results[0].asn,
        analysis_start=min(start_times) if start_times else '',
        analysis_end=max(end_times) if end_times else '',
        anomalies_detected=any(r.anomalies_detected for r in results),
        anomaly_count=sum(r.anomaly_count for r in results),
        anomalies=all_anomalies,
        confidence=ConfidenceAssessment(calibrated_confidence=avg_confidence),
    )


# =============================================================================
def wrap(
    detection_type: "DetectionType",
    raw: dict,
    *,
    asn: str = "",
    success: Optional[bool] = None,
    data_available: Optional[bool] = None,
    no_data_reason: str = "",
) -> UnifiedDetectionResult:
    """
 Wrap a raw detector dict into a UnifiedDetectionResult without forcing
 the detector author to spell out every field.

 Detection modules that already produce dicts (hijack / leak / outage /
 traffic) can pass their dict through this helper at the very end of
 the pipeline. If they also write `data_available` /
 `no_data_reason` themselves, those values win.

 Example:
 return wrap(DetectionType.HIJACK, result_dict, asn="13335")
 """
    if success is None:
        success = bool(raw.get("success", True))
    if data_available is None:
        if "data_available" in raw:
            data_available = bool(raw.get("data_available"))
        else:
            # Legacy detector that didn't write the flag: trust success
            # and "did we get any data?" heuristic.
            data_available = success and bool(
                raw.get("data_points", 0)
                or raw.get("total_announcements", 0)
                or raw.get("total_detected", 0)
                or raw.get("anomaly_count", 0)
                or raw.get("origin_hijacked")
                or raw.get("forge_hijacked")
                or raw.get("route_leaks")
                or raw.get("anomalies")
            )

    # Contract guard: data_available=False MUST carry a non-empty reason so
    # downstream agents / report renderers can tell "no data" apart from
    # "scanned and clean". Infer the reason when the detector left it blank.
    resolved_no_data_reason = no_data_reason or raw.get("no_data_reason", "") or ""
    if not data_available and not resolved_no_data_reason:
        # Order matters: pick the most specific actionable reason first so
        # report renderers can guide operators ("check inputs" beats
        # "detector failed" when the input itself was the problem).
        if raw.get("invalid_request"):
            resolved_no_data_reason = "invalid_request"
        elif raw.get("error"):
            resolved_no_data_reason = "detector_error"
        elif not success:
            resolved_no_data_reason = "detector_failure"
        else:
            resolved_no_data_reason = "no_data"

    return UnifiedDetectionResult.from_dict({
        **raw,
        "asn": asn or raw.get("asn", ""),
        "target_asn": asn or raw.get("target_asn", ""),
        "detection_type": detection_type.value,
        "success": success,
        "data_available": data_available,
        "no_data_reason": resolved_no_data_reason,
    })


# 
if __name__ == "__main__":
    print("=" * 60)
    print("")
    print("=" * 60)
    
    #  hijack 
    hijack_data = {
        'success': True,
        'asn': '12479',
        'analysis_start': '2024-01-03 14:45:00',
        'analysis_end': '2024-01-03 18:00:00',
        'origin_hijacked': [
            {
                'type': 'origin_hijack',
                'affected_prefixes': ['149.74.28.0/22'],
                'affected_asns': ['5511', '3356'],
                'event_count': 500,
                'confidence': 0.85,
            }
        ],
        'forge_hijacked': [],
    }
    
    # 
    unified = DetectionResultConverter.hijack_to_unified(hijack_data)
    print(f"\n: {hijack_data}")
    print(f"\n:")
    print(json.dumps(unified.to_dict(), indent=2, ensure_ascii=False)[:500])
    
    print(f"\n: {unified.summary()}")
    
    # （）
    legacy = unified.to_legacy_dict()
    print(f"\n（）:")
    print(legacy)

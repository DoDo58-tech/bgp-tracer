"""Tool B4: AS Historical Behavior & Incident History
==============================================="""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from tools.tool_registry import ToolParameter, register_tool
from utils.logger import logger
import re

# ── External APIs ─────────────────────────────────────────────────────────────

BGPVIEW_EVENTS_URL = "https://api.bgpview.io/asn/{asn}/events"
RIPESTAT_ORIGINS_URL = "https://stat.ripe.net/ris/origins"

# ── Local historical ground truth ─────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).parent.parent
HISTORICAL_CASES_DIR = PROJECT_ROOT / "data" / "historical_cases"


async def fetch_bgpview_events(asn: str, days: int = 365):
    """Fetch historical BGP events for an AS from BGPView.io."""
    url = BGPVIEW_EVENTS_URL.format(asn=asn)
    params = {
        "period": "days",
        "value": days,
    }
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "ok":
                events = data.get("data", {}).get("events", []) or []
                return [
                    {
                        "date": ev.get("date"),
                        "type": ev.get("type"),
                        "prefix": ev.get("prefix"),
                        "description": ev.get("description", ""),
                        "source": "bgpview",
                    }
                    for ev in events
                ]
    except (httpx.HTTPError, OSError, ValueError, KeyError, AttributeError) as e:
        logger.warning(f"[hist] BGPView events fetch failed: {e}")
    return []


async def fetch_ripestat_incidents(asn_id: str):
    """Fetch RIPE RIS incident history for an AS."""
    asn = asn_id  # NOTE: parameter is `asn_id`; body uses `asn`.
    params = {"resource": f"AS{asn}"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(RIPESTAT_ORIGINS_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
            incidents = data.get("data", {}).get("incidents", []) or []
            return [
                {
                    "date": inc.get("start_time"),
                    "type": inc.get("type"),
                    "prefixes": inc.get("affected_prefixes", []),
                    "source": "ripe",
                }
                for inc in incidents
            ]
    except (httpx.HTTPError, OSError, ValueError, KeyError, AttributeError) as e:
        logger.warning(f"[hist] RIPEstat incidents fetch failed: {e}")
    return []


def load_local_historical_cases(asn: str, timeframe_days: int = 730):
    """Load our own ground truth historical cases for this AS."""
    cases = []
    if not HISTORICAL_CASES_DIR.exists():
        return cases

    cutoff = datetime.now() - timedelta(days=timeframe_days)
    asn_str = str(asn).lstrip("AS")

    for case_file in HISTORICAL_CASES_DIR.glob("*.json"):
        try:
            with open(case_file, encoding="utf-8") as f:
                data = json.load(f)

            # Match by ASN
            case_asn = str(data.get("asn", "")).lstrip("AS")
            if case_asn != asn_str:
                continue

            # Check date
            date_str = data.get("date") or data.get("timestamp") or ""
            try:
                case_date = datetime.strptime(date_str[:10], "%Y-%m-%d")
                if case_date < cutoff:
                    continue
            except ValueError:
                pass

            cases.append({
                "date": date_str,
                "event_type": data.get("event_type") or data.get("type"),
                "description": data.get("description", "")[:300],
                "confirmed": data.get("confirmed", True),
                "root_cause": data.get("root_cause"),
                "severity": data.get("severity"),
                "source": "local_ground_truth",
            })
        except ValueError:
            pass

    return cases


def analyze_reoffense_pattern(events: list[dict]):
    """Analyze if an AS shows a pattern of repeat offenses."""
    if not events:
        return {
            "is_repeat_offender": False,
            "total_incidents": 0,
            "incident_types": {},
            "mo_signature": None,
        }

    # Count by type
    type_counts: dict[str, int] = {}
    prefix_targets: dict[str, int] = {}
    for ev in events:
        t = ev.get("type", "unknown") or "unknown"
        type_counts[t] = type_counts.get(t, 0) + 1
        pfx = ev.get("prefix") or ev.get("affected_prefixes")
        if isinstance(pfx, list):
            pfx = pfx[0] if pfx else "unknown"
        if pfx and pfx != "unknown":
            prefix_targets[pfx] = prefix_targets.get(pfx, 0) + 1

    # Determine if repeat offender
    total = len(events)
    is_repeat = total >= 2
    mo_signature = None

    if is_repeat:
        # Identify MO: same type + same target pattern
        most_common_type = max(type_counts, key=type_counts.get)
        most_targeted_prefix = max(prefix_targets, key=prefix_targets.get) if prefix_targets else None
        if most_common_type and type_counts[most_common_type] >= 2:
            mo_signature = f"Repeat {most_common_type} attacks"
            if most_targeted_prefix:
                mo_signature += f" targeting {most_targeted_prefix}"

    # Frequency analysis
    dates = []
    for ev in events:
        d = ev.get("date") or ev.get("start_time")
        if d:
            try:
                dates.append(datetime.strptime(str(d)[:10], "%Y-%m-%d"))
            except ValueError:
                pass

    frequency = "unknown"
    if len(dates) >= 2:
        dates.sort()
        intervals = [(dates[i + 1] - dates[i]).days for i in range(len(dates) - 1)]
        avg_days = sum(intervals) / len(intervals)
        if avg_days < 7:
            frequency = "frequent (multiple times per week)"
        elif avg_days < 30:
            frequency = "regular (monthly)"
        elif avg_days < 180:
            frequency = "occasional (several times per year)"
        else:
            frequency = "rare"

    return {
        "is_repeat_offender": is_repeat,
        "total_incidents": total,
        "incident_types": type_counts,
        "most_common_type": max(type_counts, key=type_counts.get) if type_counts else None,
        "prefix_targets": prefix_targets,
        "most_targeted_prefix": max(prefix_targets, key=prefix_targets.get) if prefix_targets else None,
        "mo_signature": mo_signature,
        "frequency": frequency,
        "first_incident_date": min(dates).isoformat() if dates else None,
        "last_incident_date": max(dates).isoformat() if dates else None,
    }


def build_reoffense_narrative(pattern: dict, events: list[dict]):
    """Build a human-readable narrative about the AS's history."""
    if not pattern["is_repeat_offender"]:
        return (
            f"AS has {pattern['total_incidents']} historical incident(s) on record. "
            f"Type(s): {', '.join(pattern['incident_types'].keys())}. "
            f"This appears to be a first-time or infrequent offender."
        )

    parts = [
        f"AS is a REPEAT OFFENDER with {pattern['total_incidents']} historical incident(s). "
        f"Incident type(s): {', '.join(f'{k}({v})' for k, v in pattern['incident_types'].items())}. "
        f"Frequency: {pattern['frequency']}."
    ]

    if pattern.get("mo_signature"):
        parts.append(f"Identified MO: {pattern['mo_signature']}.")

    if pattern.get("most_targeted_prefix"):
        parts.append(
            f"Most targeted prefix: {pattern['most_targeted_prefix']} "
            f"({pattern['prefix_targets'][pattern['most_targeted_prefix']]} incidents)."
        )

    if events:
        local_events = [e for e in events if e.get("source") == "local_ground_truth"]
        if local_events:
            confirmed_types = [e.get("event_type") for e in local_events if e.get("confirmed")]
            if confirmed_types:
                causes = [e.get("root_cause") for e in local_events if e.get("root_cause")]
                if causes:
                    parts.append(f"Known root causes from our records: {'; '.join(set(causes))}.")

    return " ".join(parts)


async def historical_behavior_lookup(tool_input: dict, session):
    """Look up an AS's historical BGP incident record.
    
    Returns:
    - bgpview_events: events from BGPView.io
    - ripestat_incidents: incidents from RIPEstat
    - local_cases: our own ground truth cases
    - reoffense_pattern: analysis of repeat-offense patterns
    - narrative: human-readable history summary
    - risk_assessment: based on history
    - observation: LLM-readable summary"""
    asn = str(tool_input.get("asn", "")).lstrip("AS")
    timeframe_days = int(tool_input.get("timeframe_days", 730))
    include_local = tool_input.get("include_local", True)

    logger.info(f"[hist] Looking up historical behavior for AS{asn}, last {timeframe_days} days")

    # Fetch from all sources concurrently
    bgpview_events, ripestat_incidents, local_cases = await asyncio.gather(
        fetch_bgpview_events(asn, days=min(timeframe_days, 365)),
        fetch_ripestat_incidents(asn),
        asyncio.to_thread(load_local_historical_cases, asn, timeframe_days) if include_local else asyncio.coroutine(lambda: [])(),
    )

    # Combine all events
    all_events = bgpview_events + ripestat_incidents + local_cases
    all_events.sort(key=lambda e: e.get("date", ""), reverse=True)

    # Analyze reoffense pattern
    pattern = analyze_reoffense_pattern(all_events)

    # Build narrative
    narrative = build_reoffense_narrative(pattern, local_cases)

    # Risk assessment
    risk_factors = []
    if pattern["is_repeat_offender"] and pattern["total_incidents"] >= 3:
        risk_factors.append("multiple past incidents")
    if pattern.get("frequency") == "frequent":
        risk_factors.append("frequent reoffense")
    if pattern.get("most_common_type"):
        risk_factors.append(f"repeated {pattern['most_common_type']} type")

    # Cross-reference with local ground truth
    if local_cases:
        confirmed_hijacks = [e for e in local_cases if e.get("event_type") in ("hijack", "origin_hijack")]
        confirmed_leaks = [e for e in local_cases if e.get("event_type") in ("leak", "route_leak")]
        if confirmed_hijacks:
            risk_factors.append(f"{len(confirmed_hijacks)} confirmed hijack(s) in our records")
        if confirmed_leaks:
            risk_factors.append(f"{len(confirmed_leaks)} confirmed route leak(s) in our records")

    if risk_factors:
        risk_level = "HIGH" if len(risk_factors) >= 2 else "MEDIUM"
        risk_assessment = f"Risk level: {risk_level}. Factors: {', '.join(risk_factors)}."
    else:
        risk_level = "LOW"
        risk_assessment = f"Risk level: LOW. AS has clean or minimal incident history."

    # Top events for display
    top_events = all_events[:10]

    observation = (
        f"Historical behavior for AS{asn}: "
        f"total_past_incidents={pattern['total_incidents']}, "
        f"repeat_offender={pattern['is_repeat_offender']}, "
        f"most_common_type={pattern.get('most_common_type')}, "
        f"mo_signature={pattern.get('mo_signature')}, "
        f"frequency={pattern.get('frequency')}, "
        f"risk_level={risk_level}, "
        f"bgpview_events={len(bgpview_events)}, "
        f"ripestat_incidents={len(ripestat_incidents)}, "
        f"local_cases={len(local_cases)}."
    )

    return {
        "success": True,
        "asn": f"AS{asn}",
        "timeframe_days": timeframe_days,
        "bgpview_events": bgpview_events,
        "ripestat_incidents": ripestat_incidents,
        "local_cases": local_cases,
        "total_events": len(all_events),
        "reoffense_pattern": pattern,
        "top_events": top_events,
        "narrative": narrative,
        "risk_assessment": risk_assessment,
        "risk_level": risk_level,
        "observation": observation,
    }


register_tool(
    name="historical_behavior",
    description=(
        "Look up an AS's historical BGP incident record. "
        "Checks: BGPView.io events, RIPEstat incidents, and local ground truth cases. "
        "Determines if an AS is a first-time offender or repeat offender, "
        "identifies modus operandi (MO) patterns, frequency, and most-targeted prefixes. "
        "Use when: you detect a hijack/leak and want to know if this AS has done this before. "
        "This changes the root cause explanation significantly: repeat offenders suggest intentionality, "
        "first-time offenders suggest misconfiguration or account compromise."
    ),
    parameters=[
        ToolParameter("asn", "AS number to investigate", "string"),
        ToolParameter("timeframe_days", "How far back to look (default: 730 days / 2 years)", "string", required=False),
        ToolParameter("include_local", "Include our own ground truth cases (default: True)", "string", required=False),
    ],
    handler=historical_behavior_lookup,
)
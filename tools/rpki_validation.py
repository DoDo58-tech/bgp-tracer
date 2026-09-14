"""
Tool A6: RPKI / ROA validation using Cloudflare's free RPKI API.
================================================================

Validates whether BGP announcements are covered by a valid ROA.
This dramatically increases hijack detection confidence:
  - Route covered by valid ROA → high-confidence
  - Route NOT covered by any ROA → cannot determine, flag as "no ROA"
  - Route covered by INVALID ROA (wrong origin) → RPKI-invalid hijack

Cloudflare RPKI Validator API (free, no auth):
    https://rpki.cloudflare.com/api/v1/roas
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import httpx
from tools.tool_registry import ToolParameter, register_tool
from utils.logger import logger

RPKI_API = "https://rpki.cloudflare.com/rpki.json"


async def _rpki_validate(tool_input: dict, session) -> dict:
    """
    Validate BGP announcements against RPKI ROAs.

    Required params:
        asn (str): AS number to validate announcements for
        announcements (list[dict], optional): list of {
            "prefix": "8.8.8.0/24",
            "origin_asn": "15169",
            "timestamp": "2025-06-21T00:30:00Z"
        }
        If not provided, will try to derive from routing_result in session.

    Returns:
        - validation: list of {prefix, origin_asn, status, roa}
          where status is "valid" | "invalid" | "not_found"
        - summary: {total, valid_count, invalid_count, not_found_count}
        - invalid_events: events with RPKI-invalid announcements
    """
    asn = str(tool_input.get("asn", ""))

    # Gather announcements from session evidence if not provided
    announcements = tool_input.get("announcements")
    if not announcements:
        # Try to derive from routing evidence
        routing = session.get_evidence("analyze_routing")
        if routing:
            routing_data = routing.get("result", {})
            announcements = _extract_announcements(routing_data, asn)

    if not announcements:
        return {
            "success": True,
            "validation": [],
            "summary": {"total": 0, "valid_count": 0, "invalid_count": 0, "not_found_count": 0},
            "observation": f"No announcements to validate for AS{asn}.",
        }

    logger.info(f"[rpki_validate] Fetching ROA data, validating {len(announcements)} announcements")

    # Step 1: fetch all ROAs (cached for 5 minutes)
    roas = await _fetch_roas_cached(session)
    roa_map = _build_roa_map(roas)

    # Step 2: validate each announcement
    results = []
    for ann in announcements:
        prefix = ann.get("prefix", "")
        origin = str(ann.get("origin_asn", ""))
        ts = ann.get("timestamp", "")
        status, matched_roa = _validate_announcement(prefix, origin, roa_map)
        results.append({
            "prefix": prefix,
            "origin_asn": origin,
            "timestamp": ts,
            "status": status,
            "roa": matched_roa,
        })

    valid = [r for r in results if r["status"] == "valid"]
    invalid = [r for r in results if r["status"] == "invalid"]
    not_found = [r for r in results if r["status"] == "not_found"]

    # High-confidence invalid events
    invalid_events = [r for r in invalid if r["roa"]]

    summary = {
        "total": len(results),
        "valid_count": len(valid),
        "invalid_count": len(invalid),
        "not_found_count": len(not_found),
    }

    if invalid_events:
        narrative = (
            f"RPKI validation: {len(valid)} valid, {len(invalid)} invalid, {len(not_found)} no ROA. "
            f"⚠️ {len(invalid_events)} RPKI-invalid announcements detected — "
            f"these are likely hijacks (origin AS does not match ROA)."
        )
    elif not_found:
        narrative = (
            f"RPKI validation: {len(valid)} valid, {len(not_found)} with no published ROA. "
            f"Cannot determine validity for unauthenticated prefixes."
        )
    else:
        narrative = f"All {len(valid)} announcements are RPKI-valid. No RPKI-invalid hijacks detected."

    return {
        "success": True,
        "asn": asn,
        "validation": results,
        "summary": summary,
        "invalid_events": invalid_events,
        "observation": narrative,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

# Simple in-memory cache: (fetched_at, data)
_roa_cache: tuple[float, List[dict]] | None = None


async def _fetch_roas_cached(session) -> List[dict]:
    """Fetch all ROAs from Cloudflare, caching for 5 minutes."""
    global _roa_cache
    import time

    now = time.time()
    if _roa_cache and (now - _roa_cache[0]) < 300:
        return _roa_cache[1]

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(RPKI_API)
            # Cloudflare RPKI API may return 404 if no data available
            if resp.status_code == 404:
                logger.warning(f"[rpki] Cloudflare ROA fetch returned 404, using cache if available")
                return _roa_cache[1] if _roa_cache else []
            resp.raise_for_status()
            data = resp.json()
            roas = data if isinstance(data, list) else data.get("roas", [])
            _roa_cache = (now, roas)
            logger.info(f"[rpki] Fetched {len(roas)} ROAs from Cloudflare RPKI")
            return roas
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.warning(f"[rpki] Cloudflare ROA fetch returned 404, using cache if available")
            return _roa_cache[1] if _roa_cache else []
        logger.error(f"[rpki] Failed to fetch ROAs: {e}")
        return _roa_cache[1] if _roa_cache else []
    except Exception as e:
        logger.error(f"[rpki] Failed to fetch ROAs: {e}")
        return _roa_cache[1] if _roa_cache else []


def _build_roa_map(roas: List[dict]) -> dict:
    """
    Build lookup map: prefix → list of (origin_asn, max_prefix_len, expires)
    """
    from ipaddress import ip_network

    mp = {}
    for roa in roas:
        try:
            prefix_str = roa.get("prefix", "")
            if not prefix_str:
                continue
            prefix = ip_network(prefix_str, strict=False)
            origin = str(roa.get("asn", ""))
            max_len = roa.get("maxLength", 0) or prefix.num_addresses - 1
            expires = roa.get("expires", "")
            mp.setdefault(prefix_str, []).append({
                "origin_asn": origin,
                "max_prefix_len": max_len,
                "expires": expires,
                "validation": roa.get("validation", ""),
            })
        except Exception:
            continue
    return mp


def _validate_announcement(prefix: str, origin_asn: str, roa_map: dict) -> tuple[str, dict | None]:
    """
    Validate a single announcement against ROA map.
    Returns: (status, matched_roa_dict)
      status: "valid" | "invalid" | "not_found"
    """
    from ipaddress import ip_network

    if not prefix or not origin_asn:
        return "not_found", None

    try:
        ann_prefix = ip_network(prefix, strict=False)
    except Exception:
        return "not_found", None

    candidates = []
    for roa_prefix, roa_list in roa_map.items():
        try:
            if ann_prefix.overlaps(ip_network(roa_prefix, strict=False)):
                for roa in roa_list:
                    if roa["origin_asn"] == origin_asn:
                        candidates.append(roa)
        except Exception:
            continue

    if not candidates:
        return "not_found", None

    # Check if announcement prefix length <= maxLength of any valid ROA
    ann_prefix_len = ann_prefix.prefixlen
    valid_roas = [r for r in candidates if ann_prefix_len <= r["max_prefix_len"]]
    if valid_roas:
        return "valid", valid_roas[0]

    # Prefix matches but origin AS does not match any ROA → RPKI-invalid
    invalid_roas = [r for r in candidates if r["origin_asn"] != origin_asn]
    if candidates:
        return "invalid", candidates[0]

    return "not_found", None


def _extract_announcements(routing_data: dict, asn: str) -> List[dict]:
    """Extract announcements from routing_result for a given AS."""
    announcements = []
    for key in ["origin_hijacked", "forge_hijacked", "route_leaks"]:
        events = routing_data.get(key, []) or []
        for event in events:
            pref = event.get("prefix") or event.get("announced_prefix")
            if pref:
                announcements.append({
                    "prefix": pref,
                    "origin_asn": str(asn),
                    "timestamp": event.get("timestamp", ""),
                    "event_type": key,
                })
    return announcements


# ── Tool registration ────────────────────────────────────────────────────────

register_tool(
    name="rpki_validation",
    description=(
        "Validate BGP announcements against RPKI/ROA records using Cloudflare's free RPKI API. "
        "Flags RPKI-invalid announcements (hijacks where origin AS does not match any valid ROA). "
        "Cloudflare API: https://rpki.cloudflare.com/api/v1/roas"
    ),
    parameters=[
        ToolParameter("asn", "AS number to validate", "string"),
        ToolParameter(
            "announcements", "Optional: list of {prefix, origin_asn, timestamp} to validate. "
            "If omitted, extracts from routing_result in session.", "object", required=False
        ),
    ],
    handler=_rpki_validate,
)

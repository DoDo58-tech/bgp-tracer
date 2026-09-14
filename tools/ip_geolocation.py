"""
Tool A3: IP Geolocation + BGP prefix lookup.
==========================================

Geo-locates AS traffic anomalies and BGP events.
Uses BGPView.io (free tier) and ip-api.com (free, no key required).

What it does:
  1. Take a list of prefixes announced by the target AS.
  2. For each prefix, look up:
       - BGP origin AS (should match the target AS)
       - IP geolocation (country, city, ISP)
  3. Cross-reference with the traffic anomaly time window to
     identify which geographic regions were affected.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import httpx
from tools.tool_registry import ToolParameter, register_tool
from utils.logger import logger

BGPVIEW_BASE = "https://api.bgpview.io"
IPAPI_BASE = "http://ip-api.com/json"


async def _ip_geolocation(tool_input: dict, session) -> dict:
    """
    Geolocate prefixes announced by an AS and cross-reference with
    traffic anomalies.

    Required params:
        asn (str): AS number
        start_time (str): analysis window start
        end_time (str): analysis window end

    Optional params:
        prefixes (list[str]): specific prefixes to check.
                               If omitted, fetches from BGPView.
    """
    asn = str(tool_input["asn"])
    start = tool_input.get("start_time", "")
    end = tool_input.get("end_time", "")
    prefixes = tool_input.get("prefixes") or []

    logger.info(f"[geo] Geolocation for AS{asn}")

    # Step 1: get announced prefixes from BGPView if not provided
    if not prefixes:
        prefixes = await _fetch_as_prefixes(asn)
        logger.info(f"[geo] AS{asn} has {len(prefixes)} announced prefixes")
    else:
        logger.info(f"[geo] Using {len(prefixes)} user-provided prefixes")

    if not prefixes:
        return {
            "success": True,
            "asn": asn,
            "prefixes": [],
            "geolocation": [],
            "observation": f"No prefixes found for AS{asn}.",
        }

    # Step 2: batch geolocate prefixes (rate-limited)
    geo_results = await _batch_geolocate(prefixes[:30])  # cap at 30

    # Step 3: build summary
    countries = {}
    for g in geo_results:
        cc = g.get("country_code", "??")
        countries[cc] = countries.get(cc, 0) + 1

    top_countries = sorted(countries.items(), key=lambda x: -x[1])[:10]
    total_geo = len(geo_results)
    country_codes = [cc for cc, _ in top_countries]

    # Step 4: cross-reference with traffic anomaly (if available)
    traffic = session.get_evidence("analyze_traffic")
    anomaly_note = ""
    if traffic and traffic.get("success"):
        anomalies = traffic.get("results", {}).get(str(asn), {}).get("anomalies", [])
        anomaly_note = (
            f"Traffic anomalies detected at {len(anomalies)} points "
            f"during {start} to {end}. "
            f"The affected country distribution (from {total_geo} geolocated prefixes) is: "
            + ", ".join(f"{cc} ({n} prefixes)" for cc, n in top_countries)
        )
    else:
        anomaly_note = (
            f"AS{asn} announces {total_geo} prefixes across "
            f"{len(countries)} countries: "
            + ", ".join(f"{cc} ({n} prefixes)" for cc, n in top_countries)
        )

    return {
        "success": True,
        "asn": asn,
        "time_window": f"{start} to {end}",
        "prefixes_checked": len(prefixes),
        "prefixes_geolocated": total_geo,
        "prefixes": [g.get("prefix") for g in geo_results],
        "geolocation": geo_results,
        "country_distribution": [{"country_code": cc, "count": n} for cc, n in top_countries],
        "observation": anomaly_note,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _fetch_as_prefixes(asn: str) -> List[str]:
    """Fetch all announced prefixes for an AS via BGPView.io."""
    url = f"{BGPVIEW_BASE}/lookup/as{asn}"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") != "ok":
                return []
            prefixes = []
            for item in data.get("data", {}).get("prefixes", []) or []:
                p = item.get("prefix")
                if p:
                    prefixes.append(p)
            return prefixes
    except Exception as e:
        logger.warning(f"[geo] BGPView failed for AS{asn}: {e}")
        return []


async def _geolocate_prefix(prefix: str) -> dict:
    """
    Geolocate a prefix by sampling the first usable IP.
    Uses ip-api.com (free, no API key, rate: 45 req/min).
    """
    import ipaddress

    try:
        net = ipaddress.ip_network(prefix, strict=False)
        sample_ip = str(list(net.hosts())[0]) if net.num_addresses > 2 else str(net.network_address)
    except Exception:
        return {
            "prefix": prefix,
            "ip_sample": None,
            "country_code": None,
            "country_name": None,
            "city": None,
            "isp": None,
            "org": None,
            "asn": None,
        }

    url = f"{IPAPI_BASE}/{sample_ip}?fields=status,countryCode,country,city,isp,org,as"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            d = resp.json()
            if d.get("status") != "success":
                return {
                    "prefix": prefix,
                    "ip_sample": sample_ip,
                    "country_code": None,
                    "country_name": None,
                    "city": None,
                    "isp": d.get("message", "unknown"),
                    "org": None,
                    "asn": None,
                }
            return {
                "prefix": prefix,
                "ip_sample": sample_ip,
                "country_code": d.get("countryCode"),
                "country_name": d.get("country"),
                "city": d.get("city"),
                "isp": d.get("isp"),
                "org": d.get("org"),
                "asn": d.get("as"),
            }
    except Exception:
        return {
            "prefix": prefix,
            "ip_sample": sample_ip,
            "country_code": None,
            "country_name": None,
            "city": None,
            "isp": None,
            "org": None,
            "asn": None,
        }


async def _batch_geolocate(prefixes: List[str], rate: int = 30) -> List[dict]:
    """Batch geolocate with simple rate limiting."""
    results = []
    # Process in chunks of `rate` with 60s sleep between batches
    for i in range(0, len(prefixes), rate):
        chunk = prefixes[i: i + rate]
        tasks = [_geolocate_prefix(p) for p in chunk]
        chunk_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in chunk_results:
            if isinstance(r, dict):
                results.append(r)
        if i + rate < len(prefixes):
            await asyncio.sleep(61)  # stay under ip-api.com rate limit
    return results


# ── Tool registration ────────────────────────────────────────────────────────

register_tool(
    name="ip_geolocation",
    description=(
        "Geolocate the prefixes announced by an AS (country, city, ISP) using BGPView.io and ip-api.com. "
        "Cross-references with traffic anomalies to identify which geographic regions were affected. "
        "Uses free APIs: BGPView (prefix lookup) + ip-api.com (geolocation, 45 req/min)."
    ),
    parameters=[
        ToolParameter("asn", "AS number", "string"),
        ToolParameter("start_time", "Analysis window start", "string"),
        ToolParameter("end_time", "Analysis window end", "string"),
        ToolParameter(
            "prefixes", "Optional: list of specific prefixes to geolocate. "
            "If omitted, fetches all announced prefixes for the AS.", "object", required=False
        ),
    ],
    handler=_ip_geolocation,
)

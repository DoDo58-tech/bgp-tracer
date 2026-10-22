"""
Tool A2: AS Topology Position — Tier / Provider-Customer-Peer analysis.
=====================================================================

Determines an AS's position in the Internet topology:
  - Tier-1:    no upstream providers (peers with everyone)
  - Transit:   has both upstream + downstream customers
  - Stub:      only upstream providers, no downstream customers
  - Content:   has massive customer cone (CDN/Cloud provider)

Also fetches:
  - Direct neighbors (providers, customers, peers) from RIPEstat
  - AS name / description from WHOIS
  - PeeringDB info (if ASN is registered)

This directly answers: "is this AS likely a major transit provider or a stub?"
  → Stub AS announcing a Tier-1's prefix = high-confidence hijack

RIPEstat API: https://stat.ripe.net/docs/02.api-basics
  - No auth needed for basic queries (rate: 10 req/s)
  - More data with RIPE Access Token (free)
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any, Dict, List, Optional

import httpx
from tools.tool_registry import ToolParameter, register_tool
from utils.logger import logger
from config import RIPE_DB_WHOIS_USERNAME, RIPESTAT_TOKEN

RIPESTAT_BASE = "https://rest.db.ripe.net"   # RIPE Whois DB REST API (authenticated)
RIPESTAT_API = "https://stat.ripe.net"       # RIPEstat (free, no auth)
PEERINGDB_URL = "https://www.peeringdb.com/api/jsonp/org"


def _ripe_auth_headers():
    """Headers for RIPE Whois DB REST API."""
    return {"Accept": "application/json"}


def _ripe_url(path_str):
    """
    Build RIPE Whois DB URL.

    Correct path: /ripe/aut-num/AS{asn}
    The 'My Resources' key (keyId) is for RIPE Atlas, NOT for the Whois DB REST API.
    The Whois DB REST API is publicly accessible without authentication.
    """
    return f"https://rest.db.ripe.net/ripe{path}"


async def _as_topology(tool_input, session):
    """
    Determine AS topology position and neighbor relationships.

    Required params:
        asn (str): AS number
    """
    asn = str(tool_input["asn"])
    logger.info(f"[topology] Analyzing AS{asn}")

    # Run all API calls concurrently
    results = await asyncio.gather(
        _fetch_ripe_atlas_whois(asn),
        _fetch_ripe_atlas_neighbours(asn),
        _fetch_peeringdb(asn),
        return_exceptions=True,
    )

    whois_data, neighbour_data, peeringdb_data = results
    errors = [str(r) for r in results if isinstance(r, Exception)]

    # Parse whois (handles both RIPE Whois DB flat format and RIPEstat nested format)
    as_name = whois_data.get("as_name") or whois_data.get("data", {}).get("holder", "") or ""
    as_desc = whois_data.get("description") or whois_data.get("data", {}).get("description", "") or ""
    country = whois_data.get("country") or ""
    abuse_contacts = whois_data.get("abuse_contacts") or []
    mnt_by = whois_data.get("mnt_by") or []
    orgs = whois_data.get("orgs") or []

    # Parse neighbours
    neighbour_d = neighbour_data.get("data", {}) if isinstance(neighbour_data, dict) else {}
    providers = neighbour_d.get("providers", [])
    customers = neighbour_d.get("customers", [])
    peers = neighbour_d.get("peers", [])
    announced_prefixes = neighbour_d.get("_announced_prefixes", [])

    def extract_asns(items):
        return sorted(set(str(x.get("asn", "")) for x in items if x.get("asn")))

    providers_list = extract_asns(providers)
    customers_list = extract_asns(customers)
    peers_list = extract_asns(peers)

    # Determine tier: try neighbor data first, fall back to heuristics
    peeringdb_type = (peeringdb_data.get("type") or "").lower()
    as_name_lower = as_name.lower()
    known_tier1 = {"1299", "3356", "3257", "7018", "1239", "701", "6453", "7922", "174", "6939"}

    if not providers_list and not customers_list and not peers_list:
        # No neighbor data → use heuristics
        if asn.lstrip("AS") in known_tier1 or "arelion" in as_name_lower or "telia" in as_name_lower:
            tier, tier_reason = "tier1", f"AS{asn} is a known Tier-1 carrier ('{as_name}')."
        elif any(k in as_name_lower for k in ["telecom", "isp", "carrier", "backbone", "cable", "broadband", "wireless", "cellular", "netcologne", "airnet", "syntho"]):
            tier, tier_reason = "isp/telecom", f"AS name '{as_name}' indicates ISP or telecom operations."
        elif any(k in as_name_lower for k in ["cloud", "cdn", "cache", "aws", "azure", "gcp", "fastly", "akamai", "limelight"]):
            tier, tier_reason = "cdn/cloud", f"AS name '{as_name}' indicates CDN or cloud infrastructure."
        elif peeringdb_type in ("nsp", "isp"):
            tier, tier_reason = "isp/transit", f"PeeringDB network_type='{peeringdb_type}'."
        elif peeringdb_type in ("content", "enterprise", "hosting"):
            tier, tier_reason = "hosting/enterprise", f"PeeringDB network_type='{peeringdb_type}'."
        else:
            tier, tier_reason = "unknown", (
                "No topology neighbor data available. "
                "A RIPE Atlas token would enable full AS relationship analysis."
            )
    elif not providers_list:
        tier, tier_reason = "tier1", "No upstream providers — peers at the global core."
    elif not customers_list:
        tier, tier_reason = "stub", "Has upstream providers but no downstream customers."
    else:
        tier, tier_reason = "transit", "Has both upstream providers and downstream customers."

    # Override: massive customer cone
    customer_cone_size = len(customers_list)
    if customer_cone_size > 1000:
        tier, tier_reason = "cdn/cloud", f"{customer_cone_size} direct customers — large CDN/cloud provider."

    # Build evidence summary for the report
    evidence = []
    if tier == "tier1":
        evidence.append(f"AS{asn} is classified as Tier-1 ('{as_name}'). Routing anomalies here could have global propagation impact.")
    elif tier == "stub":
        evidence.append(f"AS{asn} is a Stub AS (no downstream customers). Anomalous routing announcements warrant investigation.")
    elif tier == "cdn/cloud":
        evidence.append(f"AS{asn} is a large CDN/Cloud provider ({customer_cone_size} direct customers). Traffic anomalies may affect many downstream ASes.")
    elif tier == "isp/telecom":
        evidence.append(f"AS{asn} appears to be an ISP/telecom provider ('{as_name}'). Outages may affect subscriber traffic broadly.")
    elif tier == "hosting/enterprise":
        evidence.append(f"AS{asn} appears to be a hosting/enterprise AS ('{as_name}'). Anomalies may impact hosted services.")
    elif tier == "unknown":
        evidence.append(f"AS{asn} ('{as_name}') tier could not be automatically determined. Manual investigation recommended.")

    # Peer overlap with traffic anomaly ASes
    # (deferred: would need session context for multi-AS analysis)

    observation = (
        f"AS{asn} ('{as_name}') is classified as {tier.upper()}. "
        f"Providers: {len(providers_list)}, Customers: {len(customers_list)}, Peers: {len(peers_list)}. "
        f"{tier_reason}"
    )

    return {
        "success": True,
        "asn": asn,
        "as_name": as_name,
        "as_description": as_desc,
        "tier": tier,
        "tier_reason": tier_reason,
        "providers": providers_list[:20],
        "customers": customers_list[:20],
        "peers": peers_list[:20],
        "announced_prefixes": announced_prefixes[:20],
        "provider_count": len(providers_list),
        "customer_count": len(customers_list),
        "peer_count": len(peers_list),
        "customer_cone_size": customer_cone_size,
        "country": country,
        "abuse_contacts": abuse_contacts,
        "maintainers": mnt_by[:10],
        "orgs": orgs[:10],
        "peeringdb": peeringdb_data if isinstance(peeringdb_data, dict) else {},
        "evidence": evidence,
        "observation": observation,
    }


# ── RIPEstat API helpers ──────────────────────────────────────────────────────

async def _fetch_ripe_atlas_whois(asn_id):
    """
    Fetch AS WHOIS data from RIPE Whois Database REST API.

    Primary:   https://rest.db.ripe.net/ripe/aut-num/AS{asn}  (RIPE-region ASes)
    Fallbacks: APNIC Whois (apnic), RADB (radb), BGPView (free)
    """
    # Method 1: RIPE Whois DB REST API
    url = _ripe_url(f"/aut-num/AS{asn}")
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=_ripe_auth_headers())
            resp.raise_for_status()
            data = resp.json()

            attrs = (
                data.get("objects", {})
                .get("object", [{}])[0]
                .get("attributes", {})
                .get("attribute", [])
            )
            result = {}
            for a in attrs:
                name = a.get("name", "")
                value = a.get("value", "")
                if name == "aut-num":
                    result["asn"] = value
                elif name == "as-name":
                    result["as_name"] = value
                elif name == "descr":
                    result.setdefault("descriptions", []).append(value)
                elif name == "country":
                    result["country"] = value
                elif name == "org":
                    result.setdefault("orgs", []).append(value)
                elif name == "mnt-by":
                    result.setdefault("mnt_by", []).append(value)
                elif name == "abuse-c":
                    result.setdefault("abuse_contacts", []).append(value)

            result["description"] = "; ".join(result.get("descriptions", []))
            logger.info(f"[topology] RIPE Whois DB fetched AS{asn}: name={result.get('as_name', 'N/A')}")
            return result

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.info(f"[topology] AS{asn} not in RIPE DB — trying APNIC/RADB/BGPView")
        else:
            logger.warning(f"[topology] RIPE Whois DB HTTP error: {e}")
    except Exception as e:
        logger.warning(f"[topology] RIPE Whois DB failed: {e}")

    # Method 2: APNIC Whois via RDAP (for APNIC-region ASes like AS135826)
    # Correct URL: /autnum/{asn}  (no "AS" prefix)
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(
                f"https://rdap.apnic.net/autnum/{asn.lstrip('AS')}",
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                d = resp.json()
                result = {
                    "as_name": d.get("name", ""),
                    "description": d.get("handle", ""),
                    "country": d.get("country", ""),
                }
                logger.info(f"[topology] APNIC fetched AS{asn}: name={result['as_name']}")
                return result
    except Exception as e:
        logger.warning(f"[topology] APNIC RDAP failed for AS{asn}: {e}")

    # Method 3: BGPView (last resort)
    return await _fetch_bgpview_whois(asn)


async def _fetch_bgpview_whois(asn_id):
    """Fallback: BGPView WHOIS lookup."""
    url = f"https://api.bgpview.io/asn/{asn}/info"
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "ok":
                info = data.get("data", {})
                return {
                    "data": {
                        "holder": info.get("name") or info.get("owner", {}).get("name", ""),
                        "description": info.get("description") or info.get("owner", {}).get("description", ""),
                    }
                }
    except Exception:
        pass
    return {}


async def _fetch_ripe_atlas_neighbours(asn_id):
    """
    Fetch AS neighbours (providers/customers/peers) and announced prefixes.

    Primary:   RIPEstat /ris/paths  (if RIPESTAT_TOKEN set)
    Fallback:  BGPView prefix lookup + asns.live relationship data
    """
    # Method 1: RIPEstat /ris/paths (needs RIPESTAT_TOKEN for full data)
    if RIPESTAT_TOKEN:
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                resp = await client.get(
                    "https://stat.ripe.net/ris/paths",
                    params={"resource": f"AS{asn}"},
                    headers={"Authorization": f"Bearer {RIPESTAT_TOKEN}"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    paths = data.get("data", {}).get("paths", [])
                    return _infer_relationships(asn, paths)
        except Exception as e:
            logger.warning(f"[topology] RIPEstat paths failed: {e}")

    # Method 2: BGPView prefix lookup + asns.live
    neighbours = await _fetch_bgpview_neighbours(asn)
    if neighbours.get("data"):
        return neighbours

    return {"data": {"providers": [], "customers": [], "peers": [], "_announced_prefixes": []}}


async def _fetch_bgpview_neighbours(asn_id):
    """Fallback: BGPView neighbour lookup."""
    url = f"https://api.bgpview.io/asn/{asn}/contacts"
    neighbours = {"providers": [], "customers": [], "peers": []}
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
    except Exception:
        pass

    # BGPView doesn't directly expose relationships, use as-rel.io as alternative
    try:
        url2 = f"https://asns.live/rs/asn_{asn}.json"
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(url2)
            resp.raise_for_status()
            data = resp.json()
            neighbours = data.get("neighbours", {})
    except Exception:
        pass

    return {"data": neighbours}


def _infer_relationships(asn, paths: List[list]):
    """
    Infer AS relationships from collected BGP paths.
    Simple heuristic (Valley-Free principle):
      - In a path A-B-C: B is a provider of A, C is a customer of B
      - In a path A-B: if B is larger AS, A is likely customer
    """
    providers = set()
    customers = set()
    peers = set()

    for path in paths:
        if not isinstance(path, list):
            continue
        # path is a list of AS numbers from origin outward
        path_strs = [str(x) for x in path]
        if str(asn) not in path_strs:
            continue
        idx = path_strs.index(str(asn))
        # ASes before this AS in the path are upstream (providers or peers)
        for upstream in path_strs[:idx]:
            # If upstream has the current AS as provider in other paths, it's a peer
            # Simple heuristic: ASes at same level are peers
            if upstream not in (str(asn),):
                providers.add(upstream)
        # ASes after this AS are downstream (customers)
        for downstream in path_strs[idx + 1:]:
            if downstream not in (str(asn),):
                customers.add(downstream)

    return {
        "data": {
            "providers": [{"asn": a} for a in sorted(providers)],
            "customers": [{"asn": a} for a in sorted(customers)],
            "peers": [{"asn": a} for a in sorted(peers)],
        }
    }


async def _fetch_peeringdb(asn_id):
    """Fetch PeeringDB info for an ASN (no auth needed)."""
    # PeeringDB has a free JSON API
    url = f"https://www.peeringdb.com/api/net?asn={asn}"
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            results = data.get("data", [])
            if results:
                r = results[0]
                return {
                    "name": r.get("name"),
                    "aka": r.get("aka"),
                    "website": r.get("website"),
                    "looking_glass": r.get("looking_glass"),
                    "type": r.get("network_type"),
                    "irr_as_set": r.get("irr_as_set"),
                }
    except Exception as e:
        logger.warning(f"[topology] PeeringDB failed for AS{asn}: {e}")
    return {}


def _get_nested(d, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d if d is not None else default


# ── Tool registration ────────────────────────────────────────────────────────

register_tool(
    name="as_topology_position",
    description=(
        "Determine an AS's position in the Internet topology (Tier-1 / Transit / Stub / CDN). "
        "Fetch direct neighbours (providers, customers, peers) and PeeringDB info. "
        "Uses free APIs: RIPEstat + BGPView + PeeringDB."
    ),
    parameters=[
        ToolParameter("asn", "AS number", "string"),
    ],
    handler=_as_topology,
)

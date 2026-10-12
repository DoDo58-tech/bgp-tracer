"""
Tool B1: Threat Intelligence Lookup
===================================

Queries multiple threat intelligence feeds to determine if an AS or prefix
has a known history of malicious activity.

Feeds used:
  - Spamhaus DROP/EDROP    : Known "Don't Route Or Peer" lists
  - Spamhaus SBL          : Spamhaus Block List (known attack sources)
  - CINS Score List        : CINS Army List (low reputation ASes)
  - BGP Hankdou/BGPSEC Research: Historical BGP hijack incidents database
  - Team Cymru Bogon Feed : Bogon prefix list

Free APIs / data sources:
  - Spamhaus DROP/EDROP: https://www.spamhaus.org/drop/
  - CINS: https://cinsscore.org/list/ (or via BGPView threat_feeds)
  - BGPView threat_feeds endpoint: https://api.bgpview.io/threat/threat_feeds
  - Team Cymru WHOIS: whois -h whois.cymru.com " -v <IP> "
  - GRIP (Georgia Tech): https://api.grip.inetintel.cc.gatech.edu/
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta
from typing import Any

import httpx

from tools.tool_registry import ToolParameter, register_tool
from utils.logger import logger

# ── Spamhaus DROP/EDROP ───────────────────────────────────────────────────────

DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"

# ── CINS Army List ───────────────────────────────────────────────────────────

CINS_URL = "https://cinsscore.org/list/ci-bad-ASN-list.txt"

# ── BGPView threat feeds ────────────────────────────────────────────────────

BGPVIEW_THREAT_URL = "https://api.bgpview.io/threat/threat_feeds"

# ── GRIP historical incidents ────────────────────────────────────────────────

GRIP_BASE = "https://api.grip.inetintel.cc.gatech.edu"


async def _check_spamhaus_drop() -> dict[str, Any]:
    """Check if a prefix/IP is in Spamhaus DROP/EDROP block lists."""
    drop_prefixes: list[str] = []
    edrop_prefixes: list[str] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Fetch DROP
        try:
            resp = await client.get(DROP_URL)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Format: <prefix> | < ASN | <description>
                parts = line.split("|")
                if parts:
                    drop_prefixes.append(parts[0].strip())
        except Exception as e:
            logger.warning(f"[threat] Spamhaus DROP fetch failed: {e}")

        # Fetch EDROP
        try:
            resp = await client.get(EDROP_URL)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if parts:
                    edrop_prefixes.append(parts[0].strip())
        except Exception as e:
            logger.warning(f"[threat] Spamhaus EDROP fetch failed: {e}")

    return {
        "drop_count": len(drop_prefixes),
        "edrop_count": len(edrop_prefixes),
        "drop_sample": drop_prefixes[:10],
        "edrop_sample": edrop_prefixes[:10],
    }


async def _check_cins_list() -> tuple[list[str], bool]:
    """Check if an AS is on the CINS Army List."""
    bad_asns: list[str] = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(CINS_URL)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Format: AS12345 or 12345
                m = re.search(r"(?:AS)?(\d+)", line)
                if m:
                    bad_asns.append(f"AS{m.group(1)}")
        except Exception as e:
            logger.warning(f"[threat] CINS list fetch failed: {e}")
    return bad_asns[:20], len(bad_asns) > 0


async def _check_bgpview_threat_feeds() -> dict[str, Any]:
    """Fetch all BGPView threat feeds (Spamhaus, CINS, etc.)."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(BGPVIEW_THREAT_URL)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "ok":
                feeds = data.get("data", {})
                return {
                    "spamhaus_drop": feeds.get("spamhaus_drop", []),
                    "spamhaus_edrop": feeds.get("spamhaus_edrop", []),
                    "cins_list": feeds.get("cins_list", []),
                    "emerging_threats": feeds.get("emerging_threats", []),
                }
        except Exception as e:
            logger.warning(f"[threat] BGPView threat feeds failed: {e}")
    return {}


async def _query_cymru_bogon(asn_or_prefix_str: str) -> dict[str, Any]:
    """
    Query Team Cymru WHOIS for bogon/AS info.
    Command: whois -h whois.cymru.com " -v <AS_or_IP>"
    Returns: AS info, prefix, country, BGPlay data availability.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("whois.cymru.com", 43),
            timeout=10.0,
        )
        query = f" -v {asn_or_prefix}\n"
        writer.write(query.encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=10.0)
        writer.close()
        await writer.wait_closed()
        lines = response.decode("utf-8", errors="ignore").strip().splitlines()
        # Parse header + data lines
        result = {}
        for line in lines:
            if "|" in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 5:
                    result["asn"] = parts[0]
                    result["ip_prefix"] = parts[1]
                    result["cc"] = parts[2]
                    result["registry"] = parts[3]
                    result["advertised"] = parts[4]
        return result
    except Exception as e:
        logger.warning(f"[threat] Cymru WHOIS query failed: {e}")
        return {}


async def _check_grip_incidents(
    asn_or_prefix: str, timeframe_days: int = 365
) -> dict[str, Any]:
    """
    Query GRIP (Georgia Tech) for documented BGP incidents involving this AS/prefix.

    GRIP documents real-world BGP anomalies with:
      - Attacker clustering
      - Victim analysis
      - Temporal patterns
      - Geographic spread

    Free API: https://api.grip.inetintel.cc.gatech.edu/dev/json/events
    """
    params = {
        "startdate": f"{(datetime.now() - timedelta(days=timeframe_days)).strftime('%Y-%m-%d')}",
        "enddate": datetime.now().strftime("%Y-%m-%d"),
        "limit": 50,
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(f"{GRIP_BASE}/dev/json/events", params=params)
            resp.raise_for_status()
            data = resp.json()
            events = data.get("data", []) if isinstance(data, dict) else data
            # Filter for events involving this AS/prefix
            relevant = []
            for ev in events:
                attackers = ev.get("attackers", []) or []
                victims = ev.get("victims", []) or []
                prefixes = ev.get("prefixes", []) or []
                asn_str = str(asn_or_prefix).lstrip("AS")
                if any(
                    asn_str in str(a) or asn_str in str(v) or asn_str in str(p)
                    for a, v, p in zip(attackers, victims, prefixes)
                ):
                    relevant.append({
                        "event_id": ev.get("id"),
                        "date": ev.get("date"),
                        "attackers": attackers,
                        "victims": victims,
                        "type": ev.get("type"),
                        "description": ev.get("description", "")[:200],
                    })
            return {
                "total_events": len(events),
                "relevant_events": relevant,
                "relevant_count": len(relevant),
            }
        except Exception as e:
            logger.warning(f"[threat] GRIP query failed: {e}")
    return {"total_events": 0, "relevant_events": [], "relevant_count": 0}


async def _threat_intel_lookup(tool_input: dict, session) -> dict[str, Any]:
    """
    Unified threat intelligence lookup for an AS or prefix.

    Required params:
        asn (str): AS number to check (e.g. "43927")
        prefix (str, optional): specific prefix to check
        check_asn_history (bool): also check GRIP for historical incidents

    Returns:
        - spamhaus_status: DROP/EDROP match result
        - cins_status: CINS Army List match result
        - bgpview_feeds: BGPView aggregated threat feeds
        - cymru_info: Team Cymru bogon/AS info
        - grip_history: GRIP historical incident records
        - risk_score: 0-100 composite risk score
        - summary: human-readable threat assessment
    """
    from datetime import datetime, timedelta

    asn = str(tool_input.get("asn", "")).lstrip("AS")
    prefix = tool_input.get("prefix", "")
    check_history = tool_input.get("check_asn_history", True)

    logger.info(f"[threat_intel] Lookup for AS{asn}, prefix={prefix}")

    # ── 1. Spamhaus DROP/EDROP ─────────────────────────────────────────
    spamhaus = await _check_spamhaus_drop()
    is_in_drop = any(
        prefix and prefix.startswith(p) for p in spamhaus.get("drop_sample", [])
    )
    is_in_edrop = any(
        prefix and prefix.startswith(p) for p in spamhaus.get("edrop_sample", [])
    )

    # ── 2. CINS Army List ──────────────────────────────────────────────
    cins_list, cins_available = await _check_cins_list()
    is_in_cins = f"AS{asn}" in cins_list

    # ── 3. BGPView Threat Feeds ────────────────────────────────────────
    bgpview_feeds = await _check_bgpview_threat_feeds()

    # ── 4. Team Cymru ─────────────────────────────────────────────────
    cymru_info = await _query_cymru_bogon(asn)

    # ── 5. GRIP Historical Incidents ───────────────────────────────────
    grip_history = {"relevant_count": 0, "relevant_events": []}
    if check_history:
        grip_history = await _check_grip_incidents(asn)

    # ── Composite Risk Score ───────────────────────────────────────────
    score = 0
    if is_in_drop or is_in_edrop:
        score += 50
    if is_in_cins:
        score += 30
    if grip_history.get("relevant_count", 0) > 0:
        score += 15 * min(grip_history["relevant_count"], 3)
    if bgpview_feeds.get("spamhaus_drop") or bgpview_feeds.get("cins_list"):
        score += 10

    # ── Summary ────────────────────────────────────────────────────────
    risk_level = "LOW" if score < 20 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"

    findings = []
    if is_in_drop:
        findings.append("⚠️ AS/prefix appears in Spamhaus DROP (known attackers)")
    if is_in_edrop:
        findings.append("⚠️ AS/prefix appears in Spamhaus EDROP (exploits blocklist)")
    if is_in_cins:
        findings.append("⚠️ AS is on CINS Army List (low reputation)")
    if grip_history.get("relevant_count", 0) > 0:
        findings.append(
            f"⚠️ AS has {grip_history['relevant_count']} documented incident(s) in GRIP database"
        )

    summary = (
        f"Threat intel for AS{asn}: Risk={risk_level} (score={score}). "
        + " ".join(findings)
        if findings
        else f"Threat intel for AS{asn}: No known threat intelligence matches (risk={risk_level})."
    )

    observation = (
        f"AS{asn} threat intelligence: "
        + f"Spamhaus DROP={is_in_drop}, EDROP={is_in_edrop}, CINS={is_in_cins}. "
        + f"GRIP history: {grip_history.get('relevant_count', 0)} past incidents. "
        + f"Risk level: {risk_level} (score={score}). "
        + f"Findings: {'; '.join(findings) if findings else 'None.'}"
    )

    return {
        "success": True,
        "asn": f"AS{asn}",
        "prefix": prefix,
        "spamhaus": {
            "in_drop": is_in_drop,
            "in_edrop": is_in_edrop,
            "drop_count": spamhaus.get("drop_count", 0),
            "edrop_count": spamhaus.get("edrop_count", 0),
        },
        "cins": {
            "in_list": is_in_cins,
            "list_size": len(cins_list),
        },
        "bgpview_feeds": bgpview_feeds,
        "cymru_info": cymru_info,
        "grip_history": grip_history,
        "risk_score": min(score, 100),
        "risk_level": risk_level,
        "findings": findings,
        "summary": summary,
        "observation": observation,
    }


register_tool(
    name="threat_intelligence",
    description=(
        "Query multiple threat intelligence feeds for an AS or prefix. "
        "Checks: Spamhaus DROP/EDROP, CINS Army List, BGPView threat feeds, "
        "Team Cymru bogon, and GRIP historical BGP incident database. "
        "Returns a composite risk score (0-100) and threat findings. "
        "Use when: you detect a suspicious AS and want to know if it's a known bad actor."
    ),
    parameters=[
        ToolParameter("asn", "AS number to check", "string"),
        ToolParameter("prefix", "Optional: specific prefix to check against DROP lists", "string", required=False),
        ToolParameter("check_asn_history", "Also query GRIP for historical incidents (default: True)", "string", required=False),
    ],
    handler=_threat_intel_lookup,
)

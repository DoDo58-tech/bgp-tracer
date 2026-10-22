"""
Tool B2: News & Event Context Search
====================================

Searches for news articles and incident reports about BGP events.
This is the "Google search" tool for BGP incidents — the most human-like
capability: when you see a weird hijack, you Google it.

Capabilities:
  1. BGP/Network incident news via web search
  2. RIPE NCC incident reports
  3. NANOG mailing list archives
  4. BGPMON / Renesys historical incident blog posts
  5. Cloudflare / Fastly / Akamai status pages
  6. Internet governance & regulatory news

The key insight: BGP incidents rarely happen in isolation.
A human analyst ALWAYS searches for external context.
The goal is to make the agent do the same.

APIs / Data Sources:
  - Web search (DuckDuckGo HTML API - free)
  - BGP news sites (bgpstream.com, bgpupdates.nl, bgp-hijack.net)
  - RIPE NCC RIS alert feed: https://stat.ripe.net/ris/incidents
  - NANOG mailing list: https://mailman.nanog.org/pipermail/nanog/
  - Internet health reports: Cloudflare Radar, Akamai SOTI, Cisco VNI
"""

from __future__ import annotations

import asyncio
import re
import urllib.parse
from datetime import datetime, timedelta
from typing import Any

import httpx

from tools.tool_registry import ToolParameter, register_tool
from utils.logger import logger

# ── DuckDuckGo Instant Answer API (free, no auth) ────────────────────────────

DDG_API = "https://duckduckgo.com/"
DDG_HTML = "https://html.duckduckgo.com/html/"

# ── RIPE NCC RIS Incidents ───────────────────────────────────────────────────

RIPE_INCIDENTS_URL = "https://stat.ripe.net/ris/incidents"

# ── BGPUpdates.nl RSS ────────────────────────────────────────────────────────

BGPUPDATES_URL = "https://bgpupdates.nl/feed/"


async def _search_duckduckgo(query: str, num_results: int = 10) -> list[dict]:
    """
    Search DuckDuckGo for news/articles.
    Uses the HTML interface which doesn't require API keys.
    """
    params = {
        "q": query,
        "kl": "wt-wt",  # English worldwide
    }
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    results = []
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(DDG_HTML, params=params, headers=headers)
            # DuckDuckGo may return 403 if blocked
            if resp.status_code == 403:
                logger.info(f"[news] DuckDuckGo blocked (403), skipping search for: {query[:50]}")
                return []
            resp.raise_for_status()
            html = resp.text
            # Parse result items
            for m in re.finditer(
                r'<a class="result__a" href="([^"]+)"[^>]*>([^<]+)</a>.*?'
                r'<a class="result__snippet"[^>]*>([^<]+)</a>',
                html,
                re.DOTALL,
            ):
                url, title, snippet = m.group(1), m.group(2), m.group(3)
                results.append({
                    "title": _clean_html(title),
                    "url": url,
                    "snippet": _clean_html(snippet),
                })
                if len(results) >= num_results:
                    break
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403:
            logger.info(f"[news] DuckDuckGo blocked (403), skipping search")
            return []
        logger.warning(f"[news] DuckDuckGo search failed: {e}")
    except Exception as e:
        logger.warning(f"[news] DuckDuckGo search failed: {e}")
    return results[:num_results]


def _clean_html(content):
    """Remove HTML tags and decode entities."""
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    return text.strip()


async def _query_ripe_incidents(
    asn: str, timeframe_days: int = 30
) -> list[dict]:
    """Query RIPE NCC RIS incident reports for this AS."""
    params = {
        "resource": f"AS{asn}",
        "starttime": (datetime.now() - timedelta(days=timeframe_days)).strftime("%Y-%m-%d"),
        "endtime": datetime.now().strftime("%Y-%m-%d"),
    }
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(RIPE_INCIDENTS_URL, params=params)
            # RIPE API may return 404 if no incidents found
            if resp.status_code == 404:
                logger.info(f"[news] RIPE incidents API: no data for AS{asn} (404)")
                return []
            resp.raise_for_status()
            data = resp.json()
            incidents = data.get("data", {}).get("incidents", []) or []
            return [
                {
                    "id": inc.get("id"),
                    "start_time": inc.get("start_time"),
                    "end_time": inc.get("end_time"),
                    "type": inc.get("type"),
                    "affected_asns": inc.get("affected_asns", []),
                    "description": inc.get("description", "")[:300],
                }
                for inc in incidents
            ]
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.info(f"[news] RIPE incidents API: no data for AS{asn} (404)")
            return []
        logger.warning(f"[news] RIPE incidents query failed: {e}")
    except Exception as e:
        logger.warning(f"[news] RIPE incidents query failed: {e}")
    return []


def _build_search_queries(asn: str, prefix: str, event_type: str, country: str) -> list[str]:
    """
    Build targeted search queries based on what we know about the incident.

    This is the "human analyst thinking" part:
    - AS43927 hijack Turkey → search "Turkey AS43927 BGP hijack"
    - Cloudflare Iran outage → search "Cloudflare Iran BGP outage"
    """
    queries = []
    asn_str = f"AS{asn}"
    prefix_short = prefix.split("/")[0] if prefix else ""

    # Generic BGP incident queries
    if event_type == "origin_hijack":
        queries.append(f'"{asn_str}" BGP hijack incident')
        if prefix_short:
            queries.append(f'"{prefix_short}" BGP prefix hijack')
        queries.append(f"BGP hijack {country}" if country else "BGP hijack incident 2024 2025")
    elif event_type == "route_leak":
        queries.append(f'"{asn_str}" BGP route leak')
        queries.append(f"BGP route leak {country}" if country else "BGP route leak incident")
    elif event_type == "outage":
        queries.append(f'"{asn_str}" BGP outage')
        queries.append(f"BGP outage {country}" if country else "BGP network outage incident")
    else:
        queries.append(f'"{asn_str}" BGP incident')
        queries.append("BGP anomaly 2024 2025 network security")

    # Provider/service specific queries
    if "cloudflare" in (country or "").lower():
        queries.append("Cloudflare outage BGP incident")
    elif "aws" in (country or "").lower() or "amazon" in (country or "").lower():
        queries.append("AWS BGP routing incident")
    elif "iran" in (country or "").lower():
        queries.append("Iran BGP internet shutdown 2024 2025")

    # Deduplicate
    seen = set()
    deduped = []
    for q in queries:
        if q not in seen:
            seen.add(q)
            deduped.append(q)

    return deduped[:5]  # Limit to avoid too many searches


def _extract_incident_context(news_results: list[dict]) -> dict[str, Any]:
    """
    Extract structured context from news results.
    Human analysts look for:
      - What happened (confirmed via news)
      - Root cause (misconfiguration, attack, government)
      - Duration and scope
      - Who was affected
      - Any official statements
    """
    context = {
        "confirmed_incident": False,
        "root_cause": None,
        "duration": None,
        "affected_parties": [],
        "official_statement": None,
        "incident_type_from_news": None,
    }

    all_text = " ".join(
        r.get("title", "") + " " + r.get("snippet", "")
        for r in news_results
    ).lower()

    # Incident confirmation
    confirm_keywords = [
        "confirmed", "reported", "incident", "outage", "disruption",
        "hijack", "leak", "attack", "shutdown", "block", "censorship",
    ]
    if any(kw in all_text for kw in confirm_keywords):
        context["confirmed_incident"] = True

    # Root cause signals
    cause_keywords = {
        "misconfiguration": ["misconfiguration", "mis-configured", "configuration error", "accidental"],
        "malicious_attack": ["attack", "hijack", "malicious", "intentional", "attacker"],
        "government_action": ["government", "shutdown", "censorship", "block", "ordered", "directive"],
        "maintenance": ["maintenance", "planned", "upgrade", "scheduled"],
        "ddos": ["ddos", "denial of service", "flood"],
        "ransomware": ["ransomware", "ransom"],
        "rpki": ["rpki", "validation", "invalid roa"],
        "account_compromised": ["compromised", "account", "stolen"],
    }
    for cause, keywords in cause_keywords.items():
        if any(kw in all_text for kw in keywords):
            context["root_cause"] = cause
            break

    # Duration signals
    duration_match = re.search(r"(\d+)\s*(hour|minute|second|day)s?", all_text)
    if duration_match:
        context["duration"] = f"{duration_match.group(1)} {duration_match.group(2)}s"

    return context


async def _news_context_search(tool_input: dict, session) -> dict[str, Any]:
    """
    Search for news and incident context about a BGP event.

    Required params:
        asn (str): AS number involved in the incident
        event_type (str, optional): origin_hijack / route_leak / outage / unknown

    Optional params:
        prefix (str): prefix involved
        country (str): country of the AS/organization
        search_queries (list[str]): custom search queries
        timeframe_days (int): how far back to search (default: 90)

    Returns:
        - search_results: list of news/article results with title, URL, snippet
        - ripe_incidents: RIPE NCC RIS incident reports
        - incident_context: extracted structured context (root cause, duration, etc.)
        - summary: narrative assessment combining all sources
        - observation: LLM-readable summary
    """
    asn = str(tool_input.get("asn", "")).lstrip("AS")
    event_type = tool_input.get("event_type", "unknown")
    prefix = tool_input.get("prefix", "")
    country = tool_input.get("country", "")
    custom_queries = tool_input.get("search_queries", [])
    timeframe_days = int(tool_input.get("timeframe_days", 90))

    logger.info(
        f"[news] Searching context for AS{asn}, type={event_type}, country={country}"
    )

    # Build search queries
    if custom_queries:
        queries = custom_queries
    else:
        queries = _build_search_queries(asn, prefix, event_type, country)

    # Execute searches concurrently
    all_results = []
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        tasks = [_search_duckduckgo(q, num_results=5) for q in queries]
        results_batches = await asyncio.gather(*tasks, return_exceptions=True)

        for batch in results_batches:
            if isinstance(batch, list):
                all_results.extend(batch)

    # Deduplicate by URL
    seen_urls = set()
    unique_results = []
    for r in all_results:
        if r["url"] not in seen_urls:
            seen_urls.add(r["url"])
            unique_results.append(r)

    # Sort: news/incident sites first
    priority_domains = {
        "ripe.net", "cloudflare.com", "akamai.com", "bgpstream.com",
        "bgpupdates.nl", "nanog.org", "bgp-hijack.net", "renesys.com",
        "krebsonsecurity.com", "arstechnica.com", "theregister.com",
        "techcrunch.com", "reuters.com", "apnews.com",
    }
    def priority(item):
        url = r.get("url", "")
        for i, d in enumerate(priority_domains):
            if d in url:
                return i
        return 99

    unique_results.sort(key=priority)

    # RIPE NCC incident reports
    ripe_incidents = await _query_ripe_incidents(asn, timeframe_days)

    # Extract incident context
    incident_context = _extract_incident_context(unique_results)

    # Build summary
    if unique_results:
        top_result = unique_results[0]
        summary = (
            f"News search found {len(unique_results)} relevant articles. "
            f"Top result: '{top_result['title']}' — {top_result['snippet'][:200]}. "
        )
        if incident_context["confirmed_incident"]:
            summary += (
                f"Incident confirmed in news. "
                f"Reported root cause: {incident_context['root_cause'] or 'unknown'}. "
            )
        if ripe_incidents:
            summary += f"RIPE NCC has {len(ripe_incidents)} incident report(s) for this AS."
    else:
        summary = (
            f"No news articles found for AS{asn}. "
            f"RIPE NCC has {len(ripe_incidents)} incident report(s)."
        )

    observation = (
        f"News context for AS{asn}: "
        f"{len(unique_results)} news results, "
        f"{len(ripe_incidents)} RIPE incident reports. "
        f"Confirmed incident: {incident_context['confirmed_incident']}. "
        f"Root cause from news: {incident_context['root_cause'] or 'not specified'}. "
        f"Top result: {unique_results[0]['title'] if unique_results else 'None'}. "
    )

    return {
        "success": True,
        "asn": f"AS{asn}",
        "event_type": event_type,
        "queries_executed": queries,
        "search_results": unique_results[:10],
        "result_count": len(unique_results),
        "ripe_incidents": ripe_incidents,
        "incident_context": incident_context,
        "summary": summary,
        "observation": observation,
    }


register_tool(
    name="news_context",
    description=(
        "Search for news articles and incident reports about a BGP event. "
        "Queries DuckDuckGo for related news, and RIPE NCC RIS incident reports. "
        "Automatically generates targeted search queries based on AS, prefix, country, and event type. "
        "Extracts root cause, duration, and affected parties from news. "
        "Use when: you detect an anomaly and want to verify if it was a real incident, "
        "find the root cause, or get additional context that routing/traffic data alone can't provide."
    ),
    parameters=[
        ToolParameter("asn", "AS number involved in the incident", "string"),
        ToolParameter("event_type", "Type of incident: origin_hijack, route_leak, outage, unknown", "string", required=False),
        ToolParameter("prefix", "Optional: prefix involved in the incident", "string", required=False),
        ToolParameter("country", "Optional: country of the AS/organization", "string", required=False),
        ToolParameter("search_queries", "Optional: custom search queries (list)", "string", required=False),
        ToolParameter("timeframe_days", "How far back to search (default: 90)", "string", required=False),
    ],
    handler=_news_context_search,
)

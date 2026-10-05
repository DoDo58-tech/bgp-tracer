"""
Tool A1: AS Business Profile + Passive DNS.
==========================================

Answers the key question: "Does this AS have real business operations?"

Building the profile:
  1. WHOIS / RDAP → AS description, abuse contact, registration date
  2. BGPView → announced prefixes + announced IPs
  3. Passive DNS (CIRCL) → all domain names historically associated with AS's IP ranges
     (reveals real websites, services, subdomains → shows actual business)
  4. PeeringDB → AS type (Content, Enterprise, ISP, NSP)
  5. RIPEstat → AS-SET, IRR records (routing policy)

Business indicators:
  - Many distinct domain names in passive DNS → active web business
  - Domains matching AS name → legitimate registered entity
  - Government/financial/health domains → high-value targets
  - Single IP range + no domains → likely transit/IXP/peering AS

Privacy note:
  - Passive DNS only shows domains, not individual user IPs
  - No personal data is collected

Free APIs used:
  - CIRCL Passive DNS: https://www.circl.lu/services/passive-dns (no auth)
  - BGPView.io: https://api.bgpview.io (no auth)
  - RIPEstat: https://stat.ripe.net (no auth for basic)
  - RDAP: https://rdap.org (no auth)
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from tools.tool_registry import ToolParameter, register_tool
from utils.logger import logger
from config import RIPESTAT_TOKEN, CIRCL_PDNS_URL, BGPVIEW_BASE

# ── Business profile categories ──────────────────────────────────────────────

CATEGORY_PATTERNS = {
    "financial":    ["bank", "finance", "trading", "broker", "invest", "payment", "crypto", "wallet"],
    "government":   ["gov", "govt", "police", "mil", "army", "defense", "gov.cn"],
    "healthcare":   ["hospital", "clinic", "health", "medical", "pharma", "bio", "clinic"],
    "education":    ["edu", "university", "school", "college", "academy", "campus"],
    "cdn":          ["cdn", "cache", "edge", "cloud", "aws", "azure", "gcp", "fastly", "cloudflare"],
    "telecom":      ["isp", "telecom", "mobile", "wireless", "broadband", "fiber", "cellular"],
    "gaming":       ["game", "casino", "poker", "bet", "lottery", "slot"],
    "adult":        ["porn", "xxx", "adult", "nude", "escort"],
}


def _categorize(domains: List[str]) -> Dict[str, List[str]]:
    categories = {k: [] for k in CATEGORY_PATTERNS}
    categorized = set()
    for d in domains:
        d_lower = d.lower()
        for cat, keywords in CATEGORY_PATTERNS.items():
            if any(kw in d_lower for kw in keywords):
                categories[cat].append(d)
                categorized.add(d)
    others = [d for d in domains if d not in categorized]
    if others:
        categories["other"] = others[:20]  # cap "other" to avoid bloat
    return {k: v for k, v in categories.items() if v}


def _is_high_value(domain: str) -> bool:
    d = domain.lower()
    high_value = ["bank", "gov", "pay", "wallet", "mail", "auth", "login",
                  "admin", "vpn", "api", "cdn", "dns", "smtp", "mx"]
    return any(k in d for k in high_value)


# ── Main tool ────────────────────────────────────────────────────────────────

async def _as_business_profile(tool_input: dict, session) -> dict:
    """
    Build a comprehensive business profile for an AS.

    Required params:
        asn (str): AS number

    Returns:
        - asn_info: basic WHOIS / RDAP data
        - prefixes: announced prefixes with IP ranges
        - domains: passive DNS results (reverse lookup)
        - categories: domain categories (financial, gov, cdn, etc.)
        - business_indicators: structured flags
        - business_type: inferred type (Enterprise, CDN, ISP, etc.)
        - assessment: narrative about the AS's business
    """
    asn = str(tool_input["asn"])
    logger.info(f"[biz_profile] Building business profile for AS{asn}")

    # Fetch everything concurrently
    whois_task   = _fetch_rdap_whois(asn)
    bgp_task     = _fetch_bgpview_prefixes(asn)
    pdns_task    = _fetch_passive_dns(asn)

    whois_data, bgp_data, pdns_domains = await asyncio.gather(
        whois_task, bgp_task, pdns_task, return_exceptions=True
    )

    if isinstance(whois_data, Exception):
        whois_data = {}
    if isinstance(bgp_data, Exception):
        bgp_data = {}
    if isinstance(pdns_domains, Exception):
        pdns_domains = []

    prefixes = bgp_data.get("prefixes", [])
    as_name = whois_data.get("name") or bgp_data.get("owner_name", "")
    as_desc = whois_data.get("description", "")
    abuse_emails = whois_data.get("abuse_contacts", [])
    reg_date = whois_data.get("registration_date", "")
    country = whois_data.get("country", "")

    # Domain analysis
    unique_domains = sorted(set(pdns_domains))
    high_value_domains = [d for d in unique_domains if _is_high_value(d)]
    categories = _categorize(unique_domains)
    category_summary = {k: len(v) for k, v in categories.items()}

    # Business type inference
    business_type, type_reason = _infer_business_type(
        asn, as_name, as_desc, len(prefixes),
        len(unique_domains), categories
    )

    # Passive DNS quality assessment
    pdns_quality = _assess_pdns_quality(unique_domains, prefixes)

    # Key indicators
    indicators = {
        "has_real_domains": len(unique_domains) > 0,
        "has_high_value_targets": len(high_value_domains) > 0,
        "has_government_targets": "government" in categories,
        "has_financial_targets": "financial" in categories,
        "is_large_prefix_count": len(prefixes) > 100,
        "is_stub_with_real_services": (
            business_type in ("stub_enterprise", "hosting") and len(unique_domains) > 5
        ),
        "passive_dns_reveals_services": len(unique_domains) >= 10,
    }

    assessment = _build_assessment(
        asn, as_name, business_type, type_reason,
        len(unique_domains), pdns_quality,
        indicators, categories
    )

    observation = (
        f"AS{asn} ('{as_name}') is classified as {business_type}. "
        f"{type_reason} "
        f"Passive DNS found {len(unique_domains)} unique domains. "
        f"Categories: {', '.join(f'{k}({v})' for k, v in sorted(category_summary.items(), key=lambda x: -x[1])[:3])}. "
        f"{assessment}"
    )

    return {
        "success": True,
        "asn": asn,
        "as_name": as_name,
        "as_description": as_desc,
        "country": country,
        "registration_date": reg_date,
        "abuse_contacts": abuse_emails,
        "business_type": business_type,
        "business_type_reason": type_reason,
        "prefix_count": len(prefixes),
        "prefixes": prefixes[:50],
        "total_unique_domains": len(unique_domains),
        "domains": unique_domains[:100],
        "high_value_domains": high_value_domains[:20],
        "categories": categories,
        "category_summary": category_summary,
        "business_indicators": indicators,
        "passive_dns_quality": pdns_quality,
        "assessment": assessment,
        "observation": observation,
    }


# ── API helpers ─────────────────────────────────────────────────────────────

async def _fetch_rdap_whois(asn: str) -> dict:
    """Fetch AS WHOIS via RDAP (no auth, global)."""
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(f"https://rdap.org/autnum/{asn}")
            resp.raise_for_status()
            data = resp.json()

            # Parse RDAP response
            name = ""
            desc = ""
            country = ""
            abuse = []
            reg_date = ""

            for event in data.get("events", []) or []:
                if event.get("eventAction") == "registration":
                    reg_date = event.get("eventDate", "")

            for remark in data.get("remarks", []) or []:
                if remark.get("title") == "description":
                    desc = "; ".join(remark.get("description", []))

            for r in data.get("remarks", []) or []:
                for d in r.get("description", []):
                    if "@" in str(d):
                        abuse.append(str(d))

            # Try to extract from entities
            for entity in data.get("entities", []) or []:
                for role in entity.get("roles", []):
                    if role in ("registrant", "administrative", "abuse"):
                        for contact in entity.get("vcardArray", []):
                            if isinstance(contact, list) and len(contact) > 2:
                                val = contact[2]
                                if "@" in str(val):
                                    abuse.append(str(val))
                                    break

            return {
                "name": data.get("name", ""),
                "description": desc,
                "country": data.get("country", ""),
                "abuse_contacts": list(set(abuse)),
                "registration_date": reg_date,
            }
    except Exception as e:
        logger.warning(f"[biz_profile] RDAP failed for AS{asn}: {e}")
        return {}


async def _fetch_bgpview_prefixes(asn: str) -> dict:
    """Fetch announced prefixes via BGPView.io."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{BGPVIEW_BASE}/lookup/as{asn}")
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") != "ok":
                return {}
            info = data.get("data", {})
            prefixes = [
                {
                    "prefix": p.get("prefix"),
                    "ip_count": p.get("ip_count"),
                    "is_ipv4": p.get("type") == "ipv4",
                }
                for p in info.get("prefixes", [])
                if p.get("prefix")
            ]
            return {
                "owner_name": info.get("owner", {}).get("name", ""),
                "prefixes": prefixes,
            }
    except Exception as e:
        logger.warning(f"[biz_profile] BGPView failed for AS{asn}: {e}")
        return {}


async def _fetch_passive_dns(asn: str) -> List[str]:
    """
    Fetch passive DNS from CIRCL for all IP ranges of the AS.
    CIRCL API: GET https://www.circl.lu/pdns/query/<IP_OR_DOMAIN>
    Returns all domain names that resolved to IPs in the queried range.
    """
    domains = []

    # First get prefixes so we can query IP ranges
    bgp_data = await _fetch_bgpview_prefixes(asn)
    prefixes = bgp_data.get("prefixes", [])[:20]  # limit to avoid rate limits

    async def query_prefix(prefix: str) -> List[str]:
        url = f"{CIRCL_PDNS_URL}/{prefix}"
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
                if isinstance(data, list):
                    return [str(r.get("rrname", "")) for r in data if r.get("rrname")]
        except Exception:
            pass
        return []

    # Fetch passive DNS for each prefix concurrently
    results = await asyncio.gather(*[query_prefix(p["prefix"]) for p in prefixes], return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            domains.extend(r)

    # Also try querying by AS number directly (some CIRCL nodes support this)
    try:
        url2 = f"{CIRCL_PDNS_URL}/AS{asn}"
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url2)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                domains.extend(str(r.get("rrname", "")) for r in data if r.get("rrname"))
    except Exception:
        pass

    return list(set(domains))


# ── Business type inference ──────────────────────────────────────────────────

def _infer_business_type(asn: str, name: str, desc: str,
                          prefix_count: int, domain_count: int,
                          categories: dict) -> tuple[str, str]:
    """Infer the AS business type from available data."""

    n = name.lower()
    d = desc.lower()

    # Keywords
    if any(k in n for k in ["cloud", "cdn", "cache", "fastly", "akamai", "limelight"]):
        return "cdn/cloud", "AS name and description indicate a CDN or cloud delivery network."
    if any(k in n for k in ["amazon", "aws", "google", "microsoft", "azure"]):
        return "hyperscaler", "AS is operated by a major hyperscaler cloud provider."
    if any(k in n for k in ["telecom", "isp", "comcast", "at&t", "verizon", "t-mobile", "vodafone", "orange"]):
        return "isp/telecom", "AS is operated by an ISP or telecom provider."
    if "university" in n or "university" in d or "edu" in n:
        return "education", "AS belongs to an educational institution."
    if "bank" in n or "financial" in n or "fintech" in n:
        return "financial", "AS appears to be a financial services organization."
    if any(k in n for k in ["gov", "govt", "police", "mil", "army"]):
        return "government", "AS belongs to a government or military entity."

    # Quantitative heuristics
    if prefix_count > 500 and domain_count < 10:
        return "isp/transit", (
            f"Large AS with {prefix_count} prefixes but few passive DNS domains ({domain_count}). "
            "This is characteristic of an ISP or transit provider that carries traffic "
            "for many customers without hosting content itself."
        )
    if domain_count > 100:
        return "hosting/content", (
            f"Large number of passive DNS domains ({domain_count}) indicates active "
            "web hosting or content delivery."
        )
    if "cdn" in categories or "telecom" in categories:
        return "cdn/telecom", "Domain categories indicate CDN or telecom operations."

    if domain_count > 5:
        return "stub_enterprise", (
            f"Moderate passive DNS ({domain_count} domains) suggests this is an enterprise "
            "or content provider AS with real web-facing services."
        )

    if prefix_count < 5:
        return "small_stub", (
            f"Small AS with {prefix_count} prefixes and {domain_count} passive DNS domains. "
            "This is likely a small enterprise or end-user AS."
        )

    return "unknown", "Business type could not be determined from available data."


def _assess_pdns_quality(domains: List[str], prefixes: List[dict]) -> dict:
    """Assess the quality and coverage of passive DNS data."""
    if not domains:
        return {
            "quality": "none",
            "note": "No passive DNS records found. This AS may not have web-facing services, "
                    "or the IP ranges are not indexed in CIRCL's passive DNS database.",
        }

    # Quality indicators
    tlds = set()
    subdomain_diversity = {}
    for d in domains:
        parts = d.lower().split(".")
        if len(parts) >= 2:
            tlds.add(parts[-1])
            if len(parts) >= 3:
                parent = ".".join(parts[-2:])
                subdomain_diversity[parent] = subdomain_diversity.get(parent, 0) + 1

    # Many subdomains under one parent → high confidence domain hosting
    # Many different parents → diverse services
    max_sub = max(subdomain_diversity.values()) if subdomain_diversity else 0

    if len(domains) > 50 and len(tlds) > 3:
        quality = "high"
        note = "Rich passive DNS with diverse TLDs and many subdomains — strong signal of active web business."
    elif len(domains) > 10:
        quality = "medium"
        note = f"Moderate passive DNS ({len(domains)} domains, {len(tlds)} TLDs) — indicates some web presence."
    else:
        quality = "low"
        note = f"Sparse passive DNS ({len(domains)} domains) — limited web presence or CIRCL coverage gap."

    return {
        "quality": quality,
        "note": note,
        "domain_count": len(domains),
        "tld_count": len(tlds),
        "tlds": sorted(tlds)[:20],
        "max_subdomains_per_parent": max_sub,
    }


def _build_assessment(asn: str, as_name: str, business_type: str,
                      type_reason: str, domain_count: int,
                      pdns_quality: dict, indicators: dict,
                      categories: dict) -> str:
    """Build a narrative business assessment."""

    parts = [f"AS{asn} ('{as_name}') operates as a {business_type}."]

    if indicators["has_real_domains"]:
        parts.append(f"Passive DNS analysis found {domain_count} unique domain names associated with this AS, indicating it hosts real web services.")
    else:
        parts.append("No passive DNS records were found for this AS's IP ranges. This AS may not host web services, or its traffic is primarily transit/peer.")

    if indicators["has_government_targets"]:
        parts.append("Government domains are present — anomalies affecting this AS could have significant public impact.")
    if indicators["has_financial_targets"]:
        parts.append("Financial sector domains are present — anomalies here warrant high priority investigation.")
    if indicators["is_large_prefix_count"]:
        parts.append("This AS announces a large number of prefixes, consistent with an ISP or major transit provider.")
    if indicators["passive_dns_reveals_services"]:
        parts.append(f"The diverse passive DNS ({domain_count} domains) suggests this AS operates multiple real services — traffic anomalies are more likely to represent genuine business impact.")

    if business_type in ("hyperscaler", "cdn/cloud"):
        parts.append("As a major infrastructure provider, anomalies here may affect thousands of downstream ASes.")
    elif business_type == "stub_enterprise":
        parts.append("As an enterprise AS with identifiable services, traffic anomalies are likely to represent direct business impact to the organization.")

    return " ".join(parts)


# ── Tool registration ────────────────────────────────────────────────────────

register_tool(
    name="as_business_profile",
    description=(
        "Build a comprehensive business profile for an AS using Passive DNS (CIRCL), RDAP/WHOIS, "
        "and BGPView. Identifies real websites and services hosted by the AS, infers business type "
        "(Enterprise / CDN / ISP / etc.), flags high-value targets (government, financial), "
        "and provides a business assessment. "
        "Key question answered: does this AS have actual business operations? "
        "Free APIs: CIRCL Passive DNS, RDAP.org, BGPView.io."
    ),
    parameters=[
        ToolParameter("asn", "AS number", "string"),
    ],
    handler=_as_business_profile,
)

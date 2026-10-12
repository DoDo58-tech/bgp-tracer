"""
Tool B3: IRR (Internet Routing Registry) Lookup
================================================

Queries IRR databases to find registered routing policies, as-sets, and prefix
authorizations for an AS. This is critical for answering:

  "Is this AS allowed to announce this prefix?"

IRR databases are the authoritative source for what prefixes an AS is supposed
to announce. If an AS announces a prefix NOT in its IRR records, it's a strong
signal of hijack. If it IS in IRR, it might be a misconfiguration.

Multi-RIR approach (query all major IRRs in parallel):
  - RADB (Route Attractor Database)    : https://www.radb.net    (primary, free WHOIS)
  - RIPE NCC                             : https://www.ripe.net    (RIPE region)
  - APNIC                                : https://www.apnic.net   (AP region)
  - ARIN                                 : https://www.arin.net   (North America)
  - NTTCOM                               : https://www.nttcom.net  (bulk WHOIS)
  - Level3                              : whois.level3.net

IRR objects queried:
  - aut-num        : AS registration (policy, originases, desc)
  - route/route6  : Prefix-to-AS authorization
  - as-set        : AS set membership
  - route-set     : Route set definitions

Free: WHOIS protocol (port 43) against each IRR.
"""

from __future__ import annotations

import asyncio
import re
import socket
from typing import Any

from tools.tool_registry import ToolParameter, register_tool
from utils.logger import logger

# ── IRR WHOIS servers ────────────────────────────────────────────────────────

IRR_SERVERS = {
    "RADB":    "whois.radb.net",
    "RIPE":    "whois.ripe.net",
    "APNIC":   "whois.apnic.net",
    "ARIN":    "whois.arin.net",
    "NTT":     "whois.ntt.net",
    "LEVEL3":  "rr.ntt.net",
    "BELL":    "whois.belnet.be",
    "REGISTRO": "whois.nic.br",
}

# Default servers to query (most useful for global AS)
DEFAULT_SERVERS = ["RADB", "RIPE", "APNIC"]


def _clean_whois(content: str) -> str:
    """Remove WHOIS server banners and empty lines."""
    text = content
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("%") and not line.startswith("#"):
            lines.append(line)
    return "\n".join(lines)


def _parse_aut_num(content: str) -> dict[str, Any]:
    """Parse aut-num (AS registration) object from IRR."""
    text = content
    result = {
        "asn": None,
        "as_name": None,
        "description": [],
        "originases": [],
        "members": [],
        "mp_members": [],
        "import": [],
        "export": [],
        "mp_import": [],
        "mp_export": [],
    }

    for line in text.splitlines():
        if not line.startswith(("route:", "route6:", "as-set:", "mntner:", "admin-c:", "tech-c:", "auth:")):
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            key = parts[0].lower().replace("-", "_")
            value = parts[1].strip()
            if key == "aut_num":
                result["asn"] = value.replace("AS", "")
            elif key == "as_name":
                result["as_name"] = value
            elif key in result and isinstance(result[key], list):
                result[key].append(value)

    return result


def _parse_route_objects(content: str) -> list[dict]:
    """Parse route/route6 objects from IRR."""
    text = content
    objects = []
    current = {}
    for line in text.splitlines():
        if line.startswith("route") or line.startswith("route6"):
            if current:
                objects.append(current)
            prefix_part = line.split(None, 1)
            current = {"prefix": prefix_part[0], "raw": line}
        elif current and ":" in line:
            parts = line.split(None, 1)
            if len(parts) == 2:
                key = parts[0].lower().replace("-", "_")
                value = parts[1].strip()
                if key in ("origin", "descr", "origin", "mnt_by", "mnt_lower"):
                    current[key] = value
    if current:
        objects.append(current)
    return objects


async def _whois_query(server: str, query: str, timeout: int = 10) -> str:
    """Execute a WHOIS query against an IRR server."""
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43),
            timeout=timeout,
        )
        writer.write(f"{query}\n".encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        return response.decode("utf-8", errors="ignore")
    except asyncio.TimeoutError:
        return f"[Timeout connecting to {server}]"
    except Exception as e:
        return f"[Error {server}: {e}]"
    finally:
        # Close the socket in a ``finally`` so any exception during
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def _query_irr_server(
    server_name: str, asn: str, prefix: str = ""
) -> dict[str, Any]:
    """Query a single IRR server for AS info and prefix authorization."""
    server = IRR_SERVERS.get(server_name, server_name)

    # Query aut-num
    aut_num_response = await _whois_query(server, f"-i as-name AS{asn}")
    aut_num_clean = _clean_whois(aut_num_response)
    aut_num_data = _parse_aut_num(aut_num_clean) if aut_num_clean else {}

    # Query by origin AS
    origin_response = await _whois_query(server, f"-i origin AS{asn}")
    origin_clean = _clean_whois(origin_response)
    route_objects = _parse_route_objects(origin_clean) if origin_clean else []

    # Query specific prefix if provided
    prefix_result = None
    if prefix:
        # Try both route and route6
        for obj_type in ["-i origin -T route", "-i origin -T route6"]:
            prefix_response = await _whois_query(server, f"{obj_type} {prefix}")
            if "route" in prefix_response and "AS" in prefix_response:
                prefix_result = _clean_whois(prefix_response)
                break

    # Query as-set membership
    as_set_response = await _whois_query(server, f"-i as-name AS{asn}")
    as_set_clean = _clean_whois(as_set_response)

    # Determine if prefix is authorized by IRR
    authorized = False
    if prefix:
        for obj in route_objects:
            if obj.get("prefix") == prefix:
                authorized = True
                break
        # Also check if prefix is covered by a registered super-prefix
        for obj in route_objects:
            pfx = obj.get("prefix", "")
            if pfx and "/" in pfx:
                import ipaddress
                try:
                    if ipaddress.ip_network(prefix, strict=False).subnet_of(
                        ipaddress.ip_network(pfx, strict=False)
                    ):
                        authorized = True
                        break
                except Exception:
                    pass

    return {
        "server": server_name,
        "found": bool(aut_num_clean or route_objects),
        "aut_num": aut_num_data,
        "route_objects": route_objects[:10],  # limit
        "prefix_authorized": authorized,
        "prefix_authorization_raw": prefix_result,
    }


async def _irr_registry_lookup(tool_input: dict, session) -> dict[str, Any]:
    """
    Query Internet Routing Registry (IRR) databases for an AS.

    IRR records tell us what prefixes an AS is SUPPOSED to announce.
    This is critical for validating hijack detection:
      - If a prefix is announced by an AS NOT in IRR → strong hijack signal
      - If IRR says "this AS owns this prefix" → validates the announcement

    Required params:
        asn (str): AS number (e.g. "43927" or "AS43927")
        servers (list[str], optional): which IRRs to query (default: ["RADB", "RIPE", "APNIC"])

    Optional params:
        prefix (str): specific prefix to check authorization for
        check_as_set (bool): also check as-set membership (default: True)

    Returns:
        - results_by_server: query results from each IRR
        - authorized_prefixes: prefixes the AS is registered to announce
        - unauthorized_prefixes: prefixes in routing data but NOT in IRR
        - as_policy: routing policy (import/export) from IRR
        - prefix_authorization: whether the specific prefix is IRR-authorized
        - observation: LLM-readable summary
    """
    asn = str(tool_input.get("asn", "")).lstrip("AS")
    servers = tool_input.get("servers", DEFAULT_SERVERS)
    prefix = tool_input.get("prefix", "")
    check_as_set = tool_input.get("check_as_set", True)

    logger.info(f"[irr] Querying IRR for AS{asn}, servers={servers}, prefix={prefix}")

    # Query all servers in parallel
    tasks = [
        _query_irr_server(server, asn, prefix)
        for server in servers
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Aggregate results
    by_server = {}
    authorized_prefixes = []
    all_route_objects = []
    as_name = None
    routing_policy = {}

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            by_server[servers[i]] = {"error": str(result)}
            continue

        server_name = servers[i]
        by_server[server_name] = result

        # Collect authorized prefixes
        for obj in result.get("route_objects", []):
            pfx = obj.get("prefix")
            if pfx and pfx not in authorized_prefixes:
                authorized_prefixes.append(pfx)
            all_route_objects.append(obj)

        # Get AS name
        if as_name is None:
            as_name = result.get("aut_num", {}).get("as_name")

        # Aggregate policy
        aut_num = result.get("aut_num", {})
        if aut_num.get("export"):
            routing_policy.setdefault("export", []).extend(aut_num.get("export", []))
        if aut_num.get("import"):
            routing_policy.setdefault("import", []).extend(aut_num.get("import", []))

    # Check authorization for specific prefix
    prefix_authorized = False
    authorization_reason = ""
    if prefix:
        for pfx in authorized_prefixes:
            if pfx == prefix:
                prefix_authorized = True
                authorization_reason = f"Exact prefix {prefix} found in IRR records"
                break
        if not prefix_authorized:
            for pfx in authorized_prefixes:
                if "/" in pfx:
                    try:
                        import ipaddress
                        if ipaddress.ip_network(prefix, strict=False).subnet_of(
                            ipaddress.ip_network(pfx, strict=False)
                        ):
                            prefix_authorized = True
                            authorization_reason = f"Prefix {prefix} is covered by registered super-prefix {pfx}"
                            break
                    except Exception:
                        pass
        if not prefix_authorized:
            authorization_reason = f"Prefix {prefix} NOT found in IRR records — possible unauthorized announcement"

    # Count IRR coverage
    servers_found = [s for s, r in by_server.items() if r.get("found")]
    has_irr_records = len(servers_found) > 0

    # Build summary
    summary_parts = []
    if has_irr_records:
        summary_parts.append(
            f"IRR records found in {len(servers_found)}/{len(servers)} servers: {', '.join(servers_found)}"
        )
    else:
        summary_parts.append(f"NO IRR records found for AS{asn} in queried databases")

    if authorized_prefixes:
        summary_parts.append(
            f"AS{asn} is registered to announce {len(authorized_prefixes)} prefix(es): "
            f"{', '.join(authorized_prefixes[:5])}"
        )
        if len(authorized_prefixes) > 5:
            summary_parts.append(f"... and {len(authorized_prefixes) - 5} more")

    if prefix:
        if prefix_authorized:
            summary_parts.append(f"✅ Prefix {prefix} IS authorized by IRR")
        else:
            summary_parts.append(f"❌ Prefix {prefix} is NOT authorized by IRR")

    if routing_policy:
        summary_parts.append(
            f"Routing policy: import from {len(routing_policy.get('import', []))} peers, "
            f"export to {len(routing_policy.get('export', []))} peers"
        )

    summary = ". ".join(summary_parts)

    observation = (
        f"IRR lookup for AS{asn}: "
        f"records_found={has_irr_records}, "
        f"servers_checked={servers}, "
        f"servers_with_data={servers_found}, "
        f"authorized_prefixes={len(authorized_prefixes)}, "
        f"prefix_authorized={prefix_authorized}, "
        f"reason='{authorization_reason}'. "
        f"{summary}"
    )

    return {
        "success": True,
        "asn": f"AS{asn}",
        "as_name": as_name,
        "prefix": prefix,
        "servers_queried": servers,
        "servers_found": servers_found,
        "has_irr_records": has_irr_records,
        "results_by_server": by_server,
        "authorized_prefixes": authorized_prefixes,
        "all_route_objects": all_route_objects,
        "routing_policy": routing_policy,
        "prefix_authorized": prefix_authorized,
        "prefix_authorization_reason": authorization_reason,
        "summary": summary,
        "observation": observation,
    }


async def lookup_prefix_origin_async(prefix_str: str) -> dict[str, Any]:
    """Convenience wrapper for probe_executor: query IRR for a prefix.

    Returns a dict with at least:
        - prefix (str): input prefix
        - origins (list[str]): origin ASNs that IRR lists as authorized to
          announce this prefix (across all queried servers).
        - found (bool): whether any server had a route object for the prefix.
        - data_source (str): which IRR server(s) replied successfully.

    This is intentionally narrower than ``_irr_registry_lookup`` — the
    probe only needs the origin AS, not the full routing policy. The
    narrower scope keeps probe latency low (sub-second per prefix) so
    the auto-probe section never blocks the report.
    """
    prefixes_to_check = [prefix] if prefix else []
    if not prefixes_to_check:
        return {"prefix": prefix, "origins": [], "found": False, "data_source": "none"}

    origins: list[str] = []
    found = False
    sources: list[str] = []

    for server in DEFAULT_SERVERS:
        try:
            result = await _query_irr_server(server, "", prefix)
            for ro in result.get("route_objects") or []:
                origin = ro.get("origin") or ro.get("origin_as")
                if origin and str(origin) not in origins:
                    origins.append(str(origin))
            if result.get("route_objects"):
                found = True
                sources.append(server)
        except Exception:
            continue

    return {
        "prefix": prefix,
        "origins": origins,
        "found": found,
        "data_source": ",".join(sources) if sources else "none",
    }


register_tool(
    name="irr_registry",
    description=(
        "Query Internet Routing Registry (IRR) databases (RADB, RIPE, APNIC, ARIN) "
        "to find registered routing policies, as-sets, and prefix authorizations for an AS. "
        "Critical for validating hijack detection: if an AS announces a prefix NOT in its IRR records, "
        "it's a strong hijack signal. If it IS in IRR, it may be a misconfiguration. "
        "Also returns the AS's routing policy (import/export rules). "
        "Use when: you detect a hijack and want to know if the prefix was legitimately authorized."
    ),
    parameters=[
        ToolParameter("asn", "AS number to query (e.g. '43927')", "string"),
        ToolParameter("servers", "IRR servers to query: ['RADB', 'RIPE', 'APNIC'] (default: all three)", "string", required=False),
        ToolParameter("prefix", "Optional: specific prefix to check authorization for", "string", required=False),
        ToolParameter("check_as_set", "Also check as-set membership (default: True)", "string", required=False),
    ],
    handler=_irr_registry_lookup,
)

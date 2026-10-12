"""

==============

, , . 

: 
- check_victim_traffic: AS
- bgp_path_analysis: RIPE RIS / RouteViewsAS_PATH
- traceroute_probing: traceroute
- collect_traffic_data: Cloudflare
- rpki_validation: RPKI
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, List

from utils.logger import logger

try:
    from tools.probing_tools import (
        TracerouteProbe, BGPLookingGlass, RIPERisAPI,
        CloudflareRealtime, ProbingOrchestrator, ProbeResult,
    )
    PROBING_TOOLS_AVAILABLE = True
    # Check if scapy-based traceroute is available (works without root)
    _PROBE_BACKEND = "scapy" if hasattr(TracerouteProbe, 'probe') else "system"
except ImportError as e:
    logger.warning(f"probing_tools ，: {e}")
    PROBING_TOOLS_AVAILABLE = False
    _PROBE_BACKEND = "none"

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


@dataclass
class AutoProbeFinding:
    """"""
    action: str                # e.g., "check_victim_traffic"
    target: str                # 
    success: bool              # 
    summary: str               # 
    data: dict = field(default_factory=dict)
    error: str = ""
    execution_time_s: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class AutoProbeExecutor:
    """
 : agent, API/. 

 : 
 executor = AutoProbeExecutor(timeout=10)
 findings = await executor.execute_probes(probing_recommendations, target_as="12479")
 """

    # Cloudflare Radar API（，token） AS 
    CF_RADAR_BASE = "https://api.cloudflare.com/client/v4/radar"

    def __init__(self, timeout: float = 10.0, enable_external: bool = True):
        """
 Args:
 timeout: ()
 enable_external: (false skipped)
 """
        self.timeout = timeout
        self.enable_external = enable_external

    async def execute_probes(
        self,
        probing_recommendations: List[dict],
        target_as: str = "",
        analysis_window: dict = None,
    ) -> List[AutoProbeFinding]:
        """
 

 Args:
 probing_recommendations: _report_agent._generate_refutable_hypotheses 
 : {"action": str, "target": str, "reason": str, "method": str}
 target_as: AS
 analysis_window: {"start": iso, "end": iso} 

 Returns:
 list[AutoProbeFinding]
 """
        if not probing_recommendations:
            return []

        if not self.enable_external:
            return [
                AutoProbeFinding(
                    action=r.get("action", "unknown"),
                    target=r.get("target", ""),
                    success=False,
                    summary="external probing disabled (enable_external=False)",
                    error="external probing disabled"
                )
                for r in probing_recommendations
            ]

        tasks = []
        for rec in probing_recommendations:
            action = (rec.get("action") or "").strip()
            target = (rec.get("target") or "").strip()

            task = asyncio.create_task(
                self._dispatch_one(action, target, target_as, analysis_window)
            )
            tasks.append(task)

        # Bug fix 2026-09-13 (BUG-R115): ``asyncio.gather(*tasks)``
        if self.timeout > 0:
            timeout_tasks = [
                asyncio.wait_for(t, timeout=self.timeout + 5.0)
                for t in tasks
            ]
            results = await asyncio.gather(*timeout_tasks, return_exceptions=True)
        else:
            results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: List[AutoProbeFinding] = []
        for rec, res in zip(probing_recommendations, results):
            action = rec.get("action", "")
            target = rec.get("target", "")
            if isinstance(res, Exception):
                findings.append(AutoProbeFinding(
                    action=action, target=target, success=False,
                    summary=f": {res}",
                    error=str(res),
                ))
            else:
                findings.append(res)
        return findings

    async def _dispatch_one(
        self,
        action: str,
        target: str,
        target_as: str,
        analysis_window: Optional[dict],
    ) -> AutoProbeFinding:
        """ action """
        started = datetime.now()
        base = AutoProbeFinding(action=action, target=target, success=False, summary="")

        try:
            if action == "check_victim_traffic":
                finding = await self._probe_victim_traffic(target, target_as)
            elif action == "bgp_path_analysis":
                finding = await self._probe_bgp_path(target)
            elif action == "traceroute_probing":
                finding = await self._probe_traceroute(target, target_as)
            elif action == "collect_traffic_data":
                finding = await self._probe_traffic_data(target, target_as, analysis_window)
            elif action == "prefix_specific_traffic":
                finding = await self._probe_prefix_specific_traffic(target, target_as)
            elif action == "rpki_validation":
                finding = await self._probe_rpki(target)
            elif action == "as_topology":
                finding = await self._probe_as_topology(target)
            elif action == "irr_registry":
                finding = await self._probe_irr_registry(target)
            elif action == "rdap_query":
                finding = await self._probe_rdap(target)
            else:
                finding = AutoProbeFinding(
                    action=action, target=target, success=False,
                    summary=f" '{action}'，",
                    error="not_implemented",
                )

            finding.execution_time_s = (datetime.now() - started).total_seconds()
            return finding
        except Exception as e:
            logger.warning(f" {action} : {e}")
            return AutoProbeFinding(
                action=action, target=target, success=False,
                summary=f": {e}",
                error=str(e),
                execution_time_s=(datetime.now() - started).total_seconds(),
            )

    # ----------  ----------
    async def _probe_victim_traffic(
        self, target: str, target_as: str
    ) -> AutoProbeFinding:
        """
 victim ASes 

 target : "victim ASes: 20119, 34927, 207564, 34854, 3257"
 """
        ases = extract_as_numbers(target)
        if not ases:
            return AutoProbeFinding(
                action="check_victim_traffic", target=target, success=False,
                summary=" target  AS ",
                error="no_as_extracted",
            )

        results = []
        for asn in ases[:5]:  # 5AS
            try:
                data = await self._query_cloudflare_radar_as(asn)
                results.append({"asn": asn, **data})
            except Exception as e:
                results.append({"asn": asn, "error": str(e)})

        success_count = sum(1 for r in results if "error" not in r)
        summary_parts = []
        for r in results:
            if "error" in r:
                summary_parts.append(f"AS{r['asn']}: ")
            else:
                top_loc = (r.get("top_location") or "unknown")
                pct = r.get("observed_traffic_percent_change")
                if pct is not None:
                    summary_parts.append(f"AS{r['asn']} {pct:+.1f}% (top: {top_loc})")
                else:
                    summary_parts.append(f"AS{r['asn']} (top: {top_loc})")

        return AutoProbeFinding(
            action="check_victim_traffic", target=target,
            success=success_count > 0,
            summary="; ".join(summary_parts) if summary_parts else "",
            data={"as_results": results},
        )

    async def _probe_bgp_path(self, target: str) -> AutoProbeFinding:
        """
 RIPE RIS / RouteViews AS_PATH

 target : "prefixes: 90.174.144.0/20, 85.54.152.0/22, ..."
 """
        prefixes = extract_prefixes(target)
        if not prefixes:
            return AutoProbeFinding(
                action="bgp_path_analysis", target=target, success=False,
                summary=" target ",
                error="no_prefix_extracted",
            )

        results = []
        for prefix in prefixes[:3]:
            try:
                origin_data = await self._query_ripe_ris_origin(prefix)
                results.append({"prefix": prefix, **origin_data})
            except Exception as e:
                results.append({"prefix": prefix, "error": str(e)})

        success_count = sum(1 for r in results if "error" not in r)
        summary_parts = []
        for r in results:
            if "error" in r:
                summary_parts.append(f"{r['prefix']}:  ({r['error'][:50]})")
            else:
                origins = r.get("origins") or []
                if origins:
                    summary_parts.append(f"{r['prefix']}AS: {','.join(origins[:3])}")
                else:
                    summary_parts.append(f"{r['prefix']}")

        return AutoProbeFinding(
            action="bgp_path_analysis", target=target,
            success=success_count > 0,
            summary="; ".join(summary_parts) if summary_parts else "",
            data={"prefix_results": results},
        )

    async def _probe_traceroute(self, target: str, target_as: str) -> AutoProbeFinding:
        """
 traceroute ( scapy, root )

 target : "target AS12479"
 """
        #  AS ， AS info  IP
        target_ip = await self._resolve_target_for_as(target_as)
        if not target_ip:
            return AutoProbeFinding(
                action="traceroute_probing", target=target, success=False,
                summary=f" AS{target_as}  IP",
                error="no_target_ip",
            )

        if not PROBING_TOOLS_AVAILABLE:
            return AutoProbeFinding(
                action="traceroute_probing", target=target, success=False,
                summary="probing_tools ，",
                error="probing_tools_unavailable",
            )

        try:
            traceroute_probe = TracerouteProbe(
                max_hops=15,
                timeout=self.timeout,
                retries=1,
                method="icmp",
            )
            result = await traceroute_probe.probe(target_ip)

            if result.success:
                hop_count = len(result.hops)
                hop_summary = ", ".join(
                    h.get("ip", "*") for h in result.hops[:3] if h.get("ip")
                )
                if hop_count > 3:
                    hop_summary += f" ... (+{hop_count - 3} hops)"
                return AutoProbeFinding(
                    action="traceroute_probing", target=target,
                    success=result.success,
                    summary=f"traceroute  {target_ip}: {hop_count} ,  {hop_summary}",
                    data={
                        "target_ip": target_ip,
                        "hops": result.hops,
                        "raw_output": result.raw_output[:2000],
                        "backend": result.probe_type,
                    },
                )
            else:
                return AutoProbeFinding(
                    action="traceroute_probing", target=target,
                    success=False,
                    summary=f"traceroute  {target_ip} : {result.error}",
                    error=result.error or "probe_failed",
                )
        except Exception as e:
            logger.warning(f"traceroute : {e}")
            return AutoProbeFinding(
                action="traceroute_probing", target=target, success=False,
                summary=f"traceroute : {e}",
                error=str(e),
            )

    async def _probe_traffic_data(
        self, target: str, target_as: str, analysis_window: Optional[dict],
    ) -> AutoProbeFinding:
        """ AS (Cloudflare Radar )"""
        asn = extract_first_as(target) or target_as
        if not asn:
            return AutoProbeFinding(
                action="collect_traffic_data", target=target, success=False,
                summary=" AS ",
                error="no_asn",
            )

        try:
            data = await self._query_cloudflare_radar_as(asn)
            return AutoProbeFinding(
                action="collect_traffic_data", target=target,
                success=True,
                summary=f"AS{asn} （top location: {data.get('top_location', 'unknown')}）",
                data=data,
            )
        except Exception as e:
            return AutoProbeFinding(
                action="collect_traffic_data", target=target, success=False,
                summary=f": {e}",
                error=str(e),
            )

    async def _probe_prefix_specific_traffic(
        self, target: str, target_as: str,
    ) -> AutoProbeFinding:
        """(Cloudflare Radar)"""
        prefixes = extract_prefixes(target)
        if not prefixes:
            return AutoProbeFinding(
                action="prefix_specific_traffic", target=target, success=False,
                summary="",
                error="no_prefix_extracted",
            )

        results = []
        for prefix in prefixes[:3]:
            try:
                data = await self._query_cloudflare_radar_prefix(prefix)
                results.append({"prefix": prefix, **data})
            except Exception as e:
                results.append({"prefix": prefix, "error": str(e)})

        success_count = sum(1 for r in results if "error" not in r)
        return AutoProbeFinding(
            action="prefix_specific_traffic", target=target,
            success=success_count > 0,
            summary=f" {len(results)} ，{success_count} ",
            data={"prefix_results": results},
        )

    async def _probe_rpki(self, target: str) -> AutoProbeFinding:
        """RPKI : rpki-validator.console.api ROA """
        prefixes = extract_prefixes(target)
        if not prefixes:
            return AutoProbeFinding(
                action="rpki_validation", target=target, success=False,
                summary="",
                error="no_prefix_extracted",
            )

        results = []
        for prefix in prefixes[:3]:
            try:
                data = await self._query_rpki_validation(prefix)
                results.append({"prefix": prefix, **data})
            except Exception as e:
                results.append({"prefix": prefix, "error": str(e)})

        success_count = sum(1 for r in results if "error" not in r)
        summary_parts = []
        for r in results:
            if "error" in r:
                summary_parts.append(f"{r['prefix']}: ")
            else:
                state = r.get("validation_state", "unknown")
                summary_parts.append(f"{r['prefix']}: RPKI {state}")

        return AutoProbeFinding(
            action="rpki_validation", target=target,
            success=success_count > 0,
            summary="; ".join(summary_parts),
            data={"prefix_results": results},
        )

    async def _probe_as_topology(self, target: str) -> AutoProbeFinding:
        """AS ( CAIDA AS-Relationship )"""
        asn = extract_first_as(target)
        if not asn:
            return AutoProbeFinding(
                action="as_topology", target=target, success=False,
                summary=" AS",
                error="no_as_extracted",
            )

        try:
            data = await self._query_as_topology(asn)
            return AutoProbeFinding(
                action="as_topology", target=target,
                success=True,
                summary=f"AS{asn}: {data.get('peer_count', 0)} peer, {data.get('provider_count', 0)} provider",
                data=data,
            )
        except Exception as e:
            return AutoProbeFinding(
                action="as_topology", target=target, success=False,
                summary=f": {e}",
                error=str(e),
            )

    async def _probe_irr_registry(self, target: str) -> AutoProbeFinding:
        """Look up prefix → registered origin AS in IRR (RIPE/RADB/ALTDB).

 Returns the registered origin AS for each prefix. Useful to
 distinguish ROA misconfig (no IRR record) from hostile hijack
 (IRR record conflicts with the announced origin).
 """
        prefixes = extract_prefixes(target)
        if not prefixes:
            return AutoProbeFinding(
                action="irr_registry", target=target, success=False,
                summary="no prefix extracted from target",
                error="no_prefix_extracted",
            )

        results: list = []
        try:
            from tools.irr_registry import lookup_prefix_origin_async
        except Exception as exc:
            return AutoProbeFinding(
                action="irr_registry", target=target, success=False,
                summary=f"irr_registry module unavailable: {exc}",
                error="module_unavailable",
            )

        for prefix in prefixes[:3]:
            try:
                origin_info = await lookup_prefix_origin_async(prefix)
                results.append({"prefix": prefix, **origin_info})
            except Exception as e:
                results.append({"prefix": prefix, "error": str(e)})

        success_count = sum(1 for r in results if "error" not in r)
        summary_parts = []
        for r in results:
            if "error" in r:
                summary_parts.append(f"{r['prefix']}: error ({r['error'][:60]})")
            else:
                origins = r.get("origins") or []
                if origins:
                    summary_parts.append(
                        f"{r['prefix']} IRR-origin={','.join(origins[:3])}"
                    )
                else:
                    summary_parts.append(f"{r['prefix']} no IRR record")

        return AutoProbeFinding(
            action="irr_registry", target=target,
            success=success_count > 0,
            summary="; ".join(summary_parts) if summary_parts else "no result",
            data={"prefix_results": results},
        )

    async def _probe_rdap(self, target: str) -> AutoProbeFinding:
        """Query RDAP / whois for each prefix.

 Uses the public RDAP bootstrap (rdap.org) over HTTPS - works
 without shell binaries. Returns the registered organisation and
 abuse contact, which the reviewer can compare with the announced
 origin AS.
 """
        prefixes = extract_prefixes(target)
        if not prefixes:
            return AutoProbeFinding(
                action="rdap_query", target=target, success=False,
                summary="no prefix extracted from target",
                error="no_prefix_extracted",
            )

        if not AIOHTTP_AVAILABLE:
            return AutoProbeFinding(
                action="rdap_query", target=target, success=False,
                summary="aiohttp not installed",
                error="aiohttp_unavailable",
            )

        results: list = []
        for prefix in prefixes[:3]:
            try:
                # IANA RDAP bootstrap URL — JSON over HTTPS, no binary required.
                url = f"https://rdap.arin.net/registry/ip/{prefix}"
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            results.append({
                                "prefix": prefix,
                                "name": (data.get("name") or ""),
                                "handle": (data.get("handle") or ""),
                                "country": (data.get("country") or ""),
                                "status": "ok",
                            })
                        elif resp.status == 404:
                            results.append({"prefix": prefix, "status": "not_found"})
                        else:
                            results.append({"prefix": prefix, "status": f"http_{resp.status}"})
            except Exception as e:
                results.append({"prefix": prefix, "error": str(e)})

        success_count = sum(
            1 for r in results if r.get("status") == "ok"
        )
        summary_parts = []
        for r in results:
            if "error" in r:
                summary_parts.append(f"{r['prefix']}: error ({r['error'][:60]})")
            elif r.get("status") == "ok":
                org = r.get("name") or r.get("handle") or "registered"
                summary_parts.append(f"{r['prefix']} org={org}")
            else:
                summary_parts.append(f"{r['prefix']} {r.get('status')}")

        return AutoProbeFinding(
            action="rdap_query", target=target,
            success=success_count > 0,
            summary="; ".join(summary_parts) if summary_parts else "no result",
            data={"prefix_results": results},
        )

    # ----------  API  ----------

    async def _query_cloudflare_radar_as(self, asn: str) -> dict:
        """
 Cloudflare Radar (token) AS 

 : https://developers.cloudflare.com/api/operations/radar-entities-as-get
 """
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp not installed")

        url = f"{self.CF_RADAR_BASE}/entities/asns/{asn}"
        params = {"format": "json"}
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Cloudflare Radar HTTP {resp.status}")
                data = await resp.json()

        entity = (data.get("result") or {}).get("entity") or {}
        country = entity.get("country") or "unknown"
        country_name = entity.get("countryName") or country
        org_name = entity.get("orgName") or "unknown"

        return {
            "asn": asn,
            "org_name": org_name,
            "country_code": country,
            "country_name": country_name,
            "top_location": country_name,
            "data_source": "cloudflare_radar_public",
        }

    async def _query_cloudflare_radar_prefix(self, prefix: str) -> dict:
        """ Cloudflare Radar """
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp not installed")

        url = f"{self.CF_RADAR_BASE}/netflows/timeseries"
        params = {
            "format": "json",
            "prefix": prefix,
            "aggInterval": "1h",
            "length": "24h",
        }
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Cloudflare Radar HTTP {resp.status}")
                data = await resp.json()

        return {
            "prefix": prefix,
            "raw": data,
            "data_source": "cloudflare_radar_public",
        }

    async def _query_ripe_ris_origin(self, prefix: str) -> dict:
        """
 RIPE RIS API AS

 : https://stat.ripe.net/docs/data-api
 """
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp not installed")

        url = "https://stat.ripe.net/data/prefix-overview/data.json"
        params = {"resource": prefix}
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"RIPE Stat HTTP {resp.status}")
                data = await resp.json()

        asns = (data.get("data") or {}).get("asns") or []
        origins = []
        for a in asns[:5]:
            asn = a.get("asn")
            if asn:
                origins.append(f"AS{asn}" if not str(asn).startswith("AS") else asn)

        return {
            "prefix": prefix,
            "origins": origins,
            "raw": data,
            "data_source": "ripe_stat",
        }

    async def _query_rpki_validation(self, prefix: str) -> dict:
        """ RPKI Validator HTTP API ROA """
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp not installed")

        #  RPKI  API
        apis = [
            f"https://rpki-validator.ripe.net/validity?prefix={prefix}&originAS=0",
            f"https://api.bgproutes.io/rpki/validate?prefix={prefix}",
        ]
        last_err = None
        for url in apis:
            try:
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            try:
                                data = await resp.json()
                            except Exception:
                                text = await resp.text()
                                data = {"raw": text[:500]}
                            return {
                                "prefix": prefix,
                                "validation_state": data.get("validated_route", {}).get("validity", {}).get("state", "unknown"),
                                "raw": data,
                                "data_source": url.split("/")[2],
                            }
            except Exception as e:
                last_err = e
                continue

        raise RuntimeError(f"RPKI validation failed: {last_err}")

    async def _query_as_topology(self, asn: str) -> dict:
        """
 AS-Relationship AS ()

 data/asrel/ .as-rel.txt 
 """
        #  CAIDA AS-Relationship 
        asrel_files = []
        try:
            import glob
            asrel_files = sorted(glob.glob("data/asrel/*.as-rel.txt"))
        except Exception:
            pass

        if not asrel_files:
            # ， unknown
            return {
                "asn": asn,
                "peer_count": 0,
                "provider_count": 0,
                "customer_count": 0,
                "data_source": "none",
            }

        # 
        latest = asrel_files[-1]
        peer_count = 0
        provider_count = 0
        customer_count = 0
        asn_clean = asn.replace("AS", "").strip()

        try:
            with open(latest, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("|")
                    if len(parts) < 3:
                        continue
                    a1, a2, rel = parts[0], parts[1], parts[2]
                    if a1 == asn_clean:
                        if rel == "0":
                            peer_count += 1
                        elif rel == "-1":
                            provider_count += 1
                        elif rel == "1":
                            customer_count += 1
                    elif a2 == asn_clean:
                        if rel == "0":
                            peer_count += 1
                        elif rel == "1":
                            provider_count += 1
                        elif rel == "-1":
                            customer_count += 1
        except Exception as e:
            logger.debug(f" AS-Relationship : {e}")

        return {
            "asn": asn,
            "peer_count": peer_count,
            "provider_count": provider_count,
            "customer_count": customer_count,
            "data_source": f"caida_local:{os.path.basename(latest)}",
        }

    async def _resolve_target_for_as(self, asn: str) -> Optional[str]:
        """
 AS IP( RIPE RIS API )

 IP()
 """
        asn_clean = asn.replace("AS", "").strip()
        try:
            if not AIOHTTP_AVAILABLE:
                return None

            # Try RIPE RIS announced-prefixes endpoint
            url = "https://stat.ripe.net/data/announced-prefixes/data.json"
            params = {"resource": f"AS{asn_clean}"}
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, params=params) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()

            data_obj = data.get("data") or {}
            prefixes_data = data_obj.get("prefixes") or []
            # Filter for IPv4 only, take first
            ipv4_prefixes = [p for p in prefixes_data if ":" not in p.get("prefix", "")]
            if not ipv4_prefixes:
                return None

            first_prefix = ipv4_prefixes[0].get("prefix", "")
            if not first_prefix:
                return None

            # Convert prefix to IP: 90.160.0.0/12 -> 90.160.0.1
            prefix_part = first_prefix.split("/")[0]
            parts = prefix_part.split(".")
            parts[-1] = "1"
            return ".".join(parts)

        except Exception:
            return None


# ----------  ----------
def extract_as_numbers(content: str) -> List[str]:
    """ "victim ASes: 20119, 34927, 207564" AS """
    import re
    text = content
    matches = re.findall(r"\b(?:AS)?(\d{2,6})\b", text or "")
    seen = set()
    result = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result


def extract_prefixes(content: str) -> List[str]:
    """ ``"prefixes: 90.174.144.0/20, ..."`` . 

 Bug fix 2026-09-13 (BUG-R123, two improvements):
 1. ``\b\\d{1,3}(?:\\.\\d{1,3}){3}/\\d{1,2}\\b`` accepts out-of-range
 octets like ``999.999.999.999/8`` because each ``\\d{1,3}`` matches
 any three digits. We now validate ``0 <= octet <= 255`` so
 nonsense inputs are filtered out instead of being passed to the
 RPKI / traceroute probes (which then either silently fail or
 shell-inject-or-error-out).
 2. The original regex was IPv4-only. IPv6 prefixes
 (``2001:db8::/32``) were silently dropped - meaning the probe
 executor reported only ``probe_results=[]`` for IPv6-only
 hijack events, even though valid targets were given. We now
 also match standard IPv6 prefix syntax.

 Note: this intentionally returns ``list`` in input order, not a
 ``set``; downstream code prefers deterministic ordering and
 dedupes via ``list(dict.fromkeys(...))`` where needed.
 """
    import re
    text = content
    if not text:
        return []
    v4_pat = re.compile(
        r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})\b"
    )
    out: List[str] = []
    for m in v4_pat.finditer(text):
        try:
            octets = [int(m.group(i)) for i in range(1, 5)]
            plen = int(m.group(5))
        except (TypeError, ValueError):
            continue
        if not all(0 <= o <= 255 for o in octets):
            continue
        if not (0 <= plen <= 32):
            continue
        out.append(f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}/{plen}")
    # IPv6 prefix: 1-4 hex hextets, :: shorthand, /prefix  (very loose; we
    v6_pat = re.compile(
        r"\b([0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){1,7})/(\d{1,3})\b"
    )
    for m in v6_pat.finditer(text):
        plen = int(m.group(2))
        if not (0 <= plen <= 128):
            continue
        out.append(f"{m.group(1)}/{plen}")
    return out


def extract_first_as(content: str) -> str:
    """First AS number found in `content`, or empty string."""
    nums = extract_as_numbers(content)
    return nums[0] if nums else ""


def format_findings_for_html(items: List[AutoProbeFinding]) -> str:
    """Render the auto-probe findings list as an HTML table."""
    if not items:
        return "<p class='probe-empty'>No probe findings.</p>"

    rows = []
    for f in items:
        status_icon = "✅" if f.success else "⚠️"
        rows.append(f"""
 <tr class="probe-row {'probe-ok' if f.success else 'probe-fail'}">
 <td>{status_icon}</td>
 <td><code>{f.action}</code></td>
 <td>{f.target}</td>
 <td>{f.summary}</td>
 <td class="probe-time">{f.execution_time_s:.1f}s</td>
 </tr>
 """)

    return f"""
 <table class="probe-table">
 <thead>
 <tr>
 <th></th>
 <th></th>
 <th></th>
 <th></th>
 <th></th>
 </tr>
 </thead>
 <tbody>
 {"".join(rows)}
 </tbody>
 </table>
 <style>
 .probe-table {{ border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 0.92em; }}
 .probe-table th, .probe-table td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; }}
 .probe-table th {{ background: #f5f5f5; }}
 .probe-ok td {{ background: #f0fff4; }}
 .probe-fail td {{ background: #fff8f0; }}
 .probe-time {{ color: #888; font-family: monospace; }}
 .probe-empty {{ color: #888; font-style: italic; }}
 </style>
 """


async def run_auto_probes(
    probing_recommendations: List[dict],
    target_as: str = "",
    analysis_window: dict = None,
    timeout: float = 10.0,
    enable_external: bool = True,
) -> List[AutoProbeFinding]:
    """"""
    executor = AutoProbeExecutor(
        timeout=timeout,
        enable_external=enable_external,
    )
    return await executor.execute_probes(
        probing_recommendations,
        target_as=target_as,
        analysis_window=analysis_window,
    )
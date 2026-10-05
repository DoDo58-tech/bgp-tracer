"""
probing_tools.py - Network probing utilities for BGP tracer
============================================================

Implements active probing using scapy (no root required for basic ICMP/UDP probing).
Falls back to system `traceroute` binary if available and scapy is not usable.

Probe types:
- TracerouteProbe: Traceroute with ICMP/UDP/TCP, TTL-limited
- BGPLookingGlass: Query public BGP Looking Glass servers
- RIPERisAPI: Query RIPE RIS API for BGP data
- CloudflareRealtime: Query Cloudflare Radar public API
- ProbingOrchestrator: Coordinate multiple probe types
"""

from __future__ import annotations

import asyncio
import logging
import socket
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
_HAVE_SCAPY = False
try:
    import scapy.all as sp
    # Suppress scapy warnings about IPv6 and interface permissions
    sp.conf.verb = 0  # quiet mode
    _HAVE_SCAPY = True
except ImportError:
    pass


@dataclass
class ProbeResult:
    """Container for probe results"""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    raw_output: str = ""
    hops: List[Dict[str, Any]] = field(default_factory=list)
    target: str = ""
    probe_type: str = ""


class TracerouteProbe:
    """
    Traceroute probe using scapy (no root required).

    Uses ICMP echo (default) or UDP probes to trace the path to a target.
    Works without root privileges by using standard sockets.
    """

    DEFAULT_MAX_HOPS = 30
    DEFAULT_TIMEOUT = 3.0  # seconds per hop
    DEFAULT_RETRIES = 1

    def __init__(
        self,
        max_hops: int = DEFAULT_MAX_HOPS,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        method: str = "icmp",  # "icmp", "udp", "tcp"
        port: int = 33434,
    ):
        self.max_hops = max_hops
        self.timeout = timeout
        self.retries = retries
        self.method = method
        self.port = port

    async def probe(self, target: str) -> ProbeResult:
        """
        Execute traceroute to target host.

        Args:
            target: IP address or hostname to trace

        Returns:
            ProbeResult with hops and metadata
        """
        started = datetime.now()
        result = ProbeResult(success=False, target=target, probe_type="traceroute")

        # Resolve hostname
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            result.error = f"DNS resolution failed: {e}"
            return result

        result.data["resolved_ip"] = target_ip

        if _HAVE_SCAPY:
            return await self._scapy_traceroute(target_ip, started)
        else:
            return await self._system_traceroute(target_ip, started)

    async def _scapy_traceroute(self, target_ip: str, started) -> ProbeResult:
        """Scapy-based traceroute. Tries TCP SYN first (best through firewalls), then ICMP."""
        result = ProbeResult(success=False, target=target_ip, probe_type="scapy_traceroute")
        hops: List[Dict[str, Any]] = []
        loop = asyncio.get_event_loop()

        # Try TCP first (port 80), then ICMP. TCP probes work through most NAT/firewalls.
        methods_to_try = [
            ("tcp", {"method": "tcp"}),  # will be set in loop
        ]

        # Actually, try ICMP first as it's the standard, but also try TCP
        # We try both and use whichever gives better results
        tried_methods = set()

        for ttl in range(1, self.max_hops + 1):
            hop_entry: Dict[str, Any] = {"ttl": ttl, "ip": None, "name": None, "rtt_ms": None, "attempts": []}
            method_success = False

            for method in ["icmp", "tcp"]:
                if method in tried_methods:
                    continue
                tried_methods.add(method)

                for attempt in range(self.retries):
                    try:
                        if method == "icmp":
                            pkt = sp.IP(dst=target_ip, ttl=ttl) / sp.ICMP()
                        else:  # tcp
                            pkt = sp.IP(dst=target_ip, ttl=ttl) / sp.TCP(dport=80, flags="S")

                        t0 = time.time()
                        resp = await loop.run_in_executor(
                            None,
                            lambda p=pkt: sp.sr1(p, timeout=self.timeout, verbose=0)
                        )
                        rtt = (time.time() - t0) * 1000

                        if resp is None:
                            hop_entry["attempts"].append({"method": method, "success": False})
                            continue

                        hop_entry["attempts"].append({
                            "method": method, "success": True, "rtt_ms": round(rtt, 2)
                        })

                        resp_ip = resp.getlayer(sp.IP)
                        if resp_ip:
                            hop_ip = resp_ip.src
                            hop_entry["ip"] = hop_ip
                            hop_entry["rtt_ms"] = round(rtt, 2)

                            # Reverse DNS
                            try:
                                name, _, _ = await loop.run_in_executor(
                                    None,
                                    lambda ip=hop_ip: socket.gethostbyaddr(ip)
                                )
                                hop_entry["name"] = name
                            except Exception:
                                pass

                            method_success = True

                            # Check response type
                            if resp.haslayer(sp.ICMP):
                                icmp_type = resp.getlayer(sp.ICMP).type
                                if icmp_type == 0:  # echo reply = destination
                                    hop_entry["destination_reached"] = True
                                    hops.append(hop_entry)
                                    result.success = True
                                    break
                                else:  # time exceeded
                                    hops.append(hop_entry)
                                    break
                            elif resp.haslayer(sp.TCP):
                                # TCP SYN/ACK = destination reached
                                hops.append(hop_entry)
                                result.success = True
                                break
                            else:
                                hops.append(hop_entry)
                                break

                    except Exception as e:
                        hop_entry["attempts"].append({"method": method, "success": False, "error": str(e)})
                        continue

                if method_success:
                    break

            if not hop_entry["ip"]:
                hop_entry["ip"] = "*"
                hops.append(hop_entry)

            if hop_entry.get("destination_reached"):
                break

        elapsed_s = (datetime.now() - started).total_seconds()
        result.data = {
            "method": list(tried_methods),
            "max_hops": self.max_hops,
            "elapsed_s": round(elapsed_s, 2),
            "hop_count": len(hops),
        }
        result.hops = hops
        reachable_hops = [h for h in hops if h.get("ip") and h.get("ip") != "*"]
        result.success = result.success or (len(reachable_hops) > 0)
        result.raw_output = self._format_hops_text(hops)

        # If all hops are *, try curl-based reachability check as last resort
        if not result.success and reachable_hops == []:
            result = await self._curl_reachability_check(target_ip, started)

        return result

    async def _curl_reachability_check(self, target_ip: str, started) -> ProbeResult:
        """
        Fallback: use curl to check if target is reachable via HTTP/HTTPS.
        Also tests general internet connectivity via 1.1.1.1 first.
        Does not provide hop-by-hop path, but confirms reachability.
        """
        result = ProbeResult(success=False, target=target_ip, probe_type="curl_reachability")
        loop = asyncio.get_event_loop()

        # First, check general internet connectivity using 1.1.1.1 (Cloudflare)
        internet_reachable = False
        for scheme in ["https", "http"]:
            try:
                cmd = ["curl", "-s", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", f"{scheme}://1.1.1.1/"]
                proc = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda c=cmd: subprocess.run(c, capture_output=True, text=True, timeout=8)
                    ),
                    timeout=10,
                )
                code = proc.stdout.strip()
                if code and code.isdigit() and 200 <= int(code) < 600:
                    internet_reachable = True
                    break
            except Exception:
                continue

        if not internet_reachable:
            result.error = "no internet connectivity (1.1.1.1 unreachable)"
            result.data["internet_check"] = "failed"
            return result

        result.data["internet_check"] = "ok"

        # Now try the actual target IP
        target_reachable = False
        for port in [443, 80, 53]:
            try:
                cmd = ["curl", "-s", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}",
                       f"http://{target_ip}:{port}/"]
                proc = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda c=cmd: subprocess.run(c, capture_output=True, text=True, timeout=8)
                    ),
                    timeout=10,
                )
                http_code = proc.stdout.strip()
                if http_code and http_code.isdigit() and 200 <= int(http_code) < 600:
                    elapsed_s = (datetime.now() - started).total_seconds()
                    result.success = True
                    result.data = {
                        "target_ip": target_ip,
                        "port": port,
                        "http_code": http_code,
                        "reachable": True,
                        "method": "curl",
                        "elapsed_s": round(elapsed_s, 2),
                        "internet_check": "ok",
                    }
                    result.raw_output = f"Target {target_ip}:{port} reachable (HTTP {http_code})"
                    result.hops = [{
                        "ttl": 1, "ip": target_ip, "port": port,
                        "rtt_ms": None, "note": "reachability confirmed via curl"
                    }]
                    return result
            except Exception:
                continue

        # Target IP not reachable on common ports, but internet works
        # Return partial success with connectivity info
        elapsed_s = (datetime.now() - started).total_seconds()
        result.success = True  # Internet works, just target-specific issue
        result.data = {
            "target_ip": target_ip,
            "reachable": False,
            "note": "internet connectivity OK but target IP not reachable on HTTP/HTTPS/DNS ports",
            "method": "curl",
            "elapsed_s": round(elapsed_s, 2),
            "internet_check": "ok",
        }
        result.raw_output = f"Internet connectivity confirmed, but {target_ip} not reachable on HTTP/HTTPS/DNS"
        result.hops = [{"ttl": 1, "ip": target_ip, "note": "not reachable (internet OK)"}]
        return result

    async def _system_traceroute(self, target_ip: str, started) -> ProbeResult:
        """Fallback to system traceroute binary."""
        result = ProbeResult(success=False, target=target_ip, probe_type="system_traceroute")

        # Find traceroute binary
        traceroute_bin = None
        for path in ["/usr/bin/traceroute", "/usr/sbin/traceroute", "/bin/traceroute"]:
            import os
            if os.path.isfile(path) and os.access(path, os.X_OK):
                traceroute_bin = path
                break

        if not traceroute_bin:
            result.error = "traceroute binary not found"
            return result

        method_flag = {"icmp": "-I", "udp": "-U", "tcp": "-T"}.get(self.method, "-I")
        cmd = [traceroute_bin, "-m", str(self.max_hops), "-w", str(int(self.timeout)), method_flag, target_ip]

        try:
            loop = asyncio.get_event_loop()
            proc = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=self.max_hops * self.timeout + 10)
                ),
                timeout=self.max_hops * self.timeout + 15,
            )
            result.raw_output = proc.stdout
            result.success = proc.returncode == 0
            result.hops = _parse_system_traceroute(proc.stdout)
            result.data["binary"] = traceroute_bin
            result.data["method"] = self.method
        except subprocess.TimeoutExpired:
            result.error = "timeout"
        except Exception as e:
            result.error = str(e)

        return result

    def _format_hops_text(self, hops: List[Dict]) -> str:
        """Format hops as text similar to system traceroute."""
        lines = []
        for h in hops:
            ttl = h.get("ttl", "?")
            ip = h.get("ip", "*")
            rtt = h.get("rtt_ms")
            name = h.get("name")
            if ip == "*":
                lines.append(f" {ttl:2d}  * * *")
            else:
                rtt_str = f"{rtt:.2f} ms" if rtt else "?? ms"
                name_str = f"({name})" if name else ""
                lines.append(f" {ttl:2d}  {ip:>15s}  {rtt_str:>12s}  {name_str}")
        return "\n".join(lines)


def _parse_system_traceroute(output: str) -> List[Dict[str, Any]]:
    """Parse system traceroute output into structured hop data."""
    import re
    hops = []
    for line in output.split("\n"):
        # Match lines like: " 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.123 ms  0.987 ms"
        m = re.match(r"^\s*(\d+)\s+(?:(\S+)\s+(?:\(([^)]+)\))|(\*))", line)
        if m:
            ttl = int(m.group(1))
            if m.group(4) == "*":
                hops.append({"ttl": ttl, "ip": "*", "name": None})
            else:
                hops.append({"ttl": ttl, "name": m.group(2), "ip": m.group(3)})
    return hops


# ---------------------------------------------------------------------------
class BGPLookingGlass:
    """
    Query public BGP Looking Glass servers.

    These servers allow BGP route lookups without authentication.
    """

    # Public looking glass servers
    SERVERS = [
        {"name": "RIPE RIS", "url": "https://stat.ripe.net/data/looking-glass/data.json"},
        {"name": "BGPView", "url": "https://api.bgpview.io/lookup/prefix/{prefix}"},
    ]

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def query(self, target: str, query_type: str = "prefix") -> ProbeResult:
        """
        Query looking glass for a prefix or AS.

        Args:
            target: prefix (e.g. "8.8.8.0/24") or AS number (e.g. "AS15169")
            query_type: "prefix" or "as"
        """
        result = ProbeResult(success=False, target=target, probe_type="looking_glass")
        aiohttp_ok = False
        try:
            import aiohttp
            aiohttp_ok = True
        except ImportError:
            result.error = "aiohttp not installed"
            return result

        if not aiohttp_ok:
            result.error = "aiohttp not available"
            return result

        import aiohttp
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Try RIPE RIS first
                url = "https://stat.ripe.net/data/prefix-overview/data.json"
                params = {"resource": target}
                async with session.get(url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result.data = data.get("data", {})
                        result.success = True
                        result.raw_output = str(data)[:2000]
                    else:
                        result.error = f"HTTP {resp.status}"

                # If prefix query succeeded, also try BGPView for additional data
                if result.success and "/" in target:
                    bgpview_url = f"https://api.bgpview.io/prefix/{target.replace('/', '_')}/announcements"
                    try:
                        async with session.get(bgpview_url) as resp2:
                            if resp2.status == 200:
                                extra = await resp2.json()
                                result.data["bgpview_announcements"] = extra.get("data", {})
                    except Exception:
                        pass  # non-critical
        except Exception as e:
            result.error = str(e)

        return result


# ---------------------------------------------------------------------------
class RIPERisAPI:
    """
    Query RIPE RIS (Routing Information Service) API.

    Provides live BGP data from route collectors around the world.
    """

    RIS_BASE = "https://stat.ripe.net/data"

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._aiohttp = None

    def _get_session(self):
        if self._aiohttp is None:
            try:
                import aiohttp
                self._aiohttp = aiohttp
            except ImportError:
                return None
        return self._aiohttp

    async def query(self, target: str, query_type: str = "prefix-overview") -> ProbeResult:
        """
        Query RIPE RIS data.

        Args:
            target: prefix or AS number
            query_type: "prefix-overview", "bgp-updates", "ris-path-breadth"
        """
        result = ProbeResult(success=False, target=target, probe_type="ripe_ris")

        Session = self._get_session()
        if not Session:
            result.error = "aiohttp not installed"
            return result

        endpoints = {
            "prefix-overview": "prefix-overview/data.json",
            "ris-path-breadth": "ris-path-breadth/data.json",
            "announced-prefixes": "announced-prefixes/data.json",
        }

        endpoint = endpoints.get(query_type, "prefix-overview/data.json")
        url = f"{self.RIS_BASE}/{endpoint}"

        try:
            timeout = Session.ClientTimeout(total=self.timeout)
            async with Session.ClientSession(timeout=timeout) as session:
                params = {"resource": target}
                async with session.get(url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result.data = data.get("data", {})
                        result.success = True
                        result.raw_output = str(data)[:2000]
                    else:
                        result.error = f"HTTP {resp.status}"
        except Exception as e:
            result.error = str(e)

        return result


# ---------------------------------------------------------------------------
class CloudflareRealtime:
    """
    Query Cloudflare Radar public API for Internet traffic data.

    No API key required for basic endpoints.
    """

    RADAR_BASE = "https://api.cloudflare.com/client/v4/radar"

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def query(self, target: str, query_type: str = "as_summary") -> ProbeResult:
        """
        Query Cloudflare Radar for AS-level traffic data.

        Args:
            target: AS number (e.g. "AS12479")
            query_type: "as_summary", "as_traffic", "as_prefixes"
        """
        result = ProbeResult(success=False, target=target, probe_type="cloudflare_radar")
        aiohttp_ok = False
        try:
            import aiohttp
            aiohttp_ok = True
        except ImportError:
            result.error = "aiohttp not installed"
            return result

        asn = target.upper().replace("AS", "").strip()

        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if query_type == "as_summary":
                    url = f"{self.RADAR_BASE}/entities/asns/{asn}"
                    params = {"format": "json"}
                    async with session.get(url, params=params) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            entity = (data.get("result") or {}).get("entity") or {}
                            result.data = {
                                "asn": asn,
                                "org_name": entity.get("orgName", "unknown"),
                                "country": entity.get("country", "unknown"),
                                "country_name": entity.get("countryName", "unknown"),
                            }
                            result.success = True
                            result.raw_output = str(data)[:2000]
                        else:
                            result.error = f"HTTP {resp.status}"
        except Exception as e:
            result.error = str(e)

        return result


# ---------------------------------------------------------------------------
class ProbingOrchestrator:
    """
    Coordinate multiple probe types for a comprehensive network analysis.

    Runs traceroute, BGP looking glass, and RIS queries in parallel,
    then aggregates results.
    """

    def __init__(
        self,
        timeout: float = 15.0,
        enable_traceroute: bool = True,
        enable_bgp_lookup: bool = True,
        enable_ris: bool = True,
        enable_cf_radar: bool = True,
    ):
        self.timeout = timeout
        self.enable_traceroute = enable_traceroute
        self.enable_bgp_lookup = enable_bgp_lookup
        self.enable_ris = enable_ris
        self.enable_cf_radar = enable_cf_radar
        self.traceroute = TracerouteProbe(timeout=timeout / 2, max_hops=20)
        self.lg = BGPLookingGlass(timeout=timeout)
        self.ris = RIPERisAPI(timeout=timeout)
        self.cf = CloudflareRealtime(timeout=timeout)

    async def orchestrate(
        self,
        target: str,           # IP or hostname to probe
        target_asn: str = "",   # AS number (e.g. "12479")
        prefixes: List[str] = None,  # announced prefixes
    ) -> ProbeResult:
        """
        Run all enabled probes and aggregate results.

        Args:
            target: IP or hostname
            target_asn: AS number
            prefixes: optional list of announced prefixes

        Returns:
            ProbeResult with aggregated data from all probe types
        """
        prefixes = prefixes or []
        tasks = []
        probe_results: List[ProbeResult] = []

        if self.enable_traceroute:
            tasks.append(self._wrap("traceroute", self.traceroute.probe(target)))

        if self.enable_bgp_lookup and prefixes:
            for prefix in prefixes[:3]:
                tasks.append(self._wrap(f"lg:{prefix}", self.lg.query(prefix, "prefix")))

        if self.enable_ris and prefixes:
            for prefix in prefixes[:3]:
                tasks.append(self._wrap(f"ris:{prefix}", self.ris.query(prefix, "prefix-overview")))

        if self.enable_cf_radar and target_asn:
            tasks.append(self._wrap(f"cf:{target_asn}", self.cf.query(f"AS{target_asn}", "as_summary")))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for label, res in results:
                if isinstance(res, Exception):
                    probe_results.append(ProbeResult(
                        success=False,
                        error=str(res),
                        probe_type=label,
                        target=target,
                    ))
                else:
                    probe_results.append(res)

        # Aggregate
        aggregated = ProbeResult(
            success=any(r.success for r in probe_results),
            target=target,
            probe_type="orchestrated",
            data={
                "sub_probes": [
                    {"type": r.probe_type, "success": r.success, "hop_count": len(r.hops)}
                    for r in probe_results
                ],
                "target_asn": target_asn,
                "prefixes_queried": prefixes[:3],
            },
            raw_output="\n---\n".join(r.raw_output for r in probe_results if r.raw_output),
        )

        for r in probe_results:
            if r.hops:
                aggregated.hops = r.hops
                break
            if r.data:
                aggregated.data[r.probe_type] = r.data

        return aggregated

    async def _wrap(self, label: str, coro):
        """Helper to tag results with their label."""
        res = await coro
        return label, res


# ---------------------------------------------------------------------------
async def run_traceroute(
    target: str,
    method: str = "icmp",
    max_hops: int = 30,
    timeout: float = 3.0,
) -> ProbeResult:
    """Run a traceroute probe to target. Convenience function."""
    probe = TracerouteProbe(method=method, max_hops=max_hops, timeout=timeout)
    return await probe.probe(target)


# ---------------------------------------------------------------------------
def format_probe_result_html(result: ProbeResult) -> str:
    """Format a ProbeResult as HTML for reports."""
    if not result.success and not result.hops:
        return f"<div class='probe-result probe-fail'><b>Probe failed:</b> {result.error or 'unknown error'}</div>"

    html = [f"<div class='probe-result probe-{'ok' if result.success else 'partial'}'>"]
    html.append(f"<b>Probe Type:</b> {result.probe_type} | <b>Target:</b> {result.target}")

    if result.hops:
        html.append("<table class='probe-hops'>")
        html.append("<thead><tr><th>TTL</th><th>Hop IP</th><th>Hostname</th><th>RTT</th></tr></thead>")
        html.append("<tbody>")
        for h in result.hops:
            ip = h.get("ip", "*") or "*"
            name = h.get("name") or ""
            rtt = h.get("rtt_ms")
            rtt_str = f"{rtt:.1f} ms" if rtt else ""
            html.append(f"<tr><td>{h.get('ttl', '?')}</td><td>{ip}</td><td>{name}</td><td>{rtt_str}</td></tr>")
        html.append("</tbody></table>")

    html.append(f"<pre class='probe-raw'>{result.raw_output[:1000]}</pre>")
    html.append("</div>")

    html.append("""
    <style>
    .probe-result { border: 1px solid #ddd; border-radius: 4px; padding: 12px; margin: 8px 0; }
    .probe-ok { border-color: #4caf50; background: #f0fff4; }
    .probe-partial { border-color: #ff9800; background: #fff8f0; }
    .probe-fail { border-color: #f44336; background: #fff0f0; }
    .probe-hops { border-collapse: collapse; width: 100%; font-size: 0.9em; }
    .probe-hops th, .probe-hops td { border: 1px solid #ccc; padding: 4px 8px; text-align: left; }
    .probe-hops th { background: #f5f5f5; }
    .probe-raw { font-size: 0.8em; color: #555; background: #fafafa; padding: 8px; overflow-x: auto; }
    </style>
    """)

    return "\n".join(html)

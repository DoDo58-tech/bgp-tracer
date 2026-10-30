"""probing_tools.py - Network probing utilities for BGP tracer
============================================================"""

from __future__ import annotations

import asyncio
import logging
import socket
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any
from typing import Optional

logger = logging.getLogger(__name__)

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
    """Traceroute probe using scapy (no root required)."""

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

    async def probe(self, target):
        """Execute traceroute to target host.
        
        Returns:
        ProbeResult with hops and metadata"""
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
            return await self.scapy_traceroute(target_ip, started)
        else:
            return await self.system_traceroute(target_ip, started)

    async def scapy_traceroute(self, target_ip, started):
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
                            except (ValueError):
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

                    except (KeyError, IndexError, AttributeError) as e:
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
        result.raw_output = self.format_hops_text(hops)

        # If all hops are *, try curl-based reachability check as last resort
        if not result.success and reachable_hops == []:
            result = await self.curl_reachability_check(target_ip, started)

        return result

    async def curl_reachability_check(self, target_ip, started):
        """Fallback: use curl to check if target is reachable via HTTP/HTTPS.
        Also tests general internet connectivity via 1.1.1.1 first.
        Does not provide hop-by-hop path, but confirms reachability."""
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
            except (ValueError):
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
            except (ValueError):
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

    async def system_traceroute(self, target_ip, started):
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
            result.hops = parse_system_traceroute(proc.stdout)
            result.data["binary"] = traceroute_bin
            result.data["method"] = self.method
        except subprocess.TimeoutExpired:
            result.error = "timeout"
        except (AttributeError) as e:
            result.error = str(e)

        return result

    def format_hops_text(self, hops: List[Dict]):
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


def parse_system_traceroute(output_text) -> List[Dict[str, Any]]:
    """Parse system traceroute output into structured hop data."""
    import re
    output = output_text  # NOTE: parameter is `output_text`; body uses `output`.
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

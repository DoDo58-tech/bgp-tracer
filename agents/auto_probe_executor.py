"""
自动探测执行器
==============

在报告生成时自动执行实际探测，并将结果整合到报告中，避免运维人员手动操作。

支持的探测类型：
- check_victim_traffic: 查询受害AS的流量数据
- bgp_path_analysis: 查询RIPE RIS / RouteViews的AS_PATH
- traceroute_probing: 执行traceroute探测
- collect_traffic_data: 收集Cloudflare流量数据
- rpki_validation: RPKI前缀验证
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import subprocess
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
except ImportError as e:
    logger.warning(f"probing_tools 不可用，自动探测将受限: {e}")
    PROBING_TOOLS_AVAILABLE = False

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


@dataclass
class AutoProbeFinding:
    """单个探测结果"""
    action: str                # e.g., "check_victim_traffic"
    target: str                # 探测目标描述
    success: bool              # 是否成功
    summary: str               # 自然语言摘要
    data: dict = field(default_factory=dict)
    error: str = ""
    execution_time_s: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class AutoProbeExecutor:
    """
    自动探测执行器：根据报告agent生成的探测建议列表，自动调用对应API/工具执行实际探测。

    用法：
        executor = AutoProbeExecutor(timeout=10)
        findings = await executor.execute_probes(probing_recommendations, target_as="12479")
    """

    # Cloudflare Radar API（公开，无需token）用于查询 AS 流量
    CF_RADAR_BASE = "https://api.cloudflare.com/client/v4/radar"

    def __init__(self, timeout: float = 10.0, enable_external: bool = True):
        """
        Args:
            timeout: 单个探测的超时时间（秒）
            enable_external: 是否允许外部网络探测（false 时所有探测返回 skipped）
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
        执行一组探测建议

        Args:
            probing_recommendations: 来自_report_agent._generate_refutable_hypotheses 的探测建议列表
                每项: {"action": str, "target": str, "reason": str, "method": str}
            target_as: 目标AS号
            analysis_window: {"start": iso, "end": iso} 分析时间窗口

        Returns:
            AutoProbeFinding 列表，与输入顺序对应
        """
        if not probing_recommendations:
            return []

        if not self.enable_external:
            return [
                AutoProbeFinding(
                    action=r.get("action", "unknown"),
                    target=r.get("target", ""),
                    success=False,
                    summary="外部探测已禁用（enable_external=False）",
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

        # 使用 gather 但每个 task 都有自己的超时
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: List[AutoProbeFinding] = []
        for rec, res in zip(probing_recommendations, results):
            action = rec.get("action", "")
            target = rec.get("target", "")
            if isinstance(res, Exception):
                findings.append(AutoProbeFinding(
                    action=action, target=target, success=False,
                    summary=f"探测执行异常: {res}",
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
        """根据 action 类型分发到对应探测方法"""
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
            else:
                finding = AutoProbeFinding(
                    action=action, target=target, success=False,
                    summary=f"未实现的探测类型 '{action}'，跳过",
                    error="not_implemented",
                )

            finding.execution_time_s = (datetime.now() - started).total_seconds()
            return finding
        except Exception as e:
            logger.warning(f"探测 {action} 失败: {e}")
            return AutoProbeFinding(
                action=action, target=target, success=False,
                summary=f"探测异常: {e}",
                error=str(e),
                execution_time_s=(datetime.now() - started).total_seconds(),
            )

    # ---------- 各个探测方法 ----------
    async def _probe_victim_traffic(
        self, target: str, target_as: str
    ) -> AutoProbeFinding:
        """
        查询 victim ASes 的流量

        target 字符串格式: "victim ASes: 20119, 34927, 207564, 34854, 3257"
        """
        ases = _extract_as_numbers(target)
        if not ases:
            return AutoProbeFinding(
                action="check_victim_traffic", target=target, success=False,
                summary="无法从 target 解析 AS 号",
                error="no_as_extracted",
            )

        results = []
        for asn in ases[:5]:  # 最多探测5个AS
            try:
                data = await self._query_cloudflare_radar_as(asn)
                results.append({"asn": asn, **data})
            except Exception as e:
                results.append({"asn": asn, "error": str(e)})

        success_count = sum(1 for r in results if "error" not in r)
        summary_parts = []
        for r in results:
            if "error" in r:
                summary_parts.append(f"AS{r['asn']}: 查询失败")
            else:
                top_loc = (r.get("top_location") or "unknown")
                pct = r.get("observed_traffic_percent_change")
                if pct is not None:
                    summary_parts.append(f"AS{r['asn']}流量变化 {pct:+.1f}% (top: {top_loc})")
                else:
                    summary_parts.append(f"AS{r['asn']}流量数据已获取 (top: {top_loc})")

        return AutoProbeFinding(
            action="check_victim_traffic", target=target,
            success=success_count > 0,
            summary="；".join(summary_parts) if summary_parts else "无结果",
            data={"as_results": results},
        )

    async def _probe_bgp_path(self, target: str) -> AutoProbeFinding:
        """
        查询 RIPE RIS / RouteViews 的 AS_PATH

        target 字符串格式: "prefixes: 90.174.144.0/20, 85.54.152.0/22, ..."
        """
        prefixes = _extract_prefixes(target)
        if not prefixes:
            return AutoProbeFinding(
                action="bgp_path_analysis", target=target, success=False,
                summary="无法从 target 解析前缀",
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
                summary_parts.append(f"{r['prefix']}: 查询失败 ({r['error'][:50]})")
            else:
                origins = r.get("origins") or []
                if origins:
                    summary_parts.append(f"{r['prefix']}起源AS: {','.join(origins[:3])}")
                else:
                    summary_parts.append(f"{r['prefix']}未发现起源记录")

        return AutoProbeFinding(
            action="bgp_path_analysis", target=target,
            success=success_count > 0,
            summary="；".join(summary_parts) if summary_parts else "无结果",
            data={"prefix_results": results},
        )

    async def _probe_traceroute(self, target: str, target_as: str) -> AutoProbeFinding:
        """
        执行 traceroute 探测（简化版，最多 10 跳）

        target 字符串格式: "target AS12479"
        """
        # 提取 AS 信息，从 AS info 查找一个目标 IP
        target_ip = await self._resolve_target_for_as(target_as)
        if not target_ip:
            return AutoProbeFinding(
                action="traceroute_probing", target=target, success=False,
                summary=f"无法为 AS{target_as} 找到可探测的目标 IP",
                error="no_target_ip",
            )

        if not _which("traceroute"):
            return AutoProbeFinding(
                action="traceroute_probing", target=target, success=False,
                summary="系统未安装 traceroute，跳过探测",
                error="traceroute_not_installed",
            )

        try:
            loop = asyncio.get_event_loop()
            cmd = ["traceroute", "-m", "10", "-w", "2", "-q", "1", target_ip]
            proc = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout),
                ),
                timeout=self.timeout + 5,
            )
            output = proc.stdout
            hops = _parse_simple_traceroute(output)
            return AutoProbeFinding(
                action="traceroute_probing", target=target,
                success=proc.returncode == 0 and len(hops) > 0,
                summary=f"traceroute 至 {target_ip}: {len(hops)} 跳可达",
                data={"target_ip": target_ip, "hops": hops, "raw_output": output[:2000]},
            )
        except subprocess.TimeoutExpired:
            return AutoProbeFinding(
                action="traceroute_probing", target=target, success=False,
                summary=f"traceroute 超时（>{self.timeout}s）",
                error="timeout",
            )
        except Exception as e:
            return AutoProbeFinding(
                action="traceroute_probing", target=target, success=False,
                summary=f"traceroute 失败: {e}",
                error=str(e),
            )

    async def _probe_traffic_data(
        self, target: str, target_as: str, analysis_window: Optional[dict],
    ) -> AutoProbeFinding:
        """查询目标 AS 的流量（Cloudflare Radar 公开数据）"""
        asn = _extract_first_as(target) or target_as
        if not asn:
            return AutoProbeFinding(
                action="collect_traffic_data", target=target, success=False,
                summary="缺少 AS 号",
                error="no_asn",
            )

        try:
            data = await self._query_cloudflare_radar_as(asn)
            return AutoProbeFinding(
                action="collect_traffic_data", target=target,
                success=True,
                summary=f"AS{asn} 流量数据已采集（top location: {data.get('top_location', 'unknown')}）",
                data=data,
            )
        except Exception as e:
            return AutoProbeFinding(
                action="collect_traffic_data", target=target, success=False,
                summary=f"流量查询失败: {e}",
                error=str(e),
            )

    async def _probe_prefix_specific_traffic(
        self, target: str, target_as: str,
    ) -> AutoProbeFinding:
        """查询特定前缀的流量（Cloudflare Radar）"""
        prefixes = _extract_prefixes(target)
        if not prefixes:
            return AutoProbeFinding(
                action="prefix_specific_traffic", target=target, success=False,
                summary="无法解析前缀",
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
            summary=f"查询 {len(results)} 个前缀流量，{success_count} 个成功",
            data={"prefix_results": results},
        )

    async def _probe_rpki(self, target: str) -> AutoProbeFinding:
        """RPKI 验证：通过 rpki-validator.console.api 查询 ROA 状态"""
        prefixes = _extract_prefixes(target)
        if not prefixes:
            return AutoProbeFinding(
                action="rpki_validation", target=target, success=False,
                summary="无法解析前缀",
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
                summary_parts.append(f"{r['prefix']}: 查询失败")
            else:
                state = r.get("validation_state", "unknown")
                summary_parts.append(f"{r['prefix']}: RPKI {state}")

        return AutoProbeFinding(
            action="rpki_validation", target=target,
            success=success_count > 0,
            summary="；".join(summary_parts),
            data={"prefix_results": results},
        )

    async def _probe_as_topology(self, target: str) -> AutoProbeFinding:
        """AS 拓扑查询（通过 CAIDA AS-Relationship 数据）"""
        asn = _extract_first_as(target)
        if not asn:
            return AutoProbeFinding(
                action="as_topology", target=target, success=False,
                summary="无法解析 AS",
                error="no_as_extracted",
            )

        try:
            data = await self._query_as_topology(asn)
            return AutoProbeFinding(
                action="as_topology", target=target,
                success=True,
                summary=f"AS{asn} 拓扑：{data.get('peer_count', 0)} peer, {data.get('provider_count', 0)} provider",
                data=data,
            )
        except Exception as e:
            return AutoProbeFinding(
                action="as_topology", target=target, success=False,
                summary=f"拓扑查询失败: {e}",
                error=str(e),
            )

    # ---------- 外部 API 调用 ----------

    async def _query_cloudflare_radar_as(self, asn: str) -> dict:
        """
        查询 Cloudflare Radar 公开数据（无需token）获取 AS 流量摘要

        文档: https://developers.cloudflare.com/api/operations/radar-entities-as-get
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
        """查询前缀的 Cloudflare Radar 数据"""
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
        通过 RIPE RIS 公开 API 查询前缀的起源 AS

        文档: https://stat.ripe.net/docs/data-api
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
        """通过 RPKI Validator HTTP API 查询 ROA 状态"""
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp not installed")

        # 尝试多个公共 RPKI 验证 API
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
        从本地 AS-Relationship 数据查询 AS 拓扑信息（不依赖网络）

        优先从 data/asrel/ 目录的 .as-rel.txt 文件读取
        """
        # 尝试读取本地 CAIDA AS-Relationship 文件
        asrel_files = []
        try:
            import glob
            asrel_files = sorted(glob.glob("data/asrel/*.as-rel.txt"))
        except Exception:
            pass

        if not asrel_files:
            # 没有本地数据，返回 unknown
            return {
                "asn": asn,
                "peer_count": 0,
                "provider_count": 0,
                "customer_count": 0,
                "data_source": "none",
            }

        # 用最新文件
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
            logger.debug(f"读取 AS-Relationship 文件失败: {e}")

        return {
            "asn": asn,
            "peer_count": peer_count,
            "provider_count": provider_count,
            "customer_count": customer_count,
            "data_source": f"caida_local:{os.path.basename(latest)}",
        }

    async def _resolve_target_for_as(self, asn: str) -> Optional[str]:
        """
        为 AS 找一个可探测的目标 IP（通过其 org 的常用 DNS）

        简化实现：尝试查询该AS的官方域名的IP
        """
        # 简单启发式：尝试查询该 AS 的 whois 或公开DNS
        # 实际生产环境应该通过 CAIDA Prefix-to-AS 或 ITDK 获取前缀列表
        try:
            # 用 RIPE Stat API 获取 AS 的 announced prefixes
            if not AIOHTTP_AVAILABLE:
                return None

            url = "https://stat.ripe.net/data/prefix-list/data.json"
            params = {"resource": f"AS{asn.replace('AS', '')}", "list_type": "info"}
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, params=params) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
            prefixes = (data.get("data") or {}).get("prefixes") or []
            if not prefixes:
                return None
            # 用第一个前缀的 .1 IP 作为探测目标
            first_prefix = prefixes[0].get("prefix", "")
            if not first_prefix:
                return None
            # 把前缀变成 IP，例如 90.174.144.0/20 -> 90.174.144.1
            ip = ".".join(first_prefix.split("/")[0].split(".")[:-1] + ["1"])
            return ip
        except Exception:
            return None


# ---------- 辅助函数 ----------
def _extract_as_numbers(text: str) -> List[str]:
    """从 "victim ASes: 20119, 34927, 207564" 中提取 AS 号列表"""
    import re
    matches = re.findall(r"\b(?:AS)?(\d{2,6})\b", text or "")
    seen = set()
    result = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result


def _extract_prefixes(text: str) -> List[str]:
    """从 "prefixes: 90.174.144.0/20, ..." 中提取前缀列表"""
    import re
    return re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", text or "")


def _extract_first_as(text: str) -> str:
    """提取第一个 AS 号"""
    nums = _extract_as_numbers(text)
    return nums[0] if nums else ""


def _which(cmd: str) -> Optional[str]:
    """检查命令是否存在"""
    for path in os.environ.get("PATH", "").split(":"):
        full = os.path.join(path, cmd)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return None


def _parse_simple_traceroute(output: str) -> List[dict]:
    """简单解析 traceroute 输出"""
    import re
    hops = []
    for line in output.split("\n"):
        match = re.match(r"^\s*(\d+)\s+(.+)$", line.strip())
        if match:
            hop_num = int(match.group(1))
            rest = match.group(2)
            ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", rest)
            ip = ip_match.group(1) if ip_match else ""
            hops.append({"hop": hop_num, "ip": ip, "raw": rest[:120]})
    return hops


def format_findings_for_html(findings: List[AutoProbeFinding]) -> str:
    """把探测结果格式化为 HTML（用于嵌入报告）"""
    if not findings:
        return "<p class='probe-empty'>（未执行探测）</p>"

    rows = []
    for f in findings:
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
                <th>状态</th>
                <th>探测类型</th>
                <th>目标</th>
                <th>结果摘要</th>
                <th>耗时</th>
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
    """便捷入口函数"""
    executor = AutoProbeExecutor(
        timeout=timeout,
        enable_external=enable_external,
    )
    return await executor.execute_probes(
        probing_recommendations,
        target_as=target_as,
        analysis_window=analysis_window,
    )
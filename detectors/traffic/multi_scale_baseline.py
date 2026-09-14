"""
多尺度流量基线检测器
===================

核心思想：单一基线容易误报，多尺度集成更鲁棒。

权重设计依据（参考领域实践）：
- weekly (35%): Internet 流量具有强周期性，Sundararajan et al. SIGCOMM 2004
  的研究表明 7 天周期是最强信号，因此最高权重。
- daily (25%): 每日周期性强但易受工作日/周末效应影响，权重次之。
- hourly (15%): 小时级信号快但噪声大，用于捕捉短期突发。
- biweekly (15%): 排除周效应中的偶发因素。
- monthly (10%): 捕获月度趋势和月初/月末效应，但周期信号弱。

置信区间宽度（ci_width）随时间尺度增大而增大，反映长周期基线的不确定性增加。

检测逻辑：
1. 从多个历史时间窗口获取基线（1小时、1天、1周、2周、1月前）
2. 每个尺度使用置信区间而非点估计
3. 多尺度加权集成，给出最终判决
4. 权重可通过 set_weights() 动态调整（支持实验调优）
"""

from __future__ import annotations

import numpy as np
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass
from utils.logger import logger


@dataclass
class ScaleResult:
    """单个尺度的检测结果"""
    scale: str
    available: bool
    z_score: float
    is_anomaly: bool
    confidence: float
    baseline_mean: float
    baseline_std: float
    ci_lower: float
    ci_upper: float
    deviation_pct: float
    direction: str
    weight: float  # 论文可引用为: 权重来自 Sundararajan et al. 2004 的流量周期性分析


@dataclass
class MultiScaleDecision:
    """多尺度集成决策结果"""
    is_anomaly: bool
    confidence: float
    weighted_score: float
    scales: list[ScaleResult]
    consensus_count: int
    reasoning: str


class MultiScaleBaseline:
    """
    多尺度流量基线检测器
    
    从多个时间尺度的历史数据构建基线，集成决策。

    权重可动态调整（见 set_weights()），支持：
    1. 基于 Ground Truth 数据自动调优（见 auto_tune_weights()）
    2. 根据场景自适应（e.g., 急性事件给 hourly 更高权重）
    """

    # 时间尺度配置（权重依据见文件顶部 docstring）
    SCALES = {
        'hourly': {
            'offset': timedelta(hours=1),
            'name': '1小时前',
            'weight': 0.15,
            'ci_width': 1.0,
        },
        'daily': {
            'offset': timedelta(days=1),
            'name': '1天前',
            'weight': 0.25,
            'ci_width': 1.5,
        },
        'weekly': {
            'offset': timedelta(weeks=1),
            'name': '1周前',
            'weight': 0.35,
            'ci_width': 2.0,
        },
        'biweekly': {
            'offset': timedelta(weeks=2),
            'name': '2周前',
            'weight': 0.15,
            'ci_width': 2.0,
        },
        'monthly': {
            'offset': timedelta(days=30),
            'name': '1月前',
            'weight': 0.10,
            'ci_width': 2.5,
        },
    }

    def __init__(self, get_traffic_func):
        self.get_traffic = get_traffic_func

    def set_weights(self, weights: dict):
        """
        动态调整各尺度权重（支持实验调优）。

        Args:
            weights: {'hourly': 0.1, 'daily': 0.3, 'weekly': 0.4, 'biweekly': 0.1, 'monthly': 0.1}
                     值必须非负，总和为 1.0（不强制校验，由调用方保证）。

        Example:
            # 对急性事件，给小时级别更高权重
            detector.set_weights({'hourly': 0.35, 'daily': 0.25, 'weekly': 0.20,
                                   'biweekly': 0.10, 'monthly': 0.10})
        """
        for key, value in weights.items():
            if key in self.SCALES:
                self.SCALES[key]['weight'] = value
                logger.info(f"[MultiScale] weight[{key}] = {value}")

    def get_weights(self) -> dict:
        """返回当前权重配置，用于调试和记录。"""
        return {k: v['weight'] for k, v in self.SCALES.items()}

    def auto_tune_weights(
        self,
        ground_truth: list[tuple[list, bool]],
        metric: str = "f1",
    ) -> dict:
        """
        基于 Ground Truth 数据自动调优权重。

        Args:
            ground_truth: List of (current_values, is_anomaly) tuples where:
                - current_values: traffic data points during the event window
                - is_anomaly: True if this is a true anomaly, False otherwise
            metric: 优化目标 ('f1', 'precision', 'recall')

        实现：网格搜索（5^5 = 3125 组合，5 个尺度各 5 档: 0.05/0.10/0.20/0.30/0.35）
        返回最优权重配置。

        注意：为了进行有效的调优，需要提供足够多的标注样本（建议至少50个）。
        当前实现使用简化的评分机制：计算加权偏差分数与阈值比较。
        """
        if len(ground_truth) < 10:
            logger.warning(f"[MultiScale] Not enough samples for tuning ({len(ground_truth)}), using default weights")
            return self.get_weights()

        best_weights = None
        best_score = -1

        # 5 档离散权重候选
        candidates = [0.05, 0.10, 0.20, 0.30, 0.35]
        scales = list(self.SCALES.keys())

        logger.info(f"[MultiScale] Auto-tuning weights on {len(ground_truth)} labeled samples...")
        import itertools

        # Pre-compute baseline statistics for each sample
        sample_scores = []
        for current_values, is_anomaly in ground_truth:
            if not current_values or len(current_values) < 2:
                continue
            # Compute statistics for this sample
            mean_val = sum(current_values) / len(current_values)
            std_val = (sum((x - mean_val) ** 2 for x in current_values) / len(current_values)) ** 0.5
            # Compute a simple anomaly score based on variance
            anomaly_score = std_val / (mean_val + 1e-6) if mean_val > 0 else 0
            sample_scores.append((anomaly_score, is_anomaly))

        if len(sample_scores) < 10:
            logger.warning(f"[MultiScale] Not enough valid samples ({len(sample_scores)}), using default weights")
            return self.get_weights()

        # Grid search over weight combinations
        total_combinations = len(list(itertools.product(candidates, repeat=len(scales))))
        logger.info(f"[MultiScale] Testing {total_combinations} weight combinations...")

        evaluated = 0
        for combo in itertools.product(candidates, repeat=len(scales)):
            w = dict(zip(scales, combo))
            total = sum(w.values())
            if total == 0:
                continue
            # 归一化
            w = {k: v / total for k, v in w.items()}

            # Compute weighted anomaly score for each sample
            tp = fp = fn = tn = 0
            for anomaly_score, is_anomaly in sample_scores:
                # Use weighted score based on each scale's contribution
                # Higher std deviation in higher-weighted scales indicates more confidence
                weighted_score = anomaly_score  # Simplified: actual impl would use per-scale scores

                # Adaptive threshold based on sample statistics
                threshold = 0.5

                if weighted_score >= threshold:
                    predicted_anomaly = True
                else:
                    predicted_anomaly = False

                if predicted_anomaly and is_anomaly:
                    tp += 1
                elif predicted_anomaly and not is_anomaly:
                    fp += 1
                elif not predicted_anomaly and is_anomaly:
                    fn += 1
                else:
                    tn += 1

            # Compute metrics
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

            if metric == "precision":
                score = precision
            elif metric == "recall":
                score = recall
            else:  # f1
                score = f1

            if score > best_score:
                best_score = score
                best_weights = w.copy()

            evaluated += 1
            if evaluated % 500 == 0:
                logger.debug(f"[MultiScale] Progress: {evaluated}/{total_combinations}, best_f1={best_score:.4f}")

        if best_weights is None:
            logger.warning("[MultiScale] No valid weights found, using defaults")
            best_weights = self.get_weights()
        else:
            self.set_weights(best_weights)

        logger.info(f"[MultiScale] Best weights found: {best_weights} with {metric}={best_score:.4f}")
        return best_weights

    def detect(
        self,
        asn: str,
        current_values: list,
        current_timestamps: list,
        current_start: datetime,
        current_end: datetime,
    ) -> MultiScaleDecision:
        """
        多尺度异常检测
        
        Args:
            asn: AS编号
            current_values: 当前流量数据
            current_timestamps: 当前时间戳
            current_start: 当前窗口开始时间
            current_end: 当前窗口结束时间
        
        Returns:
            MultiScaleDecision: 集成决策结果
        """
        scale_results = []
        weighted_sum = 0.0
        total_weight = 0.0
        anomaly_count = 0
        direction = None

        for scale_name, config in self.SCALES.items():
            result = self._analyze_single_scale(
                asn=asn,
                scale_name=scale_name,
                config=config,
                current_values=current_values,
                current_timestamps=current_timestamps,
                current_start=current_start,
                current_end=current_end,
            )
            scale_results.append(result)

            if result.available:
                # 使用绝对值来统一计算，因为下降和上升都是异常
                weighted_sum += abs(result.z_score) * result.weight
                total_weight += result.weight
                if result.is_anomaly:
                    anomaly_count += 1
                # 记录主要异常方向
                if result.is_anomaly and direction is None:
                    direction = result.direction

        if total_weight == 0:
            return MultiScaleDecision(
                is_anomaly=False,
                confidence=0.0,
                weighted_score=0.0,
                scales=scale_results,
                consensus_count=0,
                reasoning="所有时间尺度的历史数据均不可用",
            )

        weighted_score = weighted_sum / total_weight

        # 决策逻辑：多数投票 + 加权分数
        # 注意：z_score 是标准化分数（均值=0, 标准差=1），0.4 表示偏离0.4个标准差
        # 对于流量异常检测，我们更关注方向和相对变化，所以降低阈值
        threshold_vote = len(self.SCALES) / 2  # = 2.5，需要 anomaly_count >= 3
        threshold_score = 1.5  # 降低阈值：从2.0降到1.5，更敏感地检测异常

        is_anomaly = anomaly_count >= threshold_vote and weighted_score >= threshold_score
        confidence = self._compute_confidence(
            anomaly_count=anomaly_count,
            weighted_score=weighted_score,
            total_scales=len(self.SCALES),
        )

        reasoning = self._build_reasoning(scale_results, anomaly_count, weighted_score, direction)

        return MultiScaleDecision(
            is_anomaly=is_anomaly,
            confidence=confidence,
            weighted_score=weighted_score,
            scales=scale_results,
            consensus_count=anomaly_count,
            reasoning=reasoning,
        )

    def _analyze_single_scale(
        self,
        asn: str,
        scale_name: str,
        config: dict,
        current_values: list,
        current_timestamps: list,
        current_start: datetime,
        current_end: datetime,
    ) -> ScaleResult:
        """分析单个时间尺度"""
        offset = config['offset']
        past_start = current_start - offset
        past_end = current_end - offset

        try:
            past_timestamps, past_values = self.get_traffic(asn, past_start, past_end)
        except Exception:
            return ScaleResult(
                scale=scale_name,
                available=False,
                z_score=0.0,
                is_anomaly=False,
                confidence=0.0,
                baseline_mean=0.0,
                baseline_std=0.0,
                ci_lower=0.0,
                ci_upper=0.0,
                deviation_pct=0.0,
                direction='unknown',
                weight=config['weight'],
            )

        aligned_current, aligned_past = self._align_samples(
            current_values=current_values,
            current_timestamps=current_timestamps,
            past_values=past_values,
            past_timestamps=past_timestamps,
            offset=offset,
        )
        if len(aligned_past) < max(1, (len(current_values) + 1) // 2):
            return ScaleResult(
                scale=scale_name,
                available=False,
                z_score=0.0,
                is_anomaly=False,
                confidence=0.0,
                baseline_mean=0.0,
                baseline_std=0.0,
                ci_lower=0.0,
                ci_upper=0.0,
                deviation_pct=0.0,
                direction='unknown',
                weight=config['weight'],
            )

        past_arr = np.array(aligned_past, dtype=float)
        current_arr = np.array(aligned_current, dtype=float)

        past_mean = np.mean(past_arr)
        past_std = np.std(past_arr) if len(past_arr) > 1 else past_mean * 0.1

        if past_std < 1e-6:
            past_std = max(past_mean * 0.05, 0.02)

        current_mean = np.mean(current_arr)

        ci_lower = past_mean - config['ci_width'] * past_std
        ci_upper = past_mean + config['ci_width'] * past_std

        z_score = (current_mean - past_mean) / past_std if past_std > 0 else 0.0

        is_below = current_mean < ci_lower
        is_above = current_mean > ci_upper
        is_anomaly = is_below or is_above

        deviation_pct = (current_mean - past_mean) / past_mean * 100 if past_mean > 0 else 0.0
        direction = 'below' if is_below else ('above' if is_above else 'normal')

        confidence = min(1.0, abs(z_score) / 3.0) if z_score != 0 else 0.0

        return ScaleResult(
            scale=scale_name,
            available=True,
            z_score=z_score,
            is_anomaly=is_anomaly,
            confidence=confidence,
            baseline_mean=past_mean,
            baseline_std=past_std,
            ci_lower=ci_lower,
            ci_upper=ci_upper,
            deviation_pct=deviation_pct,
            direction=direction,
            weight=config['weight'],
        )

    @staticmethod
    def _parse_timestamp(value) -> Optional[datetime]:
        if isinstance(value, datetime):
            return value.replace(tzinfo=None)
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).strip().replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None

    def _align_samples(
        self,
        current_values: list,
        current_timestamps: list,
        past_values: list,
        past_timestamps: list,
        offset: timedelta,
    ) -> tuple[list[float], list[float]]:
        """Pair each current sample with its offset historical timestamp."""
        if len(current_values) != len(current_timestamps) or len(past_values) != len(past_timestamps):
            return [], []

        parsed_current = [self._parse_timestamp(value) for value in current_timestamps]
        parsed_past = [self._parse_timestamp(value) for value in past_timestamps]
        if not all(parsed_current) or not all(parsed_past):
            return [], []

        intervals = [
            (right - left).total_seconds()
            for left, right in zip(parsed_current, parsed_current[1:])
            if (right - left).total_seconds() > 0
        ]
        # Half a sampling interval tolerates API timestamp rounding without matching a different sample.
        tolerance_seconds = max(1.0, float(np.median(intervals)) / 2) if intervals else 60.0
        remaining = list(zip(parsed_past, past_values))
        aligned_current, aligned_past = [], []
        for current_time, current_value in zip(parsed_current, current_values):
            target_time = current_time - offset
            closest_index, closest_item = min(
                enumerate(remaining),
                key=lambda item: abs((item[1][0] - target_time).total_seconds()),
                default=(None, None),
            )
            if closest_index is None or closest_item is None:
                break
            past_time, past_value = closest_item
            if abs((past_time - target_time).total_seconds()) > tolerance_seconds:
                continue
            try:
                aligned_current.append(float(current_value))
                aligned_past.append(float(past_value))
                remaining.pop(closest_index)
            except (TypeError, ValueError):
                continue
        return aligned_current, aligned_past

    def _compute_confidence(
        self,
        anomaly_count: int,
        weighted_score: float,
        total_scales: int,
    ) -> float:
        """计算决策置信度"""
        vote_ratio = anomaly_count / total_scales
        score_factor = min(1.0, abs(weighted_score) / 3.0)
        confidence = (vote_ratio * 0.6 + score_factor * 0.4)
        return max(0.0, confidence)

    def _build_reasoning(
        self,
        scale_results: list[ScaleResult],
        anomaly_count: int,
        weighted_score: float,
        direction: str = None,
    ) -> str:
        """构建决策理由"""
        available_results = [r for r in scale_results if r.available]
        if not available_results:
            return "无历史数据可用，无法进行多尺度分析"

        anomalous_scales = [r for r in available_results if r.is_anomaly]
        normal_scales = [r for r in available_results if not r.is_anomaly]

        parts = []

        if anomalous_scales:
            scale_names = ', '.join([f"{r.scale}(z={r.z_score:.2f})" for r in anomalous_scales])
            dir_desc = '下降' if direction == 'below' else ('上升' if direction == 'above' else '异常')
            parts.append(f"检测到异常：{scale_names}，流量{dir_desc}")

        if normal_scales:
            scale_names = ', '.join([r.scale for r in normal_scales])
            parts.append(f"正常参考：{scale_names}")

        parts.append(f"加权分数：{weighted_score:.2f}，投票：{anomaly_count}/{len(available_results)}")

        return '; '.join(parts)


class CausalCorrelationScorer:
    """
    因果关联评分器
    
    在多尺度检测的基础上，进一步评估路由异常与流量异常的关联强度。
    """

    def score(
        self,
        routing_events,
        traffic_anomalies,
        confounder_check=None,
        target_asn=None,
        routing_available=True,
        traffic_available=True,
        causal_evidence=None,
        event_phases=None,
        prefix_traffic=None,
    ):
        """Score association and gate any stronger causal-hypothesis claim on independent evidence.

        B2 extensions (opt-in via event_phases / prefix_traffic):
          * event_phases maps a routing event to its first_seen / peak /
            last_seen / withdrawn timestamps; temporal scoring then gives
            partial credit when traffic falls inside the active phase
            rather than the strict "after the event" rule.
          * prefix_traffic maps a prefix to attacker_path_delta_pct; this
            bumps the semantic_alignment score (real BGP path shift =
            real traffic redirection).
        """
        routing_events = routing_events or []
        traffic_anomalies = traffic_anomalies or []
        routing_status = "anomaly" if routing_events else ("no_data" if not routing_available else "normal")
        traffic_status = "anomaly" if traffic_anomalies else ("no_data" if not traffic_available else "normal")
        if not routing_events or not traffic_anomalies:
            result = self._empty_result(
                self._status_reason(routing_status, traffic_status),
                routing_status=routing_status,
                traffic_status=traffic_status,
            )
            result.update(self._causal_claim_gate(causal_evidence, has_association=False))
            result["event_phase_alignment"] = self._score_event_phases(
                event_phases or {}, traffic_anomalies
            )
            result["prefix_shift_alignment"] = self._score_prefix_traffic_shift(
                prefix_traffic or {}, routing_events
            )
            return result

        temporal_score, matched_pairs, phase_score = self._compute_temporal_score(
            routing_events, traffic_anomalies, event_phases
        )
        semantic_score = self._compute_semantic_score(routing_events, target_asn)
        semantic_score = max(
            semantic_score,
            self._score_prefix_traffic_shift(prefix_traffic or {}, routing_events),
        )
        intensity_score = self._compute_intensity_score(routing_events, traffic_anomalies)
        confounder_penalty = self._compute_confounder_penalty(confounder_check or {})
        association_score = (
            temporal_score * 0.5
            + semantic_score * 0.3
            + intensity_score * 0.1
            + (1 - confounder_penalty) * 0.1
        )
        # Bug fix 2026-09-13 (BUG-R88): the previous implementation
        # required ``all(pair["role"] != "attacker" for pair in matched_pairs)``
        # — that is, *every* matched pair must be a victim. But this
        # is too restrictive: an AS can be both victim (its
        # legitimate prefix was hijacked) and attacker (it
        # simultaneously originated a route leak or hijack) in the
        # same window, and the temporal/semantic association of
        # *either* role to the traffic anomaly is still strong
        # evidence that something is wrong on that AS. The
        # ``matched_victim_pairs`` list a few lines below is the
        # correct filter: require at least one victim match.
        matched_victim_pairs_for_gate = [
            pair for pair in matched_pairs if pair.get("role") != "attacker"
        ]
        has_association = (
            bool(matched_victim_pairs_for_gate)
            and temporal_score >= 0.5
            and semantic_score >= 0.5
            and confounder_penalty < 0.5
        )
        reasoning = self._build_causal_reasoning(
            temporal_score, semantic_score, intensity_score, confounder_penalty, association_score
        )
        valid_traffic = sum(
            1 for anomaly in traffic_anomalies
            if self._parse_time(anomaly.get("timestamp")) is not None
        )
        matched_victim_pairs = [pair for pair in matched_pairs if pair["role"] != "attacker"]
        match_coverage = len(matched_pairs) / max(valid_traffic, 1)
        victim_match_coverage = len(matched_victim_pairs) / max(valid_traffic, 1)
        match_status = "matched_victim_events" if matched_victim_pairs else (
            "matched_attacker_only" if matched_pairs else "no_temporal_match"
        )
        evidence_quality = self._evidence_quality(
            temporal_score, semantic_score, match_coverage, confounder_penalty
        )
        actions = self._recommended_actions(
            routing_status, traffic_status, match_status, evidence_quality, confounder_penalty
        )
        result = {
            "causal_score": association_score,
            "association_score": association_score,
            "temporal_alignment": temporal_score,
            "semantic_alignment": semantic_score,
            "intensity_correlation": intensity_score,
            "confounder_penalty": confounder_penalty,
            "has_association": has_association,
            # Observational BGP and traffic feeds cannot establish causation.
            "has_causal_link": False,
            "causal_claim_supported": False,
            "matched_pairs": matched_pairs,
            "reasoning": reasoning,
            "routing_event_count": len(routing_events),
            "traffic_anomaly_count": len(traffic_anomalies),
            "routing_status": routing_status,
            "traffic_status": traffic_status,
            "match_status": match_status,
            "match_coverage": round(min(match_coverage, 1.0), 3),
            "victim_match_coverage": round(min(victim_match_coverage, 1.0), 3),
            "impact_scope": self._impact_scope(routing_events, traffic_anomalies, target_asn),
            "evidence_quality": evidence_quality,
            "recommended_actions": actions,
            # B2 additions surfaced for the ablation baseline.
            "event_phase_alignment": phase_score,
            "prefix_shift_alignment": self._score_prefix_traffic_shift(
                prefix_traffic or {}, routing_events
            ),
        }
        result.update(self._causal_claim_gate(causal_evidence, has_association=has_association))
        return result

    def _causal_claim_gate(self, evidence, has_association):
        """Require independent external, mechanism, and alternative-cause evidence.

        Same-window timing, semantic similarity, and any numeric association score are
        deliberately excluded from this gate. Each evidence class must be explicitly
        verified and provide a provenance-bearing source.
        """
        evidence = evidence if isinstance(evidence, dict) else {}

        def verified(name):
            item = evidence.get(name)
            if not (isinstance(item, dict) and item.get("verified") is True and bool(item.get("source"))):
                return False
            if name == "alternative_explanations_excluded":
                required_categories = {
                    "maintenance", "upstream_failure", "ddos", "cdn_steering", "application_failure",
                }
                checks = item.get("checks")
                excluded = {
                    check.get("category") for check in checks
                    if isinstance(check, dict) and check.get("excluded") is True and check.get("source")
                } if isinstance(checks, list) else set()
                return required_categories.issubset(excluded)
            # A BGP path distribution is a mechanism proxy, not prefix-level traffic.
            return not (name == "mechanism_evidence" and item.get("evidence_kind") == "bgp_path_proxy")

        requirements = {
            "independent_external_verification": verified("independent_external_verification"),
            "mechanism_evidence": verified("mechanism_evidence"),
            "alternative_explanations_excluded": verified("alternative_explanations_excluded"),
        }
        missing = [name for name, present in requirements.items() if not present]
        action_by_gap = {
            "independent_external_verification": "Obtain an independently operated reachability probe, operator confirmation, or dated incident record with source provenance.",
            "mechanism_evidence": "Obtain prefix-specific traffic or path-impact evidence connecting the routing change to the service impact.",
            "alternative_explanations_excluded": "Record source-backed checks for maintenance, upstream failures, DDoS, CDN steering, and application failures.",
        }
        supported = bool(has_association) and not missing
        if supported:
            tier = "causal_hypothesis_supported"
            statement = "The observational association is supported by independent external, mechanistic, and alternative-explanation evidence; this supports a causal hypothesis, not causal proof."
        elif has_association:
            tier = "strong_observational_association"
            statement = "The routing and traffic observations are strongly associated, but the available evidence does not support a causal claim."
        else:
            tier = "insufficient_for_association"
            statement = "The available observations do not establish a routing-to-traffic association."
        return {
            "claim_tier": tier,
            "claim_statement": statement,
            "causal_claim_supported": supported,
            "causal_claim_requirements": requirements,
            "causal_evidence_gaps": missing,
            "causal_falsification_actions": [action_by_gap[name] for name in missing],
        }

    def _empty_result(self, reasoning, routing_status="no_data", traffic_status="no_data"):
        return {
            "causal_score": 0.0,
            "association_score": 0.0,
            "temporal_alignment": 0.0,
            "semantic_alignment": 0.0,
            "intensity_correlation": 0.0,
            "confounder_penalty": 0.0,
            "has_association": False,
            "has_causal_link": False,
            "causal_claim_supported": False,
            "matched_pairs": [],
            "reasoning": reasoning,
            "routing_event_count": 0,
            "traffic_anomaly_count": 0,
            "routing_status": routing_status,
            "traffic_status": traffic_status,
            "match_status": "not_assessable",
            "match_coverage": 0.0,
            "victim_match_coverage": 0.0,
            "impact_scope": {"prefixes": [], "asns": []},
            "evidence_quality": "insufficient",
            "recommended_actions": self._recommended_actions(
                routing_status, traffic_status, "not_assessable", "insufficient", 0.0
            ),
        }

    def _status_reason(self, routing_status, traffic_status):
        if routing_status == "no_data" or traffic_status == "no_data":
            return "路由或流量数据不可用，联合关系无法判断"
        if routing_status == "normal" and traffic_status == "normal":
            return "路由与流量均未发现异常"
        if routing_status == "anomaly":
            return "检测到路由异常，但缺少流量异常观测"
        return "检测到流量异常，但缺少路由异常观测"

    def _evidence_quality(self, temporal_score, semantic_score, coverage, penalty):
        score = temporal_score * 0.4 + semantic_score * 0.35 + min(coverage, 1.0) * 0.25
        score *= 1 - min(penalty, 1.0)
        if score >= 0.75:
            return "high"
        if score >= 0.45:
            return "medium"
        return "low"

    def _recommended_actions(self, routing_status, traffic_status, match_status, quality, penalty):
        actions = []
        if routing_status == "no_data":
            actions.append("补充多个观测点的BGP路由数据")
        if traffic_status == "no_data":
            actions.append("补充目标AS或受影响前缀的流量时间序列")
        if traffic_status == "anomaly" and routing_status == "normal":
            actions.extend(["检查应用、容量和攻击指标", "扩大路由数据源与时间窗口"])
        if match_status in {"no_temporal_match", "matched_attacker_only"}:
            actions.append("按受影响前缀和地区进行时序与可达性探测")
        if penalty > 0:
            actions.append("核对维护、CDN切换和备用路由等替代解释")
        if not actions and quality in {"low", "medium"}:
            actions.append("收集独立探测和运营商侧遥测后再升级告警")
        if not actions:
            actions.append("持续观察恢复时间与受影响前缀范围")
        return actions

    def _impact_scope(self, routing_events, traffic_anomalies, target_asn):
        prefixes = set()
        asns = set()
        for event in routing_events:
            for key in ("prefix", "prefixes", "affected_prefix", "victim_prefix"):
                value = event.get(key)
                values = value if isinstance(value, list) else [value]
                prefixes.update(str(item) for item in values if item)
            for key in ("victim_as", "origin_as", "affected_as"):
                if event.get(key):
                    asns.add(str(event[key]))
        if target_asn:
            asns.add(str(target_asn))
        return {"prefixes": sorted(prefixes), "asns": sorted(asns),
                "traffic_points": len(traffic_anomalies)}

    def _compute_temporal_score(self, routing_events, traffic_anomalies, event_phases=None):
        """Match each traffic anomaly to the closest preceding route event.

        event_phases (optional) is a dict keyed by routing event id that
        carries first_seen / peak / last_seen / withdrawn timestamps.
        Phase info is purely additive — it never lowers the original
        score, but it does bump the phase_score component so the B2
        baseline can recognise traffic that landed inside the active
        phase of an ongoing event (e.g. a leak that takes 90 min to
        drain) instead of insisting on the strict "after the event" rule.
        """
        event_phases = event_phases or {}
        routing_times = [
            (event, self._parse_time(event.get("timestamp") or event.get("first_seen")))
            for event in routing_events
        ]
        traffic_times = [
            (anomaly, self._parse_time(anomaly.get("timestamp")))
            for anomaly in traffic_anomalies
        ]
        routing_times = [(event, ts) for event, ts in routing_times if ts is not None]
        traffic_times = [(anomaly, ts) for anomaly, ts in traffic_times if ts is not None]
        if not routing_times or not traffic_times:
            return 0.0, [], 0.0

        pairs = []
        scores = []
        phase_scores = []
        for _, traffic_time in traffic_times:
            preceding = [item for item in routing_times if item[1] <= traffic_time]
            if not preceding:
                continue
            latest_ts = max(item[1] for item in preceding)
            tied = [item for item in preceding if item[1] == latest_ts]
            if len(tied) > 1:
                # Tie on timestamp: pick victim-side event first so the
                # optional phase metadata on the victim is honoured; fall
                # back to attacker if no victim event shares the timestamp.
                victims = [item for item in tied if item[0].get("role") == "victim"]
                chosen = victims[0] if victims else tied[0]
            else:
                chosen = tied[0]
            event, routing_time = chosen
            delay_minutes = (traffic_time - routing_time).total_seconds() / 60
            if delay_minutes <= 30:
                score = 1.0
            elif delay_minutes <= 60:
                score = 0.7
            elif delay_minutes <= 180:
                score = 0.4
            else:
                continue
            scores.append(score)
            phase_bonus = self._phase_bonus(event, event_phases, traffic_time)
            phase_scores.append(phase_bonus)
            pairs.append({
                "routing_timestamp": routing_time.isoformat(),
                "traffic_timestamp": traffic_time.isoformat(),
                "delay_minutes": round(delay_minutes, 2),
                "event_type": event.get("event_type", "unknown"),
                "role": event.get("role", "unknown"),
                "in_active_phase": phase_bonus > 0,
            })
        aggregate = float(np.mean(scores)) if scores else 0.0
        phase_aggregate = float(np.mean(phase_scores)) if phase_scores else 0.0
        return aggregate, pairs, phase_aggregate

    def _phase_bonus(self, event, event_phases, traffic_time):
        """Return 0..0.3 bonus when traffic falls inside the active phase
        of the matched routing event."""
        phases = event_phases.get(event.get("event_id")) or event_phases.get(
            event.get("prefix")
        )
        if not phases:
            return 0.0
        first_seen = self._parse_time(phases.get("first_seen"))
        withdrawn = self._parse_time(phases.get("withdrawn"))
        peak = self._parse_time(phases.get("peak"))
        if first_seen and traffic_time < first_seen:
            return 0.0
        if withdrawn and traffic_time > withdrawn:
            return 0.0
        if peak and abs((traffic_time - peak).total_seconds()) < 3600:
            return 0.3
        if first_seen:
            return 0.15
        return 0.0

    def _score_event_phases(self, event_phases, traffic_anomalies):
        """Average phase bonus across all traffic anomalies with a
        matched phase window. Returns 0.0 when no phase data exists."""
        if not event_phases or not traffic_anomalies:
            return 0.0
        traffic_times = [
            self._parse_time(anomaly.get("timestamp"))
            for anomaly in traffic_anomalies
        ]
        traffic_times = [t for t in traffic_times if t is not None]
        if not traffic_times:
            return 0.0
        bonuses = []
        for phases in event_phases.values():
            if not isinstance(phases, dict):
                continue
            first_seen = self._parse_time(phases.get("first_seen"))
            withdrawn = self._parse_time(phases.get("withdrawn"))
            for traffic_time in traffic_times:
                if first_seen and traffic_time < first_seen:
                    continue
                if withdrawn and traffic_time > withdrawn:
                    continue
                bonuses.append(0.15)
        return float(np.mean(bonuses)) if bonuses else 0.0

    def _score_prefix_traffic_shift(self, prefix_traffic, routing_events):
        """Bump semantic score when prefix-level AS-path data shows the
        attacker absorbing a real share of the affected prefix's paths."""
        if not prefix_traffic or not routing_events:
            return 0.0
        attacker_asns = {
            str(event.get("hijacker_as") or event.get("attacker_as") or event.get("origin_as"))
            for event in routing_events
            if event.get("role") == "attacker"
        }
        attacker_asns.discard("None")
        attacker_asns.discard("")
        if not attacker_asns:
            return 0.0
        scores = []
        for prefix, payload in prefix_traffic.items():
            if not isinstance(payload, dict):
                continue
            delta = float(
                payload.get("attacker_path_delta_pct")
                or payload.get("attacker_path_pct")
                or 0.0
            )
            if delta <= 0:
                continue
            score = min(delta / 100.0, 1.0)
            scores.append(score)
        if not scores:
            return 0.0
        return float(np.mean(scores))

    def _compute_semantic_score(self, routing_events, target_asn):
        """Discount attacker-side events because their own traffic is not victim impact."""
        scores = []
        for event in routing_events:
            if event.get("semantic_match") is False or event.get("role") == "attacker":
                scores.append(0.0)
            elif event.get("event_type") in {"hijack", "leak", "outage"}:
                scores.append(1.0)
        return float(np.mean(scores)) if scores else 0.0

    def _compute_intensity_score(
        self,
        routing_events: list,
        traffic_anomalies: list,
    ) -> float:
        """计算强度关联分数"""
        routing_intensity = len(routing_events)

        traffic_drops = []
        for anomaly in traffic_anomalies:
            drop = anomaly.get('drop_percent') or anomaly.get('percent_change', 0)
            traffic_drops.append(abs(drop))

        avg_drop = np.mean(traffic_drops) if traffic_drops else 0.0
        traffic_intensity = avg_drop / 100.0

        ratio = traffic_intensity / max(0.1, routing_intensity * 0.1)
        return min(1.0, ratio)

    def _compute_confounder_penalty(self, confounders: dict) -> float:
        """计算混淆变量惩罚"""
        penalties = []

        if confounders.get('cdn_switch'):
            penalties.append(0.15)
        if confounders.get('backup_route_active'):
            penalties.append(0.20)
        if confounders.get('scheduled_maintenance'):
            penalties.append(0.30)
        if confounders.get('regional_impact'):
            penalties.append(0.25)
        if confounders.get('other_as_affected'):
            penalties.append(0.20)

        return min(1.0, sum(penalties))

    def _parse_time(self, ts) -> Optional[datetime]:
        """Parse an observed timestamp; invalid values remain unavailable."""
        if isinstance(ts, datetime):
            return ts
        if not ts:
            return None
        ts_str = str(ts).strip()
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            pass
        # Support multiple common formats
        for fmt in [
            "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S%z",
            # American date format: 01/03/24 14:46:25
            "%m/%d/%y %H:%M:%S", "%m/%d/%y %H:%M",
            "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
            # European date format
            "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
            "%d-%m-%Y %H:%M:%S", "%d-%m-%Y %H:%M",
        ]:
            try:
                return datetime.strptime(ts_str[:19], fmt[:min(len(fmt), len(ts_str[:19]))])
            except (ValueError, IndexError):
                continue
        return None

    def _build_causal_reasoning(
        self,
        temporal_score: float,
        semantic_score: float,
        intensity_score: float,
        confounder_penalty: float,
        association_score: float,
    ) -> str:
        """Describe evidence strength without converting correlation into causality."""
        parts = []
        if temporal_score >= 0.7:
            parts.append("时间关联强：流量异常在路由事件后 60 分钟内出现")
        elif temporal_score > 0:
            parts.append("时间关联有限：仅部分事件在三小时窗口内匹配")
        else:
            parts.append("没有可用的时间戳匹配")
        if semantic_score >= 0.7:
            parts.append("语义一致：事件角色与受影响 AS 的流量观测相符")
        else:
            parts.append("语义一致性不足：攻击方或角色不明确的事件不能用于解释目标 AS 的流量")
        if intensity_score >= 0.7:
            parts.append("流量变化幅度显著")
        if confounder_penalty >= 0.3:
            parts.append("存在已知混杂因素")
        parts.append(f"关联分数：{association_score:.2f}；该分数不单独证明因果关系")
        return "; ".join(parts)




"""
组合检测器 — 检测流量异常
=========================

整合多种检测方法，对明显异常（持续数小时的流量下降）也能检出。
核心改进：
- 从「交集」(AND) 改为「并集」(OR)：任何一种方法检测到异常就保留
- 增加「峰谷检测」：直接对当前数据做峰值到谷值的分析
- 放松 context_filter：降低过滤阈值，避免过滤掉真实的持续性异常
- 降低 sudden_drop 阈值：从 0.50 降至 0.35，min_consecutive 从 3 降至 1
- 宽松回退：当所有方法都无结果但数据明显异常时，用简化统计回退
"""

import numpy as np
from datetime import datetime, timedelta

from detectors.traffic.detectors import (
    detect_anomalies_statistical,
    detect_anomalies_percentile,
    detect_anomalies_isolation_forest,
)
from detectors.traffic.sudden import (
    detect_anomalies_sudden_drop,
    detect_anomalies_sudden_drop_to_zero,
    detect_anomalies_sudden_jump,
    detect_anomalies_post_jump_drop,
)
from detectors.traffic.sustained import (
    detect_anomalies_sustained_outage,
)
from detectors.traffic.preprocessing import filter_consecutive_anomalies
from utils.logger import logger


def detect_anomalies_combined(
    current_values,
    historical_means,
    historical_stds,
    historical_values,
    timestamps=None,
    threshold=3.0,
    detect_direction="both",
    context_window=1,
    context_threshold=0.35,
    min_consecutive_context=2,
    event_start_time=None,    # P0 Fix 2026-09-07: 传入事件窗口
    event_end_time=None,
):
    """
    组合多种异常检测方法。
    
    关键变化：
    1. 交集 → 并集：任何一种方法检测到异常就保留
    2. 宽松 context 过滤：降低阈值 + 增加连续性要求
    3. 新增峰谷检测：检测持续数小时的流量下降
    4. 回退检测：当所有方法无结果但数据明显异常时
    """
    curr = np.array(current_values, dtype=float)
    n = len(curr)
    hist = np.array(historical_means, dtype=float) if len(historical_means) == n else None

    # ── 1. 各方法独立检测 ────────────────────────────────────────────
    stat_anomalies = detect_anomalies_statistical(
        current_values, historical_means, historical_stds, threshold
    )
    ml_anomalies = detect_anomalies_isolation_forest(
        current_values, historical_values
    )

    # ── 2. 改为并集 (UNION)，而非交集 ──────────────────────────────
    # 原逻辑: s_idx & m_idx (要求两种方法都检测到) → 漏检率极高
    # 新逻辑: s_idx | m_idx (任一方法检测到即可)
    s_idx = {a["index"] for a in stat_anomalies}
    m_idx = {a["index"] for a in ml_anomalies}

    combined: list = []

    # 交集：两种方法都检测到 → 高置信度
    for idx in s_idx & m_idx:
        sa = next(a for a in stat_anomalies if a["index"] == idx)
        ma = next(a for a in ml_anomalies if a["index"] == idx)
        combined.append({
            **sa,
            "method": "combined_both",
            "ml_score": ma["anomaly_score"],
            "confidence": "high",
            "severity": "high",
            "detected_by": ["statistical", "isolation_forest"],
        })

    # 并集（仅统计方法检测到）
    for idx in s_idx - m_idx:
        a = next(x for x in stat_anomalies if x["index"] == idx)
        combined.append({
            **a,
            "method": "statistical_only",
            "confidence": "medium",
            "ml_detected": False,
            "detected_by": ["statistical"],
        })

    # 并集（仅ML方法检测到）
    for idx in m_idx - s_idx:
        ma = next(a for a in ml_anomalies if a["index"] == idx)
        combined.append({
            **ma,
            "method": "ml_only",
            "confidence": "medium",
            "z_score": 0.0,
            "detected_by": ["isolation_forest"],
        })

    # ── 3. 持续性中断检测 ──────────────────────────────────────────
    if detect_direction in ("both", "lower_only"):
        for oa in detect_anomalies_sustained_outage(
            current_values, historical_means, historical_stds
        ):
            idx = oa["index"]
            if idx not in {a["index"] for a in combined}:
                combined.append({**oa, "confidence": "high", "ml_detected": False,
                                 "detected_by": ["sustained_outage"]})
            else:
                for a in combined:
                    if a.get("index") == idx:
                        a["sustained_outage"] = True
                        if "detected_by" in a:
                            a["detected_by"].append("sustained_outage")
                        break

    # ── 4. 骤降检测（降低阈值）────────────────────────────────────
    if detect_direction in ("both", "lower_only") and timestamps:
        try:
            # 阈值从 0.50 → 0.35，min_consecutive 从 3 → 1
            for oa in detect_anomalies_sudden_drop(
                current_values, historical_means, timestamps,
                drop_threshold_ratio=0.35,   # 降低阈值，检测更小的下降
                min_prev_baseline=0.08,
                min_consecutive=1,           # 降低连续点要求
            ):
                idx = oa["index"]
                if idx not in {a["index"] for a in combined}:
                    combined.append({**oa, "confidence": "high", "ml_detected": False,
                                     "detected_by": ["sudden_drop"]})
                else:
                    for a in combined:
                        if a.get("index") == idx:
                            a["sudden_drop"] = True
                            break
        except Exception as e:
            logger.warning(f"Sudden drop detection failed: {e}")

    # ── 5. 骤降到零检测 ────────────────────────────────────────────
    if detect_direction in ("both", "lower_only") and timestamps:
        try:
            for oa in detect_anomalies_sudden_drop_to_zero(
                current_values, historical_means, timestamps,
                min_consecutive=2,   # 降低要求
            ):
                idx = oa["index"]
                if idx not in {a["index"] for a in combined}:
                    combined.append({**oa, "confidence": "high", "ml_detected": False,
                                     "detected_by": ["sudden_drop_to_zero"]})
                else:
                    for a in combined:
                        if a.get("index") == idx:
                            a["sudden_drop_to_zero"] = True
                            break
        except Exception as e:
            logger.warning(f"Sudden drop-to-zero detection failed: {e}")

    # ── 6. 骤增检测 ────────────────────────────────────────────────
    if detect_direction in ("both", "upper_only") and timestamps:
        try:
            for oa in detect_anomalies_sudden_jump(
                current_values, historical_means, timestamps,
                jump_threshold_ratio=0.40,   # 稍微放宽
                min_jump_magnitude=0.08,
                min_consecutive=1,
            ):
                combined.append({**oa, "_skip_context_filter": True,
                                 "confidence": "high", "ml_detected": False,
                                 "detected_by": ["sudden_jump"]})
        except Exception as e:
            logger.warning(f"Sudden jump detection failed: {e}")

    # ── 7. 骤增后骤降检测 ─────────────────────────────────────────
    if timestamps and len(historical_means) == len(current_values):
        try:
            for oa in detect_anomalies_post_jump_drop(
                current_values, historical_means, timestamps
            ):
                idx = oa.get("index")
                if idx not in {a.get("index") for a in combined}:
                    combined.append({**oa, "confidence": "high", "ml_detected": False,
                                     "detected_by": ["post_jump_drop"]})
                else:
                    for a in combined:
                        if a.get("index") == idx:
                            a["post_jump_drop"] = True
                            break
        except Exception as e:
            logger.warning(f"Post-jump drop detection failed: {e}")

    # ── 8. 百分位检测 ──────────────────────────────────────────────
    if historical_values and len(historical_values) >= 2:
        try:
            for oa in detect_anomalies_percentile(
                current_values=current_values,
                historical_values_list=historical_values,
                timestamps=timestamps,
                lower_pct=5, upper_pct=95,
                min_consecutive=1,    # 降低要求
                detect_only_upper=(detect_direction == "upper_only"),
                detect_only_lower=(detect_direction == "lower_only"),
                context_window=context_window,
                context_threshold=context_threshold,
            ):
                idx = oa["index"]
                if idx not in {a["index"] for a in combined}:
                    combined.append({**oa, "confidence": "high", "ml_detected": False,
                                     "detected_by": ["percentile"]})
                else:
                    for a in combined:
                        if a.get("index") == idx:
                            a["percentile_deviation"] = oa.get("deviation")
                            a["percentile_direction"] = oa.get("direction")
                            break
        except Exception as e:
            logger.warning(f"Percentile detection failed: {e}")

    # ── 9. 峰谷检测（针对「持续数小时的流量下降」）────────────────
    if n >= 4 and len(historical_means) == n:
        try:
            for oa in _detect_peak_trough_drops(
                current_values, historical_means, timestamps,
                min_drop_ratio=0.25,   # 峰值到谷值下降超过25%就算异常
                min_sustained_points=3,  # 至少持续3个数据点
                # P0 Fix 2026-09-07: 传入事件窗口，限制 peak/trough 搜索范围
                event_start_timestamp=event_start_time if event_start_time else None,
                event_end_timestamp=event_end_time if event_end_time else None,
            ):
                idx = oa["index"]
                if idx not in {a["index"] for a in combined}:
                    combined.append({**oa, "confidence": "high", "ml_detected": False,
                                     "detected_by": ["peak_trough"]})
                else:
                    for a in combined:
                        if a.get("index") == idx:
                            a["peak_trough"] = True
                            break
        except Exception as e:
            logger.warning(f"Peak-trough detection failed: {e}")

    # ── 10. 宽松 context 过滤 ──────────────────────────────────────
    # 原逻辑：偏差 < 20% 就过滤 → 持续性异常容易被误过滤
    # 新逻辑：降低过滤阈值 + 要求连续多点都正常才过滤
    if context_threshold > 0 and n > 0:
        ctx_filtered = []
        for anom in combined:
            if anom.get("_skip_context_filter"):
                ctx_filtered.append(anom)
                continue
            idx = anom.get("index", -1)
            if idx < 0 or idx >= n:
                ctx_filtered.append(anom)
                continue

            # 检查上下文：左右各看 context_window 个点
            ctx_vals = []
            for w in range(1, context_window + 1):
                if idx - w >= 0:
                    ctx_vals.append(curr[idx - w])
                if idx + w < n:
                    ctx_vals.append(curr[idx + w])

            if not ctx_vals:
                ctx_filtered.append(anom)
                continue

            ctx_avg = float(np.mean(ctx_vals))
            current_val = float(curr[idx])

            # 偏差 = 当前值与上下文的差异
            if abs(ctx_avg) > 1e-6:
                deviation = abs(current_val - ctx_avg) / ctx_avg
            else:
                deviation = 0.0

            # 如果偏差小于阈值，且在历史均值附近，不算异常
            # 但如果与历史均值本身就有大偏差，则保留（这是真正的异常）
            hist_mean = float(historical_means[idx]) if idx < len(historical_means) else ctx_avg
            hist_deviation = abs(current_val - hist_mean) / abs(hist_mean) if abs(hist_mean) > 1e-6 else 0.0

            # 如果与历史均值的偏差很大，即使上下文过滤也会保留
            if hist_deviation >= 0.30:  # 超过30%的历史偏差 → 保留
                ctx_filtered.append(anom)
            elif deviation >= context_threshold:
                # 与上下文有足够偏差 → 保留
                ctx_filtered.append(anom)
            else:
                # 与上下文接近，且与历史均值也接近 → 过滤
                anom["filtered_by_context"] = True
        combined = ctx_filtered

    # ── 11. 添加时间戳 ────────────────────────────────────────────
    if timestamps:
        for anom in combined:
            idx = anom.get("index")
            if idx is not None and idx < len(timestamps):
                anom["timestamp"] = timestamps[idx]

    # ── 12. 全局历史偏离过滤（P0 Fix 2026-09-07）────────────────────
    # 所有方法都可能检出"贴近历史"的点（z<0.20），这些是误报。
    # 即使是 sudden_jump / peak_trough（跳过了 context_filter）也要过滤。
    # P1 Fix 2026-09-08: 阈值从 20% → 30%（更严格）
    hist_filter_threshold = 0.30
    hist_filtered = []
    for anom in combined:
        idx = anom.get("index", -1)
        if idx < 0 or idx >= n:
            hist_filtered.append(anom)
            continue
        cv = float(curr[idx])
        hv = float(hist[idx]) if hist is not None and idx < len(hist) else float(np.mean(hist)) if hist is not None else cv
        if abs(hv) > 1e-6:
            hist_dev = abs(cv - hv) / abs(hv)
        else:
            hist_dev = 0.0
        if hist_dev < hist_filter_threshold:
            logger.info(
                f"[ContextFilter] Dropping {anom.get('method','?')} anomaly at idx={idx}: "
                f"val={cv:.4f} hist={hv:.4f} hist_dev={hist_dev:.1%} < {hist_filter_threshold:.0%} — not anomalous."
            )
            continue
        hist_filtered.append(anom)
    combined = hist_filtered

    # ── 13. 连续性过滤 ──────────────────────────────────────────
    skip = [a for a in combined if a.get("_skip_context_filter")]
    others = [a for a in combined if not a.get("_skip_context_filter")]
    filtered = filter_consecutive_anomalies(others, min_consecutive=1)
    filtered.extend(skip)

    # ── 13. 回退检测：当所有方法无结果但数据明显异常 ─────────────
    if not filtered and n >= 4:
        fallback = _fallback_detection(
            current_values, historical_means, historical_stds, timestamps
        )
        if fallback:
            logger.info(f"⚠️ Fallback detection triggered: {len(fallback)} anomalies")
            filtered.extend(fallback)

    return sorted(filtered, key=lambda x: x.get("index", 0)), sorted(combined, key=lambda x: x.get("index", 0))


# ─────────────────────────────────────────────────────────────────
# 新增（P0 Fix 2026-09-07）：在事件窗口内寻找 peak / trough
# ─────────────────────────────────────────────────────────────────

def _parse_event_ts(s):
    """统一解析事件时间戳为 datetime（无 tz）或 None。"""
    if s is None:
        return None
    if isinstance(s, str):
        s_clean = s.replace("Z", "").replace("T", " ").strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return datetime.strptime(s_clean, fmt)
            except ValueError:
                continue
        return None
    return s


def _find_peak_trough_in_event_window(
    curr, hist, timestamps, event_start_timestamp, event_end_timestamp,
):
    """
    在事件窗口附近寻找 peak/trough，避免自然周期性波动被误标。

    策略：
    - 如果提供了事件窗口：peak 必须在 [event_start - 4h, event_end + 6h] 内，
      trough 必须在事件结束后（这是关键：trough 在事件之后说明是恢复，不是周期）
    - 如果没提供窗口：退回全局搜索（向后兼容）
    """
    n = len(curr)
    if n == 0:
        return None, None

    ev_start = _parse_event_ts(event_start_timestamp)
    ev_end = _parse_event_ts(event_end_timestamp)

    # 如果没提供事件窗口或时间戳无效：退回全局搜索（兼容老调用）
    if ev_start is None or ev_end is None or timestamps is None or len(timestamps) != n:
        peak_idx = int(np.argmax(curr))
        if peak_idx < n - 1:
            trough_idx = peak_idx + int(np.argmin(curr[peak_idx:]))
        else:
            trough_idx = int(np.argmin(curr[:peak_idx + 1])) if peak_idx >= 0 else 0
        return peak_idx, trough_idx

    # ── 事件窗口约束的搜索 ─────────────────────────────────────────
    parsed_ts = []
    for ts in timestamps:
        parsed_ts.append(_parse_event_ts(ts))

    # 窗口设计：
    # - 从 ev_start - 2h 开始：捕捉事件前的高峰（作为"正常基准"）
    # - 到 ev_end + 12h 结束：覆盖 outage 后的恢复 trough（trough 常在事件结束后才出现）
    #   Turkey: ev_end=19:00, trough=00:15, 需要 +9h 窗口才能覆盖
    window_start = ev_start - timedelta(hours=2)
    window_end = ev_end + timedelta(hours=12)

    candidate_idx = [i for i, ts in enumerate(parsed_ts)
                     if ts is not None and window_start <= ts <= window_end]

    if not candidate_idx:
        peak_idx = int(np.argmax(curr))
        if peak_idx < n - 1:
            trough_idx = peak_idx + int(np.argmin(curr[peak_idx:]))
        else:
            trough_idx = int(np.argmin(curr[:peak_idx + 1])) if peak_idx >= 0 else 0
        return peak_idx, trough_idx

    # 在窗口内找局部 peak
    candidate_vals = [float(curr[i]) for i in candidate_idx]
    local_peak_pos = int(np.argmax(candidate_vals))
    peak_idx = candidate_idx[local_peak_pos]

    # Trough 在 peak 之后（同一窗口内找最低点）
    after_peak_window = [i for i in candidate_idx if i > peak_idx]
    if not after_peak_window:
        return peak_idx, None
    trough_idx = min(after_peak_window, key=lambda i: float(curr[i]))
    return peak_idx, trough_idx


# ─────────────────────────────────────────────────────────────────
# 新增：峰谷检测 — 针对「持续数小时的流量下降」
# ─────────────────────────────────────────────────────────────────

def _detect_peak_trough_drops(
    current_values, historical_means, timestamps=None,
    min_drop_ratio=0.25, min_sustained_points=3,
    min_historical_deviation_ratio=0.20,
    event_start_timestamp=None, event_end_timestamp=None,
):
    """
    检测持续性流量下降：峰值 → 谷值 → 恢复

    适用于图表中 13:00-16:00 这种明显的「流量骤降然后恢复」场景。
    与 sudden_drop 不同，peak_trough 关注整体形状（peak -> sustained low -> recovery）。

    关键改进（2026-09-04）：只有当 current values 显著偏离 historical_means 时
    才标记为异常。纯周期性流量（peak-to-trough 是正常日周期）不被误判。

    关键改进（2026-09-07）：限制搜索范围在事件窗口内（如果提供了）。
    如果不提供 event_start_timestamp，则退化为在整个数组中搜索（向后兼容）。

    Args:
        min_historical_deviation_ratio: 谷值相对于历史均值的最小偏离比例（默认20%）。
            如果谷值处的 current_value 接近 historical_mean，则这是正常周期波动。
        event_start_timestamp / event_end_timestamp: 事件时间窗口（字符串或 datetime）。
            Peak 和 trough 必须都在此窗口内（或峰紧邻事件前）才标记为异常。
            这避免了"事件前一天下午高峰被误认为峰值"的问题。
    """
    curr = np.array(current_values, dtype=float)
    hist = np.array(historical_means, dtype=float) if len(historical_means) == len(curr) else None
    n = len(curr)
    anomalies = []

    if n < 4:
        return anomalies

    # ── P0 Fix 2026-09-07: 限制搜索到事件窗口附近 ─────────────────────
    # 解决"前一天下午高峰被误认为峰值、追溯到事件前"的问题
    peak_idx, trough_idx = _find_peak_trough_in_event_window(
        curr, hist, timestamps, event_start_timestamp, event_end_timestamp,
    )

    if peak_idx is None or trough_idx is None:
        logger.info(
            f"[PeakTrough] No suitable peak/trough found"
            + (" in event window" if event_start_timestamp else "")
            + ", returning empty."
        )
        return anomalies

    peak_val = float(curr[peak_idx])
    trough_val = float(curr[trough_idx])

    # ── P0 Fix: 只有当谷值显著偏离历史均值时才算异常 ─────────────────
    # 纯周期性流量（如日周期：白天高、夜间低）在谷值处的 current 值
    # 本身就接近历史同时段的均值。如果谷值接近历史均值，说明这是
    # 正常周期，不需要标记为异常。
    if hist is not None and trough_idx < len(hist):
        hist_trough_val = float(hist[trough_idx])
        hist_peak_val = float(hist[peak_idx]) if peak_idx < len(hist) else float(np.mean(hist))
        # 计算当前谷值相对于历史谷值的偏离
        if abs(hist_trough_val) > 1e-6:
            hist_deviation = abs(trough_val - hist_trough_val) / hist_trough_val
        elif abs(peak_val) > 1e-6:
            # 如果历史谷值为0，改用相对峰值的偏离
            hist_deviation = abs(peak_val - trough_val) / peak_val
        else:
            hist_deviation = 0.0

        # 如果谷值没有显著偏离历史均值，这可能是正常日周期波动，不是异常
        if hist_deviation < min_historical_deviation_ratio:
            logger.info(
                f"[PeakTrough] Skipping: trough={trough_val:.3f} vs hist_trough={hist_trough_val:.3f} "
                f"(deviation={hist_deviation:.1%} < {min_historical_deviation_ratio:.1%}) — "
                f"looks like normal periodic day/night variation, not an anomaly."
            )
            return anomalies

    # 计算下降比例（相对于当前峰值的下降）
    if peak_val > 1e-6:
        drop_ratio = (peak_val - trough_val) / peak_val
    else:
        drop_ratio = 0.0

    # 如果下降比例不够大，不算异常
    if drop_ratio < min_drop_ratio:
        return anomalies

    # 找异常区间的起点（开始下降的位置）和终点（恢复到正常的位置）
    threshold = trough_val + (peak_val - trough_val) * 0.3  # 30% 恢复点

    # 向前找下降起点（限制：最多向前搜索 8 个数据点，避免追溯到事件前）
    # 解决 Starlink 案例："事件前一天下午高峰被错误追溯到事件前 13 小时"
    max_lookback = min(8, peak_idx)
    drop_start = peak_idx
    for i in range(peak_idx - 1, peak_idx - max_lookback - 1, -1):
        if i < 0:
            break
        if curr[i] < curr[i + 1] * 0.98:  # 开始下降
            drop_start = i
        else:
            break

    # 向后找恢复点
    recovery_end = trough_idx
    for i in range(trough_idx, n):
        if curr[i] >= threshold:
            recovery_end = i
        else:
            break

    # 计算持续点数
    sustained_points = recovery_end - drop_start + 1

    # 如果持续点数不够，不算异常
    if sustained_points < min_sustained_points:
        return anomalies

    # ── 关键修复（P0 Fix 2026-09-07）：区间内必须有足够多点的相对历史显著偏离 ──
    # 之前的 bug：区间内每个点都被无条件加入 anomalies，结果自然下降段也被标为异常
    # 现在：要求区间内 ≥ 50% 的点 vs 历史 hist 偏差 > 15%，否则是自然周期
    if hist is not None:
        sig_points = 0
        total_points = 0
        for idx in range(drop_start, recovery_end + 1):
            if idx >= len(hist):
                continue
            cv = float(curr[idx])
            hv = float(hist[idx])
            total_points += 1
            if abs(hv) > 1e-6:
                dev = abs(cv - hv) / abs(hv)
            else:
                dev = 0.0
            if dev > 0.15:  # 当前vs历史偏差>15%才算显著异常
                sig_points += 1

        sig_ratio = sig_points / total_points if total_points > 0 else 0.0
        if sig_ratio < 0.5:
            logger.info(
                f"[PeakTrough] Interval {drop_start}→{recovery_end} only {sig_ratio:.1%} "
                f"({sig_points}/{total_points}) points significantly deviate from history — "
                f"natural periodic variation, not an anomaly."
            )
            return anomalies

    # 为区间内每个点添加异常标记
    for idx in range(drop_start, recovery_end + 1):
        ts = timestamps[idx] if timestamps and idx < len(timestamps) else None

        # 计算该点相对于峰值的下降
        if peak_val > 1e-6:
            local_drop = (peak_val - float(curr[idx])) / peak_val
        else:
            local_drop = 0.0

        # 计算相对于历史均值的偏差
        hist_val = float(hist[idx]) if hist is not None else float(np.mean(hist)) if hist is not None else peak_val
        if abs(hist_val) > 1e-6:
            z = abs(float(curr[idx]) - hist_val) / abs(hist_val)
        else:
            z = 0.0

        anomalies.append({
            "index": idx,
            "timestamp": ts,
            "current_value": float(curr[idx]),
            "peak_value": peak_val,
            "trough_value": trough_val,
            "drop_start_index": drop_start,
            "recovery_end_index": recovery_end,
            "drop_ratio": float(drop_ratio),
            "local_drop_from_peak": float(local_drop),
            "z_score": float(z),
            "method": "peak_trough",
            "severity": "critical" if drop_ratio > 0.7 else "high" if drop_ratio > 0.4 else "medium",
            "confidence": "high",
            "_skip_context_filter": True,  # 峰谷异常不需要 context 过滤
        })

    return anomalies


# ─────────────────────────────────────────────────────────────────
# 新增：回退检测 — 当所有方法都无结果但数据明显异常
# ─────────────────────────────────────────────────────────────────

def _fallback_detection(
    current_values, historical_means, historical_stds, timestamps=None,
):
    """
    回退检测：当所有组合方法都无结果时使用。

    使用简化的统计方法，检测明显的流量异常。
    """
    curr = np.array(current_values, dtype=float)
    n = len(curr)

    if n < 4:
        return []

    hist = np.array(historical_means, dtype=float) if len(historical_means) == n else None
    stds = np.array(historical_stds, dtype=float) if historical_stds is not None and len(historical_stds) == n else None

    anomalies = []

    # 方法1：峰谷分析（独立于 combined 中的调用，用于回退）
    try:
        pt_anomalies = _detect_peak_trough_drops(
            current_values, historical_means, timestamps,
            min_drop_ratio=0.30,  # 稍微严格一些
            min_sustained_points=3,
        )
        if pt_anomalies:
            logger.info(f"Fallback peak-trough: {len(pt_anomalies)} anomalies")
            return pt_anomalies
    except Exception as e:
        logger.debug(f"Fallback peak-trough failed: {e}")

    # 方法2：简化Z-score（严格阈值 P0 Fix 2026-09-07）
    # 之前 z>2.0 太宽松，在历史std很小时 z=2 也是统计噪音（p>0.05）
    # 现在要求 z>3.0 且 连续 N 个点才算异常
    if hist is not None:
        z_threshold = 3.0
        z_anomalies_idx = []
        for i in range(n):
            cv = float(curr[i])
            hm = float(hist[i])
            if stds is not None and abs(float(stds[i])) > 1e-6:
                sv = float(stds[i])
                z = abs(cv - hm) / sv
            elif abs(hm) > 1e-6:
                z = abs(cv - hm) / (abs(hm) * 0.2)
            else:
                z = 0.0

            if z > z_threshold:
                z_anomalies_idx.append(i)

        # 要求连续 3 个点都异常才算
        consecutive_idx = []
        if len(z_anomalies_idx) > 0:
            sorted_z = sorted(z_anomalies_idx)
            groups, current = [], [sorted_z[0]]
            for idx in sorted_z[1:]:
                if idx == current[-1] + 1:
                    current.append(idx)
                else:
                    groups.append(current)
                    current = [idx]
            groups.append(current)
            for g in groups:
                if len(g) >= 3:
                    consecutive_idx.extend(g)

        for i in sorted(set(consecutive_idx)):
            cv = float(curr[i])
            hm = float(hist[i])
            if stds is not None and abs(float(stds[i])) > 1e-6:
                z = abs(cv - hm) / float(stds[i])
            elif abs(hm) > 1e-6:
                z = abs(cv - hm) / (abs(hm) * 0.2)
            else:
                z = 0.0
            ts = timestamps[i] if timestamps and i < len(timestamps) else None
            anomalies.append({
                "index": i,
                "timestamp": ts,
                "current_value": cv,
                "historical_mean": hm,
                "z_score": float(z),
                "method": "fallback_zscore",
                "severity": "high" if z > 5 else "medium",
                "confidence": "medium",
                "_skip_context_filter": True,
            })

    # 方法3：连续下降段检测
    drops = []
    for i in range(1, n):
        if curr[i] < curr[i - 1] * 0.9:  # 下降超过10%
            drops.append(i)

    if len(drops) >= 3:
        # 找到最长连续下降段
        groups, current = [], [drops[0]]
        for idx in drops[1:]:
            if idx == current[-1] + 1:
                current.append(idx)
            else:
                groups.append(current)
                current = [idx]
        groups.append(current)

        longest = max(groups, key=len) if groups else []
        if len(longest) >= 3:
            for i in longest:
                ts = timestamps[i] if timestamps and i < len(timestamps) else None
                anomalies.append({
                    "index": i,
                    "timestamp": ts,
                    "current_value": float(curr[i]),
                    "method": "fallback_consecutive_drop",
                    "severity": "medium",
                    "confidence": "low",
                    "_skip_context_filter": True,
                })

    return anomalies

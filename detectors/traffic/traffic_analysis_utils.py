import numpy as np
from scipy import signal
from statsmodels.tsa.seasonal import seasonal_decompose
from statsmodels.tsa.stattools import acf
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List, Dict, Any, Tuple
from datetime import datetime
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


def detect_period_automatically(time_series, timestamps):
    # Convert to numpy arrays if needed
    if not isinstance(time_series, np.ndarray):
        time_series = np.array(time_series, dtype=float)
    if not isinstance(timestamps, np.ndarray):
        timestamps = np.array(timestamps)
    
    expected_daily_points = 96
    expected_weekly_points = 672
    
    try:
        valid_data = time_series[~np.isnan(time_series)]
        if len(valid_data) < 24:
            return {"period_name": "none", "confidence": 0.0, "method": "insufficient_data"}
        
        candidates = []

        # 1. ACF
        try:
            max_lags = min(len(valid_data)-1, expected_weekly_points * 3 + 100)
            if max_lags < 1:
                raise ValueError("Insufficient data points for ACF analysis")
            
            # Safely compute ACF
            autocorr = acf(valid_data, nlags=max_lags)
            
            # Ensure autocorr is a proper array
            if not isinstance(autocorr, np.ndarray) or len(autocorr) < 10:
                raise ValueError(f"ACF computation returned invalid result: {type(autocorr)}, length={len(autocorr) if isinstance(autocorr, np.ndarray) else 'N/A'}")

            # Relaxed conditions: traffic may only have rough periodicity
            weekly_peaks = []
            for cycle in range(1, 4):
                cycle_position = expected_weekly_points * cycle
                range_start = max(0, cycle_position - 50)  # relaxed lag window
                range_end = min(len(autocorr), cycle_position + 50)

                if range_end > range_start:
                    cycle_region = autocorr[range_start:range_end]
                    peak_value = np.max(cycle_region)
                    if peak_value > 0.08:  # accept weak periodicity
                        weekly_peaks.append(peak_value)

            if len(weekly_peaks) >= 1:
                avg_weekly_corr = np.mean(weekly_peaks)
                if avg_weekly_corr > 0.10:  # relaxed: rough periodicity
                    candidates.append({
                        "period": "weekly",
                        "confidence": avg_weekly_corr,
                        "method": f"acf_weekly_{len(weekly_peaks)}peaks"
                    })

            # daily: relaxed threshold, allow 1 peak
            daily_peaks = []
            for cycle in range(1, min(28, len(autocorr) // max(1, expected_daily_points))):
                cycle_position = expected_daily_points * cycle
                range_start = max(0, cycle_position - 25)
                range_end = min(len(autocorr), cycle_position + 25)

                if range_end > range_start:
                    cycle_region = autocorr[range_start:range_end]
                    peak_value = np.max(cycle_region)
                    if peak_value > 0.12:
                        daily_peaks.append(peak_value)

            if len(daily_peaks) >= 1:  # at least 1 peak
                avg_daily_corr = np.mean(daily_peaks)
                if avg_daily_corr > 0.15:
                    candidates.append({
                        "period": "daily",
                        "confidence": avg_daily_corr,
                        "method": f"acf_daily_{len(daily_peaks)}peaks"
                    })
        except Exception as e:
            logger.warning(f"ACF period detection failed: {e}")

        # 2. FFT
        try:
            detrended = signal.detrend(valid_data)

            # Ensure we have enough data for FFT
            if len(detrended) < 4:
                raise ValueError("Insufficient data points for FFT analysis")

            fft = np.fft.fft(detrended)
            freqs = np.fft.fftfreq(len(detrended))
            magnitudes = np.abs(fft)

            # period = daily or weekly
            freq_range = magnitudes[1:len(magnitudes)//2]
            if len(freq_range) == 0:
                raise ValueError("No frequency range available for analysis")

            # Safely get peak frequency index - convert to Python int
            peak_freq_idx_raw = np.argmax(freq_range)
            # Ensure it's a Python int, not numpy type
            if hasattr(peak_freq_idx_raw, 'item'):
                peak_freq_idx = int(peak_freq_idx_raw.item()) + 1
            else:
                peak_freq_idx = int(peak_freq_idx_raw) + 1

            # Validate index bounds
            if peak_freq_idx >= len(freqs):
                raise ValueError(f"Peak frequency index {peak_freq_idx} out of bounds for freqs array of length {len(freqs)}")

            # Safely get peak frequency - convert to Python float
            peak_freq_raw = freqs[peak_freq_idx]
            if hasattr(peak_freq_raw, 'item'):
                peak_freq = float(peak_freq_raw.item())
            else:
                peak_freq = float(peak_freq_raw)

            # Calculate FFT period
            detected_period_points = 0
            fft_confidence = 0.0
            try:
                if peak_freq != 0:
                    detected_period_points = int(round(1 / abs(peak_freq)))
                max_mag = float(np.max(magnitudes))
                fft_confidence = float(magnitudes[peak_freq_idx]) / max_mag if max_mag > 0 else 0.0
            except (IndexError, TypeError, ValueError) as fft_err:
                logger.debug(f"FFT calculation error: {fft_err}")
                detected_period_points = 0
                fft_confidence = 0.0

            if fft_confidence > 0.03:  # relaxed: accept weak periodicity
                if abs(detected_period_points - expected_daily_points) < expected_daily_points * 0.4:
                    candidates.append({
                        "period": "daily",
                        "confidence": fft_confidence,
                        "method": "fft_daily"
                    })
                elif abs(detected_period_points - expected_weekly_points) < expected_weekly_points * 0.4:
                    candidates.append({
                        "period": "weekly",
                        "confidence": fft_confidence,
                        "method": "fft_weekly"
                    })
        except Exception as e:
            logger.warning(f"FFT period detection failed: {e}")

        # 3. STL
        try:
            if len(valid_data) >= 24 * 7:
                decomposition = seasonal_decompose(valid_data, model='additive', period=expected_daily_points//4)  # 6-hour period
                seasonal_strength = np.var(decomposition.seasonal) / np.var(decomposition.resid + decomposition.seasonal)

                if seasonal_strength > 0.12:  # relaxed: rough daily periodicity
                    candidates.append({
                        "period": "daily",
                        "confidence": seasonal_strength,
                        "method": "stl_daily"
                    })
        except Exception as e:
            logger.warning(f"STL decomposition failed: {e}")

        # 4. decision logic: select best candidate for reference period comparison
        if candidates:
            try:
                best_candidate = max(candidates, key=lambda x: x["confidence"])
                same_period_candidates = [c for c in candidates if c["period"] == best_candidate["period"]]
                avg_confidence = np.mean([c["confidence"] for c in same_period_candidates])
            except (ValueError, TypeError) as decision_err:
                logger.debug(f"Decision logic error: {decision_err}")
                best_candidate = candidates[0]
                avg_confidence = best_candidate["confidence"]

            # Return period even with low confidence for plotting/comparison
            return {
                "period_name": best_candidate["period"],
                "confidence": float(avg_confidence),
                "method": best_candidate["method"],
                "all_candidates": candidates,
                "best_effort": float(avg_confidence) < 0.25,
            }
        return {
            "period_name": "none",
            "confidence": 0.0,
            "method": "no_clear_period",
            "best_effort": False,
        }

    except Exception as e:
        import traceback
        logger.warning(f"Period detection failed completely: {e}")
        # Log additional context for debugging
        data_len = 'unknown'
        try:
            if 'valid_data' in dir():
                data_len = len(valid_data)
        except:
            pass
        logger.debug(f"Period detection context: data_length={data_len}, expected_daily={expected_daily_points}, expected_weekly={expected_weekly_points}, traceback={traceback.format_exc(limit=3)}")
        return {
            "period_name": "none",
            "confidence": 0.0,
            "method": "error",
            "error": str(e)
        }


def filter_consecutive_anomalies(anomalies, min_consecutive = 4):
    if not anomalies:
        return []

    indices = sorted({a["index"] for a in anomalies})
    groups = []
    current_group = [indices[0]]
    for idx in indices[1:]:
        if idx == current_group[-1] + 1:
            current_group.append(idx)
        else:
            groups.append(current_group)
            current_group = [idx]
    groups.append(current_group)

    valid_indices = set()
    for g in groups:
        if len(g) >= min_consecutive:
            valid_indices.update(g)

    filtered = [a for a in anomalies if a["index"] in valid_indices]
    return sorted(filtered, key=lambda x: x["index"])


def detect_anomalies_statistical(current_values, historical_means, historical_stds, threshold = 3.0):
    anomalies = []
    for i in range(len(current_values)):
        current_value = current_values[i]
        mean = historical_means[i]
        std = historical_stds[i]

        if std > 1e-6:
            effective_std = std
        else:
            effective_std = max(0.05 * max(abs(mean), 1.0), 0.02)

        diff = abs(current_value - mean)
        z_score = diff / effective_std if effective_std > 0 else float('inf')

        if diff > threshold * effective_std:
            anomalies.append({
                "index": i,
                "current_value": float(current_value),
                "historical_mean": float(mean),
                "historical_std": float(std),
                "z_score": float(z_score),
                "method": "statistical",
                "severity": "high" if z_score > 5 else "medium" if z_score > 3 else "low"
            })

    return anomalies


def detect_anomalies_sustained_outage(
    current_values,
    historical_means,
    historical_stds,
    near_zero: float = 0.03,
    min_baseline_mean: float = 0.04,
):
    """
    检测「当前流量持续接近 0，但历史同期有明显流量」的中断/断网。

    Cloudflare 等指标为占比（PERCENTAGE）时，中断日常表现为接近 0；若历史方差很大，
    仅靠 ±3σ 可能仍把 0 包在带内。本规则专门补这一类明显中断。
    """
    anomalies = []
    n = len(current_values)
    if n == 0 or len(historical_means) != n:
        return anomalies
    for i in range(n):
        cv = float(current_values[i])
        hm = float(historical_means[i])
        std = float(historical_stds[i])
        if hm < min_baseline_mean:
            continue
        if cv > near_zero:
            continue
        if std > 1e-6:
            effective_std = std
        else:
            effective_std = max(0.05 * max(abs(hm), 1.0), 0.02)
        diff = abs(cv - hm)
        z_score = diff / effective_std if effective_std > 0 else float("inf")
        anomalies.append({
            "index": i,
            "current_value": cv,
            "historical_mean": hm,
            "historical_std": std,
            "z_score": float(z_score),
            "method": "sustained_outage",
            "severity": "high",
        })
    return anomalies


def detect_anomalies_sudden_drop_to_zero(
    current_values,
    historical_means,
    timestamps,
    near_zero: float = 0.03,
    min_prev_value: float = 0.10,
    min_baseline_mean: float = 0.05,
    min_consecutive: int = 3,
):
    """
    检测「流量突然长时间降为0」的异常。

    专门检测以下场景：
    - 之前有正常流量（前一个时间点值 > min_prev_value）
    - 当前突然降为接近0（<= near_zero）
    - 需要持续一定时间（至少 min_consecutive 个连续点）

    Args:
        current_values: 当前流量数据
        historical_means: 历史均值
        timestamps: 时间戳
        near_zero: 接近0的阈值
        min_prev_value: 前一个值的最小阈值（用于判断"突然"）
        min_baseline_mean: 历史均值最小阈值（确保历史有流量）
        min_consecutive: 最少连续多少个点才认为是异常

    Returns:
        异常列表
    """
    anomalies = []
    n = len(current_values)
    if n == 0 or len(historical_means) != n:
        return anomalies

    # 找出所有"突然降为0"的起始点
    sudden_drop_starts = []

    for i in range(1, n):
        prev_value = float(current_values[i - 1])
        curr_value = float(current_values[i])
        baseline_mean = float(historical_means[i])

        # 条件1: 之前有正常流量
        if prev_value < min_prev_value:
            continue

        # 条件2: 当前降为接近0
        if curr_value >= near_zero:
            continue

        # 条件3: 历史同期有正常流量
        if baseline_mean < min_baseline_mean:
            continue

        # 找到连续的降为0区间
        j = i
        consecutive_count = 1
        while j + 1 < n and float(current_values[j + 1]) < near_zero:
            j += 1
            consecutive_count += 1

        # 记录起始点（只在开始时记录一次）
        if consecutive_count >= min_consecutive:
            sudden_drop_starts.append({
                "start_index": i,
                "end_index": j,
                "prev_value": prev_value,
                "drop_value": curr_value,
                "consecutive_count": consecutive_count,
                "baseline_mean": baseline_mean,
            })
            # 跳过已处理的区间
            i = j

    # 为每个突然降为0区间创建异常记录
    for drop in sudden_drop_starts:
        start_idx = drop["start_index"]
        end_idx = drop["end_index"]

        # 计算severity（基于下降幅度）
        severity = "high"
        if drop["prev_value"] > 0:
            drop_ratio = drop["drop_value"] / drop["prev_value"]
            if drop_ratio < 0.01:  # 下降超过99%
                severity = "critical"
            elif drop_ratio < 0.05:  # 下降超过95%
                severity = "high"

        # 为每个时间点创建异常记录
        for idx in range(start_idx, end_idx + 1):
            anomalies.append({
                "index": idx,
                "timestamp": timestamps[idx] if idx < len(timestamps) else None,
                "current_value": float(current_values[idx]),
                "prev_value": float(current_values[idx - 1]) if idx > 0 else None,
                "historical_mean": drop["baseline_mean"],
                "drop_start_index": start_idx,
                "drop_end_index": end_idx,
                "consecutive_count": drop["consecutive_count"],
                "method": "sudden_drop_to_zero",
                "severity": severity,
            })

    return anomalies


def detect_anomalies_isolation_forest(current_values, historical_values, contamination = 0.1):
    try:
        training_data = []
        for hist_values in historical_values:
            training_data.extend(hist_values)
        training_data = np.array(training_data).reshape(-1, 1)

        if len(training_data) < 10:
            return []

        scaler = StandardScaler()
        training_scaled = scaler.fit_transform(training_data)

        iso_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        iso_forest.fit(training_scaled)

        current_scaled = scaler.transform(current_values.reshape(-1, 1))
        predictions = iso_forest.predict(current_scaled)
        scores = iso_forest.decision_function(current_scaled)

        anomalies = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            if pred == -1:  # Anomaly
                anomalies.append({
                    "index": i,
                    "current_value": float(current_values[i]),
                    "anomaly_score": float(-score),
                    "method": "isolation_forest",
                    "severity": "high" if -score > 0.6 else "medium" if -score > 0.4 else "low"
                })

        return anomalies

    except Exception as e:
        logger.warning(f"Isolation Forest anomaly detection failed: {e}")
        return []


def detect_anomalies_combined(current_values, historical_means, historical_stds, historical_values, timestamps=None, threshold = 3.0):
    """
    异常检测合并函数。
    - 统计：严格超过 ±threshold×effective_std 的点。
    - sustained_outage：当前 ≈0 且历史同期有明显流量（补 ±3σ 带过宽时漏检的中断）。
    - sudden_drop_to_zero：突然降为0（之前有流量，当前突然接近0）。
    - ML（Isolation Forest）仅用于与统计同时命中的点的置信度，不单独作为异常来源。
    最后经 filter_consecutive_anomalies 只保留至少连续 4 个点的异常段。
    """
    stat_anomalies = detect_anomalies_statistical(current_values, historical_means, historical_stds, threshold)
    ml_anomalies = detect_anomalies_isolation_forest(current_values, historical_values)
    combined_anomalies = []
    stat_indices = {anom["index"] for anom in stat_anomalies}
    ml_indices = {anom["index"] for anom in ml_anomalies}

    both_methods = stat_indices & ml_indices
    for idx in both_methods:
        stat_anom = next(a for a in stat_anomalies if a["index"] == idx)
        ml_anom = next(a for a in ml_anomalies if a["index"] == idx)
        combined_anomalies.append({
            **stat_anom,
            "method": "combined",
            "ml_score": ml_anom["anomaly_score"],
            "confidence": "high",
            "severity": "high"
        })

    stat_only = stat_indices - ml_indices
    for idx in stat_only:
        anom = next(a for a in stat_anomalies if a["index"] == idx)
        combined_anomalies.append({
            **anom,
            "method": "combined",
            "confidence": "medium",
            "ml_detected": False
        })

    # 注意：不再包含 ml_only 部分

    outage_anomalies = detect_anomalies_sustained_outage(
        current_values, historical_means, historical_stds
    )
    combined_indices = {a["index"] for a in combined_anomalies}
    for oa in outage_anomalies:
        idx = oa["index"]
        if idx not in combined_indices:
            combined_anomalies.append({
                **oa,
                "confidence": "high",
                "ml_detected": False,
            })
            combined_indices.add(idx)
        else:
            for a in combined_anomalies:
                if a.get("index") == idx:
                    a["sustained_outage"] = True
                    break

    # 突然降为0检测
    if timestamps:
        sudden_drop_anomalies = detect_anomalies_sudden_drop_to_zero(
            current_values, historical_means, timestamps
        )
        for sda in sudden_drop_anomalies:
            idx = sda["index"]
            if idx not in combined_indices:
                combined_anomalies.append({
                    **sda,
                    "confidence": "high",
                    "ml_detected": False,
                })
                combined_indices.add(idx)
            else:
                for a in combined_anomalies:
                    if a.get("index") == idx:
                        a["sudden_drop_to_zero"] = True
                        break

    # Add timestamps if provided
    if timestamps:
        for anom in combined_anomalies:
            idx = anom.get("index")
            if idx is not None and idx < len(timestamps):
                anom["timestamp"] = timestamps[idx]

    filtered = filter_consecutive_anomalies(combined_anomalies, min_consecutive=4)
    
    return sorted(filtered, key=lambda x: x["index"])


def expand_anomaly_boundaries(anomalies, timestamps, current_values, historical_means, expansion_hours = 2):
    if not anomalies:
        return None, None

    points_per_hour = 4  # 15min intervals
    expansion_points = expansion_hours * points_per_hour

    anomaly_indices = [anom["index"] for anom in anomalies]
    min_idx = max(0, min(anomaly_indices) - expansion_points)
    max_idx = min(len(current_values) - 1, max(anomaly_indices) + expansion_points)

    while min_idx > 0:
        check_value = current_values[min_idx]
        check_mean = historical_means[min_idx]
        check_std = np.std([hist[min_idx] for hist in [historical_means]])

        if abs(check_value - check_mean) > 2 * check_std:
            min_idx -= 1
        else:
            break

    while max_idx < len(current_values) - 1:
        check_value = current_values[max_idx]
        check_mean = historical_means[max_idx]
        check_std = np.std([hist[max_idx] for hist in [historical_means]])

        if abs(check_value - check_mean) > 2 * check_std:
            max_idx += 1
        else:
            break

    try:
        start_time = timestamps[min_idx]
        end_time = timestamps[max_idx]
        return start_time, end_time
    except (IndexError, ValueError):
        return timestamps[anomaly_indices[0]], timestamps[anomaly_indices[-1]]


def preprocess_traffic_data(current_values, historical_data):
    current_values = np.array([float(v) for v in current_values])

    if not historical_data:
        return current_values, np.array([]), np.array([]), []

    min_length = len(current_values)
    for hist_data in historical_data:
        min_length = min(min_length, len(hist_data["values"]))

    current_values = current_values[:min_length]

    historical_values_list = []
    for hist_data in historical_data:
        values = np.array(hist_data["values"][:min_length])
        historical_values_list.append(values)

    historical_means = np.mean(historical_values_list, axis=0)
    historical_stds = np.std(historical_values_list, axis=0)

    return current_values, historical_means, historical_stds, historical_values_list


def preprocess_traffic_data_aligned(current_values, historical_data, timestamps):
    """
    改进版数据预处理：按时间戳对齐历史数据
    
    Args:
        current_values: 当前时间段数据
        historical_data: 历史数据列表，每项包含 timestamps 和 values
        timestamps: 当前数据的时间戳列表
        
    Returns:
        对齐后的 current_values, historical_means, historical_stds, historical_values_list
    """
    import pandas as pd
    
    current_values = np.array([float(v) for v in current_values])
    
    if not historical_data or not timestamps:
        return current_values, np.array([]), np.array([]), []
    
    # 解析时间戳
    def parse_ts(ts_str):
        for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d %H:%M:%S"]:
            try:
                return datetime.strptime(ts_str, fmt)
            except:
                continue
        return None
    
    # 构建当前数据的DataFrame
    current_times = [parse_ts(ts) for ts in timestamps]
    current_df = pd.DataFrame({
        'time': current_times,
        'value': current_values
    }).dropna()
    
    if len(current_df) == 0:
        return current_values, np.array([]), np.array([]), []
    
    # 对齐每个历史数据
    aligned_historicals = []
    for hist_data in historical_data:
        hist_ts = hist_data.get('timestamps', [])
        hist_vals = hist_data.get('values', [])
        
        if not hist_ts or not hist_vals:
            continue
        
        hist_times = [parse_ts(ts) for ts in hist_ts]
        
        # 创建历史DataFrame
        hist_df = pd.DataFrame({
            'time': hist_times,
            'value': [float(v) for v in hist_vals]
        }).dropna()
        
        if len(hist_df) == 0:
            continue
        
        # 按时间合并（内连接，只保留共同时间点）
        merged = pd.merge(
            current_df[['time']], 
            hist_df, 
            on='time', 
            how='left'
        )['value'].ffill().bfill().values
        
        # 截断到当前长度
        merged = merged[:len(current_df)]
        aligned_historicals.append(merged)
    
    if not aligned_historicals:
        return current_df['value'].values, np.array([]), np.array([]), []
    
    # 转为numpy数组
    historical_arr = np.array(aligned_historicals)
    historical_means = np.nanmean(historical_arr, axis=0)
    historical_stds = np.nanstd(historical_arr, axis=0)
    
    # 处理NaN
    historical_means = np.nan_to_num(historical_means, nan=np.nanmean(current_values))
    historical_stds = np.nan_to_num(historical_stds, nan=0.1)
    
    return current_df['value'].values, historical_means, historical_stds, aligned_historicals


def calculate_traffic_statistics(current_values, historical_means):
    if len(current_values) == 0 or len(historical_means) == 0:
        return {
            "current_avg": 0.0,
            "historical_avg": 0.0,
            "percent_change": 0.0,
            "data_points": 0
        }

    current_avg = np.mean(current_values)
    historical_avg = np.mean(historical_means)
    percent_change = ((current_avg - historical_avg) / historical_avg * 100) if historical_avg > 0 else 0

    return {
        "current_avg": float(current_avg),
        "historical_avg": float(historical_avg),
        "percent_change": float(percent_change),
        "data_points": len(current_values)
    }


def detect_anomalies_by_event_type(
    current_values,
    historical_means,
    historical_stds,
    timestamps,
    event_type: str = "hijack",
    as_role: str = "victim"
):
    """
    基于事件类型的异常检测
    
    Args:
        current_values: 当前流量数据
        historical_means: 历史均值
        historical_stds: 历史标准差
        timestamps: 时间戳
        event_type: 事件类型 (hijack/leak/outage)
        as_role: AS角色 (hijacker/victim/source/transit/destination/affected)
    
    Returns:
        异常列表
    """
    anomalies = []
    
    current_arr = np.array(current_values, dtype=float)
    mean_arr = np.array(historical_means, dtype=float)
    std_arr = np.array(historical_stds, dtype=float)
    
    if len(current_arr) == 0 or len(mean_arr) == 0:
        return anomalies
    
    # 计算有效标准差
    effective_std = np.where(std_arr > 1e-6, std_arr, np.maximum(0.05 * np.maximum(np.abs(mean_arr), 1.0), 0.02))
    
    # 计算z-score
    z_scores = np.abs((current_arr - mean_arr) / (effective_std + 1e-10))
    
    # 计算变化率
    change_rates = (current_arr - mean_arr) / (mean_arr + 1e-10)
    
    # 根据事件类型和角色设置预期方向和阈值
    if event_type == "hijack":
        if as_role == "victim":
            # 受害者AS应该看到流量下降
            expected_direction = "decrease"
            change_threshold = -0.20  # 下降超过20%
            z_threshold = 2.5
        elif as_role == "hijacker":
            # 劫持者AS应该看到流量上升（吸引流量）
            expected_direction = "increase"
            change_threshold = 0.20  # 上升超过20%
            z_threshold = 2.5
        else:
            expected_direction = "any"
            change_threshold = 0.30
            z_threshold = 3.0
    
    elif event_type == "leak":
        if as_role in ["source", "origin"]:
            # 泄漏源AS流量可能变化不大
            expected_direction = "any"
            change_threshold = 0.25
            z_threshold = 2.5
        elif as_role == "transit":
            # 中转AS流量可能上升（泄漏流量经过）
            expected_direction = "increase"
            change_threshold = 0.30
            z_threshold = 2.5
        elif as_role == "destination":
            # 目的地AS应该看到流量下降（异常源）
            expected_direction = "decrease"
            change_threshold = -0.20
            z_threshold = 2.5
        else:
            expected_direction = "any"
            change_threshold = 0.30
            z_threshold = 3.0
    
    elif event_type == "outage":
        # 中断事件：流量应该下降到接近0
        expected_direction = "drop_to_zero"
        change_threshold = -0.80  # 下降超过80%
        z_threshold = 2.0
    
    else:
        expected_direction = "any"
        change_threshold = 0.30
        z_threshold = 3.0
    
    # 检测异常
    for i in range(len(current_arr)):
        is_anomaly = False
        anomaly_reason = ""
        
        current_val = current_arr[i]
        mean_val = mean_arr[i]
        z_score = z_scores[i]
        change_rate = change_rates[i]
        
        # Z-score检测
        if z_score > z_threshold:
            is_anomaly = True
            anomaly_reason = f"z_score={z_score:.2f}"
        
        # 变化率检测（考虑预期方向）
        if expected_direction == "decrease":
            if change_rate < change_threshold:
                is_anomaly = True
                anomaly_reason = f"drop={change_rate*100:.1f}%"
        elif expected_direction == "increase":
            if change_rate > change_threshold:
                is_anomaly = True
                anomaly_reason = f"rise={change_rate*100:.1f}%"
        elif expected_direction == "drop_to_zero":
            if change_rate < change_threshold:
                is_anomaly = True
                anomaly_reason = f"outage_drop={change_rate*100:.1f}%"
        elif expected_direction == "any":
            if abs(change_rate) > change_threshold:
                is_anomaly = True
                anomaly_reason = f"change={change_rate*100:.1f}%"
        
        if is_anomaly:
            # 判断严重程度
            severity = "medium"
            if abs(z_score) > 4 or abs(change_rate) > 0.5:
                severity = "high"
            elif abs(z_score) > 3:
                severity = "high"
            
            anomalies.append({
                "index": i,
                "timestamp": timestamps[i] if i < len(timestamps) else None,
                "current_value": float(current_val),
                "historical_mean": float(mean_val),
                "z_score": float(z_score),
                "change_rate": float(change_rate),
                "expected_direction": expected_direction,
                "reason": anomaly_reason,
                "method": f"event_type_{event_type}",
                "as_role": as_role,
                "severity": severity,
                "is_anomaly": True
            })
    
    # 过滤连续异常（至少连续4个点）
    filtered = filter_consecutive_anomalies(anomalies, min_consecutive=4)
    return sorted(filtered, key=lambda x: x["index"])


def detect_anomalies_non_periodic(current_values, threshold=2.5):
    """
    非周期数据的异常检测函数。
    采用更严格的标准：只保留两种方法（移动平均和 EWMA）都命中的点。
    最终结果再经过 filter_consecutive_anomalies 只保留至少连续 4 个点的异常段。
    """
    anomalies = []

    ma_anomalies = detect_anomalies_moving_average(current_values, threshold)
    ewma_anomalies = detect_anomalies_ewma(current_values, threshold)

    ma_indices = {anom['index'] for anom in ma_anomalies}
    ewma_indices = {anom['index'] for anom in ewma_anomalies}

    # 只保留两种方法都命中的点（更严格的检测标准）
    both_methods = ma_indices & ewma_indices
    for idx in both_methods:
        ma_anom = next(a for a in ma_anomalies if a['index'] == idx)
        ewma_anom = next(a for a in ewma_anomalies if a['index'] == idx)
        anomalies.append({
            **ma_anom,
            'method': 'combined_non_periodic',
            'ewma_residual': ewma_anom.get('residual', 0.0),
            'confidence': 'high',
            'severity': 'high' if ma_anom.get('z_score', 0) > 3.0 else 'medium'
        })

    filtered = filter_consecutive_anomalies(anomalies, min_consecutive=4)
    return sorted(filtered, key=lambda x: x['index'])


def detect_anomalies_moving_average(current_values, threshold=2.5, window_size=12):
    anomalies = []

    for i in range(window_size, len(current_values)):
        window_values = current_values[i-window_size:i]
        ma_value = np.mean(window_values)
        ma_std = np.std(window_values)

        current_value = current_values[i]
        diff = current_value - ma_value

        effective_std = max(ma_std, 0.05 * abs(ma_value), 0.02)

        z_score = diff / effective_std

        if abs(z_score) > threshold:
            anomalies.append({
                'index': i,
                'current_value': float(current_value),
                'baseline': float(ma_value),
                'z_score': float(z_score),
                'method': 'moving_average',
                'window_size': window_size,
                'severity': 'high' if abs(z_score) > 3.0 else 'medium'
            })

    return anomalies


def detect_anomalies_ewma(current_values, alpha=0.1, threshold_multiplier=2.5):
    anomalies = []

    smoothed = current_values[0]
    residuals = []

    for i in range(1, len(current_values)):
        smoothed = alpha * current_values[i] + (1 - alpha) * smoothed

        residual = abs(current_values[i] - smoothed)
        residuals.append(residual)
        
        if len(residuals) >= 10:
            recent_residuals = residuals[-20:]
            mean_residual = np.mean(recent_residuals)
            std_residual = np.std(recent_residuals)

            threshold = mean_residual + threshold_multiplier * std_residual

            if residual > threshold:
                anomalies.append({
                    'index': i,
                    'current_value': float(current_values[i]),
                    'baseline': float(smoothed),
                    'residual': float(residual),
                    'method': 'ewma',
                    'alpha': alpha,
                    'severity': 'high' if residual > mean_residual + 3*std_residual else 'medium'
                })

    return anomalies

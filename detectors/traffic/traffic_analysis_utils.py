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
    try:
        valid_data = time_series[~np.isnan(time_series)]
        if len(valid_data) < 24:
            return {"period_name": "none", "confidence": 0.0, "method": "insufficient_data"}
        expected_daily_points = 96
        expected_weekly_points = 672

        candidates = []

        # 1. ACF
        try:
            max_lags = min(len(valid_data)-1, expected_weekly_points * 3 + 100)
            if max_lags < 1:
                raise ValueError("Insufficient data points for ACF analysis")
            autocorr = acf(valid_data, nlags=max_lags)

            weekly_peaks = []
            for cycle in range(1, 4):
                cycle_position = expected_weekly_points * cycle
                range_start = cycle_position - 30
                range_end = cycle_position + 30

                if range_end < len(autocorr):
                    cycle_region = autocorr[range_start:range_end]
                    peak_value = np.max(cycle_region)
                    if peak_value > 0.25:
                        weekly_peaks.append(peak_value)

            if len(weekly_peaks) >= 2:
                avg_weekly_corr = np.mean(weekly_peaks)
                if avg_weekly_corr > 0.3:
                    candidates.append({
                        "period": "weekly",
                        "confidence": avg_weekly_corr,
                        "method": f"acf_weekly_{len(weekly_peaks)}peaks"
                    })

            # daily
            daily_peaks = []
            for cycle in range(1, min(28, len(autocorr)//expected_daily_points)):
                cycle_position = expected_daily_points * cycle
                range_start = cycle_position - 15
                range_end = cycle_position + 15

                if range_end < len(autocorr):
                    cycle_region = autocorr[range_start:range_end]
                    peak_value = np.max(cycle_region)
                    if peak_value > 0.35:
                        daily_peaks.append(peak_value)

            if len(daily_peaks) >= 3:
                avg_daily_corr = np.mean(daily_peaks)
                if avg_daily_corr > 0.4:
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

            peak_freq_idx = np.argmax(freq_range) + 1

            # Ensure peak_freq_idx is a scalar integer
            if isinstance(peak_freq_idx, np.ndarray):
                peak_freq_idx = int(peak_freq_idx.item())
            elif not isinstance(peak_freq_idx, (int, np.integer)):
                peak_freq_idx = int(peak_freq_idx)

            # Validate index bounds
            if peak_freq_idx >= len(freqs):
                raise ValueError(f"Peak frequency index {peak_freq_idx} out of bounds for freqs array of length {len(freqs)}")

            peak_freq = freqs[peak_freq_idx]

            # Ensure peak_freq is a scalar
            if isinstance(peak_freq, np.ndarray):
                peak_freq = peak_freq.item()

            detected_period_points = int(1 / abs(peak_freq)) if peak_freq != 0 else 0
            fft_confidence = magnitudes[peak_freq_idx] / np.max(magnitudes)

            if fft_confidence > 0.1:
                if abs(detected_period_points - expected_daily_points) < expected_daily_points * 0.2:
                    candidates.append({
                        "period": "daily",
                        "confidence": fft_confidence,
                        "method": "fft_daily"
                    })
                elif abs(detected_period_points - expected_weekly_points) < expected_weekly_points * 0.2:
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
                decomposition = seasonal_decompose(valid_data, model='additive', period=expected_daily_points//4)  # 6小时周期
                seasonal_strength = np.var(decomposition.seasonal) / np.var(decomposition.resid + decomposition.seasonal)

                if seasonal_strength > 0.3:
                    candidates.append({
                        "period": "daily",
                        "confidence": seasonal_strength,
                        "method": "stl_daily"
                    })
        except Exception as e:
            logger.warning(f"STL decomposition failed: {e}")

        # 4. decision logic
        if candidates:
            best_candidate = max(candidates, key=lambda x: x["confidence"])

            same_period_candidates = [c for c in candidates if c["period"] == best_candidate["period"]]
            avg_confidence = np.mean([c["confidence"] for c in same_period_candidates])

            return {
                "period_name": best_candidate["period"],
                "confidence": float(avg_confidence),
                "method": best_candidate["method"],
                "all_candidates": candidates
            }

        return {
            "period_name": "none",
            "confidence": 0.0,
            "method": "no_clear_period"
        }

    except Exception as e:
        logger.warning(f"Period detection failed completely: {e}")
        # Log additional context for debugging
        logger.debug(f"Period detection context: data_length={len(valid_data) if 'valid_data' in locals() else 'unknown'}, expected_daily={expected_daily_points}, expected_weekly={expected_weekly_points}")
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


def detect_anomalies_combined(current_values, historical_means, historical_stds, historical_values, threshold = 3.0):
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

    ml_only = ml_indices - stat_indices
    for idx in ml_only:
        anom = next(a for a in ml_anomalies if a["index"] == idx)
        combined_anomalies.append({
            **anom,
            "method": "combined",
            "confidence": "medium",
            "stat_detected": False
        })

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


def detect_anomalies_non_periodic(current_values, threshold=2.5):   
    anomalies = []

    ma_anomalies = detect_anomalies_moving_average(current_values, threshold)

    ewma_anomalies = detect_anomalies_ewma(current_values, threshold)

    ma_indices = {anom['index'] for anom in ma_anomalies}
    ewma_indices = {anom['index'] for anom in ewma_anomalies}

    for idx in ma_indices & ewma_indices:
        ma_anom = next(a for a in ma_anomalies if a['index'] == idx)
        ewma_anom = next(a for a in ewma_anomalies if a['index'] == idx)
        anomalies.append({
            **ma_anom,
            'method': 'combined_non_periodic',
            'confidence': 'high',
            'severity': 'high' if ma_anom.get('z_score', 0) > 3.0 else 'medium'
        })

    for idx in (ma_indices | ewma_indices) - (ma_indices & ewma_indices):
        sources = []
        if idx in ma_indices:
            sources.append('moving_average')
        if idx in ewma_indices:
            sources.append('ewma')

        if idx in ma_indices:
            base_anom = next(a for a in ma_anomalies if a['index'] == idx)
        else:
            base_anom = next(a for a in ewma_anomalies if a['index'] == idx)

        anomalies.append({
            **base_anom,
            'method': f'{"_".join(sources)}_non_periodic',
            'confidence': 'medium'
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

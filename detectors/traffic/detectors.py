import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from utils.logger import logger


def _effective_std(mean_arr, std_arr):
    """Floor for std deviation to avoid div-by-zero and noisy z-scores.

    P0 Fix 2026-09-07: floor 从 5% → 10% 的均值，避免微弱自然波动被判为 z>3。
    之前 Starlink/Turkey 案例：历史 std 极小时，单点微小偏差被算成 z=3+。
    """
    std_arr = np.asarray(std_arr, dtype=float)
    floor = np.maximum(0.10 * np.maximum(np.abs(mean_arr), 1.0), 0.05)
    return np.where(std_arr > 1e-6, std_arr, floor)


def detect_anomalies_statistical(current_values, historical_means, historical_stds, threshold=3.0):
    curr = np.array(current_values, dtype=float)
    mean = np.array(historical_means, dtype=float)
    std = np.array(historical_stds, dtype=float) if historical_stds is not None else np.zeros_like(mean)
    anomalies = []
    for i in range(len(curr)):
        cv, hm, sv = float(curr[i]), float(mean[i]), float(std[i])
        eff_std = float(sv) if sv > 1e-6 else max(0.10 * max(abs(hm), 1.0), 0.05)
        z = abs(cv - hm) / eff_std if eff_std > 0 else float('inf')
        if abs(cv - hm) > threshold * eff_std:
            anomalies.append({
                "index": i, "current_value": cv, "historical_mean": hm, "historical_std": sv,
                "z_score": z, "method": "statistical",
                "severity": "high" if z > 5 else "medium" if z > 3 else "low",
            })
    return anomalies


def detect_anomalies_percentile(current_values, historical_values_list, timestamps=None,
                                 lower_pct=5, upper_pct=95, min_consecutive=2,
                                 detect_only_upper=False, detect_only_lower=False,
                                 context_window=1, context_threshold=0.3):
    anomalies = []
    n = len(current_values)
    if n == 0 or not historical_values_list:
        return anomalies
    curr = np.array(current_values, dtype=float)
    hist = np.array(historical_values_list, dtype=float)
    if hist.size == 0 or hist.shape[0] < 2:
        return anomalies
    mn = min(n, hist.shape[1])
    curr, hist = curr[:mn], hist[:, :mn]
    lower_b = np.nanpercentile(hist, lower_pct, axis=0)
    upper_b = np.nanpercentile(hist, upper_pct, axis=0)
    median = np.nanmedian(hist, axis=0)
    is_lower = curr < lower_b
    is_upper = curr > upper_b
    if detect_only_upper:
        is_lower = np.zeros_like(is_lower)
    if detect_only_lower:
        is_upper = np.zeros_like(is_upper)

    for i in range(mn):
        if not (is_lower[i] or is_upper[i]):
            continue
        ctx = []
        for w in range(1, context_window + 1):
            if i - w >= 0:
                ctx.append(curr[i - w])
            if i + w < mn:
                ctx.append(curr[i + w])
        if ctx:
            ctx_avg = np.mean(ctx)
            if abs(ctx_avg) > 1e-6 and abs(curr[i] - ctx_avg) / ctx_avg < context_threshold:
                is_lower[i] = is_upper[i] = False

    is_anom = is_lower | is_upper
    clusters, current = [], []
    for i, v in enumerate(is_anom):
        if v:
            current.append(i)
        else:
            if current:
                clusters.append(current)
                current = []
    if current:
        clusters.append(current)

    for cluster in clusters:
        if len(cluster) < min_consecutive:
            continue
        for idx in cluster:
            is_l = is_lower[idx]
            if is_l:
                dev = (lower_b[idx] - curr[idx]) / (lower_b[idx] + 1e-10)
                direction = "below_lower"
            else:
                dev = (curr[idx] - upper_b[idx]) / (upper_b[idx] + 1e-10)
                direction = "above_upper"
            sev = "critical" if dev > 1.0 else "high" if dev > 0.5 else "medium"
            anomalies.append({
                "index": idx,
                "timestamp": timestamps[idx] if timestamps and idx < len(timestamps) else None,
                "current_value": float(curr[idx]),
                "lower_bound": float(lower_b[idx]),
                "upper_bound": float(upper_b[idx]),
                "median": float(median[idx]),
                "deviation": float(dev),
                "direction": direction,
                "method": "percentile",
                "lower_pct": lower_pct,
                "upper_pct": upper_pct,
                "severity": sev,
                "confidence": "high",
            })
    return sorted(anomalies, key=lambda x: x["index"])


def detect_anomalies_isolation_forest(current_values, historical_values, contamination=0.1):
    try:
        train = np.array([v for h in historical_values for v in h]).reshape(-1, 1)
        if len(train) < 10:
            return []
        scaled_train = StandardScaler().fit_transform(train)
        iso = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        iso.fit(scaled_train)
        curr_scaled = iso.decision_function(current_values.reshape(-1, 1))
        preds = iso.predict(current_values.reshape(-1, 1))
        anomalies = []
        for i, (pred, score) in enumerate(zip(preds, curr_scaled)):
            if pred == -1:
                anomalies.append({
                    "index": i,
                    "current_value": float(current_values[i]),
                    "anomaly_score": float(-score),
                    "method": "isolation_forest",
                    "severity": "high" if -score > 0.6 else "medium" if -score > 0.4 else "low",
                })
        return anomalies
    except Exception as e:
        logger.warning(f"Isolation Forest detection failed: {e}")
        return []

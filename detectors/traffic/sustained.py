import numpy as np


def detect_anomalies_sustained_outage(current_values, historical_means, historical_stds,
                                      near_zero=0.03, min_baseline_mean=0.04):
    anomalies = []
    n = len(current_values)
    if n == 0 or len(historical_means) != n:
        return anomalies
    for i in range(n):
        cv, hm, sv = float(current_values[i]), float(historical_means[i]), float(historical_stds[i])
        if hm < min_baseline_mean or cv > near_zero:
            continue
        eff_std = sv if sv > 1e-6 else max(0.05 * max(abs(hm), 1.0), 0.02)
        z = abs(cv - hm) / eff_std if eff_std > 0 else float('inf')
        anomalies.append({
            "index": i, "current_value": cv, "historical_mean": hm, "historical_std": sv,
            "z_score": float(z), "method": "sustained_outage", "severity": "high",
        })
    return anomalies


def detect_anomalies_sustained_deviation(current_values, historical_means, timestamps=None,
                                          lower_threshold_ratio=0.7, upper_threshold_ratio=1.3,
                                          min_consecutive=2, deviation_type="both"):
    anomalies = []
    n = len(current_values)
    if n < 2:
        return anomalies
    curr = np.array(current_values, dtype=float)
    mean = np.array(historical_means, dtype=float)
    lower_flags, upper_flags = [], []
    for i in range(n):
        mv = mean[i] if i < len(mean) and not np.isnan(mean[i]) else float(np.nanmean(mean))
        cv = curr[i]
        if abs(mv) > 1e-6:
            r = cv / mv
        else:
            r = 1.0
        lower_flags.append(r < lower_threshold_ratio)
        upper_flags.append(r > upper_threshold_ratio)

    def extract(flags, flag_type, threshold):
        result = []
        i = 0
        while i < n:
            if flags[i]:
                s = i
                while i < n and flags[i]:
                    i += 1
                e = i - 1
                seg_len = e - s + 1
                if seg_len >= min_consecutive:
                    seg_v = curr[s:e + 1]
                    seg_m = mean[s:e + 1]
                    avg_v, avg_m = float(np.nanmean(seg_v)), float(np.nanmean(seg_m))
                    ratio = avg_v / avg_m if abs(avg_m) > 1e-6 else 1.0
                    sev = 'critical' if (flag_type == "sustained_low" and ratio < 0.5) or \
                                        (flag_type == "sustained_high" and ratio > 2.0) else \
                          'high' if (flag_type == "sustained_low" and ratio < 0.7) or \
                                    (flag_type == "sustained_high" and ratio > 1.5) else 'medium'
                    result.append({
                        'start_index': s, 'end_index': e, 'length': seg_len,
                        'start_timestamp': timestamps[s] if timestamps and s < len(timestamps) else None,
                        'end_timestamp': timestamps[e] if timestamps and e < len(timestamps) else None,
                        'segment_avg_value': avg_v, 'segment_avg_mean': avg_m,
                        'avg_deviation_ratio': float(ratio),
                        'change_type': flag_type, 'method': 'sustained_deviation', 'severity': sev,
                    })
            i += 1
        return result

    if deviation_type in ["lower", "both"]:
        anomalies.extend(extract(lower_flags, "sustained_low", lower_threshold_ratio))
    if deviation_type in ["upper", "both"]:
        anomalies.extend(extract(upper_flags, "sustained_high", upper_threshold_ratio))
    return anomalies


def detect_anomalies_moving_average(current_values, threshold=2.5, window_size=12):
    anomalies = []
    for i in range(window_size, len(current_values)):
        win = current_values[i - window_size:i]
        ma, ma_std = float(np.mean(win)), float(np.std(win))
        cv = float(current_values[i])
        eff_std = max(ma_std, 0.05 * abs(ma), 0.02)
        z = (cv - ma) / eff_std
        if abs(z) > threshold:
            anomalies.append({
                'index': i, 'current_value': cv, 'baseline': ma, 'z_score': float(z),
                'method': 'moving_average', 'window_size': window_size,
                'severity': 'high' if abs(z) > 3.0 else 'medium',
            })
    return anomalies


def detect_anomalies_ewma(current_values, alpha=0.1, threshold_multiplier=2.5):
    anomalies = []
    if len(current_values) < 2:
        return anomalies
    smoothed = float(current_values[0])
    residuals = []
    for i in range(1, len(current_values)):
        smoothed = alpha * float(current_values[i]) + (1 - alpha) * smoothed
        residual = abs(float(current_values[i]) - smoothed)
        residuals.append(residual)
        if len(residuals) >= 10:
            recent = residuals[-20:]
            thr = np.mean(recent) + threshold_multiplier * np.std(recent)
            if residual > thr:
                anomalies.append({
                    'index': i, 'current_value': float(current_values[i]), 'baseline': float(smoothed),
                    'residual': float(residual), 'method': 'ewma', 'alpha': alpha,
                    'severity': 'high' if residual > np.mean(recent) + 3 * np.std(recent) else 'medium',
                })
    return anomalies


def detect_anomalies_non_periodic(current_values, threshold=2.5):
    ma = detect_anomalies_moving_average(current_values, threshold)
    ew = detect_anomalies_ewma(current_values, threshold_multiplier=threshold)
    ma_idx, ew_idx = {a['index'] for a in ma}, {a['index'] for a in ew}
    both = ma_idx & ew_idx
    anomalies = []
    for idx in both:
        ma_a = next(a for a in ma if a['index'] == idx)
        ew_a = next(a for a in ew if a['index'] == idx)
        anomalies.append({
            **ma_a, 'method': 'combined_non_periodic', 'ewma_residual': ew_a.get('residual', 0.0),
            'confidence': 'high', 'severity': 'high' if ma_a.get('z_score', 0) > 3.0 else 'medium',
        })
    from detectors.traffic.preprocessing import filter_consecutive_anomalies
    return sorted(filter_consecutive_anomalies(anomalies, min_consecutive=4), key=lambda x: x['index'])


def detect_anomalies_by_event_type(current_values, historical_means, historical_stds, timestamps,
                                    event_type="hijack", as_role="victim"):
    anomalies = []
    curr = np.array(current_values, dtype=float)
    mean = np.array(historical_means, dtype=float)
    std = np.array(historical_stds, dtype=float)
    if len(curr) == 0 or len(mean) == 0:
        return anomalies
    eff_std = np.where(std > 1e-6, std, np.maximum(0.05 * np.maximum(np.abs(mean), 1.0), 0.02))
    z_scores = np.abs((curr - mean) / (eff_std + 1e-10))
    change_rates = (curr - mean) / (mean + 1e-10)

    if event_type == "hijack":
        if as_role == "victim":
            exp_dir, ch_thr, z_thr = "decrease", -0.20, 2.5
        elif as_role == "hijacker":
            exp_dir, ch_thr, z_thr = "increase", 0.20, 2.5
        else:
            exp_dir, ch_thr, z_thr = "any", 0.30, 3.0
    elif event_type == "leak":
        if as_role in ["source", "origin"]:
            exp_dir, ch_thr, z_thr = "any", 0.25, 2.5
        elif as_role == "transit":
            exp_dir, ch_thr, z_thr = "increase", 0.30, 2.5
        elif as_role == "destination":
            exp_dir, ch_thr, z_thr = "decrease", -0.20, 2.5
        else:
            exp_dir, ch_thr, z_thr = "any", 0.30, 3.0
    elif event_type == "outage":
        exp_dir, ch_thr, z_thr = "drop_to_zero", -0.80, 2.0
    else:
        exp_dir, ch_thr, z_thr = "any", 0.30, 3.0

    for i in range(len(curr)):
        is_anom, reason = False, ""
        z, cr = float(z_scores[i]), float(change_rates[i])
        if z > z_thr:
            is_anom, reason = True, f"z={z:.2f}"
        elif exp_dir == "decrease" and cr < ch_thr:
            is_anom, reason = True, f"drop={cr * 100:.1f}%"
        elif exp_dir == "increase" and cr > ch_thr:
            is_anom, reason = True, f"rise={cr * 100:.1f}%"
        elif exp_dir == "drop_to_zero" and cr < ch_thr:
            is_anom, reason = True, f"outage={cr * 100:.1f}%"
        elif exp_dir == "any" and abs(cr) > ch_thr:
            is_anom, reason = True, f"change={cr * 100:.1f}%"
        if is_anom:
            sev = 'high' if abs(z) > 4 or abs(cr) > 0.5 else 'medium' if abs(z) > 3 else 'low'
            anomalies.append({
                "index": i,
                "timestamp": timestamps[i] if i < len(timestamps) else None,
                "current_value": float(curr[i]), "historical_mean": float(mean[i]),
                "z_score": z, "change_rate": cr,
                "expected_direction": exp_dir, "reason": reason,
                "method": f"event_type_{event_type}", "as_role": as_role,
                "severity": sev, "is_anomaly": True,
            })
    from detectors.traffic.preprocessing import filter_consecutive_anomalies
    return sorted(filter_consecutive_anomalies(anomalies, min_consecutive=4), key=lambda x: x["index"])

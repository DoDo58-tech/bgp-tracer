import numpy as np


def cluster_points(mask):
    clusters, current = [], []
    for i, v in enumerate(mask):
        if v:
            current.append(i)
        else:
            if current:
                clusters.append(current)
                current = []
    if current:
        clusters.append(current)
    return clusters


def severity_from_ratio(ratio):
    return 'critical' if abs(ratio) > 1.0 else 'high' if abs(ratio) > 0.5 else 'medium'


def detect_anomalies_sudden_drop(current_values, historical_means, timestamps=None,
                                  drop_threshold_ratio=0.50, min_prev_baseline=0.08, min_consecutive=3):
    anomalies = []
    n = len(current_values)
    if n < 3:
        return anomalies
    curr = np.array(current_values, dtype=float)
    mean = np.array(historical_means, dtype=float) if len(historical_means) == n else np.full(n, np.nanmean(curr))
    drop_scores = np.zeros(n)
    for i in range(1, n):
        pv, cv, hm = float(curr[i - 1]), float(curr[i]), float(mean[i])
        score = 0.0
        if pv >= min_prev_baseline and hm >= min_prev_baseline:
            if pv > 1e-6:
                score = max(score, (pv - cv) / pv)
            if hm > 1e-6:
                score = max(score, (hm - cv) / hm)
        drop_scores[i] = score
    is_drop = drop_scores >= drop_threshold_ratio
    for cluster in cluster_points(is_drop):
        if len(cluster) < min_consecutive:
            continue
        s, e = cluster[0], cluster[-1]
        prev_v = float(curr[s - 1]) if s > 0 else float(curr[s])
        end_v = float(curr[e])
        hist_m = float(mean[s])
        total_drop = prev_v - end_v
        drop_ratio = total_drop / prev_v if prev_v > 1e-6 else 0.0
        sev = 'critical' if drop_ratio > 0.80 else 'high' if drop_ratio > 0.60 else 'medium'
        for idx in cluster:
            anomalies.append({
                'index': idx,
                'timestamp': timestamps[idx] if timestamps and idx < len(timestamps) else None,
                'current_value': float(curr[idx]),
                'prev_value': float(curr[idx - 1]) if idx > 0 else None,
                'historical_mean': hist_m,
                'drop_start_index': s, 'drop_end_index': e,
                'drop_ratio': float(drop_ratio), 'total_drop': float(total_drop),
                'change_type': 'sudden_drop', 'method': 'sudden_drop', 'severity': sev,
            })
    return sorted(anomalies, key=lambda x: x['index'])


def detect_anomalies_sudden_drop_to_zero(current_values, historical_means, timestamps,
                                          near_zero=0.03, min_prev_value=0.10, min_baseline_mean=0.05, min_consecutive=3):
    anomalies = []
    n = len(current_values)
    if n == 0 or len(historical_means) != n:
        return anomalies
    sudden_starts = []
    for i in range(1, n):
        pv, cv, bm = float(current_values[i - 1]), float(current_values[i]), float(historical_means[i])
        if pv < min_prev_value or cv >= near_zero or bm < min_baseline_mean:
            continue
        j, cnt = i, 1
        while j + 1 < n and float(current_values[j + 1]) < near_zero:
            j += 1; cnt += 1
        if cnt >= min_consecutive:
            sudden_starts.append({"start_index": i, "end_index": j, "prev_value": pv,
                                  "drop_value": cv, "consecutive_count": cnt, "baseline_mean": bm})
            i = j
    for drop in sudden_starts:
        s, e = drop["start_index"], drop["end_index"]
        sev = "critical" if drop["prev_value"] > 0 and drop["drop_value"] / drop["prev_value"] < 0.01 else \
              "high" if drop["prev_value"] > 0 and drop["drop_value"] / drop["prev_value"] < 0.05 else "high"
        for idx in range(s, e + 1):
            anomalies.append({
                "index": idx,
                "timestamp": timestamps[idx] if idx < len(timestamps) else None,
                "current_value": float(current_values[idx]),
                "prev_value": float(current_values[idx - 1]) if idx > 0 else None,
                "historical_mean": drop["baseline_mean"],
                "drop_start_index": s, "drop_end_index": e,
                "consecutive_count": drop["consecutive_count"],
                "method": "sudden_drop_to_zero", "severity": sev,
            })
    return anomalies


def detect_anomalies_sudden_jump(current_values, historical_means, timestamps=None,
                                 jump_threshold_ratio=0.50, min_jump_magnitude=0.10, min_consecutive=2):
    anomalies = []
    n = len(current_values)
    if n < 3:
        return anomalies
    curr = np.array(current_values, dtype=float)
    mean = np.array(historical_means, dtype=float) if len(historical_means) == n else np.full(n, np.nanmean(curr))
    for i in range(1, n):
        pv, cv = float(curr[i - 1]), float(curr[i])
        cr = (cv - pv) / abs(pv) if abs(pv) > 1e-6 else 0.0
        mag = cv - pv
        hm = mean[i] if not np.isnan(mean[i]) else float(np.nanmean(curr))
        is_jump = (cr >= jump_threshold_ratio and mag >= min_jump_magnitude) or \
                  (abs(hm) > 1e-6 and (cv - hm) / abs(hm) >= jump_threshold_ratio)
        if is_jump:
            sev = 'critical' if cr >= 1.0 else 'high' if cr >= 0.5 else 'medium'
            anomalies.append({
                'index': i,
                'timestamp': timestamps[i] if timestamps and i < len(timestamps) else None,
                'current_value': cv, 'prev_value': pv, 'historical_mean': float(hm),
                'change_ratio': float(cr), 'change_magnitude': float(mag),
                'change_type': 'sudden_jump', 'method': 'sudden_jump', 'severity': sev,
            })
    if min_consecutive > 1 and anomalies:
        filtered, streak = [], []
        for anom in anomalies:
            if not streak:
                streak = [anom]
            elif anom['index'] == streak[-1]['index'] + 1:
                streak.append(anom)
            else:
                if len(streak) >= min_consecutive:
                    filtered.extend(streak)
                streak = [anom]
        if len(streak) >= min_consecutive:
            filtered.extend(streak)
        anomalies = filtered
    return anomalies


def detect_anomalies_post_jump_drop(current_values, historical_means, timestamps=None,
                                    jump_threshold_ratio=0.50, post_jump_drop_threshold=0.50,
                                    min_jump_value=0.50, lookback_points=3):
    anomalies = []
    n = len(current_values)
    if n < 3:
        return anomalies
    curr = np.array(current_values, dtype=float)
    mean = np.array(historical_means, dtype=float) if len(historical_means) == n else np.full(n, np.nanmean(curr))
    for i in range(1, n):
        pv, cv = float(curr[i - 1]), float(curr[i])
        if pv <= 1e-6:
            continue
        drop_ratio = (pv - cv) / pv
        if drop_ratio < post_jump_drop_threshold:
            continue
        found, jump_val, jump_idx = False, 0.0, -1
        for j in range(max(0, i - lookback_points - 1), i):
            jp, jc = float(curr[j - 1]) if j > 0 else float(curr[j]), float(curr[j])
            if jp > 1e-6:
                jch = (jc - jp) / jp
                if jch >= jump_threshold_ratio and jc >= min_jump_value:
                    found, jump_val, jump_idx = True, jc, j
                    break
        if not found:
            continue
        drop_mag = (jump_val - cv) / jump_val
        hm = mean[i] if not np.isnan(mean[i]) else float(np.nanmean(curr))
        anomalies.append({
            'index': i,
            'timestamp': timestamps[i] if timestamps and i < len(timestamps) else None,
            'jump_index': jump_idx,
            'jump_timestamp': timestamps[jump_idx] if timestamps and jump_idx < len(timestamps) else None,
            'jump_value': float(jump_val), 'current_value': cv,
            'drop_ratio': float(drop_ratio), 'drop_magnitude': float(drop_mag),
            'hist_deviation': float((cv - hm) / hm if hm > 1e-6 else 0.0),
            'change_type': 'post_jump_drop', 'method': 'post_jump_drop',
            'severity': 'high' if drop_mag > 0.80 else 'medium' if drop_mag > 0.60 else 'low',
            'confidence': 'high', '_skip_context_filter': True,
        })
    return anomalies
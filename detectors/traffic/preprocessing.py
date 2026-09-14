import numpy as np


def filter_consecutive_anomalies(anomalies, min_consecutive=4):
    if not anomalies:
        return []
    indices = sorted({a["index"] for a in anomalies})
    groups, current = [], [indices[0]]
    for idx in indices[1:]:
        if idx == current[-1] + 1:
            current.append(idx)
        else:
            groups.append(current)
            current = [idx]
    groups.append(current)
    valid = set(idx for g in groups if len(g) >= min_consecutive for idx in g)
    return sorted([a for a in anomalies if a["index"] in valid], key=lambda x: x["index"])


def preprocess_traffic_data(current_values, historical_data):
    current_values = np.array([float(v) for v in current_values])
    if not historical_data:
        return current_values, np.array([]), np.array([]), []
    min_len = min(len(current_values), min(len(h["values"]) for h in historical_data))
    current_values = current_values[:min_len]
    hist_list = [np.array(h["values"][:min_len]) for h in historical_data]
    return (
        current_values,
        np.mean(hist_list, axis=0),
        np.std(hist_list, axis=0),
        hist_list,
    )

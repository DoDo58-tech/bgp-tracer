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

    # BUG (2026-10-05): this used to truncate every series to the SHORTEST
    # historical week. Radar frequently returns a partial week (a week whose
    # cache is thin, or a live fetch that hit a gap), and the current window is
    # always the longest series here because it spans event-1d..event+6h.
    #
    # On AS8048 / 2024-08-01 the baseline weeks came back with 193/193/97/193
    # samples while the current window had 101. min_len = 97 cut the current
    # series at 2024-08-01T08:45 -- i.e. it discarded the entire event hour,
    # including the 09:15 trough. The detector then scored only the calm
    # pre-event portion and reported peak_trough_drop = 9.9% with
    # anomalies_detected = False, on a window where traffic actually fell 72.7%
    # and Cloudflare's own confidenceInfo flags a TRAFFIC_ANOMALY.
    #
    # Truncating the *event* to fit a ragged baseline destroys the very signal
    # we are looking for. Instead, align on the baselines' own length and
    # RIGHT-align them against the end of the current window, so every baseline
    # contributes its full extent and the current series keeps its tail.
    #
    # min_len still bounds the comparison (the statistic needs paired samples),
    # but it now truncates from the FRONT of the current window rather than
    # dropping its final, most event-relevant samples.
    #
    # A baseline shorter than min_len is resampled up to min_len by index
    # interpolation instead of clamping the whole comparison down to its
    # length. A 2-sample baseline must not reduce the entire analysis to 2
    # points — it contributes a coarse but usable shape. The only series that
    # genuinely cannot be lengthened is the current window, so min_len is
    # additionally capped at its length.
    usable = [h for h in historical_data if len(h.get("values") or []) > 0]
    if not usable or len(current_values) == 0:
        return current_values, np.array([]), np.array([]), []

    # A baseline too short to be a real time series is stretched by
    # interpolation, so it must not dictate the comparison length. Otherwise a
    # single 2-sample baseline collapses the whole analysis to 2 points and
    # throws away the event we are trying to detect.
    #
    # The floor keeps a degenerate baseline from doing that while still
    # bounding the result to the current window's own length.
    MIN_USEFUL_LEN = 16
    full_len = [h for h in usable if len(h["values"]) >= MIN_USEFUL_LEN]
    if not full_len:
        return current_values, np.array([]), np.array([]), []
    min_len = min(len(current_values), min(len(h["values"]) for h in full_len))
    if min_len <= 0:
        return current_values, np.array([]), np.array([]), []

    # Keep the most recent min_len samples of the current window: the tail is
    # where the event lives, the head is the calm baseline context.
    current_values = current_values[-min_len:]

    # Right-align each historical week to the same end so index i of the
    # baseline means the same relative position as index i of the current
    # window. Without this, a 193-sample week and a 97-sample week would be
    # compared offset by 96 samples (~24 h) and the baseline would be garbage.
    hist_list = []
    for h in usable:
        vals = np.array(h["values"], dtype=float)
        if len(vals) >= min_len:
            hist_list.append(vals[-min_len:])
        else:
            src = np.linspace(0.0, 1.0, num=len(vals))
            dst = np.linspace(0.0, 1.0, num=min_len)
            hist_list.append(np.interp(dst, src, vals))
    if not hist_list:
        return current_values, np.array([]), np.array([]), []
    return (
        current_values,
        np.mean(hist_list, axis=0),
        np.std(hist_list, axis=0),
        hist_list,
    )

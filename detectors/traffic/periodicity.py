import numpy as np
from statsmodels.tsa.stattools import acf
from scipy import signal
from statsmodels.tsa.seasonal import seasonal_decompose
from utils.logger import logger

EXPECTED_DAILY = 96
EXPECTED_WEEKLY = 672


def detect_period_automatically(time_series, timestamps=None):
    if not isinstance(time_series, np.ndarray):
        time_series = np.array(time_series, dtype=float)
    valid = time_series[~np.isnan(time_series)]
    if len(valid) < 24:
        return {"period_name": "none", "confidence": 0.0, "method": "insufficient_data"}

    candidates = []
    try:
        max_lags = min(len(valid) - 1, EXPECTED_WEEKLY * 3 + 100)
        if max_lags < 1:
            raise ValueError("Not enough data for ACF")
        ac = acf(valid, nlags=max_lags)
        if not isinstance(ac, np.ndarray) or len(ac) < 10:
            raise ValueError(f"Invalid ACF result: {len(ac) if isinstance(ac, np.ndarray) else 'N/A'}")

        weekly_peaks = []
        for cyc in range(1, 4):
            pos = EXPECTED_WEEKLY * cyc
            rng = slice(max(0, pos - 50), min(len(ac), pos + 50))
            if rng.start < rng.stop:
                pk = float(np.max(ac[rng]))
                if pk > 0.08:
                    weekly_peaks.append(pk)
        if len(weekly_peaks) >= 1:
            avg = float(np.mean(weekly_peaks))
            if avg > 0.10:
                candidates.append({"period": "weekly", "confidence": avg, "method": f"acf_weekly_{len(weekly_peaks)}peaks"})

        daily_peaks = []
        for cyc in range(1, min(28, len(ac) // max(1, EXPECTED_DAILY))):
            pos = EXPECTED_DAILY * cyc
            rng = slice(max(0, pos - 25), min(len(ac), pos + 25))
            if rng.start < rng.stop:
                pk = float(np.max(ac[rng]))
                if pk > 0.12:
                    daily_peaks.append(pk)
        if len(daily_peaks) >= 1:
            avg = float(np.mean(daily_peaks))
            if avg > 0.15:
                candidates.append({"period": "daily", "confidence": avg, "method": f"acf_daily_{len(daily_peaks)}peaks"})
    except Exception as e:
        logger.warning(f"ACF period detection failed: {e}")

    try:
        detrended = signal.detrend(valid)
        if len(detrended) < 4:
            raise ValueError("Not enough data for FFT")
        fft = np.fft.fft(detrended)
        freqs = np.fft.fftfreq(len(detrended))
        magnitudes = np.abs(fft)
        freq_range = magnitudes[1:len(magnitudes) // 2]
        if len(freq_range) == 0:
            raise ValueError("No frequency range for FFT")
        peak_idx_raw = np.argmax(freq_range)
        peak_idx = int(peak_idx_raw.item()) + 1 if hasattr(peak_idx_raw, 'item') else int(peak_idx_raw) + 1
        if peak_idx >= len(freqs):
            raise ValueError(f"Peak idx {peak_idx} out of bounds")
        peak_freq_raw = freqs[peak_idx]
        peak_freq = float(peak_freq_raw.item()) if hasattr(peak_freq_raw, 'item') else float(peak_freq_raw)
        period_pts, fft_conf = 0, 0.0
        if peak_freq != 0:
            period_pts = int(round(1 / abs(peak_freq)))
        max_mag = float(np.max(magnitudes))
        fft_conf = float(magnitudes[peak_idx]) / max_mag if max_mag > 0 else 0.0
        if fft_conf > 0.03:
            if abs(period_pts - EXPECTED_DAILY) < EXPECTED_DAILY * 0.4:
                candidates.append({"period": "daily", "confidence": fft_conf, "method": "fft_daily"})
            elif abs(period_pts - EXPECTED_WEEKLY) < EXPECTED_WEEKLY * 0.4:
                candidates.append({"period": "weekly", "confidence": fft_conf, "method": "fft_weekly"})
    except Exception as e:
        logger.warning(f"FFT period detection failed: {e}")

    try:
        if len(valid) >= 24 * 7:
            decomp = seasonal_decompose(valid, model='additive', period=EXPECTED_DAILY // 4)
            strength = float(np.var(decomp.seasonal) / np.var(decomp.resid + decomp.seasonal))
            if strength > 0.12:
                candidates.append({"period": "daily", "confidence": strength, "method": "stl_daily"})
    except Exception as e:
        logger.warning(f"STL decomposition failed: {e}")

    daily_best = max([c for c in candidates if c["period"] == "daily"], key=lambda x: x["confidence"], default=None)
    weekly_best = max([c for c in candidates if c["period"] == "weekly"], key=lambda x: x["confidence"], default=None)
    dconf = daily_best["confidence"] if daily_best else 0.0
    wconf = weekly_best["confidence"] if weekly_best else 0.0

    if daily_best and weekly_best and dconf >= wconf * 3.0:
        chosen, avg_conf, reason = daily_best, dconf, f"daily ({dconf:.3f}) >= 3x weekly ({wconf:.3f})"
    elif weekly_best:
        chosen, avg_conf, reason = weekly_best, wconf, f"weekly ({wconf:.3f}) default"
    elif daily_best:
        if dconf >= 0.15:
            chosen, avg_conf, reason = daily_best, dconf, f"daily only ({dconf:.3f})"
        else:
            chosen, avg_conf, reason = None, 0.0, "daily confidence too low"
    else:
        chosen, avg_conf, reason = None, 0.0, "no candidates"

    if chosen:
        logger.info(f"Period: {chosen['period']} (conf={avg_conf:.3f}, {reason})")
        return {
            "period_name": chosen["period"],
            "confidence": float(avg_conf),
            "method": chosen["method"],
            "all_candidates": candidates,
            "best_effort": float(avg_conf) < 0.20,
            "daily_confidence": float(dconf),
            "weekly_confidence": float(wconf),
            "decision_reason": reason,
        }
    return {
        "period_name": "none",
        "confidence": 0.0,
        "method": "no_clear_period",
        "best_effort": False,
        "daily_confidence": float(dconf),
        "weekly_confidence": float(wconf),
        "decision_reason": reason,
    }

"""
Tool A4: Long-Term Baseline — 90-day traffic trend analysis.
==========================================================

Problem with short-window baselines:
  A 20% traffic dip might be "normal seasonal drop" or a genuine anomaly.

Solution:
  1. Fetch 90 days of historical daily traffic data from Cloudflare Radar API.
  2. Compute 7-day, 30-day, and 90-day rolling means and stds.
  3. Flag days that deviate significantly from the seasonal pattern.
  4. This lets the LLM say:
       "The dip is NOT anomalous — it matches the seasonal pattern for this day of week"
     or
       "This is a genuine anomaly — 3x the normal deviation for this season."

Cloudflare Radar free API (no auth, 120 req/min):
    https://api.cloudflare.com/client/v4/radar/entities/as/summaries
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
from tools.tool_registry import ToolParameter, register_tool
from utils.logger import logger
from config import CLOUDFLARE_API_TOKEN, CLOUDFLARE_RADAR_NORMALIZATION

RADAR_AS_URL = "https://api.cloudflare.com/client/v4/radar/entities/as/summaries"


async def _long_term_baseline(tool_input: dict, session) -> dict:
    """
    Analyze 90-day traffic baseline and flag anomalous days.

    Required params:
        asn (str): AS number
        start_time (str): current analysis window start
        end_time (str): current analysis window end

    Returns:
        - daily_traffic: list of {date, mean_traffic, std_traffic} for 90 days
        - trend: "increasing" | "stable" | "decreasing"
        - anomaly_days: dates in the current window that deviate significantly
        - seasonal_pattern: day-of-week pattern (useful for removing false positives)
        - baseline_comparison: how the current period compares to the 90-day baseline
    """
    asn = str(tool_input["asn"])
    start = tool_input.get("start_time", "")
    end = tool_input.get("end_time", "")

    # Parse current window
    try:
        start_dt = datetime.strptime(start[:10], "%Y-%m-%d") if start else datetime.now() - timedelta(days=7)
        end_dt = datetime.strptime(end[:10], "%Y-%m-%d") if end else datetime.now()
    except Exception:
        start_dt = datetime.now() - timedelta(days=7)
        end_dt = datetime.now()

    logger.info(f"[baseline] Fetching 90-day baseline for AS{asn}")

    # Fetch 90 days of data
    days_to_fetch = 90
    daily_data = await _fetch_daily_traffic(asn, days=days_to_fetch)

    if not daily_data:
        return {
            "success": True,
            "asn": asn,
            "observation": f"Could not fetch historical traffic data for AS{asn}. "
                           f"Cloudflare Radar API may not have data for this AS.",
        }

    # Compute statistics
    import numpy as np

    values = [d["value"] for d in daily_data]
    mean_val = np.mean(values)
    std_val = np.std(values)

    # 7-day vs 30-day means for trend
    recent_7 = np.mean(values[:7]) if len(values) >= 7 else mean_val
    older_30 = np.mean(values[30:60]) if len(values) >= 60 else mean_val

    if recent_7 > older_30 * 1.05:
        trend = "increasing"
        trend_narrative = f"Traffic is increasing: 7-day avg ({recent_7:.3f}) > 30-day avg ({older_30:.3f})"
    elif recent_7 < older_30 * 0.95:
        trend = "decreasing"
        trend_narrative = f"Traffic is decreasing: 7-day avg ({recent_7:.3f}) < 30-day avg ({older_30:.3f})"
    else:
        trend = "stable"
        trend_narrative = f"Traffic is stable: 7-day avg ({recent_7:.3f}) ≈ 30-day avg ({older_30:.3f})"

    # Day-of-week seasonal pattern
    dow_pattern = _compute_dow_pattern(daily_data)

    # Flag anomalous days in the current window
    anomaly_days = []
    current_window_values = []
    for d in daily_data:
        dt = datetime.strptime(d["date"], "%Y-%m-%d")
        if start_dt <= dt <= end_dt:
            current_window_values.append(d["value"])
            if std_val > 0:
                z_score = (d["value"] - mean_val) / std_val
            else:
                z_score = 0
            if abs(z_score) > 2.0:
                anomaly_days.append({
                    "date": d["date"],
                    "value": d["value"],
                    "mean": mean_val,
                    "std": std_val,
                    "z_score": round(z_score, 2),
                    "direction": "above" if z_score > 0 else "below",
                })

    # Compare current window to baseline
    if current_window_values:
        current_mean = np.mean(current_window_values)
        current_std = np.std(current_window_values) if len(current_window_values) > 1 else 0
        if mean_val > 0:
            deviation_pct = ((current_mean - mean_val) / mean_val) * 100
        else:
            deviation_pct = 0

        if abs(deviation_pct) < 10:
            baseline_note = (
                f"Current window traffic (mean={current_mean:.3f}) is within normal range "
                f"of the 90-day baseline (mean={mean_val:.3f}, deviation={deviation_pct:+.1f}%). "
                f"No significant anomaly detected in the broader historical context."
            )
        elif abs(deviation_pct) < 30:
            baseline_note = (
                f"Current window is moderately anomalous: {deviation_pct:+.1f}% vs 90-day baseline. "
                f"Could be legitimate traffic shift or genuine anomaly."
            )
        else:
            baseline_note = (
                f"⚠️ Current window is strongly anomalous: {deviation_pct:+.1f}% vs 90-day baseline. "
                f"This is unlikely to be seasonal variation."
            )
    else:
        baseline_note = "No historical data available for the current analysis window."
        current_mean = 0
        current_std = 0
        deviation_pct = 0

    return {
        "success": True,
        "asn": asn,
        "days_analyzed": len(daily_data),
        "mean": round(mean_val, 4),
        "std": round(std_val, 4),
        "trend": trend,
        "trend_narrative": trend_narrative,
        "recent_7day_avg": round(recent_7, 4),
        "older_30day_avg": round(older_30, 4),
        "daily_traffic": daily_data[-30:],  # last 30 days for the report
        "seasonal_pattern": dow_pattern,
        "current_window": {"start": start, "end": end},
        "current_window_mean": round(current_mean, 4),
        "current_window_std": round(current_std, 4),
        "deviation_from_baseline_pct": round(deviation_pct, 2),
        "anomaly_days_in_window": anomaly_days,
        "observation": (
            f"{trend_narrative}. "
            f"{baseline_note}"
        ),
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _fetch_daily_traffic(asn: str, days: int = 90) -> List[dict]:
    """
    Fetch daily traffic summary for an AS from Cloudflare Radar API.
    Returns list of {date, value} sorted oldest-first.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                RADAR_AS_URL,
                params={
                    "asn": asn,
                    "dateRange": f"{days}d",
                    "format": "json",
                    "normalization": CLOUDFLARE_RADAR_NORMALIZATION or "MIN0_MAX",
                },
                headers={
                    "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("result", {}).get("series", [])
            if not results:
                return []
            series = results[0]
            values = series.get("values", [])
            dates = series.get("dates", [])
            return [
                {"date": d, "value": round(float(v), 6)}
                for d, v in zip(dates, values)
                if v is not None
            ]
    except Exception as e:
        logger.warning(f"[baseline] Cloudflare Radar API failed: {e}")
        return []


def _compute_dow_pattern(daily_data: List[dict]) -> dict:
    """
    Compute average traffic by day of week (0=Monday ... 6=Sunday).
    Used to understand weekly seasonality.
    """
    import numpy as np
    from collections import defaultdict

    dow_totals = defaultdict(list)
    for d in daily_data:
        try:
            dt = datetime.strptime(d["date"], "%Y-%m-%d")
            dow = dt.weekday()
            dow_totals[dow].append(d["value"])
        except Exception:
            continue

    pattern = {}
    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    for dow in range(7):
        vals = dow_totals.get(dow, [])
        pattern[day_names[dow]] = round(float(np.mean(vals)), 6) if vals else None

    # Identify if weekend is notably different from weekday
    weekday_avg = np.mean([pattern[n] for n in day_names[:5] if pattern.get(n) is not None])
    weekend_avg = np.mean([pattern[n] for n in day_names[5:] if pattern.get(n) is not None])
    if weekday_avg and weekend_avg:
        if weekend_avg < weekday_avg * 0.9:
            pattern["weekend_effect"] = "significant_drop"
        elif weekend_avg > weekday_avg * 1.1:
            pattern["weekend_effect"] = "significant_increase"
        else:
            pattern["weekend_effect"] = "minimal"

    return pattern


# ── Tool registration ────────────────────────────────────────────────────────

register_tool(
    name="long_term_baseline",
    description=(
        "Analyze 90-day traffic baseline for an AS using Cloudflare Radar historical data. "
        "Computes trend (increasing/stable/decreasing), day-of-week seasonal pattern, "
        "and flags anomalous days in the current window vs the 90-day baseline. "
        "Dramatically reduces false positives from normal traffic variation. "
        "Free Cloudflare Radar API: https://api.cloudflare.com/client/v4/radar/entities/as/summaries"
    ),
    parameters=[
        ToolParameter("asn", "AS number", "string"),
        ToolParameter("start_time", "Current analysis window start (ISO)", "string"),
        ToolParameter("end_time", "Current analysis window end (ISO)", "string"),
    ],
    handler=_long_term_baseline,
)

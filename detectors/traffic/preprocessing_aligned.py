import numpy as np
from datetime import datetime

try:
    import polars as pl
    HAS_POLARS = True
except ImportError:
    HAS_POLARS = False

from detectors.traffic.preprocessing import preprocess_traffic_data


def preprocess_traffic_data_aligned(current_values, historical_data, timestamps):
    if not HAS_POLARS:
        return preprocess_traffic_data(current_values, historical_data)

    curr_vals = np.array([float(v) for v in current_values])
    if not historical_data or not timestamps:
        return curr_vals, np.array([]), np.array([]), []

    def parse_ts(ts_str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(ts_str, fmt)
            except Exception:
                continue
        return None

    curr_times = [parse_ts(ts) for ts in timestamps]
    curr_df = (pl.DataFrame({"time": curr_times, "value": curr_vals})
               .filter(pl.col("time").is_not_null())
               .group_by("time").agg(pl.col("value").mean())
               .sort("time"))
    if len(curr_df) == 0:
        return curr_vals, np.array([]), np.array([]), []

    curr_df = curr_df.with_columns([
        (pl.col("time").dt.weekday() - 1).cast(pl.Int32).alias("dow"),
        pl.col("time").dt.strftime("%H:%M").alias("tod"),
    ])

    aligned = []
    for h in historical_data:
        h_ts, h_vals = h.get("timestamps", []), h.get("values", [])
        if not h_ts or not h_vals:
            continue
        h_times = [parse_ts(ts) for ts in h_ts]
        h_df = (pl.DataFrame({"time": h_times, "value": [float(v) for v in h_vals]})
                .filter(pl.col("time").is_not_null())
                .group_by("time").agg(pl.col("value").mean())
                .sort("time"))
        if len(h_df) == 0:
            continue
        h_df = h_df.with_columns([
            (pl.col("time").dt.weekday() - 1).cast(pl.Int32).alias("dow"),
            pl.col("time").dt.strftime("%H:%M").alias("tod"),
        ])
        lookup = {f"{r['dow']}_{r['tod']}": r["value"]
                  for r in h_df.group_by(["dow", "tod"]).agg(pl.col("value").mean())
                  .with_columns(pl.concat_str(pl.col("dow").cast(str), pl.lit("_"), pl.col("tod")).alias("key"))
                  .iter_rows(named=True)}
        merged = [lookup.get(f"{r['dow']}_{r['tod']}", float("nan"))
                  for r in curr_df.iter_rows(named=True)]
        aligned.append(np.array(merged))

    if not aligned:
        return curr_df["value"].to_numpy(), np.array([]), np.array([]), []

    arr = np.array(aligned)
    hist_mean = np.nanmean(arr, axis=0)
    hist_std = np.nanstd(arr, axis=0)
    fill = float(np.nanmean(hist_mean))
    if np.isnan(fill):
        fill = float(np.nanmean(curr_vals))
    hist_mean = np.nan_to_num(hist_mean, nan=fill)
    hist_std = np.nan_to_num(hist_std, nan=0.1)
    return curr_df["value"].to_numpy(), hist_mean, hist_std, aligned

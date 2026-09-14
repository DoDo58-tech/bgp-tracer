import matplotlib.pyplot as plt
from datetime import datetime
from typing import Any, Dict, List, Tuple
import numpy as np
import os

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


def _parse_iso_safe(ts: str):
    """Parse ISO-8601 / space-separated timestamps, always stripping microseconds and Z."""
    ts = ts.replace("Z", "+00:00").replace("z", "+00:00").rstrip("Z").rstrip("z").rstrip("+00:00").rstrip("+00").rstrip("-").strip()
    ts = ts.split(".")[0]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            pass
    return None


def _percentile_bounds_for_baseline(historical_values_list: list, current_len: int, lower_pct: float = 2.5, upper_pct: float = 97.5):
    """
    用分位数计算置信边界（替代 mean ± 3σ）。
    适用于流量等非负右偏数据，分位数天然保证下界为正。
    
    Args:
        historical_values_list: 历史数据列表，每个元素是对齐后的历史值数组
        current_len: 当前数据长度
        lower_pct: 下界百分位（默认 2.5%）
        upper_pct: 上界百分位（默认 97.5%）
    
    Returns:
        (lower_bounds, upper_bounds, median): 下界、上界、中位数数组
    """
    import numpy as np
    
    if not historical_values_list:
        return np.array([]), np.array([]), np.array([])
    
    # 转换为 numpy 数组
    hist_arr = np.array(historical_values_list, dtype=float)  # shape: (n_periods, n_timepoints)
    
    if hist_arr.size == 0:
        return np.array([]), np.array([]), np.array([])
    
    # 确保长度一致
    min_len = min(hist_arr.shape[1], current_len)
    hist_arr = hist_arr[:, :min_len]
    
    # 计算分位数
    lower_bounds = np.nanpercentile(hist_arr, lower_pct, axis=0)
    upper_bounds = np.nanpercentile(hist_arr, upper_pct, axis=0)
    median = np.nanmedian(hist_arr, axis=0)
    
    return lower_bounds, upper_bounds, median


def _effective_std_for_baseline(mean_arr: np.ndarray, std_arr: np.ndarray):
    """与 detect_anomalies_statistical 一致：极小 std 用下限，避免图上 ±3σ 与检测阈值不一致。"""
    mean_arr = np.asarray(mean_arr, dtype=float)
    std_arr = np.asarray(std_arr, dtype=float)
    floor = np.maximum(0.05 * np.maximum(np.abs(mean_arr), 1.0), 0.02)
    return np.where(std_arr > 1e-6, std_arr, floor)


def plot_traffic_comparison_beautiful(
    asn,
    start_date,
    end_date,
    timestamps,
    current_values,
    historical_data,
    historical_means,
    historical_stds,
    anomalies = None,
    overlay_series = None,
    event_name = None,
    output_dir = None,
    title_suffix = "",
    historical_values_list = None,  # 对齐后的历史数据列表，用于分位数计算
):
    try:
        plt.rcParams['font.family'] = 'DejaVu Sans'
        plt.rcParams['axes.unicode_minus'] = False

        fig, ax = plt.subplots(figsize=(18, 8))

        n_points = min(len(timestamps), len(current_values))
        timestamps = timestamps[:n_points]
        current_values = current_values[:n_points]

        def _parse_ts_for_plot(ts: str):
            dt = _parse_iso_safe(ts)
            if dt is None:
                return ts
            return dt

        time_labels = []
        for ts in timestamps:
            dt = _parse_ts_for_plot(ts)
            time_labels.append(dt.strftime("%H:%M") if isinstance(dt, datetime) else str(dt))

        # Parse dates, handling optional seconds in format
        _date_formats = ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M']
        start_time_dt = None
        for fmt in _date_formats:
            try:
                start_time_dt = datetime.strptime(start_date, fmt)
                break
            except ValueError:
                pass
        if start_time_dt is None:
            start_time_dt = datetime.strptime(start_date.split('.')[0], '%Y-%m-%d %H:%M:%S')
        end_time_dt = None
        for fmt in _date_formats:
            try:
                end_time_dt = datetime.strptime(end_date, fmt)
                break
            except ValueError:
                pass
        if end_time_dt is None:
            end_time_dt = datetime.strptime(end_date.split('.')[0], '%Y-%m-%d %H:%M:%S')

        highlight_start_dt = start_time_dt
        highlight_end_dt = end_time_dt

        x = np.arange(len(time_labels))
        current_arr = np.array(current_values)

        has_historical_data = len(historical_means) > 0 and len(historical_stds) > 0

        # Plot historical periods as reference
        period_colors = ['#F4A6A6', '#A6C4F4', '#A6E4A6', '#C0C0C0']  # light pink, light blue, light green, light gray
        def _period_label(period_key, i):
            if "weekly" in period_key.lower():
                return f"{i} week ago" if i == 1 else f"{i} weeks ago"
            return f"{i} day ago" if i == 1 else f"{i} days ago"
        if historical_data:
            for idx, h in enumerate(historical_data):
                period_ago = h.get("weekly_ago") or h.get("daily_ago")
                if period_ago is None:
                    for k, v in h.items():
                        if k.endswith("_ago") and isinstance(v, (int, float)):
                            period_ago = int(v)
                            period_key = k
                            break
                    else:
                        period_ago = idx + 1
                        period_key = "weekly_ago"
                else:
                    period_key = "weekly_ago" if "weekly_ago" in h else "daily_ago"
                label = _period_label(period_key, period_ago)
                vals = np.array(h["values"], dtype=float)
                min_len = min(len(x), len(vals))
                color = period_colors[idx % len(period_colors)]
                ax.plot(x[:min_len], vals[:min_len], color=color, linewidth=1.8, alpha=0.85, label=label)
        if has_historical_data:
            mean_arr = np.array(historical_means)
            std_arr = np.array(historical_stds)

            min_len = min(len(mean_arr), len(std_arr), len(current_arr))
            mean_arr = mean_arr[:min_len]
            std_arr = std_arr[:min_len]
            x_plot = x[:min_len]

            # 使用分位数替代 mean ± 3σ（适用于流量等非负右偏数据）
            if (historical_values_list and len(historical_values_list) >= 2) or \
               (historical_data and len(historical_data) >= 2):
                # 优先使用传入的对齐后的历史数据列表
                if historical_values_list and len(historical_values_list) >= 2:
                    hist_vals_for_percentile = historical_values_list
                else:
                    # 回退：从 historical_data 构建历史值列表
                    hist_vals_for_percentile = []
                    for h in historical_data:
                        vals = np.array(h.get("values", []), dtype=float)
                        if len(vals) >= min_len:
                            hist_vals_for_percentile.append(vals[:min_len])
                
                if len(hist_vals_for_percentile) >= 2:
                    lower_bounds, upper_bounds, median = _percentile_bounds_for_baseline(
                        hist_vals_for_percentile, min_len, lower_pct=5, upper_pct=95
                    )
                    
                    if len(lower_bounds) == min_len and len(upper_bounds) == min_len:
                        ax.fill_between(x_plot, lower_bounds, upper_bounds, 
                                        color='#D0D0D0', alpha=0.25, 
                                        label='Baseline 5%-95% Percentile')
                        ax.plot(x_plot, median, label='Historical Median', 
                                color='#FF8C42', linestyle='--', linewidth=2.5, alpha=0.9)
                    else:
                        # 回退到原来的 mean ± 3σ
                        eff_std = _effective_std_for_baseline(mean_arr, std_arr)
                        upper_3sigma = mean_arr + 3 * eff_std
                        lower_3sigma = mean_arr - 3 * eff_std
                        ax.fill_between(x_plot, lower_3sigma, upper_3sigma, color='#D0D0D0', alpha=0.25, label='Baseline ±3σ (fallback)')
                        ax.plot(x_plot, mean_arr, label='Historical Mean', color='#FF8C42', linestyle='--', linewidth=2.5, alpha=0.9)
                else:
                    # 历史数据不足，使用原来的 mean ± 3σ
                    eff_std = _effective_std_for_baseline(mean_arr, std_arr)
                    upper_3sigma = mean_arr + 3 * eff_std
                    lower_3sigma = mean_arr - 3 * eff_std
                    ax.fill_between(x_plot, lower_3sigma, upper_3sigma, color='#D0D0D0', alpha=0.25, label='Baseline ±3σ (fallback)')
                    ax.plot(x_plot, mean_arr, label='Historical Mean', color='#FF8C42', linestyle='--', linewidth=2.5, alpha=0.9)
            else:
                # 无历史数据，使用原来的 mean ± 3σ
                eff_std = _effective_std_for_baseline(mean_arr, std_arr)
                upper_3sigma = mean_arr + 3 * eff_std
                lower_3sigma = mean_arr - 3 * eff_std
                ax.fill_between(x_plot, lower_3sigma, upper_3sigma, color='#D0D0D0', alpha=0.25, label='Baseline ±3σ (fallback)')
                ax.plot(x_plot, mean_arr, label='Historical Mean', color='#FF8C42', linestyle='--', linewidth=2.5, alpha=0.9)
        else:
            current_mean = np.mean(current_arr)
            current_std = np.std(current_arr)
            ax.axhline(y=current_mean, color='#FF8C42', linestyle='--', linewidth=2.5, alpha=0.9,
                      label=f'Current Mean: {current_mean:.2f}')
            ax.axhline(y=current_mean + current_std, color='#D0D0D0', linestyle=':', linewidth=1.5, alpha=0.6,
                      label=f'Current ±1σ: {current_std:.2f}')
            ax.axhline(y=current_mean - current_std, color='#D0D0D0', linestyle=':', linewidth=1.5, alpha=0.6)

        ax.plot(
            x,
            current_arr,
            label='Current Traffic',
            color='#2E86AB',
            linewidth=3,
            marker='o',
            markersize=5,
            markerfacecolor='white',
            markeredgewidth=1.5,
            markeredgecolor='#2E86AB'
        )

        if overlay_series:
            if 'http_as' in overlay_series:
                http_vals = np.array(overlay_series['http_as']['values'][:len(x)], dtype=float)
                ax.plot(x[:len(http_vals)], http_vals, label='HTTP Requests (AS)', color='#6A5ACD', linewidth=2, alpha=0.8)
            if 'dns_as' in overlay_series:
                dns_vals = np.array(overlay_series['dns_as']['values'][:len(x)], dtype=float)
                ax.plot(x[:len(dns_vals)], dns_vals, label='DNS Queries (AS)', color='#20B2AA', linewidth=2, alpha=0.8)

        start_idx = 0
        end_idx = len(time_labels) - 1

        def _parse_ts(ts):
            dt = _parse_iso_safe(ts)
            if dt is None:
                return None
            return dt

        for i, ts in enumerate(timestamps):
            dt = _parse_ts(ts)
            if dt is None:
                continue
            if dt >= highlight_start_dt:
                start_idx = i
                break

        for i, ts in enumerate(timestamps):
            dt = _parse_ts(ts)
            if dt is None:
                continue
            if dt > highlight_end_dt:
                end_idx = max(i - 1, start_idx)
                break
                end_idx = max(i - 1, start_idx)
                break

        ax.axvspan(start_idx, end_idx, alpha=0.15, color='#FDE68A', label='Analysis Period')

        if anomalies:
            plotted = False
            for anomaly in anomalies:
                try:
                    idx = anomaly.get("index")
                    if idx is None:
                        anomaly_time = anomaly.get("timestamp")
                        if anomaly_time and anomaly_time in timestamps:
                            idx = timestamps.index(anomaly_time)
                        else:
                            continue
                    idx = int(idx)
                    if idx < 0 or idx >= len(current_arr):
                        continue

                    ax.scatter(
                        x[idx], current_arr[idx],
                        c='#E74C3C', s=80, marker='o',
                        edgecolors='none', zorder=10,
                        label='Anomaly' if not plotted else None
                    )
                    plotted = True
                except (ValueError, KeyError, TypeError):
                    continue

        step = max(1, len(time_labels) // 10)
        tick_positions = x[::step] if step < len(x) else x
        tick_labels = time_labels[::step] if step < len(time_labels) else time_labels
        ax.set_xticks(tick_positions)
        ax.set_xticklabels(tick_labels, rotation=45)
        ax.set_xlim(0, len(x) - 1)

        ax.set_title(
            f'AS{asn} Traffic Analysis - {start_date} to {end_date}{title_suffix or ""}',
            fontsize=16, fontweight='bold', pad=20,
        )

        plt.tight_layout()

        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(__file__), "..","..", "data", "traffic_plots")

        if event_name:
            output_dir = os.path.join(output_dir, event_name)

        os.makedirs(output_dir, exist_ok=True)
        output_filename = f'AS{asn}_{start_date}_to_{end_date}.png'.replace(':', '-')
        output_path = os.path.join(output_dir, output_filename)

        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white', pad_inches=0.5)
        logger.info(f"Beautiful traffic comparison chart saved to: {output_path}")

        plt.close()
        return output_path

    except Exception as e:
        logger.error(f"Error generating traffic comparison chart: {e}")
        return ""


def plot_period_detection(time_series, timestamps,
                         period_info, output_dir = None):
    try:
        fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(15, 12))

        ax1.plot(time_series, 'b-', alpha=0.7)
        ax1.set_title('Original Traffic Time Series')
        ax1.set_xlabel('Time Points')
        ax1.set_ylabel('Traffic Value')
        ax1.grid(True, alpha=0.3)

        from statsmodels.tsa.stattools import acf
        autocorr = acf(time_series, nlags=min(len(time_series)-1, 100))
        ax2.plot(autocorr, 'g-', marker='o', markersize=3)
        ax2.set_title('Autocorrelation Function')
        ax2.set_xlabel('Lag')
        ax2.set_ylabel('Autocorrelation')
        ax2.grid(True, alpha=0.3)
        ax2.axhline(y=0, color='r', linestyle='--', alpha=0.5)

        from scipy import signal
        freqs, psd = signal.periodogram(time_series)
        ax3.semilogy(freqs, psd, 'm-')
        ax3.set_title('Power Spectral Density')
        ax3.set_xlabel('Frequency')
        ax3.set_ylabel('Power')
        ax3.grid(True, alpha=0.3)

        period_text = f"Detected Period: {period_info.get('period_hours', 'N/A')} hours\n"
        period_text += f"Method: {period_info.get('method', 'N/A')}\n"
        period_text += ".2f"
        fig.suptitle(f'Period Detection Analysis\n{period_text}', fontsize=14)

        plt.tight_layout()

        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(__file__), "..", "data", "traffic_plots")

        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, 'period_detection_analysis.png')

        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        logger.info(f"Period detection plot saved to: {output_path}")

        plt.close()
        return output_path

    except Exception as e:
        logger.error(f"Error generating period detection plot: {e}")
        return ""

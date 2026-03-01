import matplotlib.pyplot as plt
from datetime import datetime
from typing import List, Dict, Any, Tuple
import numpy as np
import os

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


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
    output_dir = None
):
    try:
        plt.rcParams['font.family'] = 'DejaVu Sans'
        plt.rcParams['axes.unicode_minus'] = False

        fig, ax = plt.subplots(figsize=(18, 8))

        time_labels = []
        for ts in timestamps:
            try:
                dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                time_labels.append(dt.strftime("%H:%M"))
            except ValueError:
                time_labels.append(ts)

        start_time_dt = datetime.strptime(start_date, '%Y-%m-%d %H:%M')
        end_time_dt = datetime.strptime(end_date, '%Y-%m-%d %H:%M')

        highlight_start_dt = start_time_dt
        highlight_end_dt = end_time_dt

        x = np.arange(len(time_labels))
        current_arr = np.array(current_values)

        has_historical_data = len(historical_means) > 0 and len(historical_stds) > 0

        if has_historical_data:
            mean_arr = np.array(historical_means)
            std_arr = np.array(historical_stds)

            min_len = min(len(mean_arr), len(std_arr), len(current_arr))
            mean_arr = mean_arr[:min_len]
            std_arr = std_arr[:min_len]
            x_plot = x[:min_len]

            upper_3sigma = mean_arr + 3 * std_arr
            lower_3sigma = mean_arr - 3 * std_arr

            ax.fill_between(x_plot, lower_3sigma, upper_3sigma, color='#B0C4DE', alpha=0.15, label='Baseline ±3σ')
            ax.plot(x_plot, mean_arr, label='Baseline Mean', color='#FF8C42', linestyle='--', linewidth=2.5, alpha=0.9)
        else:
            current_mean = np.mean(current_arr)
            current_std = np.std(current_arr)
            ax.axhline(y=current_mean, color='#FF8C42', linestyle='--', linewidth=2.5, alpha=0.9,
                      label=f'Current Mean: {current_mean:.2f}')
            ax.axhline(y=current_mean + current_std, color='#B0C4DE', linestyle=':', linewidth=1.5, alpha=0.6,
                      label=f'Current ±1σ: {current_std:.2f}')
            ax.axhline(y=current_mean - current_std, color='#B0C4DE', linestyle=':', linewidth=1.5, alpha=0.6)

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

        for i, ts in enumerate(timestamps):
            try:
                dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                if dt >= highlight_start_dt:
                    start_idx = i
                    break
            except ValueError:
                continue

        for i, ts in enumerate(timestamps):
            try:
                dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                if dt > highlight_end_dt:
                    end_idx = max(i - 1, start_idx)
                    break
            except ValueError:
                continue

        ax.axvspan(start_idx, end_idx, alpha=0.15, color='#FDE68A', label='Analysis Period')

        if anomalies:
            plotted_anomaly = False
            for anomaly in anomalies:
                try:
                    anomaly_time = anomaly["timestamp"]
                    idx = timestamps.index(anomaly_time)
                    ax.scatter(
                        x[idx],
                        current_arr[idx],
                        color='#E74C3C',
                        s=180,
                        marker='o',
                        edgecolors='white',
                        linewidth=2.5,
                        zorder=10,
                        label='Anomaly' if not plotted_anomaly else None
                    )
                    plotted_anomaly = True
                except ValueError:
                    continue

        ax.set_title(f'AS{asn} Traffic Analysis - {start_date} to {end_date}',
                     fontsize=16, fontweight='bold', pad=20)
        ax.set_ylabel('Traffic Value (Normalized)', fontsize=12)
        ax.grid(True, alpha=0.3, linestyle='-')
        ax.legend(loc='upper left', framealpha=0.9)

        current_avg = np.mean(current_arr)

        if has_historical_data:
            percent_change = ((current_avg - historical_avg) / historical_avg * 100) if historical_avg > 0 else 0
        else:
            historical_avg = current_avg
            percent_change = 0.0

        stats_text = f'Current: {current_avg:.2f}\nHistorical: {historical_avg:.2f}\nChange: {percent_change:+.1f}%'
        ax.text(
            0.02,
            0.98,
            stats_text,
            transform=ax.transAxes,
            verticalalignment='top',
            bbox=dict(boxstyle='round,pad=0.5', facecolor='white', alpha=0.85),
            fontsize=10
        )

        step = max(1, len(time_labels) // 10)
        tick_positions = x[::step] if step < len(x) else x
        tick_labels = time_labels[::step] if step < len(time_labels) else time_labels
        ax.set_xticks(tick_positions)
        ax.set_xticklabels(tick_labels, rotation=45)
        ax.set_xlim(0, len(x) - 1)

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

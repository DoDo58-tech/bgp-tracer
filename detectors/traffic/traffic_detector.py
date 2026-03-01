import os
import sys
import numpy as np
from datetime import datetime, timedelta
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import CLOUDFLARE_HTTP_TIMESERIES_AS_URL, CLOUDFLARE_API_TOKEN
from detectors.traffic.traffic_plotting import plot_traffic_comparison_beautiful
from detectors.traffic.traffic_analysis_utils import (
    detect_anomalies_combined,
    detect_anomalies_non_periodic,
    preprocess_traffic_data,
    calculate_traffic_statistics,
    detect_period_automatically,
    expand_anomaly_boundaries
)
from pathlib import Path


class CloudflareRadarAPI:
    def __init__(self):
        self.base_url = CLOUDFLARE_HTTP_TIMESERIES_AS_URL
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {CLOUDFLARE_API_TOKEN}',
            'Content-Type': 'application/json'
        })

    def detect_anomalies(self, asn, start_time, end_time, plot_result=False, event_start_time=None, event_end_time=None, fast_mode=True, historical_weeks=None, anomaly_method="combined", auto_expand_boundaries=True):
        user_start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        user_end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")

        query_start = user_start_dt - timedelta(days=1)
        query_end = user_end_dt + timedelta(hours=6)

        periodicity_info = self.analyze_periodicity(asn, query_start, query_end)

        detected_periodicity = periodicity_info.get("detected_periodicity", "none")
        anomalies_detected = False
        anomaly_count = 0
        plot_path = None

        timestamps, current_values = self.get_traffic_data(asn, query_start, query_end)
        anomalies = []
        historical_data = []
        historical_means = np.array([])
        historical_stds = np.array([])
        historical_values_list = []

        if detected_periodicity in ["daily", "weekly"]:
                num_periods = 4 if detected_periodicity == "weekly" else 7
                for i in range(1, num_periods + 1):
                    if detected_periodicity == "weekly":
                        past_start = query_start - timedelta(days=7*i)
                        past_end = query_end - timedelta(days=7*i)
                    else:
                        past_start = query_start - timedelta(days=i)
                        past_end = query_end - timedelta(days=i)

                    timestamps_hist, values_hist = self.get_traffic_data(asn, past_start, past_end)
                    historical_data.append({
                    f"{detected_periodicity}_ago": i,
                        "timestamps": timestamps_hist,
                        "values": values_hist
                    })

                if historical_data:
                    current_values, historical_means, historical_stds, historical_values_list = preprocess_traffic_data(current_values, historical_data)

                anomalies = detect_anomalies_combined(current_values, historical_means, historical_stds, historical_values_list, threshold=3.0)

        elif detected_periodicity == "none":
            current_values_array = np.array(current_values)
            anomalies = detect_anomalies_non_periodic(current_values_array, threshold=2.5)

            formatted_anomalies = []
            for anomaly in anomalies:
                idx = anomaly["index"]
                formatted_anomalies.append({
                    "timestamp": timestamps[idx] if idx < len(timestamps) else timestamps[-1],
                    "current_value": anomaly["current_value"],
                    "historical_mean": historical_means[idx] if idx < len(historical_means) else 0.0,
                    "historical_std": historical_stds[idx] if idx < len(historical_stds) else 0.0,
                    "z_score": anomaly.get("z_score", 0.0),
                    "is_anomaly": True,
                    "method": anomaly.get("method", "unknown"),
                    "severity": anomaly.get("severity", "medium")
                })
            anomalies = formatted_anomalies

        expanded_start_time = None
        expanded_end_time = None
        if auto_expand_boundaries and anomalies and len(historical_means) > 0:
            try:
                expanded_start_time, expanded_end_time = expand_anomaly_boundaries(
                    anomalies, timestamps, current_values, historical_means, expansion_hours=2
                )
            except Exception as e:
                logger.warning(f"Boundary expansion failed: {e}")

        plot_path = None
        if plot_result:
                plot_path = plot_traffic_comparison_beautiful(
                    asn=asn,
                    start_date=start_time,
                    end_date=end_time,
                    timestamps=timestamps,
                    current_values=current_values,
                    historical_data=historical_data,
                    historical_means=historical_means,
                    historical_stds=historical_stds,
                anomalies=anomalies
                )

        anomalies_detected = len(anomalies) > 0
        anomaly_count = len(anomalies)

        stats = calculate_traffic_statistics(current_values, historical_means) if len(current_values) > 0 and len(historical_means) > 0 else {
            "current_avg": 0.0,
            "historical_avg": 0.0,
            "percent_change": 0.0,
            "data_points": len(current_values)
        }

        return {
            "success": True,
            "asn": asn,
            "anomalies_detected": anomalies_detected,
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "data_points": stats["data_points"],
            "percent_change": stats["percent_change"],
            "current_avg": stats["current_avg"],
            "historical_avg": stats["historical_avg"],
            "plot_path": plot_path,
            "expanded_boundaries": {
                "expanded_start": expanded_start_time if expanded_start_time else query_start.strftime("%Y-%m-%d %H:%M"),
                "expanded_end": expanded_end_time if expanded_end_time else query_end.strftime("%Y-%m-%d %H:%M")
            },
            "outage_period_anomalies": [],
            "periodicity_analysis": periodicity_info,
        }


    def analyze_periodicity(self, asn, query_start, query_end):
        try:
            historical_periods = []

            for week_offset in range(1, 5):
                period_start = query_start - timedelta(days=7*week_offset)
                period_end = query_end - timedelta(days=7*week_offset)

                try:
                    timestamps, values = self.get_traffic_data(asn, period_start, period_end)
                    if len(values) > 10:
                        historical_periods.append({
                            "week_offset": week_offset,
                            "start": period_start,
                            "end": period_end,
                            "timestamps": timestamps,
                            "values": values
                        })
                except Exception as e:
                    logger.warning(f"Failed to get historical data for week {week_offset}: {e}")
                    continue

            if len(historical_periods) < 2:
                return {
                    "detected_periodicity": "none",
                    "periodicity_confidence": 0.0,
                    "weekly_correlations": [],
                    "daily_correlations": [],
                    "analysis_period": f"Previous 4 weeks before {query_start.strftime('%Y-%m-%d %H:%M')} to {query_end.strftime('%Y-%m-%d %H:%M')}",
                    "note": "Insufficient historical data for periodicity analysis"
                }

            all_values = []
            all_timestamps = []

            for period in historical_periods:
                all_values.extend(period["values"])
                all_timestamps.extend(period["timestamps"])

            if len(all_values) < 24:
                return {
                    "detected_periodicity": "none",
                    "periodicity_confidence": 0.0,
                    "weekly_correlations": [],
                    "daily_correlations": [],
                    "analysis_period": f"Previous 4 weeks before {query_start.strftime('%Y-%m-%d %H:%M')} to {query_end.strftime('%Y-%m-%d %H:%M')}",
                    "note": "Insufficient data points for periodicity analysis"
                }

            period_result = detect_period_automatically(all_values, all_timestamps)

            detected_periodicity = period_result.get("period_name", "none")
            periodicity_confidence = period_result.get("confidence", 0.0)

            weekly_correlations = []
            daily_correlations = []

            all_candidates = period_result.get("all_candidates", [])
            for candidate in all_candidates:
                if candidate["period"] == "weekly":
                    weekly_correlations.append(candidate["confidence"])
                elif candidate["period"] == "daily":
                    daily_correlations.append(candidate["confidence"])

            return {
                "detected_periodicity": detected_periodicity,
                "periodicity_confidence": periodicity_confidence,
                "weekly_correlations": weekly_correlations,
                "daily_correlations": daily_correlations,
                "analysis_period": f"Previous 4 weeks before {query_start.strftime('%Y-%m-%d %H:%M')} to {query_end.strftime('%Y-%m-%d %H:%M')}",
                "detection_method": period_result.get("method", "unknown"),
                "historical_periods_analyzed": len(historical_periods)
            }

        except Exception as e:
            logger.warning(f"Periodicity analysis failed: {e}")
            return {
                "detected_periodicity": "none",
                "periodicity_confidence": 0.0,
                "weekly_correlations": [],
                "daily_correlations": [],
                "analysis_period": f"Previous 4 weeks before {query_start.strftime('%Y-%m-%d %H:%M')} to {query_end.strftime('%Y-%m-%d %H:%M')}",
                "error": str(e)
            }

    def get_traffic_data(self, asn, start_dt, end_dt):
        try:
            start_time_str = start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            end_time_str = end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

            params = {
                'dateStart': start_time_str,
                'dateEnd': end_time_str,
                'name': f'AS{asn}',
                'format': 'json'
            }

            logger.info(f"Fetching traffic time series for AS{asn} from {start_time_str} to {end_time_str}")
            response = self.session.get(self.base_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get('success') and 'result' in data:
                    result = data['result']
                    asn_key = f'AS{asn}'
                    if isinstance(result, dict) and asn_key in result:
                        as_data = result[asn_key]
                        if isinstance(as_data, dict) and 'timestamps' in as_data and 'values' in as_data:
                            timestamps = as_data['timestamps']
                            values = as_data['values']
                            if isinstance(timestamps, list) and isinstance(values, list) and len(values) > 0:
                                try:
                                    float_values = [float(v) for v in values if v is not None]
                                    logger.info(f"Successfully got {len(float_values)} data points for AS{asn}")
                                    return timestamps, float_values
                                except (ValueError, TypeError) as e:
                                    logger.warning(f"Data conversion error for AS{asn}: {e}")

            error_msg = f"API call failed for AS{asn}: HTTP {response.status_code}"
            logger.error(error_msg)
            raise Exception(error_msg)

        except Exception as e:
            error_msg = f"Exception in get_traffic_data for AS{asn}: {e}"
            logger.error(error_msg)
            raise Exception(error_msg)

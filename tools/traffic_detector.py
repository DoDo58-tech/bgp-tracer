import requests
import csv
import json
import os
import matplotlib.pyplot as plt
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Tuple
import numpy as np

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import (
    DATA_DIR,
    CLOUDFLARE_API_TOKEN,
    CLOUDFLARE_DEFAULT_AGG_INTERVAL,
    CLOUDFLARE_DEFAULT_THRESHOLD
)

# Cloudflare API configuration
CLOUDFLARE_API_PREFIX = "https://api.cloudflare.com/client/v4"

DEFAULT_OUTPUT_DIR = os.path.join(DATA_DIR, "traffic_plots")

class CloudflareRadarAPI:
    """Cloudflare Radar API interface class for retrieving AS traffic data and performing comprehensive analysis"""

    def __init__(self, api_token: str = CLOUDFLARE_API_TOKEN, base_url: str = None, output_dir: str = DEFAULT_OUTPUT_DIR):
        self.api_token = api_token
        # Use HTTP timeseries API with location filter
        # Note: Cloudflare HTTP API doesn't directly support AS filtering, but we can use location-based filtering
        # For AS-specific data, we'll use the timeseries endpoint with asn parameter
        self.base_url = f"{CLOUDFLARE_API_PREFIX}/radar/http/timeseries" if base_url is None else base_url
        self.output_dir = output_dir

        os.makedirs(self.output_dir, exist_ok=True)

        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        
        # Available metrics for comprehensive analysis
        self.available_metrics = {
            'traffic': 'HTTP requests and bandwidth',
            'performance': 'Response times and error rates', 
            'security': 'Security events and threats',
            'geography': 'Geographic distribution',
            'protocols': 'Protocol usage (HTTP/HTTPS, IPv4/IPv6)',
            'cache': 'Cache performance metrics'
        }

        # Map of additional Radar datasets for multi-source anomaly detection
        # Each entry contains (endpoint, params_builder)
        self.dataset_endpoints = {
            # Netflows (already used via base_url)
            'netflows': ("/radar/netflows/timeseries", lambda asn, start, end, agg: {
                'asn': asn,
                'dateStart': start,
                'dateEnd': end,
                'aggInterval': agg,
                'format': 'json',
                'normalization': 'MIN0_MAX'
            }),
            # HTTP requests over time for a specific AS (timeseries_groups/as)
            # Docs: https://developers.cloudflare.com/api/resources/radar/subresources/http/
            'http_as': ("/radar/http/timeseries_groups/as", lambda asn, start, end, agg: {
                'name': f"AS{asn}",
                'dateStart': start,
                'dateEnd': end,
                'aggInterval': agg,
                'format': 'json'
            }),
            # DNS queries over time for a specific AS (timeseries_groups/as)
            # Docs: https://developers.cloudflare.com/api/resources/radar/subresources/dns/
            'dns_as': ("/radar/dns/timeseries_groups/as", lambda asn, start, end, agg: {
                'name': f"AS{asn}",
                'dateStart': start,
                'dateEnd': end,
                'aggInterval': agg,
                'format': 'json'
            }),
            # Robots.txt user agent activity (proxy for crawler pressure)
            'robots': ("/radar/robots_txt/top/user_agents/directive", lambda asn, start, end, agg: {
                # This endpoint is top-style; we use it guardedly and ignore if fails
                'limit': 50
            }),
            # Email-related anomalies (timeouts/resets proxy)
            'tcp_resets_timeouts': ("/radar/tcp_resets_timeouts/timeseries_groups", lambda asn, start, end, agg: {
                'dateStart': start,
                'dateEnd': end,
                'aggInterval': agg,
                'format': 'json'
            })
        }
    
    def get_as_traffic(
        self,
        asn: str,
        start_date: str,
        end_date: str,
        agg_interval: str = "15m",
        format: str = "json",
        save_csv: bool = False
    ) -> Tuple[List[str], List[float]]:
        logger.info(f"Retrieving HTTP traffic data for AS{asn}...")

        if not self._validate_date(start_date) or not self._validate_date(end_date):
            logger.error("Start time or end time format is incorrect")
            return [], []

        logger.info(f"Time range: {start_date} to {end_date}")

        # Use HTTP API parameters with asn filter
        params = {
            'asn': asn,  # Use asn parameter directly
            'dateStart': start_date,
            'dateEnd': end_date,
            'aggInterval': agg_interval,
            'format': format
        }

        try:
            response = requests.get(self.base_url, headers=self.headers, params=params, timeout=30)

            if response.status_code == 200:
                logger.info("Successfully retrieved HTTP data from Cloudflare Radar API")
                data = response.json()

                if data.get('success'):
                    result = data.get('result', {})
                    # HTTP timeseries returns series data in a different format
                    serie_data = result.get('serie_0', result)
                    timestamps = serie_data.get('timestamps', [])
                    values = serie_data.get('values', [])

                    if not timestamps or not values:
                        logger.error("No valid time series found in API response data")
                        logger.debug(f"Response structure: {json.dumps(result, indent=2)[:500]}")
                        return [], []

                    logger.info(f"Retrieved HTTP data for {len(timestamps)} time points")

                    if save_csv:
                        self._save_to_csv(asn, start_date, end_date, timestamps, values)

                    return timestamps, values
                else:
                    logger.error("API returned failure")
                    logger.debug(f"Response: {json.dumps(data, indent=2)[:500]}")
                    return [], []
            else:
                logger.error(f"Request failed, status code: {response.status_code}")
                try:
                    error_details = response.json().get('errors', [{}])[0].get('message', response.text)
                except:
                    error_details = response.text
                logger.error(f"Error details: {error_details}")
                return [], []

        except requests.exceptions.RequestException as e:
            logger.error(f"Exception during network request: {e}")
            return [], []

    def _fetch_dataset_series(self, dataset_key: str, asn: str, start_date: str, end_date: str, agg_interval: str) -> Tuple[List[str], List[float]]:
        """Fetch a generic Radar dataset series. Best-effort: return empty on any incompatibility.
        Expects Cloudflare Radar envelope with result.serie_0.timestamps/values.
        """
        try:
            if dataset_key not in self.dataset_endpoints:
                return [], []
            endpoint, build_params = self.dataset_endpoints[dataset_key]
            url = f"{CLOUDFLARE_API_PREFIX}{endpoint}"
            params = build_params(asn, start_date, end_date, agg_interval)
            resp = requests.get(url, headers=self.headers, params=params, timeout=30)
            if resp.status_code != 200:
                return [], []
            data = resp.json()
            result = (data or {}).get('result') or {}
            # timeseries_groups/as returns serie_0; plain top endpoints may differ
            serie = result.get('serie_0') or {}
            ts = serie.get('timestamps') or []
            vals = serie.get('values') or []
            # Normalize to floats if possible
            try:
                vals = [float(v) for v in vals]
            except Exception:
                pass
            return ts, vals
        except Exception:
            return [], []
    
    def detect_anomalies(
        self,
        asn: str,
        start_time: str,
        end_time: str,
        threshold: float = CLOUDFLARE_DEFAULT_THRESHOLD,
        agg_interval: str = CLOUDFLARE_DEFAULT_AGG_INTERVAL,
        plot_result: bool = False,
        event_name: str = None,
        event_start_time: str = None,
        event_end_time: str = None,
        historical_weeks: List[int] = None,
        fast_mode: bool = False,
    ) -> Dict[str, Any]:
        from time import perf_counter
        _t0 = perf_counter()
        # Higher level may now pass the *outage window* (短时间窗) as start_time/end_time.
        # Here we normalize it and build the extended analysis window:
        #   [outage_start - 1 day, outage_end + 6 hours] (clipped to safe "now").
        if event_start_time and event_end_time:
            try:
                outage_start_dt = datetime.strptime(event_start_time, '%Y-%m-%d %H:%M')
                outage_end_dt = datetime.strptime(event_end_time, '%Y-%m-%d %H:%M')
            except ValueError:
                outage_start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M')
                outage_end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M')
        else:
            outage_start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M')
            outage_end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M')

        max_allowed_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=15)
        
        # Build extended analysis window and only clip the end.
        extended_start_dt = outage_start_dt - timedelta(days=1)
        extended_end_dt = outage_end_dt + timedelta(hours=6)
        detect_start_time_dt = extended_start_dt
        detect_end_time_dt = min(extended_end_dt, max_allowed_time)
        detect_start_time_str = detect_start_time_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        detect_end_time_str = detect_end_time_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

        current_timestamps, current_values = self.get_as_traffic(
            asn, 
            detect_start_time_str,
            detect_end_time_str,
            agg_interval=agg_interval,
        )
        
        # If Cloudflare returns an empty series, treat it as "no data" instead of a hard failure.
        if not current_values:
            logger.warning(
                "No Cloudflare Radar data available for AS%s in %s to %s "
                "- returning empty traffic analysis.",
                asn,
                detect_start_time_str,
                detect_end_time_str,
            )
            from time import perf_counter as _pc
            _elapsed = _pc() - _t0
            return {
                "success": True,
                "asn": asn,
                "current_date_range": f"{start_time} to {end_time}",
                "current_avg": 0.0,
                "historical_avg": 0.0,
                "percent_change": 0.0,
                "data_points": 0,
                "timestamps": [],
                "current_values": [],
                "historical_means": [],
                "historical_stds": [],
                "anomalies": [],
                "anomalies_detected": False,
                "anomaly_count": 0,
                "plot_path": None,
                "historical_data_count": 0,
                "analysis_timestamp": datetime.now().isoformat(),
                "additional_series": {},
                "elapsed_seconds": round(_elapsed, 3),
                "data_available": False,
                "note": "No Cloudflare Radar time series returned for this window.",
            }
        
        current_values = [float(v) for v in current_values]
        
        # Control historical depth:
        # - fast_mode=True -> only 1 week back
        # - historical_weeks param -> explicit list (e.g., [1, 2, 3, 4])
        # - default -> 4 weeks back
        if fast_mode:
            weeks_to_fetch = [1]
        elif historical_weeks:
            weeks_to_fetch = historical_weeks
        else:
            weeks_to_fetch = [1, 2, 3, 4]

        historical_data = []
        for weeks_ago in weeks_to_fetch:
            previous_start_dt = extended_start_dt - timedelta(days=7 * weeks_ago)
            previous_end_dt = detect_end_time_dt - timedelta(days=7 * weeks_ago)
            previous_start_time = previous_start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            previous_end_time = previous_end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            
            logger.info(f"Getting data from {weeks_ago} weeks ago: {previous_start_time} to {previous_end_time}")
            
            prev_timestamps, prev_values = self.get_as_traffic(
                asn, 
                previous_start_time,
                previous_end_time,
                agg_interval=agg_interval
            )
            
            if prev_values:
                prev_values = [float(v) for v in prev_values]
                historical_data.append({
                    "weeks_ago": weeks_ago,
                    "timestamps": prev_timestamps,
                    "values": prev_values
                })
                logger.info(f"Successfully retrieved {len(prev_values)} data points from {weeks_ago} weeks ago")
            else:
                logger.warning(f"Unable to retrieve data from {weeks_ago} weeks ago")
        
        if not historical_data:
            logger.error("Unable to retrieve any historical data for comparison")
            return {"success": False, "error": "Unable to retrieve any historical data for comparison"}
        
        min_length = len(current_values)
        for hist_data in historical_data:
            min_length = min(min_length, len(hist_data["values"]))
        
        if min_length == 0:
            logger.error("Data length after alignment is 0")
            return {"success": False, "error": "Data length after alignment is 0"}
        
        current_values = current_values[:min_length]
        current_timestamps = current_timestamps[:min_length]
        
        for hist_data in historical_data:
            hist_data["values"] = hist_data["values"][:min_length]
            hist_data["timestamps"] = hist_data["timestamps"][:min_length]
        
        historical_means = []
        historical_stds = []
        
        for i in range(min_length):
            point_values = [hist_data["values"][i] for hist_data in historical_data]
            mean_value = np.mean(point_values)
            std_value = np.std(point_values)
            
            historical_means.append(mean_value)
            historical_stds.append(std_value)
        
        anomalies = []
        for i in range(min_length):
            current_value = current_values[i]
            mean = historical_means[i]
            std = historical_stds[i]
            
            # Avoid infinite z-scores when the baseline is flat (std≈0). When
            # historical variance is zero, fall back to an adaptive tolerance
            # based on 5% of the baseline level (min 0.02 for normalized data).
            if std > 1e-6:
                effective_std = std
            else:
                effective_std = max(0.05 * max(abs(mean), 1.0), 0.02)
            
            # Prefer direct difference comparison to avoid reliance on division
            diff = abs(current_value - mean)
            tolerance = threshold * effective_std
            z_score = diff / effective_std if effective_std > 0 else float('inf')
            
            if diff > tolerance:
                anomaly = {
                    "timestamp": current_timestamps[i],
                    "current_value": current_value,
                    "historical_mean": mean,
                    "historical_std": std,
                    "z_score": z_score,
                    "is_anomaly": True
                }
                anomalies.append(anomaly)
                logger.warning(
                    "Anomaly detected: time=%s, current_value=%.4f, historical_mean=%.4f, "
                    "std_dev=%.4f, effective_std=%.4f, z_score=%.2f",
                    current_timestamps[i], current_value, mean, std, effective_std, z_score
                )
        
        current_avg = np.mean(current_values)
        historical_avg = np.mean(historical_means)
        percent_change = ((current_avg - historical_avg) / historical_avg * 100) if historical_avg > 0 else 0
        
        # Also try to pull additional datasets for correlation (best effort)
        additional_series = {}
        for key in ["http_as", "dns_as", "netflows"]:
            ts, vals = self._fetch_dataset_series(key, asn, detect_start_time_str, detect_end_time_str, agg_interval)
            if ts and vals:
                additional_series[key] = {"timestamps": ts[:len(current_timestamps)], "values": vals[:len(current_timestamps)]}

        plot_path = None
        if plot_result:
            plot_path = self._plot_comparison_beautiful(
                asn,
                start_time,
                end_time,
                current_timestamps,
                current_values,
                historical_data,
                historical_means,
                historical_stds,
                anomalies,
                overlay_series=additional_series,
                event_name=event_name,
                event_start_time=event_start_time,
                event_end_time=event_end_time,
            )
            if plot_path:
                logger.info(f"Beautiful traffic comparison chart saved to: {plot_path}")
        
        # Convert numpy types to Python native types for JSON serialization
        from time import perf_counter as _pc
        _elapsed = _pc() - _t0

        result = {
            "success": True,
            "asn": asn,
            "current_date_range": f"{start_time} to {end_time}",
            "current_avg": float(current_avg),
            "historical_avg": float(historical_avg),
            "percent_change": float(percent_change),
            "data_points": int(min_length),
            "timestamps": current_timestamps,
            "current_values": [float(v) for v in current_values],
            "historical_means": [float(v) for v in historical_means],
            "historical_stds": [float(v) for v in historical_stds],
            "anomalies": [
                {
                    "timestamp": anomaly["timestamp"],
                    "current_value": float(anomaly["current_value"]),
                    "historical_mean": float(anomaly["historical_mean"]),
                    "historical_std": float(anomaly["historical_std"]),
                    "z_score": float(anomaly["z_score"]),
                    "is_anomaly": anomaly["is_anomaly"]
                }
                for anomaly in anomalies
            ],
            "anomalies_detected": len(anomalies) > 0,
            "anomaly_count": len(anomalies),
            "plot_path": plot_path,
            "historical_data_count": len(historical_data),
            "analysis_timestamp": datetime.now().isoformat(),
            "additional_series": additional_series,
            "elapsed_seconds": round(_elapsed, 3)
        }
        
        return result
    
    def comprehensive_analysis(
        self,
        asn,
        start_time,
        end_time,
        metrics = None,
        threshold = CLOUDFLARE_DEFAULT_THRESHOLD,
        agg_interval = CLOUDFLARE_DEFAULT_AGG_INTERVAL,
        plot_result = True
    ):
        if metrics is None:
            metrics = list(self.available_metrics.keys())
        
        logger.info(f"Starting comprehensive analysis for AS{asn} with metrics: {metrics}")
        
        analysis_results = {
            "asn": asn,
            "analysis_period": f"{start_time} to {end_time}",
            "metrics_analyzed": metrics,
            "timestamp": datetime.now().isoformat(),
            "results": {}
        }
        
        # 1. Basic Traffic Analysis
        if 'traffic' in metrics:
            logger.info("Analyzing traffic metrics...")
            traffic_result = self.detect_anomalies(
                asn, start_time, end_time, 
                threshold=threshold, 
                agg_interval=agg_interval,
                plot_result=plot_result
            )
            analysis_results["results"]["traffic"] = traffic_result
        
        # 2. Performance Analysis
        if 'performance' in metrics:
            logger.info("Analyzing performance metrics...")
            performance_result = self._analyze_performance_metrics(
                asn, start_time, end_time, agg_interval
            )
            analysis_results["results"]["performance"] = performance_result
        
        # 3. Geographic Distribution Analysis
        if 'geography' in metrics:
            logger.info("Analyzing geographic distribution...")
            geo_result = self._analyze_geographic_distribution(
                asn, start_time, end_time, agg_interval
            )
            analysis_results["results"]["geography"] = geo_result
        
        # 4. Protocol Analysis
        if 'protocols' in metrics:
            logger.info("Analyzing protocol usage...")
            protocol_result = self._analyze_protocol_usage(
                asn, start_time, end_time, agg_interval
            )
            analysis_results["results"]["protocols"] = protocol_result
        
        # 5. Security Analysis
        if 'security' in metrics:
            logger.info("Analyzing security metrics...")
            security_result = self._analyze_security_metrics(
                asn, start_time, end_time, agg_interval
            )
            analysis_results["results"]["security"] = security_result
        
        # 6. Cache Performance Analysis
        if 'cache' in metrics:
            logger.info("Analyzing cache performance...")
            cache_result = self._analyze_cache_performance(
                asn, start_time, end_time, agg_interval
            )
            analysis_results["results"]["cache"] = cache_result
        
        # Generate comprehensive summary
        analysis_results["summary"] = self._generate_analysis_summary(analysis_results["results"])
        
        return analysis_results
    
    def _analyze_performance_metrics(
        self, 
        asn: str, 
        start_time: str, 
        end_time: str, 
        agg_interval: str
    ) -> Dict[str, Any]:
        """Analyze performance metrics like response times and error rates"""
        # This would use Cloudflare's performance API endpoints
        # For now, return a placeholder structure
        return {
            "success": True,
            "metrics": {
                "avg_response_time": 0.0,
                "error_rate": 0.0,
                "availability": 100.0,
                "p95_response_time": 0.0,
                "p99_response_time": 0.0
            },
            "anomalies": [],
            "note": "Performance analysis requires additional Cloudflare API endpoints"
        }
    
    def _analyze_geographic_distribution(
        self, 
        asn: str, 
        start_time: str, 
        end_time: str, 
        agg_interval: str
    ) -> Dict[str, Any]:
        """Analyze geographic distribution of traffic"""
        # This would use Cloudflare's geographic API endpoints
        return {
            "success": True,
            "top_countries": [],
            "traffic_by_region": {},
            "anomalies": [],
            "note": "Geographic analysis requires additional Cloudflare API endpoints"
        }
    
    def _analyze_protocol_usage(
        self, 
        asn: str, 
        start_time: str, 
        end_time: str, 
        agg_interval: str
    ) -> Dict[str, Any]:
        """Analyze protocol usage (HTTP/HTTPS, IPv4/IPv6)"""
        return {
            "success": True,
            "http_https_ratio": {"http": 0.0, "https": 100.0},
            "ipv4_ipv6_ratio": {"ipv4": 0.0, "ipv6": 100.0},
            "anomalies": [],
            "note": "Protocol analysis requires additional Cloudflare API endpoints"
        }
    
    def _analyze_security_metrics(
        self, 
        asn: str, 
        start_time: str, 
        end_time: str, 
        agg_interval: str
    ) -> Dict[str, Any]:
        """Analyze security events and threats"""
        return {
            "success": True,
            "threats_blocked": 0,
            "bot_traffic_percentage": 0.0,
            "ddos_attacks": 0,
            "anomalies": [],
            "note": "Security analysis requires additional Cloudflare API endpoints"
        }
    
    def _analyze_cache_performance(
        self, 
        asn: str, 
        start_time: str, 
        end_time: str, 
        agg_interval: str
    ) -> Dict[str, Any]:
        """Analyze cache performance metrics"""
        return {
            "success": True,
            "cache_hit_ratio": 0.0,
            "cache_miss_ratio": 0.0,
            "bandwidth_saved": 0.0,
            "anomalies": [],
            "note": "Cache analysis requires additional Cloudflare API endpoints"
        }
    
    def _generate_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive summary of all analysis results"""
        summary = {
            "total_anomalies": 0,
            "critical_issues": [],
            "performance_score": 0.0,
            "traffic_trend": "stable",
            "recommendations": []
        }
        
        # Count total anomalies across all metrics
        for metric, result in results.items():
            if isinstance(result, dict) and "anomalies" in result:
                summary["total_anomalies"] += len(result.get("anomalies", []))
        
        # Generate recommendations based on analysis
        if summary["total_anomalies"] > 10:
            summary["recommendations"].append("High number of anomalies detected - investigate immediately")
        elif summary["total_anomalies"] > 5:
            summary["recommendations"].append("Moderate anomalies detected - monitor closely")
        else:
            summary["recommendations"].append("Traffic appears normal - continue monitoring")
        
        return summary
    
    def _validate_date(self, date_string: str) -> bool:
        try:
            date_obj = datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%SZ')
            min_date = datetime(2022, 1, 1)
            
            if date_obj < min_date:
                logger.error(f"Date '{date_string}' is before January 1, 2022")
                logger.info("Cloudflare Radar only provides data after January 1, 2022")
                return False
            return True
        except ValueError:
            logger.error(f"Invalid date format: '{date_string}'")
            logger.info("Only supported format: YYYY-MM-DDThh:mm:ssZ (example: 2023-07-20T00:00:00Z)")
            return False
    
    def _save_to_csv(
        self, 
        asn: str, 
        start_date: str, 
        end_date: str, 
        timestamps: List[str], 
        values: List[str]
    ) -> None:
        output_filename = f"AS{asn}_traffic_{start_date}_to_{end_date}.csv"
        output_path = os.path.join(self.output_dir, output_filename)
        
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'value'])
                for ts, val in zip(timestamps, values):
                    writer.writerow([ts, val])
            logger.info(f"Data successfully saved to file: {output_path}")
        except Exception as e:
            logger.error(f"Error saving CSV file: {e}")

    def _plot_comparison_beautiful(
        self,
        asn: str,
        start_date: str,
        end_date: str,
        timestamps: List[str],
        current_values: List[float],
        historical_data: List[Dict[str, Any]],
        historical_means: List[float],
        historical_stds: List[float],
        anomalies: List[Dict[str, Any]] = None,
        overlay_series: Dict[str, Dict[str, Any]] = None,
        event_name: str = None,
        event_start_time: str = None,
        event_end_time: str = None,
    ) -> str:
        """
        Generate beautiful traffic comparison chart
        """
        try:
            # Set font style for better compatibility
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
            
            # Extended analysis window (visible X-axis span)
            start_time_dt = datetime.strptime(start_date, '%Y-%m-%d %H:%M')
            end_time_dt = datetime.strptime(end_date, '%Y-%m-%d %H:%M')
            
            # Outage / event window to highlight (defaults to full window)
            if event_start_time and event_end_time:
                try:
                    highlight_start_dt = datetime.strptime(event_start_time, '%Y-%m-%d %H:%M')
                    highlight_end_dt = datetime.strptime(event_end_time, '%Y-%m-%d %H:%M')
                except ValueError:
                    highlight_start_dt = start_time_dt
                    highlight_end_dt = end_time_dt
            else:
                highlight_start_dt = start_time_dt
                highlight_end_dt = end_time_dt
            
            x = np.arange(len(time_labels))
            mean_arr = np.array(historical_means)
            std_arr = np.array(historical_stds)
            current_arr = np.array(current_values)
            
            # Baseline ranges
            upper_std = mean_arr + std_arr
            lower_std = mean_arr - std_arr
            upper_3sigma = mean_arr + 3 * std_arr
            lower_3sigma = mean_arr - 3 * std_arr
            
            ax.fill_between(x, lower_3sigma, upper_3sigma, color='#B0C4DE', alpha=0.15, label='Baseline ±3σ')
            ax.plot(x, mean_arr, label='Baseline Mean', color='#FF8C42', linestyle='--', linewidth=2.5, alpha=0.9)
            
            # Plot current traffic data
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

            # Overlay HTTP and DNS if available
            if overlay_series:
                if 'http_as' in overlay_series:
                    http_vals = np.array(overlay_series['http_as']['values'][:len(x)], dtype=float)
                    ax.plot(x[:len(http_vals)], http_vals, label='HTTP Requests (AS)', color='#6A5ACD', linewidth=2, alpha=0.8)
                if 'dns_as' in overlay_series:
                    dns_vals = np.array(overlay_series['dns_as']['values'][:len(x)], dtype=float)
                    ax.plot(x[:len(dns_vals)], dns_vals, label='DNS Queries (AS)', color='#20B2AA', linewidth=2, alpha=0.8)
            
            # Calculate the actual time range for highlighting (original outage period)
            start_idx = 0
            end_idx = len(time_labels) - 1
            
            # Find the indices that correspond to start_time and end_time
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
            
            # Mark anomaly points with red dots
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
            
            # Set main chart style
            ax.set_title(f'AS{asn} Traffic Analysis - {start_date} to {end_date}', 
                         fontsize=16, fontweight='bold', pad=20)
            ax.set_ylabel('Traffic Value (Normalized)', fontsize=12)
            ax.grid(True, alpha=0.3, linestyle='-')
            ax.legend(loc='upper left', framealpha=0.9)
            
            # Calculate statistics
            current_avg = np.mean(current_arr)
            historical_avg = np.mean(mean_arr)
            percent_change = ((current_avg - historical_avg) / historical_avg * 100) if historical_avg > 0 else 0
            
            # Add statistics text box
            stats_text = f'Current Avg: {current_avg:.4f}\nBaseline Avg: {historical_avg:.4f}\nChange: {percent_change:+.2f}%'
            ax.text(
                0.02,
                0.98,
                stats_text,
                transform=ax.transAxes,
                    verticalalignment='top',
                bbox=dict(boxstyle='round,pad=0.5', facecolor='white', alpha=0.85),
                fontsize=10
            )
            
            # Set X-axis labels
            step = max(1, len(time_labels) // 10)
            tick_positions = x[::step] if step < len(x) else x
            tick_labels = time_labels[::step] if step < len(time_labels) else time_labels
            ax.set_xticks(tick_positions)
            ax.set_xticklabels(tick_labels, rotation=45)
            ax.set_xlim(0, len(x) - 1)
            
            # Adjust layout
            plt.tight_layout()

            # Save chart - organize by event if event_name is provided
            if event_name:
                # Create event-specific directory
                output_dir = os.path.join(self.output_dir, event_name)
            else:
                output_dir = self.output_dir

            os.makedirs(output_dir, exist_ok=True)
            output_filename = f'AS{asn}_{start_date}_to_{end_date}.png'.replace(':', '-')
            output_path = os.path.join(output_dir, output_filename)
            plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white', pad_inches=0.5)
            logger.info(f"Beautiful traffic comparison chart saved to: {output_path}")

            plt.close()
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating beautiful traffic comparison chart: {e}")
            return ""

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description='Cloudflare Radar API Traffic Analysis Tool')
    parser.add_argument('--api-token', default="ieMC57aZvmMHI_VCdBfyQg0-IEp1EEKNejuDPZWk", help='Cloudflare API token')
    parser.add_argument('--asn', required=True, help='AS number')
    parser.add_argument('--start-time', required=True, help='Start time, supported format: YYYY-MM-DD hh:mm')
    parser.add_argument('--end-time', help='End time, supported format: YYYY-MM-DD hh:mm')
    parser.add_argument('--threshold', type=float, default=3.0, help='Anomaly detection threshold (standard deviation multiplier)')
    parser.add_argument('--agg-interval', default='15m', help='Aggregation interval (15m, 1h, 1d, etc.)')
    parser.add_argument('--plot', action='store_true', help='Generate comparison chart')
    parser.add_argument('--comprehensive', action='store_true', help='Run comprehensive analysis with all metrics')
    parser.add_argument('--metrics', nargs='+', choices=['traffic', 'performance', 'geography', 'protocols', 'security', 'cache'],
                       help='Specific metrics to analyze (default: all if --comprehensive is used)')
    parser.add_argument('--output-json', help='Save results to JSON file')

    args = parser.parse_args()

    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    output_dir = DEFAULT_OUTPUT_DIR
    api = CloudflareRadarAPI(args.api_token, output_dir=output_dir)

    if args.comprehensive:
        # Run comprehensive analysis
        print(f"\n🔍 Starting Comprehensive Analysis for AS{args.asn}")
        print(f"📊 Available metrics: {', '.join(api.available_metrics.keys())}")
        
        result = api.comprehensive_analysis(
            args.asn,
            args.start_time,
            args.end_time,
            metrics=args.metrics,
            threshold=args.threshold,
            agg_interval=args.agg_interval,
            plot_result=args.plot
        )
        
        print(f"\n📈 Comprehensive Analysis Results for AS{args.asn}")
        print(f"⏰ Time Range: {result['analysis_period']}")
        print(f"📊 Metrics Analyzed: {', '.join(result['metrics_analyzed'])}")
        
        # Display summary
        summary = result.get('summary', {})
        print(f"\n📋 Summary:")
        print(f"  Total Anomalies: {summary.get('total_anomalies', 0)}")
        print(f"  Traffic Trend: {summary.get('traffic_trend', 'unknown')}")
        print(f"  Performance Score: {summary.get('performance_score', 0):.2f}")
        
        if summary.get('recommendations'):
            print(f"\n💡 Recommendations:")
            for rec in summary['recommendations']:
                print(f"  • {rec}")
        
        # Display detailed results for each metric
        for metric, data in result.get('results', {}).items():
            if isinstance(data, dict) and data.get('success'):
                print(f"\n📊 {metric.title()} Analysis:")
                if 'anomalies' in data and data['anomalies']:
                    print(f"  Anomalies detected: {len(data['anomalies'])}")
                    for i, anomaly in enumerate(data['anomalies'][:3], 1):
                        print(f"    {i}. {anomaly.get('timestamp', 'Unknown time')} - Severity: {anomaly.get('z_score', 0):.2f}")
                else:
                    print(f"  No anomalies detected")
        
    else:
        # Run basic traffic analysis
        result = api.detect_anomalies(
            args.asn,
            args.start_time,
            args.end_time,
            threshold=args.threshold,
            agg_interval=args.agg_interval,
            plot_result=args.plot
        )
        
        if result["success"]:
            print(f"\nAS{args.asn} Traffic Analysis Results:")
            print(f"Time Range: {result['current_date_range']}")
            print(f"  Total Data Points: {result['data_points']}")
            
            if result["anomalies"]:
                print("\nKey Anomalies (Top 3):")
                for i, anomaly in enumerate(result["anomalies"], 1):
                    print(f"  {i}. Time: {anomaly['timestamp']}, Severity: {anomaly['z_score']:.2f}")
            else:
                print("\nNo anomalies detected")
                
        else:
            print(f"\nAnalysis failed: {result.get('error', 'Unknown error')}")
    
    # Save results to JSON if requested
    if args.output_json:
        with open(args.output_json, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n💾 Results saved to: {args.output_json}") 
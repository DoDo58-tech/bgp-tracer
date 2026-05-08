import os
import sys
import numpy as np
from datetime import datetime, timedelta
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import (
    CLOUDFLARE_HTTP_TIMESERIES_AS_URL,
    CLOUDFLARE_API_TOKEN,
    CLOUDFLARE_TIMEOUT,
    CLOUDFLARE_DEFAULT_AGG_INTERVAL,
    CLOUDFLARE_RADAR_LOCATION,
    CLOUDFLARE_RADAR_NORMALIZATION,
)
from data.asorg_loader import get_asn_org_info
from detectors.traffic.traffic_plotting import plot_traffic_comparison_beautiful
from detectors.traffic.traffic_analysis_utils import (
    detect_anomalies_combined,
    detect_anomalies_non_periodic,
    detect_anomalies_by_event_type,
    preprocess_traffic_data,
    preprocess_traffic_data_aligned,
    calculate_traffic_statistics,
    detect_period_automatically,
    expand_anomaly_boundaries
)
from pathlib import Path

# 模块级缓存：AS 编号 -> ISO 3166-1 alpha-2 国家代码（如 "RU", "CN"）
_as_country_cache: dict[str, str] = {}


def _get_as_country(asn: int | str, target_time: datetime | None = None) -> str | None:
    """
    根据 AS 编号查询其所属国家，返回 ISO 3166-1 alpha-2 代码。
    首次查询会下载/解析 AS-Org 数据（耗时数秒），之后命中缓存直接返回。
    若查询失败或 AS 未找到，返回 None（不影响主流程）。
    target_time: 事件发生时间，用于选对应月份的 AS-Org 数据文件；默认用固定时间兜底。
    """
    asn_str = str(asn)
    if asn_str in _as_country_cache:
        return _as_country_cache[asn_str]

    # 用事件时间选数据文件；没有时就用固定近月兜底
    lookup_time = target_time if target_time else datetime(2025, 1, 1)
    info = get_asn_org_info(lookup_time, asn)
    country = info.get("country") if info.get("success") else None
    _as_country_cache[asn_str] = country
    if country:
        logger.info(f"AS{asn} 所属国家: {country} ({info.get('org_name', '')})")
    else:
        logger.warning(f"AS{asn} 未找到国家信息，使用全球视角。")
    return country


class CloudflareRadarAPI:
    def __init__(self):
        self.base_url = CLOUDFLARE_HTTP_TIMESERIES_AS_URL
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {CLOUDFLARE_API_TOKEN}',
            'Content-Type': 'application/json'
        })
        # 每个检测实例内缓存：asn -> 该次检测用的 location
        self._resolved_country: dict = {}

    def quick_screening(self, asn, start_time, end_time):
        """
        快速预检模式 - 快速判断是否需要完整分析
        
        设计目标：5-10秒内完成，用于决定是否触发完整检测
        
        Returns:
            dict: {
                "need_full_analysis": bool,  # 是否需要完整分析
                "quick_score": float,         # 0-1 异常分数
                "data_available": bool,       # 数据是否可用
                "anomaly_signals": list,      # 快速检测到的异常信号
                "decision_reasons": list      # 决策原因说明
            }
        """
        try:
            # 解析时间
            try:
                user_start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                user_start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
            
            try:
                user_end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                user_end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
            
            # 快速获取数据：仅获取事件时间段（不加扩展）
            query_start = user_start_dt
            query_end = user_end_dt
            
            timestamps, current_values = self.get_traffic_data(asn, query_start, query_end)
            
            if not current_values or len(current_values) < 5:
                return {
                    "need_full_analysis": False,
                    "quick_score": 0.0,
                    "data_available": False,
                    "anomaly_signals": [],
                    "decision_reasons": ["数据点不足，无法进行可靠分析"]
                }
            
            # 简单统计检查
            current_arr = np.array(current_values)
            current_avg = np.mean(current_arr)
            current_std = np.std(current_arr)
            
            # 获取1-2周前的同期数据作为参考
            anomaly_signals = []
            quick_score = 0.0
            
            for week_offset in [1, 2]:
                past_start = user_start_dt - timedelta(days=7 * week_offset)
                past_end = user_end_dt - timedelta(days=7 * week_offset)
                
                try:
                    _, past_values = self.get_traffic_data(asn, past_start, past_end)
                    
                    if past_values and len(past_values) >= 5:
                        past_arr = np.array(past_values)
                        past_avg = np.mean(past_arr)
                        past_std = np.std(past_arr)
                        
                        # 简单比较
                        if current_avg > 0:
                            change_pct = abs(current_avg - past_avg) / past_avg * 100
                            
                            if change_pct > 50:
                                anomaly_signals.append(f"大幅变化: {change_pct:.1f}% (vs {week_offset}周前)")
                                quick_score += 0.4
                            elif change_pct > 30:
                                anomaly_signals.append(f"中度变化: {change_pct:.1f}% (vs {week_offset}周前)")
                                quick_score += 0.25
                            elif change_pct > 15:
                                anomaly_signals.append(f"轻度变化: {change_pct:.1f}% (vs {week_offset}周前)")
                                quick_score += 0.1
                        
                        # 检查方差变化（波动性）
                        if past_avg > 0 and current_std / past_avg > 2:
                            anomaly_signals.append(f"波动性激增: {current_std/past_avg:.2f}x (vs {week_offset}周前)")
                            quick_score += 0.2
                        
                        # 只需两周数据即可做决定
                        break
                except Exception:
                    continue
            
            # 数据点稀疏性检测
            if len(current_values) < len(timestamps) * 0.5 if timestamps else False:
                anomaly_signals.append("数据稀疏性异常")
                quick_score += 0.15
            
            # 归一化分数
            quick_score = min(1.0, quick_score)
            
            # 决策阈值
            THRESHOLD_HIGH = 0.5   # 高置信度异常，必须完整分析
            THRESHOLD_LOW = 0.2    # 低阈值，考虑数据质量
            
            decision_reasons = []
            need_full_analysis = False
            
            if quick_score >= THRESHOLD_HIGH:
                need_full_analysis = True
                decision_reasons.append(f"快速评分 {quick_score:.2f} >= {THRESHOLD_HIGH}，高置信度异常")
            elif quick_score >= THRESHOLD_LOW and anomaly_signals:
                need_full_analysis = True
                decision_reasons.append(f"快速评分 {quick_score:.2f} >= {THRESHOLD_LOW}，存在异常信号")
            else:
                decision_reasons.append(f"快速评分 {quick_score:.2f} < {THRESHOLD_LOW}，无明显异常")
            
            logger.info(
                f"Quick screening AS{asn}: score={quick_score:.2f}, "
                f"signals={len(anomaly_signals)}, need_full={need_full_analysis}"
            )
            
            return {
                "need_full_analysis": need_full_analysis,
                "quick_score": quick_score,
                "data_available": True,
                "anomaly_signals": anomaly_signals,
                "decision_reasons": decision_reasons,
                "data_points_checked": len(current_values),
                "screening_time": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.warning(f"Quick screening failed for AS{asn}: {e}")
            # 快速检测失败时，默认执行完整分析以确保安全
            return {
                "need_full_analysis": True,
                "quick_score": 0.5,
                "data_available": False,
                "anomaly_signals": [f"快速检测异常: {str(e)}"],
                "decision_reasons": ["快速检测失败，执行完整分析以确保安全"],
                "error": str(e)
            }

    def detect_anomalies(self, asn, start_time, end_time, plot_result=False, event_start_time=None, event_end_time=None, fast_mode=True, historical_weeks=None, anomaly_method="combined", auto_expand_boundaries=True):
        # Handle both formats with and without seconds
        try:
            user_start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            user_start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        
        try:
            user_end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            user_end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")

        # 用事件发生时间来选对应月份的 AS-Org 数据文件
        if CLOUDFLARE_RADAR_LOCATION:
            self._resolved_country[str(asn)] = CLOUDFLARE_RADAR_LOCATION
        else:
            country = _get_as_country(asn, target_time=user_start_dt)
            self._resolved_country[str(asn)] = country
            if not country:
                logger.warning(f"AS{asn} 未找到国家信息，将使用全球视角。")

        query_start = user_start_dt - timedelta(days=1)
        query_end = user_end_dt + timedelta(hours=6)

        periodicity_info = self.analyze_periodicity(asn, query_start, query_end)

        detected_periodicity = periodicity_info.get("detected_periodicity", "none")
        periodicity_confidence = periodicity_info.get("periodicity_confidence", 0.0)
        detection_method = periodicity_info.get("detection_method", "unknown")
        best_effort = periodicity_info.get("best_effort", False)

        # Relaxed mode: use weekly as fallback when no clear periodicity detected
        use_periodicity = detected_periodicity
        if detected_periodicity == "none" and periodicity_info.get("historical_periods_analyzed", 0) >= 2:
            use_periodicity = "weekly"
            logger.info("🔄 No clear period detected; using weekly as reference for comparison (relaxed mode).")

        # Log periodicity detection results
        logger.info(f"🔄 Periodicity detection: {detected_periodicity} (confidence: {periodicity_confidence:.2%}, method: {detection_method})")
        if best_effort:
            logger.info("🔄 Using period as best-effort reference for anomaly comparison.")

        anomalies_detected = False
        anomaly_count = 0
        plot_path = None

        timestamps, current_values = self.get_traffic_data(asn, query_start, query_end)
        anomalies = []
        historical_data = []
        historical_means = np.array([])
        historical_stds = np.array([])
        historical_values_list = []

        if use_periodicity in ["daily", "weekly"]:
                num_periods = 4 if use_periodicity == "weekly" else 7
                for i in range(1, num_periods + 1):
                    if use_periodicity == "weekly":
                        past_start = query_start - timedelta(days=7*i)
                        past_end = query_end - timedelta(days=7*i)
                    else:
                        past_start = query_start - timedelta(days=i)
                        past_end = query_end - timedelta(days=i)

                    timestamps_hist, values_hist = self.get_traffic_data(asn, past_start, past_end)
                    historical_data.append({
                        f"{use_periodicity}_ago": i,
                        "timestamps": timestamps_hist,
                        "values": values_hist
                    })

                if historical_data:
                    current_values, historical_means, historical_stds, historical_values_list = preprocess_traffic_data(current_values, historical_data)
                    # 与 preprocess 截断后的序列对齐，避免 anomaly index 与 timestamps 长度不一致
                    _tl = len(current_values)
                    if len(timestamps) > _tl:
                        timestamps = timestamps[:_tl]

                anomalies = detect_anomalies_combined(current_values, historical_means, historical_stds, historical_values_list, timestamps=timestamps, threshold=3.0)

        elif detected_periodicity == "none":
            current_values_array = np.array(current_values)
            anomalies = detect_anomalies_non_periodic(current_values_array, threshold=2.5)

            formatted_anomalies = []
            for anomaly in anomalies:
                idx = anomaly["index"]
                formatted_anomalies.append({
                    "index": idx,
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
                title_suffix = ""
                if CLOUDFLARE_RADAR_LOCATION:
                    title_suffix += f" [Radar geo={CLOUDFLARE_RADAR_LOCATION}]"
                else:
                    # 自动查询的国家信息已在 _as_country_cache 中
                    country = _as_country_cache.get(str(asn))
                    if country:
                        title_suffix += f" [AS org country={country}]"
                if CLOUDFLARE_RADAR_NORMALIZATION:
                    title_suffix += f" [norm={CLOUDFLARE_RADAR_NORMALIZATION}]"
                plot_path = plot_traffic_comparison_beautiful(
                    asn=asn,
                    start_date=start_time,
                    end_date=end_time,
                    timestamps=timestamps,
                    current_values=current_values,
                    historical_data=historical_data,
                    historical_means=historical_means,
                    historical_stds=historical_stds,
                    anomalies=anomalies,
                    title_suffix=title_suffix,
                )

        anomalies_detected = len(anomalies) > 0
        anomaly_count = len(anomalies)

        # Calculate consecutive anomaly time windows
        consecutive_anomaly_windows = []
        if anomalies_detected and timestamps:
            try:
                sorted_anomalies = sorted(anomalies, key=lambda x: x.get('timestamp', ''))
                if sorted_anomalies:
                    # Find consecutive anomaly groups
                    indices = sorted({a.get('index', i) for i, a in enumerate(sorted_anomalies)})
                    groups = []
                    current_group = [indices[0]]
                    for idx in indices[1:]:
                        if idx == current_group[-1] + 1:
                            current_group.append(idx)
                        else:
                            groups.append(current_group)
                            current_group = [idx]
                    groups.append(current_group)
                    
                    # Filter groups with 4+ consecutive points
                    for g in groups:
                        if len(g) >= 4:
                            start_idx = g[0]
                            end_idx = g[-1]
                            if start_idx < len(timestamps) and end_idx < len(timestamps):
                                window = {
                                    "start": timestamps[start_idx],
                                    "end": timestamps[end_idx],
                                    "duration_points": len(g)
                                }
                                consecutive_anomaly_windows.append(window)
                                logger.info(f"📊 Detected consecutive anomaly window: {window['start']} to {window['end']} ({len(g)} points)")
            except Exception as e:
                logger.warning(f"Failed to calculate consecutive anomaly windows: {e}")

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
            "consecutive_anomaly_windows": consecutive_anomaly_windows,
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
                    "note": "Insufficient historical data for periodicity analysis",
                    "historical_periods_analyzed": len(historical_periods),
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
                    "note": "Insufficient data points for periodicity analysis",
                    "historical_periods_analyzed": len(historical_periods),
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
                "historical_periods_analyzed": len(historical_periods),
                "best_effort": period_result.get("best_effort", False),
            }

        except Exception as e:
            logger.warning(f"Periodicity analysis failed: {e}")
            return {
                "detected_periodicity": "none",
                "periodicity_confidence": 0.0,
                "weekly_correlations": [],
                "daily_correlations": [],
                "analysis_period": f"Previous 4 weeks before {query_start.strftime('%Y-%m-%d %H:%M')} to {query_end.strftime('%Y-%m-%d %H:%M')}",
                "error": str(e),
                "historical_periods_analyzed": 0,
            }

    def get_traffic_data(self, asn, start_dt, end_dt):
        try:
            start_time_str = start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            end_time_str = end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

            # 优先级：环境变量 > 本次检测已解析的国家 > 不加 location（全球）
            location = CLOUDFLARE_RADAR_LOCATION
            if not location:
                location = self._resolved_country.get(str(asn))

            params = {
                'dateStart': start_time_str,
                'dateEnd': end_time_str,
                'asn': str(asn),
                'name': f'AS{asn}',
                'format': 'json',
                'aggInterval': CLOUDFLARE_DEFAULT_AGG_INTERVAL,
            }
            if location:
                params['location'] = location
            # normalization 参数仅接受 PERCENTAGE_CHANGE / MIN0_MAX（见 Radar API 文档），不传则默认 PERCENTAGE
            if CLOUDFLARE_RADAR_NORMALIZATION:
                params['normalization'] = CLOUDFLARE_RADAR_NORMALIZATION

            logger.info(
                f"Fetching traffic time series for AS{asn} from {start_time_str} to {end_time_str} "
                f"(aggInterval={CLOUDFLARE_DEFAULT_AGG_INTERVAL}, "
                f"location={location or 'worldwide'}, "
                f"normalization={CLOUDFLARE_RADAR_NORMALIZATION or '(default PERCENTAGE)'})"
            )
            response = self.session.get(self.base_url, params=params, timeout=CLOUDFLARE_TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                if data.get('success') and 'result' in data:
                    result = data['result']
                    meta = result.get('meta') if isinstance(result, dict) else None
                    if isinstance(meta, dict):
                        logger.debug(
                            "Cloudflare Radar meta: aggInterval=%s, normalization=%s",
                            meta.get('aggInterval'),
                            meta.get('normalization'),
                        )
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
            try:
                err_detail = response.json()
            except Exception:
                err_detail = {"raw": response.text[:500]}
            logger.error(f"{error_msg} | response: {err_detail}")
            raise Exception(error_msg)

        except Exception as e:
            error_msg = f"Exception in get_traffic_data for AS{asn}: {e}"
            logger.error(error_msg)
            raise Exception(error_msg)


    def detect_anomalies_for_event(
        self,
        asn: str,
        start_time: str,
        end_time: str,
        event_type: str = "hijack",
        as_role: str = "victim",
        plot_result: bool = True,
        use_aligned_baseline: bool = True
    ):
        """
        基于事件类型的异常检测（改进版）
        
        Args:
            asn: AS号
            start_time: 开始时间
            end_time: 结束时间
            event_type: 事件类型 (hijack/leak/outage)
            as_role: AS角色 (hijacker/victim/source/transit/destination/affected)
            plot_result: 是否生成图
            use_aligned_baseline: 是否使用时间对齐的历史基线
        
        Returns:
            异常检测结果字典
        """
        # Handle both formats with and without seconds
        try:
            user_start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            user_start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        
        try:
            user_end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            user_end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        
        # 获取当前数据
        query_start = user_start_dt - timedelta(days=1)
        query_end = user_end_dt + timedelta(hours=6)
        
        timestamps, current_values = self.get_traffic_data(asn, query_start, query_end)
        
        if not timestamps or not current_values:
            return {
                "success": False,
                "asn": asn,
                "event_type": event_type,
                "as_role": as_role,
                "error": "No traffic data available"
            }
        
        # 获取历史数据（4周）
        historical_data = []
        for i in range(1, 5):
            past_start = user_start_dt - timedelta(days=7*i + 1)
            past_end = user_start_dt - timedelta(days=7*i - 1)
            ts_hist, vals_hist = self.get_traffic_data(asn, past_start, past_end)
            if ts_hist and vals_hist:
                historical_data.append({
                    "weekly_ago": i,
                    "timestamps": ts_hist,
                    "values": vals_hist
                })
        
        # 预处理数据
        if use_aligned_baseline and historical_data:
            current_arr, historical_means, historical_stds, historical_list = preprocess_traffic_data_aligned(
                current_values, historical_data, timestamps
            )
        else:
            current_arr, historical_means, historical_stds, historical_list = preprocess_traffic_data(
                current_values, historical_data
            )
            # 截断timestamps
            _tl = len(current_arr)
            if len(timestamps) > _tl:
                timestamps = timestamps[:_tl]
        
        # 使用基于事件类型的异常检测
        anomalies = detect_anomalies_by_event_type(
            current_arr,
            historical_means,
            historical_stds,
            timestamps,
            event_type=event_type,
            as_role=as_role
        )
        
        # 如果基于事件类型的检测没有结果，回退到通用检测
        if not anomalies:
            logger.info(f"No anomalies detected by event-type method, falling back to combined method")
            anomalies = detect_anomalies_combined(
                current_arr, historical_means, historical_stds, historical_list, 
                timestamps=timestamps, threshold=2.5
            )
        
        # 计算统计信息
        stats = calculate_traffic_statistics(current_arr, historical_means)
        
        # 生成图
        plot_path = None
        if plot_result:
            try:
                plot_path = plot_traffic_comparison_beautiful(
                    asn=asn,
                    start_date=start_time,
                    end_date=end_time,
                    timestamps=timestamps,
                    current_values=current_arr.tolist() if hasattr(current_arr, 'tolist') else current_arr,
                    historical_data=historical_data,
                    historical_means=historical_means.tolist() if hasattr(historical_means, 'tolist') else historical_means,
                    historical_stds=historical_stds.tolist() if hasattr(historical_stds, 'tolist') else historical_stds,
                    anomalies=anomalies,
                    title_suffix=f" [{event_type.upper()} - {as_role.upper()}]"
                )
            except Exception as e:
                logger.warning(f"Plot generation failed: {e}")
        
        return {
            "success": True,
            "asn": asn,
            "event_type": event_type,
            "as_role": as_role,
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "anomalies_detected": len(anomalies) > 0,
            "statistics": stats,
            "plot_path": plot_path,
            "analysis_timestamp": datetime.now().isoformat()
        }


def detect_anomalies_for_event_batch(
    events: list,
    output_dir: str = None
):
    """
    批量检测事件异常
    
    Args:
        events: 事件列表，每项包含:
            - asn: AS号
            - start_time: 开始时间
            - end_time: 结束时间
            - event_type: 事件类型
            - as_role: AS角色
        output_dir: 输出目录
    
    Returns:
        检测结果列表
    """
    api = CloudflareRadarAPI()
    results = []
    
    for event in events:
        result = api.detect_anomalies_for_event(
            asn=event.get('asn'),
            start_time=event.get('start_time'),
            end_time=event.get('end_time'),
            event_type=event.get('event_type', 'hijack'),
            as_role=event.get('as_role', 'victim'),
            plot_result=True
        )
        results.append(result)
        
        if result.get('anomalies_detected'):
            logger.info(f"AS{result['asn']} ({result['as_role']}): {result['anomaly_count']} anomalies detected")
        else:
            logger.info(f"AS{result['asn']} ({result['as_role']}): No anomalies detected")
    
    return results

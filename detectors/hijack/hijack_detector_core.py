import sys
import os
import re
import json
import pandas as pd
import ipaddress
from datetime import datetime
from typing import List, Dict, Set, Tuple, Any, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from detectors.hijack.hijack_utils import check_fake_connections_single_row, build_as_pair_set


def build_optimized_prefix_lookup(prefix_to_as):
    logger.info("Building optimized prefix lookup structure for efficient sub-prefix hijack detection...")
    prefix_list = []
    for prefix_str in prefix_to_as.keys():
        try:
            network = ipaddress.ip_network(prefix_str, strict=False)
            prefix_list.append((network, prefix_str))
        except Exception as e:
            logger.warning(f"Invalid prefix format: {prefix_str} - {e}")
            continue

    prefix_list.sort(key=lambda x: x[0].prefixlen, reverse=True)
    optimized_data = [(net, prefix_str, prefix_to_as[prefix_str]) for net, prefix_str in prefix_list]

    logger.info(f"Built optimized prefix lookup with {len(optimized_data)} prefixes")
    return optimized_data


def find_parent_prefix_optimized(target_prefix, optimized_prefixes):
    try:
        target_network = ipaddress.ip_network(target_prefix, strict=False)
        for parent_network, parent_prefix, origins in optimized_prefixes:
            if parent_network.supernet_of(target_network):
                return parent_prefix, origins

        return None, None

    except Exception as e:
        logger.debug(f"Error in parent prefix lookup for {target_prefix}: {e}")
        return None, None


def check_origin_hijack_vectorized(row, prefix_to_as):
    try:
        prefix = row.get('prefix', '')
        as_path = row.get('as-path', '')
        timestamp = row.get('timestamp', '')

        if not prefix or not as_path:
            return None

        legitimate_origins = None
        checked_prefix = prefix

        if prefix in prefix_to_as:
            legitimate_origins = prefix_to_as[prefix]
        else:
            # Sub-prefix hijack detection: find parent prefix using optimized lookup
            if not hasattr(check_origin_hijack_vectorized, 'optimized_prefixes'):
                check_origin_hijack_vectorized.optimized_prefixes = build_optimized_prefix_lookup(prefix_to_as)

            parent_prefix, origins = find_parent_prefix_optimized(prefix, check_origin_hijack_vectorized.optimized_prefixes)

            if parent_prefix:
                legitimate_origins = origins
                checked_prefix = parent_prefix
                logger.debug(f"Found parent prefix {parent_prefix} for sub-prefix {prefix}")

        if not legitimate_origins:
            return None

        path_parts = as_path.strip().split()
        if not path_parts:
            return None

        origin_as = path_parts[-1]
        if not origin_as:
            return None

        if origin_as in legitimate_origins:
            return None
        else:
            return {
                'hijack_type': 'origin_hijack',
                'timestamp': timestamp,
                'prefix': prefix,
                'checked_prefix': checked_prefix,
                'origin_as': origin_as,
                'legitimate_origins': legitimate_origins,
                'as_path': as_path
            }

    except Exception as e:
        logger.warning(f"Error in origin hijack check: {e}")
        return None


def detect_origin_hijacks(announcements, prefix_to_as):
    try:
        if announcements.empty:
            logger.warning("No announcements to analyze for origin hijacks")
            return []

        logger.info(f"Analyzing {len(announcements)} announcements for origin hijacks")

        hijack_alerts = []
        for idx, row in announcements.iterrows():
            hijack_info = check_origin_hijack_vectorized(row, prefix_to_as)
            if hijack_info:
                hijack_alerts.append(hijack_info)

        logger.info(f"Detected {len(hijack_alerts)} origin hijacks")
        return hijack_alerts

    except Exception as e:
        logger.error(f"Error detecting origin hijacks: {e}")
        return []


def batch_check_connection_frequency(updates_df, as_relationships,
                                   target_as, fake_conn_cache_manager, full_day_data=None):
    try:
        if updates_df.empty:
            return updates_df

        logger.info(f"Checking connection frequency for {len(updates_df)} updates")

        as_pairs = build_as_pair_set(as_relationships)

        updates_df['date'] = pd.to_datetime(updates_df['timestamp']).dt.date.astype(str)

        suspicious_updates = []

        for idx, row in updates_df.iterrows():
            try:
                date_str = row['date']
                row_dict = row.to_dict()
                as_path_str = row_dict.get('as-path', '')

                # 检查假连接 - 使用新的AS对缓存系统
                fake_connections = []
                if fake_conn_cache_manager:
                    from detectors.hijack.hijack_cache_manager import get_asrel_hash, get_cached_as_pair, set_cached_as_pair
                    asrel_hash = get_asrel_hash(as_relationships)

                    # 对AS路径中的每个连接对进行检查和缓存
                    as_path_list = as_path_str.split()
                    for i in range(len(as_path_list) - 1):
                        as1, as2 = as_path_list[i], as_path_list[i + 1]

                        # 检查缓存
                        cached_pair = get_cached_as_pair(as1, as2, date_str, asrel_hash)
                        if cached_pair is not None:
                            # 使用缓存结果
                            if cached_pair['is_fake']:
                                fake_connections.append({
                                    'as1': as1,
                                    'as2': as2,
                                    'position': i,
                                    'path': as_path_str,
                                    'timestamp': cached_pair.get('timestamp', date_str)  # 使用缓存的日期或当前日期
                                })
                        else:
                            # 计算并缓存
                            is_fake = (as1, as2) not in as_pairs
                            # 传递日期字符串，确保缓存记录有明确的日期标识
                            set_cached_as_pair(as1, as2, date_str, asrel_hash, is_fake, date_str)

                            if is_fake:
                                fake_connections.append({
                                    'as1': as1,
                                    'as2': as2,
                                    'position': i,
                                    'path': as_path_str,
                                    'timestamp': row_dict.get('timestamp', '')
                                })
                else:
                    # 回退到原始方法
                    fake_connections = check_fake_connections_single_row(row_dict, as_pairs)

                updates_df.at[idx, 'fake_connections'] = json.dumps(fake_connections)
                updates_df.at[idx, 'has_fake_connect'] = len(fake_connections) > 0

                for fake_conn in fake_connections:
                    if fake_conn_cache_manager.is_fake_conn_cached(fake_conn, date_str):
                        cached_result = fake_conn_cache_manager.get_cached_fake_conn_frequency(fake_conn, date_str)
                        if cached_result.get('is_suspicious', False):
                            suspicious_updates.append(idx)
                    else:
                        frequency_data = analyze_connection_frequency(fake_conn, date_str, full_day_data if full_day_data is not None else updates_df)
                        fake_conn_cache_manager.set_cached_fake_conn_frequency(fake_conn, date_str, frequency_data)

                        if frequency_data.get('is_suspicious', False):
                            suspicious_updates.append(idx)

            except Exception as e:
                logger.warning(f"Error checking connection frequency for update {idx}: {e}")
                continue

        updates_df['connection_frequency_suspicious'] = False
        if suspicious_updates:
            updates_df.loc[suspicious_updates, 'connection_frequency_suspicious'] = True
            logger.info(f"Marked {len(suspicious_updates)} updates as suspicious based on connection frequency")

        return updates_df

    except Exception as e:
        logger.error(f"Error in batch connection frequency check: {e}")
        updates_df['connection_frequency_suspicious'] = False
        return updates_df


def calculate_adaptive_threshold(updates_df, fake_connection, date_str):
    try:
        if updates_df is None or updates_df.empty:
            return 0.001  # Default to 0.1% if no data

        # Filter for the specific date
        date_updates = updates_df[updates_df['date'] == date_str]
        if date_updates.empty:
            return 0.001

        total_updates = len(date_updates)

        # Extract AS numbers from the fake connection (format: "AS1|AS2")
        try:
            as1, as2 = fake_connection.split('|')
            target_as = as1 if as1.isdigit() else as2  # Use the first valid AS number
        except:
            return 0.001  # Default if parsing fails

        # Count how many updates involve this AS
        as_activity_count = 0
        if 'as-path' in date_updates.columns:
            for as_path in date_updates['as-path'].fillna(''):
                if str(target_as) in str(as_path):
                    as_activity_count += 1

        # Calculate activity ratio (what percentage of all updates involve this AS)
        activity_ratio = as_activity_count / total_updates if total_updates > 0 else 0

        # Adaptive threshold based on activity level
        if activity_ratio >= 0.1:  # Very active AS (>10% of all updates)
            # Strict threshold: 0.05% (very conservative for large ISPs)
            threshold = 0.0005
        elif activity_ratio >= 0.01:  # Moderately active AS (1-10%)
            # Standard threshold: 0.1%
            threshold = 0.001
        elif activity_ratio >= 0.001:  # Low activity AS (0.1-1%)
            # Relaxed threshold: 0.2%
            threshold = 0.002
        else:  # Very low activity AS (<0.1%)
            # Very relaxed threshold: 0.5%
            threshold = 0.005

        # Ensure threshold doesn't exceed reasonable bounds
        threshold = max(0.0001, min(threshold, 0.01))  # Between 0.01% and 1%

        return threshold

    except Exception as e:
        logger.warning(f"Error calculating adaptive threshold: {e}")
        return 0.001  # Default fallback


def analyze_connection_frequency(fake_connection, date_str, updates_df):
    try:
        if updates_df is None or updates_df.empty:
            return {
                'connection': fake_connection,
                'date': date_str,
                'count': 0,
                'total_updates': 0,
                'frequency_ratio': 0.0,
                'is_suspicious': True,
                'note': 'No BGP data available for frequency analysis',
                'data_coverage': 'unavailable',
                'analysis_timestamp': datetime.now().isoformat()
            }

        # Filter updates for the specific date
        date_updates = updates_df[updates_df['date'] == date_str]

        if date_updates.empty:
            return {
                'connection': fake_connection,
                'date': date_str,
                'count': 0,
                'total_updates': 0,
                'frequency_ratio': 0.0,
                'is_suspicious': True,
                'note': f'No BGP data available for date {date_str}',
                'data_coverage': 'insufficient',
                'analysis_timestamp': datetime.now().isoformat()
            }

        # Get AS path column
        if 'as_path' in date_updates.columns:
            as_path_series = date_updates['as_path'].fillna('').astype(str)
        elif 'as-path' in date_updates.columns:
            as_path_series = date_updates['as-path'].fillna('').astype(str)
        else:
            as_path_series = pd.Series([''] * len(date_updates), index=date_updates.index)

        # Count occurrences of the fake connection in ALL BGP announcements for the day
        connection_count = 0
        for as_path in as_path_series:
            try:
                if isinstance(as_path, (list, tuple)):
                    as_path_str = ' '.join(map(str, as_path))
                else:
                    as_path_str = str(as_path)

                if fake_connection in as_path_str:
                    connection_count += 1
            except Exception:
                continue

        total_updates = len(date_updates)
        frequency_ratio = connection_count / total_updates if total_updates > 0 else 0

        # Dynamic threshold based on AS activity level
        # Calculate threshold based on the AS's activity in the full day data
        threshold_used = calculate_adaptive_threshold(updates_df, fake_connection, date_str)
        is_suspicious = frequency_ratio <= threshold_used

        result = {
            'connection': fake_connection,
            'date': date_str,
            'count': connection_count,
            'total_updates': total_updates,
            'frequency_ratio': frequency_ratio,
            'is_suspicious': is_suspicious,
            'threshold_used': threshold_used,
            'threshold_percentage': threshold_used * 100,
            'data_coverage': 'full_day',  # Now using complete BGP dataset
            'analysis_quality': 'adaptive',
            'note': f'Analyzed {total_updates:,} BGP announcements with adaptive threshold ({threshold_used*100:.2f}%)',
            'analysis_timestamp': datetime.now().isoformat()
        }

        return result

    except Exception as e:
        logger.error(f"Error analyzing connection frequency: {e}")
        return {
            'connection': fake_connection,
            'date': date_str,
            'error': str(e),
            'is_suspicious': True,  # Default to suspicious on error
            'data_coverage': 'error'
        }


def detect_forge_hijacks(updates_df, as_relationships,
                        target_as, fake_conn_cache_manager, full_day_data=None, prefix_to_as=None, *args, **kwargs):
    try:
        logger.info(f"Detecting forged path hijacks for AS{target_as}")

        if updates_df.empty:
            return [], updates_df

        analyzed_df = batch_check_connection_frequency(
            updates_df, as_relationships, target_as, fake_conn_cache_manager, full_day_data
        )

        suspicious_updates = analyzed_df[analyzed_df['connection_frequency_suspicious'] == True]

        alerts = []
        for idx, row in suspicious_updates.iterrows():
            try:
                # 从DataFrame中读取并反序列化fake_connections
                fake_connections_json = row.get('fake_connections', '[]')
                try:
                    fake_connections = json.loads(fake_connections_json) if fake_connections_json else []
                except (json.JSONDecodeError, TypeError):
                    fake_connections = []
                prefix = row.get('prefix', '')

                # 确定受害者（prefix的合法拥有者）
                victim_ases = []
                if prefix and prefix_to_as:
                    victim_ases = prefix_to_as.get(prefix, [])

                # 确定攻击者（假连接中的AS）
                attacker_ases = set()
                for fake_conn in fake_connections:
                    attacker_ases.add(fake_conn['as1'])
                    attacker_ases.add(fake_conn['as2'])

                alert = {
                    'type': 'forged_path_hijack',
                    'target_as': target_as,
                    'timestamp': row['timestamp'],
                    'prefix': prefix,
                    'as_path': row.get('as-path', ''),
                    'confidence': 'medium',
                    'reason': 'Suspicious connection frequency detected',
                    'fake_connections': fake_connections,
                    'victim_ases': victim_ases,
                    'attacker_ases': list(attacker_ases),
                    'details': {
                        'date': row.get('date', ''),
                        'analysis_type': 'connection_frequency'
                    }
                }
                alerts.append(alert)

            except Exception as e:
                logger.warning(f"Error generating alert for suspicious update {idx}: {e}")
                continue

        logger.info(f"Detected {len(alerts)} potential forged path hijacks")
        return alerts, analyzed_df

    except Exception as e:
        logger.error(f"Error detecting forged path hijacks: {e}")
        return [], updates_df


def validate_hijack_detection(hijack_alerts, updates_df):
    try:
        validation = {
            'total_alerts': len(hijack_alerts),
            'alerts_by_type': {},
            'temporal_distribution': {},
            'validation_passed': True,
            'issues': []
        }

        for alert in hijack_alerts:
            alert_type = alert.get('type', 'unknown')
            validation['alerts_by_type'][alert_type] = validation['alerts_by_type'].get(alert_type, 0) + 1

        timestamps = [alert['timestamp'] for alert in hijack_alerts if 'timestamp' in alert]
        if len(timestamps) > 1:
            time_diffs = []
            sorted_times = sorted(timestamps)
            for i in range(1, len(sorted_times)):
                try:
                    dt1 = datetime.fromisoformat(sorted_times[i-1].replace('Z', '+00:00'))
                    dt2 = datetime.fromisoformat(sorted_times[i].replace('Z', '+00:00'))
                    time_diffs.append((dt2 - dt1).total_seconds())
                except:
                    continue

            if time_diffs and all(diff < 60 for diff in time_diffs):
                validation['issues'].append("All alerts clustered within 1 minute - possible false positive")

        valid_alerts = 0
        for alert in hijack_alerts:
            if 'timestamp' in alert and 'prefix' in alert:
                matching_updates = updates_df[
                    (updates_df['timestamp'] == alert['timestamp']) &
                    (updates_df['prefix'] == alert['prefix'])
                ]
                if not matching_updates.empty:
                    valid_alerts += 1

        if valid_alerts != len(hijack_alerts):
            validation['issues'].append(f"Only {valid_alerts}/{len(hijack_alerts)} alerts correspond to actual updates")
            validation['validation_passed'] = False

        return validation

    except Exception as e:
        logger.error(f"Error validating hijack detection: {e}")
        return {
            'validation_passed': False,
            'error': str(e)
        }

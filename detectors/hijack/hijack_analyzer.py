import sys
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Tuple
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


def aggregate_anomalies(anomalies):
    try:
        if not anomalies:
            return []

        logger.info(f"Aggregating {len(anomalies)} anomalies")

        aggregated = {}
        time_window_seconds = 300

        for anomaly in anomalies:
            try:
                anomaly_type = anomaly.get('type', 'unknown')
                prefix = anomaly.get('prefix', 'unknown')
                timestamp = anomaly.get('timestamp', '')

                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    time_key = int(dt.timestamp() // time_window_seconds) * time_window_seconds
                except:
                    time_key = 0

                group_key = f"{anomaly_type}|{prefix}|{time_key}"

                if group_key not in aggregated:
                    aggregated[group_key] = {
                        'type': anomaly_type,
                        'prefix': prefix,
                        'time_window_start': time_key,
                        'count': 0,
                        'anomalies': [],
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'confidence': anomaly.get('confidence', 'low')
                    }

                agg = aggregated[group_key]
                agg['count'] += 1
                agg['anomalies'].append(anomaly)
                agg['last_seen'] = timestamp

                if agg['count'] >= 5:
                    agg['confidence'] = 'high'
                elif agg['count'] >= 2:
                    agg['confidence'] = 'medium'

            except Exception as e:
                logger.warning(f"Error aggregating anomaly: {e}")
                continue

        result = list(aggregated.values())
        result.sort(key=lambda x: x['count'], reverse=True)

        logger.info(f"Aggregated into {len(result)} anomaly groups")
        return result

    except Exception as e:
        logger.error(f"Error aggregating anomalies: {e}")
        return anomalies


def pick_timestamp(current, candidate, prefer_min = True):
    try:
        if not current:
            return candidate
        if not candidate:
            return current

        dt_current = datetime.fromisoformat(current.replace('Z', '+00:00'))
        dt_candidate = datetime.fromisoformat(candidate.replace('Z', '+00:00'))

        if prefer_min:
            return current if dt_current <= dt_candidate else candidate
        else:
            return current if dt_current >= dt_candidate else candidate

    except Exception as e:
        logger.warning(f"Error comparing timestamps: {e}")
        return current or candidate


def save_alert_messages(target_as, start_time, end_time,
                       mitm_alerts, origin_alerts):
    try:
        alerts_dir = Path(__file__).resolve().parent.parent.parent / "results" / "json"
        alerts_dir.mkdir(parents=True, exist_ok=True)

        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        filename = f"hijack_alerts_AS{target_as}_{start_dt.strftime('%Y%m%d_%H%M')}_{end_dt.strftime('%Y%m%d_%H%M')}.json"

        alert_file = alerts_dir / filename

        alert_data = {
            'target_as': target_as,
            'analysis_period': {
                'start_time': start_time,
                'end_time': end_time
            },
            'alerts': {
                'mitm_hijacks': mitm_alerts,
                'origin_hijacks': origin_alerts,
                'total_mitm': len(mitm_alerts),
                'total_origin': len(origin_alerts),
                'total_alerts': len(mitm_alerts) + len(origin_alerts)
            },
            'generated_at': datetime.now().isoformat(),
            'analysis_summary': {
                'most_common_hijack_type': 'mitm' if len(mitm_alerts) >= len(origin_alerts) else 'origin',
                'severity_assessment': assess_alert_severity(mitm_alerts + origin_alerts)
            }
        }

        with open(alert_file, 'w', encoding='utf-8') as f:
            json.dump(alert_data, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"Saved {alert_data['alerts']['total_alerts']} hijack alerts to {alert_file}")
        return str(alert_file)

    except Exception as e:
        logger.error(f"Error saving alert messages: {e}")
        return ""


def assess_alert_severity(alerts):
    try:
        if not alerts:
            return "none"

        total_alerts = len(alerts)
        high_confidence = sum(1 for alert in alerts if alert.get('confidence') == 'high')

        if total_alerts >= 10 or high_confidence >= 5:
            return "critical"
        elif total_alerts >= 5 or high_confidence >= 2:
            return "high"
        elif total_alerts >= 2 or high_confidence >= 1:
            return "medium"
        else:
            return "low"

    except Exception as e:
        logger.error(f"Error assessing alert severity: {e}")
        return "unknown"


def generate_hijack_report(target_as, alerts,
                          analysis_period):
    try:
        report = {
            'target_as': target_as,
            'analysis_period': analysis_period,
            'report_generated_at': datetime.now().isoformat(),
            'summary': {
                'total_alerts': len(alerts),
                'alert_types': {},
                'severity_levels': {},
                'time_distribution': {},
                'affected_prefixes': set()
            },
            'details': {
                'alerts': alerts,
                'recommendations': [],
                'risk_assessment': {}
            }
        }

        for alert in alerts:
            alert_type = alert.get('type', 'unknown')
            report['summary']['alert_types'][alert_type] = report['summary']['alert_types'].get(alert_type, 0) + 1

            severity = alert.get('confidence', 'low')
            report['summary']['severity_levels'][severity] = report['summary']['severity_levels'].get(severity, 0) + 1

            prefix = alert.get('prefix', '')
            if prefix:
                report['summary']['affected_prefixes'].add(prefix)

        report['summary']['affected_prefixes'] = list(report['summary']['affected_prefixes'])

        report['details']['recommendations'] = _generate_hijack_recommendations(report['summary'])

        report['details']['risk_assessment'] = _assess_hijack_risk(report['summary'])

        return report

    except Exception as e:
        logger.error(f"Error generating hijack report: {e}")
        return {
            'target_as': target_as,
            'error': str(e),
            'report_generated_at': datetime.now().isoformat()
        }


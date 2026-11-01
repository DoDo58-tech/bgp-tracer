import sys
import os
import json
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


class StreamingAnomalyAggregator:
    def __init__(self):
        self._groups: dict = {}
        self._time_window_seconds = 300

    def add_chunk(self, chunk_alerts):
        """Process and aggregate one chunk's alerts; they are discarded after return."""
        if not chunk_alerts:
            return

        for anomaly in chunk_alerts:
            try:
                atype = anomaly.get('type', 'unknown')
                prefix = anomaly.get('prefix', 'unknown')
                timestamp = anomaly.get('timestamp', '')

                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    time_key = int(dt.timestamp() // self._time_window_seconds) * self._time_window_seconds
                except ValueError:
                    time_key = 0

                key = f"{atype}|{prefix}|{time_key}"

                if key not in self._groups:
                    self._groups[key] = {
                        'type': atype,
                        'prefix': prefix,
                        'time_window_start': time_key,
                        'count': 0,
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'confidence': anomaly.get('confidence', 'low')
                    }

                g = self._groups[key]
                g['count'] += 1
                g['last_seen'] = timestamp

                if g['count'] >= 5:
                    g['confidence'] = 'high'
                elif g['count'] >= 2:
                    g['confidence'] = 'medium'

            except ValueError:
                continue

        # Allow GC to reclaim the chunk list immediately
        chunk_alerts.clear()

    def finalize(self):
        """Return the sorted list of aggregated groups."""
        result = list(self._groups.values())
        result.sort(key=lambda x: x['count'], reverse=True)
        self._groups.clear()
        return result


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

        # Write atomically: parallel verification workers can otherwise read a
        # half-written file and report a spurious JSONDecodeError.
        tmp_file = alert_file.with_suffix(alert_file.suffix + f".tmp{os.getpid()}")
        with open(tmp_file, 'w', encoding='utf-8') as f:
            json.dump(alert_data, f, indent=2, ensure_ascii=False, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, alert_file)

        logger.info(f"Saved {alert_data['alerts']['total_alerts']} hijack alerts to {alert_file}")
        return str(alert_file)

    except AttributeError as e:
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

    except AttributeError as e:
        logger.error(f"Error assessing alert severity: {e}")
        return "unknown"

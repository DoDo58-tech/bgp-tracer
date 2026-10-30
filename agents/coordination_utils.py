"""Shared utilities for the BGP Tracer multi-agent system."""

import json
from datetime import datetime, timedelta
from pathlib import Path

from utils.logger import logger


def load_json(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (AttributeError) as e:
        logger.warning(f"Failed to load JSON from {filepath}: {e}")
        return {}


def lookup_org_info(asn, asorg_file):
    if not asorg_file or not Path(asorg_file).exists():
        return {"success": False, "error": "AS organization data file not available", "asn": asn}
    data = load_json(asorg_file)
    asn_to_org_id = data.get("asn_to_org_id", {})
    asn_to_name = data.get("asn_to_name", {})
    org_id_to_info = data.get("org_id_to_info", {})

    asn_norm = str(asn).strip().upper()
    if asn_norm.startswith("AS"):
        asn_norm = asn_norm[2:]
    try:
        asn_norm = str(int(asn_norm))
    except (ValueError):
        pass

    org_id = asn_to_org_id.get(asn_norm)
    as_name = asn_to_name.get(asn_norm, "Unknown")
    if not org_id:
        return {"success": False, "asn": asn, "as_name": as_name, "error": "ASN not found in organization mappings"}
    org_info = org_id_to_info.get(org_id, {})
    return {
        "success": True,
        "asn": asn,
        "as_name": as_name,
        "org_id": org_id,
        "org_name": org_info.get("org_name") or org_info.get("name", "Unknown"),
        "country": org_info.get("country", "Unknown"),
        "source": org_info.get("source", "Unknown"),
    }


def normalize_time(value):
    for fmt in ["%Y-%m-%d %H:%M", "%Y:%m:%d %H:%M", "%Y/%m/%d %H:%M"]:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError):
            continue
    return value


def query_as_relationships(asn, asrel_file):
    if not asrel_file or not Path(asrel_file).exists():
        return {"success": False, "error": "AS relationship data file not available", "asn": asn}
    data = load_json(asrel_file)
    if not data:
        return {"success": False, "error": "Failed to load AS relationship data", "asn": asn}
    providers_data = data.get("providers", {})
    peers_data = data.get("peers", {})
    asn_stripped = str(asn).strip().upper().lstrip("AS")

    def lookup(d, asn_key):
        v = d.get(asn_key, [])
        if v:
            return v
        return d.get(f"AS{asn_key}", [])

    providers = lookup(providers_data, asn_stripped)
    peers = lookup(peers_data, asn_stripped)
    customers = []
    for customer_asn, customer_providers in providers_data.items():
        try:
            normalised = [str(x).strip().upper().lstrip("AS") for x in customer_providers]
            if asn_stripped in normalised:
                customers.append(str(customer_asn).strip().upper().lstrip("AS"))
        except (ValueError):
            continue
    return {
        "success": True,
        "asn": asn,
        "providers": providers,
        "peers": peers,
        "customers": customers,
        "total_providers": len(providers),
        "total_peers": len(peers),
        "total_customers": len(customers),
    }






def query_as_prefixes(asn, prefix2as_file):
    if not prefix2as_file or not Path(prefix2as_file).exists():
        return {"success": False, "error": "Prefix-to-AS data file not available", "asn": asn}
    data = load_json(prefix2as_file)
    if not data:
        return {"success": False, "error": "Failed to load prefix-to-AS data", "asn": asn}
    asn_str = str(asn)
    asn_stripped = asn_str.upper().lstrip("AS")
    prefixes = []
    for prefix, origin in data.items():
        if isinstance(origin, list):
            owners = origin
        else:
            owners = [origin]
        for o in owners:
            if o is None:
                continue
            owner_norm = str(o).strip().upper().lstrip("AS")
            if owner_norm == asn_stripped:
                prefixes.append(prefix)
                break
    return {"success": True, "asn": asn, "prefixes": prefixes, "total_prefixes": len(prefixes)}




# ── Timestamp & anomaly helpers ─────────────────────────────────────────────────

def parse_anomaly_timestamp(timestamp_str):
    """Parse a timestamp string into a datetime object. Returns None on failure."""
    if not timestamp_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue
    logger.warning(f"Failed to parse anomaly timestamp: {timestamp_str}")
    return None


def identify_consecutive_anomaly_periods(
    anomalies,
    min_consecutive_count=3,
    max_gap_minutes=60,
):
    """Group anomalies into consecutive periods.
    
    Returns:
    List of (start_dt, end_dt) tuples for periods meeting the criteria."""
    if not anomalies:
        return []
    times = sorted(
        t for t in (parse_anomaly_timestamp(a.get("timestamp", "")) for a in anomalies)
        if t
    )
    if not times:
        return []

    periods = []
    cur_start = cur_end = times[0]
    count = 1
    for t in times[1:]:
        if (t - cur_end).total_seconds() / 60 <= max_gap_minutes:
            cur_end = t
            count += 1
        else:
            if count >= min_consecutive_count:
                periods.append((cur_start, cur_end))
            cur_start = cur_end = t
            count = 1
    if count >= min_consecutive_count:
        periods.append((cur_start, cur_end))
    return periods


def extract_anomaly_time_range(
    anomalies,
    buffer_hours=0,
    use_consecutive_periods=True,
    min_consecutive_count=3,
    max_gap_minutes=60,
):
    """Extract a (start, end) datetime range from a list of anomalies.
    
    When use_consecutive_periods=True (default), picks the longest period
    among consecutive anomaly clusters."""
    if not anomalies:
        return None, None

    if use_consecutive_periods:
        periods = identify_consecutive_anomaly_periods(
            anomalies,
            min_consecutive_count=min_consecutive_count,
            max_gap_minutes=max_gap_minutes,
        )
        if not periods:
            logger.info(
                f"No consecutive anomaly periods found (need ≥{min_consecutive_count} "
                f"consecutive anomalies, max gap {max_gap_minutes} min). "
                f"Total anomalies: {len(anomalies)}"
            )
            return None, None
        start_dt, end_dt = max(periods, key=lambda p: (p[1] - p[0]).total_seconds())
    else:
        times = [
            t for t in (parse_anomaly_timestamp(a.get("timestamp", "")) for a in anomalies)
            if t
        ]
        if not times:
            return None, None
        start_dt, end_dt = min(times), max(times)

    start_dt -= timedelta(hours=buffer_hours)
    end_dt += timedelta(hours=buffer_hours)
    logger.info(
        f"Extracted anomaly range (±{buffer_hours}h buffer): "
        f"{start_dt.strftime('%Y-%m-%d %H:%M')} → {end_dt.strftime('%Y-%m-%d %H:%M')}"
    )
    return start_dt, end_dt


def count_consecutive_anomalies_in_longest_period(
    anomalies,
    min_consecutive_count=3,
    max_gap_minutes=60,
):
    """Count anomalies within the longest consecutive period."""
    periods = identify_consecutive_anomaly_periods(
        anomalies,
        min_consecutive_count=min_consecutive_count,
        max_gap_minutes=max_gap_minutes,
    )
    if not periods:
        return 0
    period_start, period_end = max(periods, key=lambda p: (p[1] - p[0]).total_seconds())
    count = 0
    for a in anomalies:
        ts = parse_anomaly_timestamp(a.get("timestamp", ""))
        if ts is None:
            continue
        if period_start <= ts <= period_end:
            count += 1
    return count


def clean_timestamps(data):
    """Recursively replace datetime objects with ISO strings for JSON serialization."""
    if isinstance(data, dict):
        return {k: clean_timestamps(v) for k, v in data.items()}
    if isinstance(data, list):
        return [clean_timestamps(item) for item in data]
    if hasattr(data, "strftime"):
        return str(data)
    return data
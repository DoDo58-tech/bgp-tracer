import json
from datetime import datetime
from typing import Dict, Any, List, Set
from pathlib import Path

from .traffic_detect import CloudflareRadarAPI
from .hijack_detect import detect_hijacks
from data.asorg_loader import get_asorg_data, parse_asorg_file
from utils.logger import logger

_CURRENT_CTX: Dict[str, Any] = {"as_rel_data": {}, "as_prefixes_data": {}, "asorg_parsed": {}}


def set_current_context(ctx: Dict[str, Any]) -> None:
    try:
        _CURRENT_CTX["as_rel_data"] = ctx.get("as_relationships", {}) or {}
        _CURRENT_CTX["as_prefixes_data"] = ctx.get("prefix_to_as", {}) or {}
        _CURRENT_CTX["asorg_parsed"] = ctx.get("asorg_parsed", {}) or _CURRENT_CTX.get("asorg_parsed", {})
    except Exception:
        pass

def make_json_safe(value: Any) -> Any:
    try:
        if value is None:
            return None
        if isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, set):
            return sorted([make_json_safe(v) for v in value])
        if isinstance(value, (list, tuple)):
            return [make_json_safe(v) for v in value]
        if isinstance(value, dict):
            return {str(k): make_json_safe(v) for k, v in value.items()}
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Path):
            return str(value)
        return str(value)
    except Exception:
        return str(value)

def get_legal_prefixes_for_as(asn: str, prefix_to_as: Dict[str, Any]) -> Dict[str, Any]:
    try:
        asn_str = asn if isinstance(asn, str) else str(asn)
        if asn_str.upper().startswith("AS"):
            asn_str = asn_str[2:]
        prefixes = [p for p, a in (prefix_to_as or {}).items() if str(a) == asn_str]
        return {
            "success": True,
            "asn": asn,
            "prefixes": prefixes,
            "total_prefixes": len(prefixes),
        }
    except Exception as e:
        return {"success": False, "error": str(e), "asn": asn, "prefixes": [], "total_prefixes": 0}


def get_legal_prefixes_for_as_ctx(asn: str) -> Dict[str, Any]:
    try:
        result = get_legal_prefixes_for_as(asn, _CURRENT_CTX.get("as_prefixes_data", {}))
        if not isinstance(result, dict):
            return {"success": False, "error": "Invalid result format", "asn": asn, "prefixes": [], "total_prefixes": 0}
        return result
    except Exception as e:
        return {"success": False, "error": str(e), "asn": asn, "prefixes": [], "total_prefixes": 0}


def get_org_info_all(date_or_datetime: str) -> Dict[str, Any]:
    try:
        try:
            dt = datetime.strptime(date_or_datetime, "%Y-%m-%d %H:%M")
        except Exception:
            dt = datetime.strptime(date_or_datetime, "%Y-%m-%d")
        txt_path = get_asorg_data(dt)
        parsed = parse_asorg_file(txt_path)
        return parsed
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_org_info_for_as(asn: str, asorg_parsed: Dict[str, Any]) -> Dict[str, Any]:
    try:
        parsed = asorg_parsed or {}
        asn_to_org_id = parsed.get("asn_to_org_id", {})
        asn_to_name = parsed.get("asn_to_name", {})
        org_id_to_info = parsed.get("org_id_to_info", {})
        
        key = str(asn)
        if key.upper().startswith("AS"):
            key = key[2:]
        try:
            key = str(int(key))
        except Exception:
            pass
            
        org_id = asn_to_org_id.get(key)
        as_name = asn_to_name.get(key, "Unknown")
        org_info = org_id_to_info.get(org_id or "", {})
        
        return {
            "success": bool(org_id),
            "asn": asn,
            "as_name": as_name,
            "org_id": org_id or "",
            "org_name": org_info.get("name", "Unknown"),
            "country": org_info.get("country", "Unknown"),
            "source": org_info.get("source", "Unknown"),
            "changed": org_info.get("changed", ""),
        }
    except Exception as e:
        return {"success": False, "asn": asn, "error": str(e)}


def get_org_info_for_as_ctx(asn: str) -> Dict[str, Any]:
    try:
        parsed = _CURRENT_CTX.get("asorg_parsed", {}) or {}
        if not parsed:
            return {"success": False, "asn": asn, "error": "as-org context not set"}
        result = get_org_info_for_as(asn, parsed)
        if not isinstance(result, dict):
            return {"success": False, "asn": asn, "error": "Invalid result format"}
        return result
    except Exception as e:
        return {"success": False, "asn": asn, "error": str(e)}


def get_relationships_from_map(asn: str, as_rel_data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        providers_map = as_rel_data.get("providers") or {}
        peers_map = as_rel_data.get("peers") or {}
        asn_str = asn if isinstance(asn, str) else str(asn)
        
        providers = sorted(list(providers_map.get(asn_str, set()) or set()))
        peers = sorted(list(peers_map.get(asn_str, set()) or set()))
        
        customers: List[str] = []
        for customer_as, their_providers in providers_map.items():
            try:
                if asn_str in (their_providers or set()):
                    customers.append(customer_as)
            except Exception:
                continue
                
        return {
            "success": True,
            "asn": asn_str,
            "providers": providers,
            "peers": peers,
            "customers": customers,
            "total_providers": len(providers),
            "total_peers": len(peers),
            "total_customers": len(customers),
        }
    except Exception as e:
        return {"success": False, "asn": asn, "error": str(e), "providers": [], "peers": [], "customers": []}


def get_relationships_ctx(asn: str) -> Dict[str, Any]:
    try:
        result = get_relationships_from_map(asn, _CURRENT_CTX.get("as_rel_data", {}))
        if not isinstance(result, dict):
            return {"success": False, "asn": asn, "error": "Invalid result format", "providers": [], "peers": [], "customers": []}
        return result
    except Exception as e:
        return {"success": False, "asn": asn, "error": str(e), "providers": [], "peers": [], "customers": []}


def analyze_traffic(asn: str, start_time: str, end_time: str) -> Dict[str, Any]:
    try:
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        
        min_date = datetime(2022, 1, 1)
        if start_dt < min_date:
            return {
                "success": False,
                "error": f"Start time {start_time} is before January 1, 2022. Cloudflare Radar only provides data after this date",
                "anomalies": [],
                "timestamps": [],
                "current_values": [],
                "historical_means": [],
                "historical_stds": [],
                "percent_change": 0
            }
        
        api = CloudflareRadarAPI()
        result = api.detect_anomalies(
            asn=asn,
            start_time=start_time,
            end_time=end_time,
            plot_result=False
        )
        return result
        
    except ValueError as e:
        return {
            "success": False,
            "error": f"Time format error: {e}, please use format YYYY-MM-DD HH:MM",
            "anomalies": [],
            "timestamps": [],
            "current_values": [],
            "historical_means": [],
            "historical_stds": [],
            "percent_change": 0
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Traffic analysis failed: {str(e)}",
            "anomalies": [],
            "timestamps": [],
            "current_values": [],
            "historical_means": [],
            "historical_stds": [],
            "percent_change": 0
        }


def analyze_routing(asn: str, start_time: str, end_time: str) -> Dict[str, Any]:
    try:
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")

        origin_hijacked, forge_hijacked, origin_hijacking, forge_hijacking, hijack_ctx = detect_hijacks(start_dt, end_dt, asn)
        
        set_current_context(hijack_ctx)

        routing = {
            "success": True,
            "origin_hijacked": origin_hijacked,
            "forge_hijacked": forge_hijacked,
            "origin_hijacking": origin_hijacking,
            "forge_hijacking": forge_hijacking,
            "total_victim_events": len(origin_hijacked) + len(forge_hijacked),
            "total_attacker_events": len(origin_hijacking) + len(forge_hijacking)
        }

        try:
            cnt_oh = len(origin_hijacked)
            cnt_oi = len(origin_hijacking)
            cnt_fh = len(forge_hijacked)
            cnt_fi = len(forge_hijacking)
            
            logger.info(f"[ROUTING] origin_hijacked count={cnt_oh}")
            logger.info(f"[ROUTING] origin_hijacking count={cnt_oi}")
            logger.info(f"[ROUTING] forge_hijacked count={cnt_fh}")
            logger.info(f"[ROUTING] forge_hijacking count={cnt_fi}")

            if (cnt_oh + cnt_oi) > 0:
                routing["primary_classification"] = "Origin Hijacking"
            elif (cnt_fh + cnt_fi) > 0:
                routing["primary_classification"] = "Path Forgery (Man-in-the-Middle)"
            else:
                routing["primary_classification"] = "Route Leak or No Anomaly"
                
            routing["classification_counts"] = {
                "origin_hijacked": cnt_oh,
                "origin_hijacking": cnt_oi,
                "forge_hijacked": cnt_fh,
                "forge_hijacking": cnt_fi,
            }
        except Exception:
            pass

        return routing
    except Exception as e:
        return {
            "success": False,
            "error": f"Routing analysis failed: {str(e)}",
            "origin_hijacked": [],
            "forge_hijacked": [],
            "origin_hijacking": [],
            "forge_hijacking": [],
            "total_victim_events": 0,
            "total_attacker_events": 0
        } 
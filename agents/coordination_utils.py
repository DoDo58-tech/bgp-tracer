import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from utils.logger import logger


def load_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load JSON from {path}: {e}")
        return {}


def lookup_org_info(asn: str, asorg_file: str) -> Dict[str, Any]:
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
    except Exception:
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


def normalize_time(value: str) -> str:
    """Normalize multiple input formats to YYYY-MM-DD HH:MM."""
    fmts = [
        "%Y-%m-%d %H:%M",
        "%Y:%m:%d %H:%M",
        "%Y/%m/%d %H:%M",
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            continue
    return value


def query_as_organization(asn: str, asorg_file: str) -> Dict[str, Any]:
    return lookup_org_info(asn, asorg_file)


def query_as_relationships(asn: str, asrel_file: str) -> Dict[str, Any]:
    if not asrel_file or not Path(asrel_file).exists():
        return {"success": False, "error": "AS relationship data file not available", "asn": asn}
    data = load_json(asrel_file)
    if not data:
        return {"success": False, "error": "Failed to load AS relationship data", "asn": asn}
    providers_data = data.get("providers", {})
    peers_data = data.get("peers", {})
    asn_str = str(asn)
    providers = providers_data.get(asn_str, [])
    peers = peers_data.get(asn_str, [])
    customers: List[str] = []
    for customer_asn, customer_providers in providers_data.items():
        try:
            if asn_str in customer_providers:
                customers.append(customer_asn)
        except Exception:
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


def query_as_prefixes(asn: str, prefix2as_file: str) -> Dict[str, Any]:
    if not prefix2as_file or not Path(prefix2as_file).exists():
        return {"success": False, "error": "Prefix-to-AS data file not available", "asn": asn}
    data = load_json(prefix2as_file)
    if not data:
        return {"success": False, "error": "Failed to load prefix-to-AS data", "asn": asn}
    asn_str = str(asn)
    prefixes = [prefix for prefix, origin_asn in data.items() if origin_asn == asn_str]
    return {"success": True, "asn": asn, "prefixes": prefixes, "total_prefixes": len(prefixes)}


def generate_integrated_report(
    routing_analysis: Dict[str, Any] = None,
    traffic_analysis: Dict[str, Any] = None,
    law_analysis: Dict[str, Any] = None,
    reasoning_analysis: Dict[str, Any] = None,
    start_time: str = None,
    output_dir: Optional[Path] = None,
    org_name: Optional[str] = None,
    asn: str = None,
) -> Dict[str, Any]:
    try:
        victim_events = 0
        attacker_events = 0
        traffic_anomalies = 0
        
        # Extract ASN information from various analysis sources, prioritizing direct asn parameter
        asn_info = asn or "Unknown"
        if asn_info == "Unknown":
            if routing_analysis and routing_analysis.get("asn"):
                asn_info = str(routing_analysis.get("asn"))
            elif traffic_analysis and traffic_analysis.get("asn"):
                asn_info = str(traffic_analysis.get("asn"))
            elif reasoning_analysis and reasoning_analysis.get("asn"):
                asn_info = str(reasoning_analysis.get("asn"))
        
        time_period = start_time or "Unknown"
        org_name_final = org_name or "Unknown"
        risk_level = "Unknown"

        # Prepare output directories early (needed for asset handling)
        if output_dir is None:
            output_dir = Path("results") / "html"
        assets_dir = output_dir / "assets"
        output_dir.mkdir(exist_ok=True, parents=True)
        assets_dir.mkdir(exist_ok=True, parents=True)

        # Extract routing results - try reasoning_analysis first, then routing_analysis
        origin_hijacked: List[Dict[str, Any]] = []
        forge_hijacked: List[Dict[str, Any]] = []
        origin_hijacking: List[Dict[str, Any]] = []
        forge_hijacking: List[Dict[str, Any]] = []
        victim_events = 0
        attacker_events = 0
        asn_info = asn or "Unknown"
        time_period = start_time or "Unknown"
        
        # First try to extract from reasoning_analysis (new workflow)
        if reasoning_analysis and hasattr(reasoning_analysis, 'get') and reasoning_analysis.get("success"):
            logger.info(f"🔍 DEBUG: Found reasoning_analysis with success=True")
            # Extract from evidence_pool if available
            evidence_summary = reasoning_analysis.get("evidence_summary", {})
            logger.info(f"🔍 DEBUG: evidence_summary keys: {list(evidence_summary.keys())}")
            
            routing_data = evidence_summary.get("routing_data", {})
            traffic_data = evidence_summary.get("traffic_data", {})
            
            logger.info(f"🔍 DEBUG: routing_data keys: {list(routing_data.keys())}")
            logger.info(f"🔍 DEBUG: traffic_data keys: {list(traffic_data.keys())}")
            
            if routing_data:
                origin_hijacked = routing_data.get("origin_hijacked", [])
                forge_hijacked = routing_data.get("forge_hijacked", [])
                origin_hijacking = routing_data.get("origin_hijacking", [])
                forge_hijacking = routing_data.get("forge_hijacking", [])
                victim_events = len(origin_hijacked) + len(forge_hijacked)
                attacker_events = len(origin_hijacking) + len(forge_hijacking)
                asn_info = routing_data.get("asn", asn_info)
                time_period = routing_data.get("analysis_period", time_period)
                
                logger.info(f"🔍 DEBUG: Extracted from routing_data - origin_hijacked: {len(origin_hijacked)}, origin_hijacking: {len(origin_hijacking)}")
                logger.info(f"🔍 DEBUG: victim_events: {victim_events}, attacker_events: {attacker_events}")
            else:
                logger.warning(f"🔍 DEBUG: routing_data is empty or None")
        
        # Handle string reasoning_analysis (fallback case)
        elif isinstance(reasoning_analysis, str):
            logger.info(f"🔍 DEBUG: Found string reasoning_analysis, attempting to parse")
            try:
                # Try to parse as JSON first
                parsed_reasoning = json.loads(reasoning_analysis)
            except:
                try:
                    # Try to parse as Python dict string
                    parsed_reasoning = eval(reasoning_analysis)
                except Exception as e:
                    logger.warning(f"🔍 DEBUG: Could not parse string reasoning_analysis: {e}")
                    parsed_reasoning = None
            
            if parsed_reasoning and parsed_reasoning.get("success"):
                logger.info(f"🔍 DEBUG: Successfully parsed string reasoning_analysis")
                evidence_summary = parsed_reasoning.get("evidence_summary", {})
                routing_data = evidence_summary.get("routing_data", {})
                traffic_data = evidence_summary.get("traffic_data", {})
                
                if routing_data:
                    origin_hijacked = routing_data.get("origin_hijacked", [])
                    forge_hijacked = routing_data.get("forge_hijacked", [])
                    origin_hijacking = routing_data.get("origin_hijacking", [])
                    forge_hijacking = routing_data.get("forge_hijacking", [])
                    victim_events = len(origin_hijacked) + len(forge_hijacked)
                    attacker_events = len(origin_hijacking) + len(forge_hijacking)
                    asn_info = routing_data.get("asn", asn_info)
                    time_period = routing_data.get("analysis_period", time_period)
                    
                    logger.info(f"🔍 DEBUG: Extracted from parsed routing_data - origin_hijacked: {len(origin_hijacked)}, origin_hijacking: {len(origin_hijacking)}")
                    logger.info(f"🔍 DEBUG: victim_events: {victim_events}, attacker_events: {attacker_events}")
        
        # Fallback to direct routing_analysis (legacy workflow)
        elif routing_analysis and routing_analysis.get("success"):
            origin_hijacked = routing_analysis.get("origin_hijacked", [])
            forge_hijacked = routing_analysis.get("forge_hijacked", [])
            origin_hijacking = routing_analysis.get("origin_hijacking", [])
            forge_hijacking = routing_analysis.get("forge_hijacking", [])
            victim_events = len(origin_hijacked) + len(forge_hijacked)
            attacker_events = len(origin_hijacking) + len(forge_hijacking)
            asn_info = routing_analysis.get("asn", asn_info)
            time_period = routing_analysis.get("analysis_period", time_period)

        # Extract traffic results - try reasoning_analysis first, then traffic_analysis
        plot_path = None
        data_points = 0
        percent_change = 0.0
        anomalies: List[Dict[str, Any]] = []
        traffic_anomalies = 0
        
        # First try to extract from reasoning_analysis (new workflow)
        if reasoning_analysis and hasattr(reasoning_analysis, 'get') and reasoning_analysis.get("success"):
            evidence_summary = reasoning_analysis.get("evidence_summary", {})
            traffic_data = evidence_summary.get("traffic_data", {})
            
            if traffic_data:
                traffic_anomalies = traffic_data.get("anomaly_count", 0)
                plot_path = traffic_data.get("plot_path")
                data_points = traffic_data.get("data_points", 0)
                percent_change = traffic_data.get("percent_change", 0.0)
                anomalies = traffic_data.get("anomalies", [])
        
        # Handle string reasoning_analysis for traffic data (fallback case)
        elif isinstance(reasoning_analysis, str):
            try:
                parsed_reasoning = json.loads(reasoning_analysis)
            except:
                try:
                    parsed_reasoning = eval(reasoning_analysis)
                except:
                    parsed_reasoning = None
            
            if parsed_reasoning and parsed_reasoning.get("success"):
                evidence_summary = parsed_reasoning.get("evidence_summary", {})
                traffic_data = evidence_summary.get("traffic_data", {})
                
                if traffic_data:
                    traffic_anomalies = traffic_data.get("anomaly_count", 0)
                    plot_path = traffic_data.get("plot_path")
                    data_points = traffic_data.get("data_points", 0)
                    percent_change = traffic_data.get("percent_change", 0.0)
                    anomalies = traffic_data.get("anomalies", [])
        
        # Fallback to direct traffic_analysis (legacy workflow)
        elif traffic_analysis and traffic_analysis.get("success"):
            traffic_anomalies = traffic_analysis.get("anomaly_count", 0)
            plot_path = traffic_analysis.get("plot_path")
            data_points = traffic_analysis.get("data_points", 0)
            percent_change = traffic_analysis.get("percent_change", 0.0)
            anomalies = traffic_analysis.get("anomalies", [])

        risk_level = (
            "Critical" if victim_events > 0 else ("Medium" if attacker_events > 0 or traffic_anomalies > 0 else "Low")
        )

        # Prepare traffic chart (prefer file reference for large images)
        traffic_chart_src = ""
        if plot_path:
            try:
                import os
                import shutil
                file_size_bytes = os.path.getsize(plot_path)
                size_threshold_inline = 300_000
                if file_size_bytes > size_threshold_inline:
                    sanitized_time = (start_time or "").replace(' ', '_').replace(':', '-')
                    ext = plot_path.split('.')[-1].lower() or 'png'
                    dest_path = assets_dir / f"traffic_AS{asn_info}_{sanitized_time}.{ext}"
                    shutil.copyfile(plot_path, dest_path)
                    traffic_chart_src = dest_path.name if dest_path.parent == output_dir else f"assets/{dest_path.name}"
                else:
                    import base64
                    with open(plot_path, 'rb') as img_file:
                        img_data = img_file.read()
                        img_base64 = base64.b64encode(img_data).decode('utf-8')
                        img_extension = plot_path.split('.')[-1].lower()
                        mime_type = f"image/{img_extension}" if img_extension in ['png', 'jpg', 'jpeg'] else "image/png"
                        traffic_chart_src = f"data:{mime_type};base64,{img_base64}"
            except Exception as e:
                logger.warning(f"Could not inline traffic plot, will reference path. Error: {e}")
                traffic_chart_src = plot_path

        def html_escape(text: str) -> str:
            try:
                return (str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))
            except Exception:
                return str(text)

        def build_rows(events: List[Dict[str, Any]], label: str) -> str:
            rows: List[str] = []
            for ev in events:
                rows.append(
                    f"<tr><td>{label}</td>"
                    f"<td>{html_escape(ev.get('timestamp', 'Unknown'))}</td>"
                    f"<td>{html_escape(ev.get('prefix', 'Unknown'))}</td>"
                    f"<td style=\"max-width:520px;word-break:break-all;\">{html_escape(ev.get('as_path', 'Unknown'))}</td>"
                    f"<td>{html_escape(ev.get('hijacker_as', 'Unknown'))}</td></tr>"
                )
            return "\n".join(rows)

        routing_rows_html = "\n".join([
            build_rows(origin_hijacked, "Origin Hijack Victim"),
            build_rows(forge_hijacked, "Path Forgery Victim"),
            build_rows(origin_hijacking, "Origin Hijack Attacker"),
            build_rows(forge_hijacking, "Path Forgery Attacker"),
        ])

        anomalies_rows_html = "\n".join([
            f"<tr><td>{html_escape(a.get('timestamp',''))}</td>"
            f"<td>{html_escape(a.get('z_score',''))}</td>"
            f"<td>{html_escape(a.get('value',''))}</td>"
            f"<td>{html_escape(a.get('note',''))}</td></tr>" for a in anomalies[:50]
        ])

        # Delegate to the rich HTML generator in utils.report_generator so that
        # layout matches comprehensive_analysis_*.html (Executive Summary,
        # Impact Assessment, Traffic Analysis, Routing Analysis, Root Cause, Recommendations, etc.).
        from utils.report_generator import render_summary_html

        summary_payload = {
            "executive_summary": {
                "overview": f"Integrated traffic and routing analysis for AS{asn_info} over {time_period}.",
                "key_findings": [],
            },
            "traffic_analysis": {},
            "routing_analysis": {},
            "root_cause": {},
            "impact_assessment": {},
            "recommendations": {},
            "technical_details": {},
        }

        html_content = render_summary_html(
            summary_payload=summary_payload,
            routing_analysis=routing_analysis or {
                "origin_hijacked": origin_hijacked,
                "forge_hijacked": forge_hijacked,
                "origin_hijacking": origin_hijacking,
                "forge_hijacking": forge_hijacking,
                "asn": asn_info,
                "analysis_period": time_period,
            },
            traffic_analysis=traffic_analysis or {
                "anomaly_count": traffic_anomalies,
                "plot_path": plot_path,
                "data_points": data_points,
                "percent_change": percent_change,
            },
            law_analysis=law_analysis or {},
            reasoning_analysis=reasoning_analysis or {},
            org_name=org_name_final,
            asn=str(asn_info),
            start_time=time_period,
        )

        filename_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_file = output_dir / f"traffic_outage_analysis_{filename_time}.html"
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"HTML report has been saved to: {html_file}")
        return {
            "success": True,
            "html_report_path": str(html_file),
            "generated_by_llm": False,
            "generation_timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Failed to generate integrated report: {e}")
        return {"success": False, "error": f"Failed to generate integrated report: {str(e)}", "timestamp": datetime.now().isoformat()}




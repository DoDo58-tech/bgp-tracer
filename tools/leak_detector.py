import os
import sys
from typing import Dict, Any, List, Tuple, Optional
from sortedcontainers import SortedDict
from pathlib import Path
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import PROJECT_ROOT, PATHPROB_SEARCH_PATHS, PATHPROB_AE_ROOT

DEFAULT_LEAK_THRESHOLD = 0.4


def find_pathprob_file(pathprob_file: Optional[str] = None) -> Optional[str]:
    """
    Find pathprob.txt file in common locations.
    
    Args:
        pathprob_file: Optional explicit path to pathprob.txt
        
    Returns:
        Path to pathprob.txt if found, None otherwise
    """
    if pathprob_file and os.path.exists(pathprob_file):
        logger.info(f"Using specified PathProb file: {pathprob_file}")
        return pathprob_file
    
    # Try all search paths
    for search_path in PATHPROB_SEARCH_PATHS:
        if isinstance(search_path, str):
            search_path = Path(search_path)
        
        if search_path.exists() and search_path.is_file():
            logger.info(f"Found PathProb file at: {search_path}")
            return str(search_path)
        elif search_path.exists() and search_path.is_dir():
            # If it's a directory, try pathprob.txt inside it
            candidate = search_path / "pathprob.txt"
            if candidate.exists():
                logger.info(f"Found PathProb file at: {candidate}")
                return str(candidate)
    
    # If not found, provide helpful error message
    logger.error("PathProb file not found in any of the following locations:")
    for i, search_path in enumerate(PATHPROB_SEARCH_PATHS, 1):
        logger.error(f"  {i}. {search_path}")
    logger.error(f"\nTo fix this issue:")
    logger.error(f"  1. Generate pathprob.txt using PathProb_AE:")
    logger.error(f"     cd {PATHPROB_AE_ROOT}")
    logger.error(f"     python3 infer_prob/asrel_prob.py --path_dir <path_dir> --print_dir <print_dir>")
    logger.error(f"  2. Or set PATHPROB_FILE environment variable:")
    logger.error(f"     export PATHPROB_FILE=/path/to/pathprob.txt")
    logger.error(f"  3. Or place pathprob.txt in: {PROJECT_ROOT / 'data' / 'pathprob' / 'pathprob.txt'}")
    
    return None


def _read_prob(probfile):
    prob = {}
    try:
        with open(probfile, 'r', encoding='utf-8') as f:
            for line in f:
                if line and not line.startswith("#"):
                    parts = line.strip().split("|")
                    if len(parts) >= 5:
                        as1, as2, p2c, p2p, c2p = parts[0], parts[1], parts[2], parts[3], parts[4]
                        probs = [float(p2c), float(p2p), float(c2p)]
                        if as1 > as2:
                            probs = [float(c2p), float(p2p), float(p2c)]
                        prob[(min(as1, as2), max(as1, as2))] = probs
    except Exception as e:
        logger.error(f"Error reading PathProb file {probfile}: {e}")
    
    logger.info(f"Loaded {len(prob)} AS relationship probabilities from {probfile}")
    return prob


def _parse_as_path(as_path_str):
    if not as_path_str:
        return []
    if '|' in as_path_str:
        path = as_path_str.split('|')
    else:
        path = as_path_str.split()
    
    path = [asn.strip() for asn in path if asn.strip()]
    return path


def _detect_leak_by_prob(path, asrelprob, threshold = DEFAULT_LEAK_THRESHOLD):
    if len(path) < 2:
        return False, 1.0
    
    prob = 1.0
    c2p0 = 1.0
    
    for i in range(len(path) - 1):
        as1, as2 = path[i], path[i + 1]
        link = (min(as1, as2), max(as1, as2))
        
        if link in asrelprob:
            p2c, _, c2p = asrelprob[link]
        elif link[::-1] in asrelprob:
            c2p, _, p2c = asrelprob[link[::-1]]
        else:
            continue
        
        prob = min(p2c + c2p0 - p2c * c2p0, prob)
        c2p0 = c2p
    
    # Path is a leak if probability is below threshold
    is_leak = prob < threshold
    return is_leak, prob


def detect_route_leaks_in_announcements(
    announcements_df,
    asrelprob,
    threshold
):
    leaks = []
    
    if announcements_df is None or announcements_df.empty:
        return leaks
    
    if 'as-path' not in announcements_df.columns:
        logger.warning("DataFrame missing 'as-path' column")
        return leaks
    
    for idx, row in announcements_df.iterrows():
        as_path_str = str(row.get('as-path', ''))
        if not as_path_str:
            continue
        
        path = _parse_as_path(as_path_str)
        if len(path) < 2:
            continue
        
        is_leak, leak_prob = _detect_leak_by_prob(path, asrelprob, threshold)
        
        if is_leak:
            leak_event = {
                "timestamp": row.get('timestamp', row.get('time', '')),
                "prefix": row.get('prefix', ''),
                "as-path": as_path_str,
                "origin-as": path[-1] if path else '',
                "leak_probability": leak_prob,
                "threshold": threshold,
                "path_length": len(path),
                "detection_method": "PathProb"
            }
            
            # Add additional fields if available
            for field in ['collector', 'peer-as', 'type']:
                if field in row:
                    leak_event[field] = row[field]
            
            leaks.append(leak_event)
    
    return leaks


def analyze_leak_surface(
    asn,
    start_time,
    end_time,
    pathprob_file: str | None = None,
    threshold: float = DEFAULT_LEAK_THRESHOLD,
    target_asns: List[str] | None = None,
):
    """
    Analyze route leaks for specified AS and time period.
    
    Args:
        asn: Primary AS number
        start_time: Start time string (format: "YYYY-MM-DD HH:MM")
        end_time: End time string (format: "YYYY-MM-DD HH:MM")
        pathprob_file: Optional path to pathprob.txt file
        threshold: Leak detection threshold (default: 0.4)
        target_asns: List of AS numbers to filter by. Only messages containing these ASNs will be analyzed.
                    If None, analyzes all messages (backward compatibility).
    
    Returns:
        Dictionary with leak analysis results
    """
    from data.updates_loader import get_updates_streaming
    
    asn_clean = str(asn).replace('AS', '').replace('as', '')
    
    # Normalize target ASNs
    if target_asns is None:
        target_asns = [asn_clean]
    else:
        target_asns = [str(a).replace('AS', '').replace('as', '') for a in target_asns]
        if asn_clean not in target_asns:
            target_asns.append(asn_clean)
    
    logger.info(f"Route leak detection: filtering for AS paths containing: {target_asns}")
    
    # Normalize time window for streaming loader
    try:
        start_dt = datetime.strptime(str(start_time), "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(str(end_time), "%Y-%m-%d %H:%M")
    except Exception as e:
        logger.error(f"Invalid time format for leak analysis: {e}")
        return {
            "success": False,
            "asn": asn_clean,
            "analysis_period": f"{start_time} to {end_time}",
            "error": f"Invalid time format: {e}",
        }
    
    if pathprob_file is None:
        pathprob_file = find_pathprob_file()
        
        if pathprob_file is None:
            return {
                "success": False,
                "asn": asn_clean,
                "analysis_period": f"{start_time} to {end_time}",
                "error": "PathProb file not found",
                "message": "Please provide pathprob_file path or ensure pathprob.txt exists. Check logs for search locations.",
                "search_paths": [str(p) for p in PATHPROB_SEARCH_PATHS]
            }
    
    asrelprob = _read_prob(pathprob_file)
    
    if len(asrelprob) == 0:
        logger.error("Failed to load AS relationship probabilities")
        return {
            "success": False,
            "asn": asn_clean,
            "analysis_period": f"{start_time} to {end_time}",
            "error": "Failed to load AS relationship probabilities"
        }
    
    all_leaks = []
    total_announcements = 0
    filtered_announcements = 0
    chunk_count = 0
    
    for df_chunk in get_updates_streaming(start_dt, end_dt):
        chunk_count += 1
        
        if df_chunk is None or df_chunk.empty:
            continue
        
        announcements = df_chunk[df_chunk['A/W'] == 'A']
        if announcements.empty:
            continue
        
        total_announcements += len(announcements)
        
        # Filter announcements: only keep those with AS paths containing target ASNs
        filtered_ann = announcements.copy()
        if target_asns:
            mask = filtered_ann['as-path'].apply(
                lambda x: any(target_asn in str(x) for target_asn in target_asns)
            )
            filtered_ann = filtered_ann[mask]
            filtered_announcements += len(filtered_ann)
        
        if filtered_ann.empty:
            continue
        
        # Detect leaks in this filtered chunk
        chunk_leaks = detect_route_leaks_in_announcements(
            filtered_ann,
            asrelprob,
            threshold
        )
        all_leaks.extend(chunk_leaks)
        
        if chunk_leaks:
            logger.info(f"Chunk {chunk_count}: detected {len(chunk_leaks)} route leaks from {len(filtered_ann)} filtered announcements")
    
    logger.info(f"Route leak analysis completed: {len(all_leaks)} leaks detected from {filtered_announcements} filtered announcements (out of {total_announcements} total)")
    
    return {
        "success": True,
        "asn": asn_clean,
        "analysis_period": f"{start_time} to {end_time}",
        "pathprob_file": pathprob_file,
        "threshold": threshold,
        "target_asns": target_asns,
        "asrel_count": len(asrelprob),
        "route_leaks": all_leaks,
        "leak_count": len(all_leaks),
        "total_announcements": total_announcements,
        "filtered_announcements": filtered_announcements,
        "analysis_timestamp": datetime.now().isoformat()
    }


def detect_route_leaks_streaming(
    announcements_df,
    asrelprob,
    pathprob_file,
    threshold
):
    if asrelprob is None:
        if pathprob_file is None:
            pathprob_file = find_pathprob_file()
        
        if pathprob_file is None or not os.path.exists(pathprob_file):
            logger.warning("PathProb file not found, skipping route leak detection")
            return []
        
        asrelprob = _read_prob(pathprob_file)
        if len(asrelprob) == 0:
            logger.warning("Failed to load AS relationship probabilities")
            return []
    
    # Detect leaks
    leaks = detect_route_leaks_in_announcements(announcements_df, asrelprob, threshold)
    
    if leaks:
        logger.info(f"Detected {len(leaks)} route leaks")
    
    return leaks


__all__ = [
    "analyze_leak_surface",
    "detect_route_leaks_in_announcements",
    "detect_route_leaks_streaming",
    "find_pathprob_file",
    "DEFAULT_LEAK_THRESHOLD"
]

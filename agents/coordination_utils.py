"""
Shared utilities for the BGP Tracer multi-agent system.

Functions here are stateless helpers used across agents, workflow engine,
and detectors. Keep this module lightweight — no agent logic.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

from utils.logger import logger


def load_json(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
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


def normalize_time(value):
    for fmt in ["%Y-%m-%d %H:%M", "%Y:%m:%d %H:%M", "%Y/%m/%d %H:%M"]:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            continue
    return value


def query_as_organization(asn, asorg_file):
    return lookup_org_info(asn, asorg_file)


def query_as_relationships(asn, asrel_file):
    if not asrel_file or not Path(asrel_file).exists():
        return {"success": False, "error": "AS relationship data file not available", "asn": asn}
    data = load_json(asrel_file)
    if not data:
        return {"success": False, "error": "Failed to load AS relationship data", "asn": asn}
    providers_data = data.get("providers", {})
    peers_data = data.get("peers", {})
    # Bug fix 2026-09-13 (BUG-R65): AS-rel files from different
    asn_stripped = str(asn).strip().upper().lstrip("AS")

    def _lookup(d, asn_key):
        v = d.get(asn_key, [])
        if v:
            return v
        return d.get(f"AS{asn_key}", [])

    providers = _lookup(providers_data, asn_stripped)
    peers = _lookup(peers_data, asn_stripped)
    customers = []
    for customer_asn, customer_providers in providers_data.items():
        try:
            # Bug fix 2026-09-13 (BUG-R65 corollary): the providers
            normalised = [str(x).strip().upper().lstrip("AS") for x in customer_providers]
            if asn_stripped in normalised:
                customers.append(str(customer_asn).strip().upper().lstrip("AS"))
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


def build_as_topology(asn, asrel_file, max_depth=3, max_nodes=400):
    """Build an ASN -> neighbour map with edge relation labels.

    The CAIDA as-rel snapshot stores relationships in three buckets:

    * ``providers[X]`` — the ASes that *provide transit to* X. X is their
      **customer**. So a provider edge is directed provider -> customer.
    * ``peers[X]`` — symmetric peer links, stored on both endpoints.
    * customers are the inverse of the provider index and are not stored
      separately in the file; they are recovered by scanning the provider
      index (this is what :func:`query_as_relationships` does).

    The returned topology is the structure the HCAF cascade estimator
    (CIC) needs to walk a routing anomaly outward across the AS graph.
    Each neighbour is a dict carrying the relation type so the cascade
    can weight edges by commercial relationship rather than treating
    every hop as an undirected tie.

    Args:
        asn: the AS of interest (the origin of the cascade).
        asrel_file: path to the parsed as-rel JSON snapshot.
        max_depth: how many hops from the origin to include.
        max_nodes: hard cap on the number of ASes expanded, so a
            well-connected Tier-1 cannot drag the whole graph in.

    Returns:
        dict with keys:
            ``adjacency``   — {asn_str: [neighbour_asn_str, ...]}
            ``edge_types``  — {asn_str: {neighbour_asn_str: "provider"|"peer"|"customer"}}
            ``origin``      — the normalised origin ASN string
            ``nodes``       — total number of ASes in the map
    """
    origin = str(asn).strip().upper().lstrip("AS")
    empty = {
        "adjacency": {},
        "edge_types": {},
        "origin": origin,
        "nodes": 0,
        "reason": "no_asrel_data",
    }
    if not asrel_file or not Path(asrel_file).exists():
        return empty
    data = load_json(asrel_file)
    if not data:
        return empty

    providers_index = data.get("providers", {}) or {}
    peers_index = data.get("peers", {}) or {}

    def _asn_list(raw):
        out = []
        for x in raw or []:
            s = str(x).strip().upper().lstrip("AS")
            if s and s not in out:
                out.append(s)
        return out

    # Reverse index: provider -> its customers. Building this once is
    # O(N) rather than O(N) *per lookup*, which matters because the
    # cascade walks hundreds of ASes.
    customer_index = {}
    for cust, provs in providers_index.items():
        cust_s = str(cust).strip().upper().lstrip("AS")
        for p in _asn_list(provs):
            customer_index.setdefault(p, []).append(cust_s)

    # Direct neighbours of the origin, labelled by relation.
    def _neighbours_of(asn_key):
        """Return {neighbour_asn: relation} for one AS.

        Relation semantics are from the *current* AS's point of view:
        ``provider`` = the neighbour provides transit to the current AS,
        ``customer`` = the current AS provides transit to the neighbour,
        ``peer`` = symmetric settlement-free link.
        """
        out = {}
        for p in _asn_list(providers_index.get(asn_key, [])):
            out[p] = "provider"
        for pe in _asn_list(peers_index.get(asn_key, [])):
            out.setdefault(pe, "peer")
        for cust_s in customer_index.get(asn_key, []):
            out.setdefault(cust_s, "customer")
        return out

    # A Tier-1 AS has thousands of customers (AS3356 has 6,264), and
    # expanding into all of them is both useless for cascade scope and
    # expensive. We rank edges by how much they can plausibly carry a
    # routing change toward a traffic impact:
    #   provider (upstream transit dependency) > peer > customer.
    # Customers are stub networks whose traffic is usually unaffected by
    # a transit change, so they rank last and are capped hardest.
    _RELATION_RANK = {"provider": 0, "peer": 1, "customer": 2}
    _MAX_CUSTOMER_EDGES = 8
    # Hard per-node fan-out. Without this a single Tier-1 node consumes
    # the whole node budget on its own edges and the BFS never reaches
    # depth 2.
    _MAX_FANOUT = 16

    def _ranked_neighbours(asn_key):
        nbrs = _neighbours_of(asn_key)
        by_rank = {}
        for nxt, rel in nbrs.items():
            by_rank.setdefault(_RELATION_RANK.get(rel, 3), []).append((nxt, rel))
        ranked = []
        for rank in sorted(by_rank):
            bucket = sorted(by_rank[rank])
            if rank == 2:  # customer bucket
                bucket = bucket[:_MAX_CUSTOMER_EDGES]
            ranked.extend(bucket)
        return ranked[:_MAX_FANOUT]

    origin_neighbours = dict(_ranked_neighbours(origin))
    if not origin_neighbours:
        return {**empty, "reason": "origin_not_in_asrel_snapshot"}

    # Breadth-first expansion up to max_depth so the cascade can cross
    # transit hops, not just the origin's immediate peers. The reverse
    # relation is recorded when we walk outward: if X is a provider of the
    # origin, then the origin is a *customer* of X.
    adjacency = {origin: sorted(origin_neighbours.keys())}
    edge_types = {origin: dict(origin_neighbours)}
    seen = {origin}
    frontier = [origin]
    for _depth in range(max_depth):
        if not frontier or len(seen) >= max_nodes:
            break
        next_frontier = []
        for current in frontier:
            if len(seen) >= max_nodes:
                break
            for nxt, rel in _ranked_neighbours(current):
                if nxt in seen:
                    continue
                rev = {"provider": "customer", "customer": "provider"}.get(rel, "peer")
                adjacency.setdefault(current, []).append(nxt)
                edge_types.setdefault(current, {})[nxt] = rev
                seen.add(nxt)
                next_frontier.append(nxt)
                if len(seen) >= max_nodes:
                    break
        frontier = next_frontier

    for key in adjacency:
        adjacency[key] = sorted(set(adjacency[key]))

    # `nodes` counts the ASes *discovered* (origin + every neighbour
    # reached), not the ASes that were expanded. Those are different
    # numbers: a depth-2 walk over a wide Tier-1 discovers hundreds of
    # ASes while expanding only a handful.
    discovered = {origin}
    for nbrs in adjacency.values():
        discovered.update(nbrs)

    return {
        "adjacency": adjacency,
        "edge_types": edge_types,
        "origin": origin,
        "nodes": len(discovered),
        "expanded_nodes": len(adjacency),
        "reason": "ok",
    }


# Substrings that mark an AS organisation as a content / CDN network in
# the CAIDA as-org naming. Content networks' traffic can shift for
# reasons unrelated to BGP (cache repopulation, anycast re-steering,
# application deploys), so they are a classic confounder for a
# routing->traffic attribution.
_CONTENT_NAME_MARKERS = (
    "cloudflare", "akamai", "fastly", "cdn", "edgecast", "limelight",
    "amazon", "aws", "google", "microsoft", "azure", "alibaba", "tencent",
    "facebook", "meta", "apple", "netflix", "github", "gitlab",
    "verizon digital", "digital ocean", "stackpath", "bunny", "leaseweb",
    "hetzner", "contabo", "ovh", "scaleway", "alibaba cloud",
)


def classify_content_asns(asns, asorg_file):
    """Return the subset of ``asns`` that are content / CDN networks.

    The classification is name-based over the CAIDA as-org snapshot, so
    it is deterministic and auditable rather than a learned model.

    Args:
        asns: iterable of ASNs to classify.
        asorg_file: path to the parsed as-org2info JSON snapshot.

    Returns:
        set of ASN strings that look like content providers.
    """
    asns = {str(a).strip().upper().lstrip("AS") for a in (asns or []) if a}
    if not asns or not asorg_file or not Path(asorg_file).exists():
        return set()
    data = load_json(asorg_file)
    if not data:
        return set()
    name_map = data.get("asn_to_name", {}) or {}
    content = set()
    for asn in asns:
        raw_name = name_map.get(asn)
        if not raw_name:
            continue
        low = str(raw_name).lower()
        if any(marker in low for marker in _CONTENT_NAME_MARKERS):
            content.add(asn)
    return content


def query_as_prefixes(asn, prefix2as_file):
    if not prefix2as_file or not Path(prefix2as_file).exists():
        return {"success": False, "error": "Prefix-to-AS data file not available", "asn": asn}
    data = load_json(prefix2as_file)
    if not data:
        return {"success": False, "error": "Failed to load prefix-to-AS data", "asn": asn}
    asn_str = str(asn)
    # Bug fix 2026-09-13 (BUG-R64): CAIDA's pfx2as schema historically
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


def generate_integrated_report(
    routing_analysis=None,
    traffic_analysis=None,
    law_analysis=None,
    reasoning_analysis=None,
    start_time=None,
    output_dir=None,
    org_name=None,
    asn=None,
):
    try:
        asn_info = asn or "Unknown"
        if asn_info == "Unknown":
            if routing_analysis and routing_analysis.get("asn"):
                asn_info = str(routing_analysis.get("asn"))
            elif traffic_analysis and traffic_analysis.get("asn"):
                asn_info = str(traffic_analysis.get("asn"))
            elif reasoning_analysis and hasattr(reasoning_analysis, "get") and reasoning_analysis.get("asn"):
                asn_info = str(reasoning_analysis.get("asn"))

        time_period = start_time or "Unknown"
        org_name_final = org_name or "Unknown"

        if output_dir is None:
            output_dir = Path("results") / "html"
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True, parents=True)

        origin_hijacked = []
        forge_hijacked = []
        origin_hijacking = []
        forge_hijacking = []
        route_leaks = []
        victim_events = 0
        attacker_events = 0
        leak_events = 0

        # ── Extract routing data from whichever source has it ─────────────────
        routing_data = None
        if reasoning_analysis and hasattr(reasoning_analysis, "get") and reasoning_analysis.get("success"):
            evidence_summary = reasoning_analysis.get("evidence_summary", {})
            routing_data = evidence_summary.get("routing_data", {})
        elif isinstance(reasoning_analysis, str):
            # Bug fix (2026-09-13): the previous implementation fell back to
            import ast
            parsed = None
            try:
                parsed = json.loads(reasoning_analysis)
            except Exception:
                try:
                    parsed = ast.literal_eval(reasoning_analysis)
                except Exception:
                    parsed = None
            if parsed and parsed.get("success"):
                routing_data = parsed.get("evidence_summary", {}).get("routing_data", {})
        elif routing_analysis and routing_analysis.get("success"):
            routing_data = routing_analysis

        if routing_data:
            origin_hijacked = routing_data.get("origin_hijacked", [])
            forge_hijacked = routing_data.get("forge_hijacked", [])
            origin_hijacking = routing_data.get("origin_hijacking", [])
            forge_hijacking = routing_data.get("forge_hijacking", [])
            route_leaks = routing_data.get("route_leaks", [])
            victim_events = len(origin_hijacked) + len(forge_hijacked)
            attacker_events = len(origin_hijacking) + len(forge_hijacking)
            leak_events = len(route_leaks)
            asn_info = routing_data.get("asn", asn_info)
            time_period = routing_data.get("analysis_period", time_period)

        # ── Extract traffic data ──────────────────────────────────────────────
        plot_path = None
        data_points = 0
        percent_change = 0.0
        anomalies = []
        traffic_anomalies = 0

        traffic_data = None
        if reasoning_analysis and hasattr(reasoning_analysis, "get") and reasoning_analysis.get("success"):
            traffic_data = reasoning_analysis.get("evidence_summary", {}).get("traffic_data", {})
        elif isinstance(reasoning_analysis, str):
            # Bug fix (2026-09-13): see the routing_data branch above — the
            import ast
            parsed = None
            try:
                parsed = json.loads(reasoning_analysis)
            except Exception:
                try:
                    parsed = ast.literal_eval(reasoning_analysis)
                except Exception:
                    parsed = None
            if parsed and parsed.get("success"):
                traffic_data = parsed.get("evidence_summary", {}).get("traffic_data", {})
        elif traffic_analysis and traffic_analysis.get("success"):
            traffic_data = traffic_analysis

        if traffic_data:
            traffic_anomalies = traffic_data.get("anomaly_count", 0)
            plot_path = traffic_data.get("plot_path")
            data_points = traffic_data.get("data_points", 0)
            percent_change = traffic_data.get("percent_change", 0.0)
            anomalies = traffic_data.get("anomalies", [])

        from agents.report_agent import generate_report_html

        # ── Resolve start / end time from time_period ─────────────────────────
        if " to " in str(time_period):
            _tp_split = str(time_period).split(" to ", 1)
            _s, _e = _tp_split[0], _tp_split[1]
        else:
            _s, _e = str(time_period), "Unknown"

        # ── Traffic anomaly window ────────────────────────────────────────────
        traffic_anomaly_window = None
        if plot_path:
            traffic_anomaly_window = {
                "detected_start": _s,
                "detected_end": _e,
            }

        # ── LLM-driven HTML generation ────────────────────────────────────────
        html_path = generate_report_html(
            asn=str(asn_info),
            start_time=_s,
            end_time=_e,
            traffic_result=traffic_analysis or {},
            routing_result=routing_analysis or {
                "origin_hijacked": origin_hijacked,
                "forge_hijacked": forge_hijacked,
                "origin_hijacking": origin_hijacking,
                "forge_hijacking": forge_hijacking,
                "route_leaks": route_leaks,
                "asn": asn_info,
                "analysis_period": time_period,
            },
            reasoning_result=reasoning_analysis or {},
            traffic_plot_path=plot_path,
            traffic_anomaly_window=traffic_anomaly_window,
            law_analysis=law_analysis,
            org_name=org_name_final,
            output_dir=str(output_dir),
        )

        return {
            "success": True,
            "html_report_path": html_path,
            "generated_by_llm": True,
            "generation_timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Failed to generate integrated report: {e}")
        return {"success": False, "error": str(e), "timestamp": datetime.now().isoformat()}


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
        List of (start_dt, end_dt) tuples for periods meeting the criteria.
    """
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
    among consecutive anomaly clusters.
    """
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
    # Bug fix 2026-09-13 (BUG-R83): the previous expression
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

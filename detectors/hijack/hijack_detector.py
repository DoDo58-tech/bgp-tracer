import os
import sys
import gc
import json
import time
import polars as pl
from collections import deque
from datetime import datetime
from pathlib import Path
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from utils.logger import logger
from detectors.input_validation import InputValidationError, validate_detection_request
from detectors.hijack.hijack_prefix_processor import get_target_prefixes_batch, build_prefix_trie
from detectors.hijack.hijack_detector_core import detect_origin_hijacks, detect_forge_hijacks, analyze_connection_frequency
from detectors.hijack.hijack_analyzer import save_alert_messages, StreamingAnomalyAggregator
from detectors.unified_result import wrap, DetectionType

from data.updates_loader import get_updates_streaming
from data.prefix2as_loader import process_prefix2as, load_prefix2as_json
from data.asorg_loader import process_asorg
from data.asrel_loader import process_asrel
from config import MAX_WORKERS, IO_BUSY_THRESHOLD
import ipaddress as ipa

# Per-AS alert sample cap.  The full counts live in the aggregator; this
# bound only limits the raw alert lists handed to downstream agents and the
# HTML report, which is what used to balloon memory.
MAX_ALERT_SAMPLE = 500

# Maximum number of RRC00 chunks whose serialised rows may be in flight at
CHUNK_INFLIGHT = int(os.environ.get("BGP_TRACER_CHUNK_INFLIGHT", "8"))


def group_alerts_by_asn(alerts):
    """Bucket a chunk's alerts by the target AS they implicate."""
    grouped: dict = {}
    for alert in alerts or []:
        if not isinstance(alert, dict):
            continue
        asn = alert.pop("__asn", None)
        if not asn:
            continue
        grouped.setdefault(asn, []).append(alert)
    return grouped


def merge_chunk_alerts(batch_results, alerts):
    """Fold one chunk's alerts into the per-AS accumulators and samples.
    
    Must be called in chunk order so the retained alert samples read
    chronologically.  Alerts for ASes outside this batch are dropped."""
    for asn, alerts_for_asn in group_alerts_by_asn(alerts).items():
        entry = batch_results.get(asn)
        if entry is None:
            continue
        buckets = {
            "origin_hijacked": [
                h for h in alerts_for_asn if h.get("hijack_type") == "origin_hijacked"
            ],
            "origin_hijacking": [
                h for h in alerts_for_asn if h.get("hijack_type") == "origin_hijacking"
            ],
            "forge_hijack": [
                h for h in alerts_for_asn
                if h.get("alert_type") == "forge_hijack"
                or h.get("hijack_type") in ("forge_hijack", "forge_hijacking")
            ],
        }
        for key, hits in buckets.items():
            if not hits:
                continue
            entry["_aggregator"].add_chunk(list(hits))
            sample = entry[key]
            room = MAX_ALERT_SAMPLE - len(sample)
            if room > 0:
                sample.extend(hits[:room])


def build_covered_subnet_set(target_prefixes):
    covered = set()
    for pf in target_prefixes:
        covered.add(pf) 
        try:
            net = ipa.ip_network(pf, strict=False)
            if net.version == 4:
                if net.prefixlen >= 24:
                    continue 
                frontier = [str(net)]
                while frontier:
                    current_str = frontier.pop()
                    cur_net = ipa.ip_network(current_str, strict=False)
                    if cur_net.prefixlen >= 24:
                        covered.add(current_str)
                        continue
                    next_pl = cur_net.prefixlen + 1
                    for sub in cur_net.subnets(new_prefix=next_pl):
                        frontier.append(str(sub))
            else:
                # IPv6:  /48
                if net.prefixlen >= 48:
                    continue
                frontier = [str(net)]
                while frontier:
                    current_str = frontier.pop()
                    cur_net = ipa.ip_network(current_str, strict=False)
                    if cur_net.prefixlen >= 48:
                        covered.add(current_str)
                        continue
                    next_pl = cur_net.prefixlen + 1
                    for sub in cur_net.subnets(new_prefix=next_pl):
                        frontier.append(str(sub))
        except ValueError:
            pass
    return len(covered), covered


def load_full_day_bgp_data(start_time, end_time):
    """Load BGP announcements covering exactly [start_time, end_time]."""
    from data.parquet_cache import iter_window_chunks

    try:
        logger.info(
            f"Loading BGP announcements for window "
            f"{getattr(start_time, 'isoformat', lambda: start_time)()} → "
            f"{getattr(end_time, 'isoformat', lambda: end_time)()}"
        )

        parts = []
        for chunk in iter_window_chunks(start_time, end_time):
            parts.append(chunk)

        if not parts:
            return pl.DataFrame()

        df = pl.concat(parts, how="vertical_relaxed")
        gc.collect()
        return df

    except AttributeError as e:
        logger.error(f"Error loading BGP window data: {e}")
        return pl.DataFrame()


def detect_hijacks_streaming(
    start_time,
    end_time,
    target_as,
    validate_with_updates = False,
    save_alerts = True,
    update_workers = 1,
    io_busy_threshold = 85,
    skip_forge_detection = True,  #  forge ( ES + , )
):
    # Validate BEFORE any I/O. Without this, a swapped call such as
    try:
        target_as, _start_dt, _end_dt = validate_detection_request(
            target_as, start_time, end_time
        )
    except InputValidationError as exc:
        logger.error(f"[hijack] rejected request: {exc}")
        return wrap(DetectionType.HIJACK, {
            "success": False,
            "error": str(exc),
            "asn": str(target_as),
            "analysis_period": f"{start_time} to {end_time}",
            "origin_hijacked": [],
            "forge_hijacked": [],
            "origin_hijacking": [],
            "forge_hijacking": [],
            "mitm_alerts": [],
            "data_available": False,
            "no_data_reason": "invalid_request",
            "invalid_request": True,
        }, asn=str(target_as)).to_dict()

    try:
        logger.info(f"Starting hijack detection for AS{target_as} from {start_time} to {end_time} (skip_forge: {skip_forge_detection})")

        batch_results = detect_hijacks_batch(
            start_time=start_time,
            end_time=end_time,
            target_as_list=[target_as],
            validate_with_updates=validate_with_updates,
            save_alerts=save_alerts,
            update_workers=update_workers,
            io_busy_threshold=io_busy_threshold,
            skip_forge_detection=skip_forge_detection
        )

        # Ensure batch_results is a valid dict
        if batch_results is None or not isinstance(batch_results, dict):
            batch_results = {"success": False, "error": "batch_results is None or invalid", "results_by_as": {}}

        # Try both integer and string key (batch_results uses strings, but target_as might be integer)
        raw_results_by_as = batch_results.get("results_by_as")
        results_by_as = raw_results_by_as if isinstance(raw_results_by_as, dict) else {}

        # Normalize the key - results_by_as uses string keys
        as_key_str = str(target_as)
        as_key_int = int(target_as) if str(target_as).isdigit() else target_as

        # Check which key exists in results_by_as (safely handle None results_by_as)
        actual_key = None
        if results_by_as:  # Only check if results_by_as is a valid non-empty dict
            if as_key_str in results_by_as:
                actual_key = as_key_str
            elif as_key_int in results_by_as:
                actual_key = as_key_int

        if batch_results.get("success") and actual_key is not None:
            as_result = results_by_as[actual_key]
            result = {
                "success": True,
                "origin_hijacked": as_result.get("origin_hijacked", []),
                "forge_hijacked": as_result.get("forge_hijacked", []),
                "origin_hijacking": as_result.get("origin_hijacking", []),
                "forge_hijacking": as_result.get("forge_hijacking", []),
                "total_announcements": as_result.get("total_announcements", 0),
                "batch_mode": False,
                "aggregated_alerts": as_result.get("aggregated_alerts", []),
                # Unified schema: RIPE RIS updates are loaded from disk, so
                "data_available": bool(as_result.get("total_announcements", 0)),
                "no_data_reason": (
                    "" if as_result.get("total_announcements", 0)
                    else "no_announcements_in_window"
                ),
            }
            return wrap(DetectionType.HIJACK, result, asn=target_as).to_dict()

        # If we reach here, something went wrong
        return wrap(DetectionType.HIJACK, {
            "success": False,
            "error": "Detection failed - condition not met",
            "asn": target_as,
            "analysis_period": f"{start_time} to {end_time}",
            "origin_hijacked": [],
            "forge_hijacked": [],
            "origin_hijacking": [],
            "forge_hijacking": [],
            "mitm_alerts": [],
            "data_available": False,
            "no_data_reason": "ripestat_or_batch_failed",
        }, asn=target_as).to_dict()

    except AttributeError as e:
        logger.error(f"Hijack detection failed for AS{target_as}: {e}")
        import traceback as _tb_hijack
        _tb_hijack.print_exc()
        return wrap(DetectionType.HIJACK, {
            "success": False,
            "error": str(e),
            "asn": target_as,
            "analysis_period": f"{start_time} to {end_time}",
            "origin_hijacked": [],
            "forge_hijacked": [],
            "origin_hijacking": [],
            "forge_hijacking": [],
            "mitm_alerts": [],
            "data_available": False,
            "no_data_reason": "hijack_detector_exception",
        }, asn=target_as).to_dict()


def detect_hijacks(
    start_time,
    end_time,
    target_as,
    validate_with_updates = False,
    save_alerts = True,
    update_workers = 1,
    io_busy_threshold = 85,
    skip_forge_detection = True,  #  forge (utils.es_conn_freq  + )
):
    return detect_hijacks_streaming(
        start_time=start_time,
        end_time=end_time,
        target_as=target_as,
        validate_with_updates=validate_with_updates,
        save_alerts=save_alerts,
        update_workers=update_workers,
        io_busy_threshold=io_busy_threshold,
        skip_forge_detection=skip_forge_detection,
    )


def process_chunk_worker(args):
    """Worker function for parallel chunk processing (Round-24 perf fix).
    
    Returns:
    list of dicts: each dict is one alert produced by this chunk.
    The main process merges these into batch_results[asn]."""
    import polars as pl
    import logging as _logging
    from detectors.hijack.hijack_detector_core import (
        detect_origin_hijacks, detect_forge_hijacks,
    )

    chunk_records, params = args
    if not chunk_records:
        return []

    chunk_df = pl.DataFrame(chunk_records)

    announcements = chunk_df.filter(pl.col('A/W') == 'A').select(
        ['prefix', 'as-path', 'timestamp']
    )
    if announcements.is_empty():
        return []

    # The AS path is kept as it arrived.  An earlier version of this
    # function removed repeated hops before scoring it, which silently
    # changed the origin: an AS that prepends itself to its own path
    # (13335 3356 13335) came out as 13335 3356, so the origin read as
    # 3356 instead of 13335.  Every prefix the prepending AS announced
    # was then attributed to the wrong origin, which is what turned
    # legitimate announcements into hijack accusations.
    announcements = announcements.with_columns([
        pl.col("as-path")
          .str.strip_chars()
          .str.split(by=' ')
          .alias('as_path_list'),
        pl.col('as-path')
          .str.strip_chars()
          .str.split(by=' ')
          .list.last()
          .alias('origin_as'),
    ])

    union_target_prefixes = set(params["union_target_prefixes"])
    covered_subnet_set = set(params["covered_subnet_set"])
    cleaned_as_set = set(params["cleaned_as_set"])
    cleaned_as_list = params["cleaned_as_list"]

    mask1 = announcements['prefix'].is_in(union_target_prefixes)
    mask2 = announcements['prefix'].is_in(covered_subnet_set)

    mask3 = None
    for target_as in cleaned_as_set:
        as_mask = announcements["as_path_list"].list.contains(target_as)
        mask3 = as_mask if mask3 is None else (mask3 | as_mask)

    announcements = announcements.filter(mask1 | mask2 | mask3)
    if announcements.is_empty():
        return []

    prefix_to_as = params.get("prefix_to_as_subset") or {}
    as_relationships_data = params.get("as_relationships_data") or {}
    # The target's own prefixes, resolved once for the whole scan.
    #
    # `detect_origin_hijacks` needs to know which prefixes the target
    # legitimately owns.  When it is not told, it derives that set by
    # scanning the prefix-to-AS map it was given -- and the worker gives
    # it a map trimmed to the prefixes that appear in this chunk.  A
    # prefix the target owns but does not announce in this chunk is then
    # invisible, and the announcement of it by someone else is not
    # recognised as a hijack.
    prefixes_by_as = params.get("prefixes_by_as") or None

    alerts = []
    worker_log = _logging.getLogger(__name__)
    for asn in cleaned_as_list:
        asn_str = str(asn)
        # Two kinds of row matter for this AS:
        #
        #   * rows whose path mentions the AS -- the AS is in the path,
        #     which is how it shows up as a hijacking *perpetrator*;
        #   * rows for a prefix the AS owns -- someone else announcing
        #     the AS's own prefix is how it shows up as a hijacking
        #     *victim*, and such a path does not mention the AS at all.
        #
        # Filtering on the path alone therefore dropped every victim-side
        # announcement, which is why the streaming detector reported no
        # origin hijacks where the single-pass path reported hundreds.
        as_mask = announcements["as_path_list"].list.contains(asn_str)
        owned_prefixes = (prefixes_by_as or {}).get(asn_str) if prefixes_by_as else None
        if owned_prefixes:
            owned_mask = announcements["prefix"].is_in(list(owned_prefixes))
            df_asn = announcements.filter(as_mask | owned_mask)
        else:
            df_asn = announcements.filter(as_mask)
        if df_asn.is_empty():
            continue

        analyzed_df = df_asn
        if not params["skip_forge_detection"]:
            try:
                forge_result = detect_forge_hijacks(
                    df_asn,
                    as_relationships_data,
                    asn,
                    full_day_data=None,
                    prefix_to_as=prefix_to_as,
                    use_es=False,
                )
                forge_alerts = forge_result[0] if isinstance(forge_result, tuple) else forge_result
                if not isinstance(forge_alerts, list):
                    forge_alerts = []
                for alert in forge_alerts:
                    if isinstance(alert, dict):
                        alert.setdefault("__asn", asn_str)
                        alerts.append(alert)
            except AttributeError as e:
                worker_log.debug(
                    f"[chunk-worker] forge detection failed for AS{asn}: {e}"
                )

        try:
            origin_hijacks = detect_origin_hijacks(
                analyzed_df, prefix_to_as, target_as=asn,
                prefixes_by_as=prefixes_by_as,
            )
        except AttributeError as e:
            worker_log.debug(
                f"[chunk-worker] origin detection failed for AS{asn}: {e}"
            )
            origin_hijacks = []

        for h in origin_hijacks:
            if isinstance(h, dict):
                h.setdefault("__asn", asn_str)
                alerts.append(h)

    return alerts


def detect_hijacks_batch(
    start_time,
    end_time,
    target_as_list,
    validate_with_updates = False,
    save_alerts = True,
    update_workers = 1,
    io_busy_threshold = 85,
    skip_forge_detection = True,  #  forge (utils.es_conn_freq  + )
    use_csv_for_origin = True,     # CSVOrigin Hijack（ES）
):
    logger.info(f"Starting BATCH hijack detection for {len(target_as_list)} AS from {start_time} to {end_time}")
    logger.info(f"Configuration: skip_forge={skip_forge_detection}, use_csv_for_origin={use_csv_for_origin}")

    # start_time / end_time can be passed in as either datetime objects
    def coerce_dt(value):
        if value is None:
            return None
        if hasattr(value, "strftime"):
            return value
        from datetime import datetime as _dt
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
            try:
                return _dt.strptime(str(value), fmt)
            except ValueError:
                continue
        return None

    start_time_dt = coerce_dt(start_time)
    end_time_dt = coerce_dt(end_time)
    if start_time_dt is not None:
        start_time = start_time_dt
    if end_time_dt is not None:
        end_time = end_time_dt

    cleaned_as_list = []
    for asn in target_as_list:
        asn_clean = str(asn).replace('AS', '').replace('as', '')
        cleaned_as_list.append(asn_clean)
    
    logger.info(f"Target AS list: {', '.join(['AS' + asn for asn in cleaned_as_list])}")

    # AS
    asrel_result = process_asrel(start_time)
    if isinstance(asrel_result, str) and asrel_result and os.path.exists(asrel_result):
        with open(asrel_result, 'r', encoding='utf-8') as f:
            as_relationships_data = json.load(f)
        logger.info("Successfully loaded AS relationship data")
    else:
        logger.error("Failed to load AS relationship data")
        as_relationships_data = {}

    prefix2as_path = process_prefix2as(start_time)
    prefix_to_as = load_prefix2as_json(prefix2as_path)
    if prefix_to_as is None:
        prefix2as_path = process_prefix2as(start_time)
        prefix_to_as = load_prefix2as_json(prefix2as_path) or {}
    if prefix_to_as:
        logger.info(f"Loaded prefix-to-AS mappings from {prefix2as_path}")
    else:
        logger.error("Failed to load prefix-to-AS mappings")
        prefix_to_as = {}

    #  IPv6 （CAIDA RouteViews prefix2as  IPv6）
    try:
        from data.ipv6_prefix_loader import load_ipv6_prefixes_for_as, merge_prefix2as_with_ipv6

        ipv6_prefixes_count = 0
        for asn in cleaned_as_list:
            ipv6_prefixes = load_ipv6_prefixes_for_as(asn)
            if ipv6_prefixes:
                old_count = len(prefix_to_as)
                prefix_to_as = merge_prefix2as_with_ipv6(prefix_to_as, ipv6_prefixes, asn)
                added = len(prefix_to_as) - old_count
                ipv6_prefixes_count += added
                logger.info(f"AS{asn}: Added {added} IPv6 prefixes from RIPEstat (total IPv6: {len(ipv6_prefixes)})")

        if ipv6_prefixes_count > 0:
            logger.info(f"Total IPv6 prefixes added from RIPEstat: {ipv6_prefixes_count}")
    except AttributeError as e:
        logger.warning(f"Failed to load IPv6 prefixes from RIPEstat: {e}")

    #  RPKI ROA （ IPv4/IPv6 ）
    try:
        from data.rpki_roa_loader import get_rpki_loader, merge_roa_with_prefix2as

        rpki_loader = get_rpki_loader()
        rpki_data = rpki_loader.fetch_roa_data(start_time)

        if rpki_data:
            old_count = len(prefix_to_as)
            prefix_to_as = merge_roa_with_prefix2as(prefix_to_as, rpki_data)
            added = len(prefix_to_as) - old_count

            rpki_ipv4 = sum(1 for p in rpki_data if ':' not in p)
            rpki_ipv6 = sum(1 for p in rpki_data if ':' in p)
            logger.info(f"RPKI ROA: Added {added} prefixes (IPv4: {rpki_ipv4}, IPv6: {rpki_ipv6})")
    except AttributeError as e:
        logger.warning(f"Failed to load RPKI ROA data: {e}")

    prefixes_by_as = get_target_prefixes_batch(cleaned_as_list, prefix_to_as)
    union_target_prefixes = set().union(*prefixes_by_as.values()) if prefixes_by_as else set()
    cleaned_as_set = set(cleaned_as_list)

    # Trie
    prefix_trie = build_prefix_trie(union_target_prefixes)

    _covered_subnet_prefixes = build_covered_subnet_set(union_target_prefixes)
    logger.info(f"Pre-computed {_covered_subnet_prefixes[0]} covered subnet prefixes for fast vectorized filtering")
    covered_subnet_set = _covered_subnet_prefixes[1]

    full_day_data = None
    if validate_with_updates and not skip_forge_detection:
        logger.info("Pre-loading full day BGP data for forge hijack detection...")
        full_day_data = load_full_day_bgp_data(start_time, end_time)
        logger.info(f"Loaded {len(full_day_data) if full_day_data is not None else 0} announcements for full day analysis")

    prefix_owner_map = {}
    for asn, pref_set in prefixes_by_as.items():
        for p in pref_set:
            prefix_owner_map.setdefault(p, []).append(asn)
    
    for asn in cleaned_as_list:
        prefix_count = len(prefixes_by_as.get(asn, set()))
        logger.info(f"AS{asn}: {prefix_count} target prefixes")
    
    batch_results = {}
    for asn in cleaned_as_list:
        batch_results[asn] = {
            "origin_hijacked": [],
            "origin_hijacking": [],
            "forge_hijack": [],
            "forge_hijacking": [],
            "total_announcements": 0,
            "_aggregator": StreamingAnomalyAggregator(),  # ，finalize
        }
    
    total_processed_rows = 0
    chunk_count = 0
    memory_peaks = []
    processing_times = []
    
    # ── Round-24 perf: parallel chunk processing via ProcessPool ───────
    import os as _os
    _parallel_chunks = _os.environ.get("BGP_TRACER_PARALLEL_CHUNKS", "1") != "0"
    _chunk_workers = max(1, min(MAX_WORKERS, _os.cpu_count() or 4))
    logger.info(
        f"Hijack detection: parallel_chunks={_parallel_chunks} "
        f"chunk_workers={_chunk_workers} (out of {MAX_WORKERS} configured)"
    )

    # Pre-build the per-chunk params dict (pickle-friendly subset of state).
    _chunk_params_base = {
        "union_target_prefixes": list(union_target_prefixes),
        "covered_subnet_set": list(covered_subnet_set),
        "cleaned_as_set": list(cleaned_as_set),
        "cleaned_as_list": cleaned_as_list,
        "skip_forge_detection": skip_forge_detection,
        # prefix_to_as is huge; each worker only needs the rows that appear
        # in its chunk. We populate prefix_to_as_subset per-chunk below.
        "prefix_to_as_subset": {},
        "as_relationships_data": as_relationships_data,
    }

    if _parallel_chunks:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=_chunk_workers) as _ex:
            import time as _t
            _t0 = _t.monotonic()

            # Bounded in-flight window.  Queuing every 5-minute bucket of the
            _total_alerts = 0
            _stream = get_updates_streaming(
                start_time, end_time,
                workers=MAX_WORKERS,
                io_busy_threshold=IO_BUSY_THRESHOLD,
                auto_download=True,
            )
            _pending: deque = deque()
            _exhausted = False
            while not _exhausted or _pending:
                while not _exhausted and len(_pending) < CHUNK_INFLIGHT:
                    df_chunk = next(_stream, None)
                    if df_chunk is None:
                        _exhausted = True
                        break
                    if df_chunk.is_empty():
                        continue
                    chunk_count += 1
                    try:
                        _keep_cols = ["prefix", "as-path", "A/W", "timestamp"]
                        _cols_present = [c for c in _keep_cols if c in df_chunk.columns]
                        _chunk_records = df_chunk.select(_cols_present).to_dicts()
                    except AttributeError as _exc:
                        logger.debug(f"[chunk-iter] serialise failed: {_exc}; skipping {chunk_count}")
                        continue

                    _seen_prefixes = {r.get("prefix") for r in _chunk_records if r.get("prefix")}
                    _params = dict(_chunk_params_base)
                    _params["prefix_to_as_subset"] = {
                        p: prefix_to_as[p] for p in _seen_prefixes if p in prefix_to_as
                    }
                    _pending.append(
                        _ex.submit(process_chunk_worker, (_chunk_records, _params))
                    )
                    total_processed_rows += len(_chunk_records)
                    del df_chunk, _chunk_records, _params

                if _pending:
                    _alerts = _pending.popleft().result()
                    _total_alerts += len(_alerts)
                    merge_chunk_alerts(batch_results, _alerts)
                    del _alerts

            logger.info(
                f"[chunk-iter] streamed {chunk_count} chunks "
                f"(cap={CHUNK_INFLIGHT}) in {_t.monotonic() - _t0:.1f}s"
            )

            try:
                import psutil
                _mb = psutil.Process().memory_info().rss / 1024 / 1024
                memory_peaks.append(_mb)
                logger.info(f"[chunk-iter] memory after parallel run: {_mb:.1f}MB")
            except ValueError:
                pass

    else:
        # Serial path (legacy behaviour). Kept for debugging; gated by
        # BGP_TRACER_PARALLEL_CHUNKS=0.
        for df_chunk in get_updates_streaming(start_time, end_time, workers=MAX_WORKERS, io_busy_threshold=IO_BUSY_THRESHOLD, auto_download=True):
            # `time` is now imported at module level; using it for chunk timing
            chunk_start_time = time.time()

            chunk_count += 1

            if df_chunk is None or df_chunk.is_empty():
                logger.info(f"Chunk {chunk_count} is empty, skipping")
                continue

            chunk_rows = len(df_chunk)
            logger.info(f"Processing chunk {chunk_count} with {chunk_rows} rows")

            announcements = df_chunk.filter(pl.col('A/W') == 'A').select(['prefix', 'as-path', 'timestamp'])
            if announcements.is_empty():
                logger.info(f"Chunk {chunk_count} has no announcements, skipping")
                continue

            # chunk（ announcements，df_chunk ）
            del df_chunk
            gc.collect()

            # as-path: AS + origin（Polars，Python）
            announcements = announcements.with_columns([
                # 1. AS: split → unique () → join
                pl.col("as-path")
                  .str.strip_chars()
                  .str.split(by=' ')
                  .list.unique()
                  .list.join(' ')
                  .alias('as-path'),
                # 2. origin AS () — origin
                pl.col('as-path')
                  .str.strip_chars()
                  .str.split(by=' ')
                  .list.last()
                  .alias('origin_as'),
            ])

            # 1: prefix（O(N) hash lookup）
            mask1 = announcements['prefix'].is_in(union_target_prefixes)

            # 2: prefix（，O(N) is_in， map_elements  100x）
            mask2 = announcements['prefix'].is_in(covered_subnet_set)

            # 3: ASAS（polars list.contains，）
            _has_aspath = "as_path_list" in announcements.columns
            if not _has_aspath:
                announcements = announcements.with_columns(
                    pl.col("as-path").str.strip_chars()
                      .str.split(by=" ")
                      .alias("as_path_list")
                )
            mask3 = None
            for target_as in cleaned_as_set:
                as_mask = announcements["as_path_list"].list.contains(target_as)
                mask3 = as_mask if mask3 is None else (mask3 | as_mask)

            # OR
            announcements = announcements.filter(mask1 | mask2 | mask3)

            if announcements.is_empty():
                logger.info(f"Chunk {chunk_count}: no relevant announcements after filtering")
                continue

            for asn in cleaned_as_list:
                asn_str = str(asn)
                as_mask = announcements["as_path_list"].list.contains(asn_str)
                df_asn = announcements.filter(as_mask)
                if df_asn.is_empty():
                    continue

                forge_alerts = []
                analyzed_df = df_asn
                if not skip_forge_detection:
                    alerts, analyzed_df = detect_forge_hijacks(
                        df_asn,
                        as_relationships_data,
                        asn,
                        full_day_data=full_day_data,
                        prefix_to_as=prefix_to_as,
                        use_es=True  # ES enabled when MITM detection is active
                    )
                    forge_alerts = alerts if isinstance(alerts, list) else []

                origin_hijacks = []
                if not analyzed_df.is_empty():
                    origin_hijacks = detect_origin_hijacks(analyzed_df, prefix_to_as, target_as=asn, prefixes_by_as=prefixes_by_as)

                for key, key_list in [
                    ("origin_hijacked", [h for h in origin_hijacks if h.get("hijack_type") == "origin_hijacked"]),
                    ("origin_hijacking", [h for h in origin_hijacks if h.get("hijack_type") == "origin_hijacking"]),
                    ("forge_hijack", forge_alerts),
                ]:
                    if key_list:
                        batch_results[asn]["_aggregator"].add_chunk(list(key_list))
                        target_list = batch_results[asn][key]
                        remaining = MAX_ALERT_SAMPLE - len(target_list)
                        if remaining > 0:
                            target_list.extend(key_list[:remaining])
                batch_results[asn]["total_announcements"] += len(df_asn)

            del announcements
            # gc.collect() removed: when running the parallel branch the main
            chunk_time = time.time() - chunk_start_time
            processing_times.append(chunk_time)

            # chunk
            import psutil
            memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
            memory_peaks.append(memory_mb)
            avg_time = sum(processing_times[-min(10, len(processing_times)):]) / len(processing_times[-min(10, len(processing_times)):])
            logger.info(f"Chunk {chunk_count}: {avg_time:.2f}s avg, {memory_mb:.1f}MB memory")

            total_processed_rows += chunk_rows
            logger.info(f"Chunk {chunk_count}: Processed {chunk_rows} rows for {len(cleaned_as_list)} AS")


    all_fake_connection_groups = {}
    if validate_with_updates:
        logger.info("Collecting fake connections for batch validation...")
        for asn in cleaned_as_list:
            forge_alerts = batch_results[asn]["forge_hijack"]
            for alert in forge_alerts:
                if isinstance(alert, dict):
                    fake_conn = alert.get('fake_connection', '')
                    prefix = alert.get('prefix', '')
                    timestamp = alert.get('timestamp', '')
                    as_path = alert.get('as-path', '')

                    if fake_conn and prefix:
                        key = (asn, prefix, fake_conn)
                        if key not in all_fake_connection_groups:
                            all_fake_connection_groups[key] = {
                                'prefix': prefix,
                                'fake_connection': fake_conn,
                                'first_seen': str(timestamp),
                                'last_seen': str(timestamp),
                                'as_path': as_path,
                                'paths': [as_path],
                                'announcement_count': 1
                            }
                        else:
                            all_fake_connection_groups[key]['last_seen'] = max(
                                all_fake_connection_groups[key]['last_seen'],
                                str(timestamp)
                            )
                            all_fake_connection_groups[key]['announcement_count'] += 1
                            if as_path not in all_fake_connection_groups[key]['paths']:
                                all_fake_connection_groups[key]['paths'].append(as_path)

    batch_connection_frequencies = {}
    if validate_with_updates and all_fake_connection_groups:
        logger.info(f"Validating {len(all_fake_connection_groups)} fake connections with full day data...")

        unique_fake_connections = {}
        for key, group in all_fake_connection_groups.items():
            validation_key = (group['prefix'], group['fake_connection'])
            if validation_key not in unique_fake_connections:
                unique_fake_connections[validation_key] = group
            else:
                existing = unique_fake_connections[validation_key]
                existing['last_seen'] = max(existing['last_seen'], group['last_seen'])
                existing['announcement_count'] += group['announcement_count']
                if group['as_path'] not in existing['paths']:
                    existing['paths'].append(group['as_path'])

        validated_connections = {}
        for validation_key, group in unique_fake_connections.items():
            try:
                fake_conn = group['fake_connection']
                # Use the last_seen timestamp of this connection as the end of the ES 7-day window
                end_ts = group.get('last_seen', start_time.strftime('%Y-%m-%d'))
                frequency_result = analyze_connection_frequency(
                    fake_conn,
                    start_time.strftime('%Y-%m-%d'),
                    full_day_data,
                    end_timestamp=end_ts,
                )
                validated_connections[validation_key] = frequency_result
            except (KeyError, IndexError, AttributeError) as e:
                logger.warning(f"Error validating connection {validation_key}: {e}")
                validated_connections[validation_key] = {'is_suspicious': True, 'error': str(e)}

        logger.info(f"Validation completed: {len(validated_connections)} unique connections checked")

        for key, group in all_fake_connection_groups.items():
            validation_key = (group['prefix'], group['fake_connection'])
            if validation_key in validated_connections:
                result = validated_connections[validation_key]
                batch_connection_frequencies[key] = {
                    'is_suspicious': result.get('is_suspicious', True),
                    'frequency_ratio': result.get('frequency_ratio', 0),
                    'count': result.get('count', 0),
                    'total_updates': result.get('total_updates', 0),
                    'threshold_used': result.get('threshold_used', 0.001)
                }

    if validate_with_updates and batch_connection_frequencies:
        logger.info("Re-validating forge hijacks with batch-computed frequencies...")
        for asn in cleaned_as_list:
            for alert in batch_results[asn]["forge_hijack"]:
                fake_conn = alert.get('fake_connection', '')
                prefix = alert.get('prefix', '')
                if fake_conn and prefix:
                    key = (asn, prefix, fake_conn)
                    freq_data = batch_connection_frequencies.get(key, {})
                    frequency_ratio = freq_data.get('frequency_ratio', 0)
                    is_suspicious = freq_data.get('is_suspicious', True)

                    alert['connection_frequency_past_week'] = freq_data.get('count', 0)
                    alert['frequency_ratio'] = frequency_ratio
                    alert['is_legitimate'] = not is_suspicious
                    alert['detection_status'] = 'legitimate_connection' if not is_suspicious else 'illegal_connection'
                    alert['validation_threshold'] = freq_data.get('threshold_used', 0.001)
    
    asorg_path = process_asorg(start_time)
    
    all_final_results = {}
    for asn in cleaned_as_list:
        result_data = batch_results[asn]

        aggregated_alerts = result_data["_aggregator"].finalize()
        all_anomalies_count = sum(
            len(lst) for lst in
            (result_data["origin_hijacked"], result_data["origin_hijacking"],
             result_data["forge_hijack"], result_data["forge_hijacking"])
        )

        logger.info(f"AS{asn} Detection: {len(result_data['origin_hijacked'])} origin hijacked, "
                   f"{len(result_data['origin_hijacking'])} origin hijacking, "
                   f"{len(result_data['forge_hijack'])} forge hijacked, "
                   f"{len(result_data['forge_hijacking'])} forge hijacking")

        #  (must copy lists BEFORE finalize clears them)
        all_final_results[asn] = {
            "success": True,
            "asn": asn,
            "analysis_period": f"{start_time} to {end_time}",
            "origin_hijacked": list(result_data["origin_hijacked"]),
            "origin_hijacking": list(result_data["origin_hijacking"]),
            "forge_hijacked": list(result_data["forge_hijack"]),
            "forge_hijacking": list(result_data["forge_hijacking"]),
            "all_anomalies": aggregated_alerts,
            "all_anomalies_count": all_anomalies_count,
            "aggregated_alerts": aggregated_alerts,
            "prefix2as_file": prefix2as_path,
            "asorg_file": asorg_path,
            "target_prefixes": list(prefixes_by_as[asn]),
            "total_announcements": result_data["total_announcements"],
            "analysis_timestamp": datetime.now().isoformat(),
            # Unified schema fields. Availability must reflect whether any
            "data_available": bool(result_data["total_announcements"]),
            "no_data_reason": (
                "" if result_data["total_announcements"] else "no_announcements_in_window"
            ),
            "anomalies_detected": all_anomalies_count > 0,
            "anomaly_count": all_anomalies_count,
        }

        if save_alerts:
            start_time_str = start_time.strftime("%Y-%m-%d %H:%M") if hasattr(start_time, 'strftime') else str(start_time)
            end_time_str = end_time.strftime("%Y-%m-%d %H:%M") if hasattr(end_time, 'strftime') else str(end_time)
            save_alert_messages(
                asn,
                start_time_str,
                end_time_str,
                result_data["forge_hijack"],
                result_data["origin_hijacked"]
            )

        for key in ("origin_hijacked", "origin_hijacking", "forge_hijack", "forge_hijacking"):
            result_data[key].clear()

        #  batch_results  AS
        del batch_results[asn]

    gc.collect()

    logger.info(f"Batch detection completed for {len(cleaned_as_list)} AS")

    if processing_times:
        total_time = sum(processing_times)
        avg_chunk_time = total_time / len(processing_times)
        total_chunks = len(processing_times)

        logger.info(f"🎯 Performance Optimization Results:")
        logger.info(f"   Processed {total_chunks} chunks, {total_processed_rows:,} total rows")
        logger.info(f"   Average chunk time: {avg_chunk_time:.2f}s")
        logger.info(f"   Total processing time: {total_time:.1f}s")
        logger.info(f"   Processing rate: {total_processed_rows/total_time:.0f} rows/sec")

        if memory_peaks:
            avg_memory = sum(memory_peaks) / len(memory_peaks)
            max_memory = max(memory_peaks)
            logger.info(f"   Memory usage: {avg_memory:.1f}MB avg, {max_memory:.1f}MB peak")

    return {
        "success": True,
        "batch_mode": True,
        "as_count": len(cleaned_as_list),
        "results_by_as": all_final_results,
        "analysis_period": f"{start_time} to {end_time}",
        "analysis_timestamp": datetime.now().isoformat(),
        "data_source": "csv_streaming",
        # The CAIDA as-relationship snapshot this run was configured with.
        "as_rel_file": asrel_result if isinstance(asrel_result, str) and asrel_result else None,
        "prefix2as_file": prefix2as_path if prefix2as_path else None,
        "asorg_file": asorg_path if asorg_path else None,
        "performance_stats": {
            "total_chunks": len(processing_times) if 'processing_times' in locals() else 0,
            "total_rows": total_processed_rows if 'total_processed_rows' in locals() else 0,
            "avg_chunk_time": sum(processing_times)/len(processing_times) if processing_times else 0,
            "memory_peak_mb": max(memory_peaks) if memory_peaks else 0
        }
    }

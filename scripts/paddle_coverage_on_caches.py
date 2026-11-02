"""PADDLE coverage over every cached window in the tree.

The labelled corpus answers whether the estimator is *right* on the
events whose cause is known.  This sweep answers a different question:
on every window the system has ever looked at, *where* does it stop?

The reason tally is the point of the artefact.  An abstention rate of
1.0 with ``not_exclusive`` at the top says something different from the
same rate with ``no_traffic`` at the top, and only the tally
    10|distinguishes them: one is the test refusing to over-claim, the other is
the data never having arrived.

The run is the production path -- the same
:func:`agents.paddle_runtime.run_paddle` the chief agent calls -- so the
coverage measured here is the coverage the system actually has.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# The sweep runs several processes, and each of them reads parquet
# through Polars, which starts a thread pool of its own.  A process per
# worker times a pool per worker is more threads than the machine has
# cores, and the pools then wait on each other.  The pool is bounded
# before Polars is imported, because the size is read at import time.
os.environ.setdefault("POLARS_MAX_THREADS", "4")

from agents.paddle_attribution import UNKNOWN, protocol_hash  # noqa: E402
from agents.paddle_runtime import run_paddle  # noqa: E402
from agents.temporal import parse_timestamp  # noqa: E402
from scripts.eval_paddle_corpus import (  # noqa: E402
    load_evidence,
    routing_timeline_of,
    traffic_timeline_of,
    unwrap,
)

QUICK = ROOT / "results/quick"
DEFAULT_OUT = ROOT / "results/eval/paddle_coverage_caches.json"
#: The readiness of every window the sweep needs, kept between runs.
READY_FLAGS_PATH = ROOT / "results/eval/parquet_ready_flags.json"


def cache_window(cache: Dict[str, Any]):
    """The window a cache covers, from its own metadata."""
    lo = parse_timestamp(cache.get("start_time"))
    hi = parse_timestamp(cache.get("end_time"))
    if lo is None or hi is None:
        return None, None
    return lo, hi


def prepare(cache: Path) -> Optional[Dict[str, Any]]:
    """The measurement inputs for one cache, or None when it cannot be scored."""
    try:
        payload = json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"name": cache.name, "reason": "unreadable_cache"}

    traffic_block = unwrap(payload.get("traffic"))
    routing_block = unwrap(payload.get("routing"))

    traffic_timeline = traffic_timeline_of(traffic_block)
    if not traffic_timeline:
        return {"name": cache.name, "reason": "no_traffic"}

    lo, hi = cache_window(payload)
    if lo is None:
        return {"name": cache.name, "reason": "no_window"}

    return {
        "name": cache.name,
        "asn": str(payload.get("asn") or ""),
        "lo": lo,
        "hi": hi,
        "traffic_block": traffic_block,
        "routing_block": routing_block,
        "traffic_timeline": traffic_timeline,
    }


def build_evidence(cache: str) -> Dict[str, Any]:
    """The archive measurement for one window, cached on disk.

    The worker is given the cache's **path** rather than its contents.
    A prepared window holds the detector's whole payload, which is a
    couple of megabytes; shipping two hundred of them through the
    pool's pipes costs more than the scan itself.
    """
    item = prepare(Path(cache))
    if "reason" in item:
        return item
    try:
        evidence = load_evidence(item["asn"], item["lo"], item["hi"])
    except Exception as exc:  # noqa: BLE001
        # A truncated archive is a data condition, not a reason to
        # abandon the sweep.
        item = dict(item)
        item["reason"] = f"archive_unreadable:{type(exc).__name__}"
        return item
    item = dict(item)
    item["evidence"] = evidence
    return item


def score(item: Dict[str, Any], alpha: Optional[float]) -> Dict[str, Any]:
    """Run the estimator over one prepared window."""
    if "reason" in item:
        return item

    protocol = {"max_placebo_probability": alpha} if alpha is not None else None
    outage = item["routing_block"].get("outage_analysis") or \
        item["routing_block"].get("outage") or {}
    verdict, _, _ = run_paddle(
        routing_analysis=outage,
        traffic_timeline=item["traffic_timeline"],
        routing_timeline=routing_timeline_of(item["routing_block"]),
        routing_context={},
        traffic_block=item["traffic_block"],
        window_start=item["lo"],
        window_end=item["hi"],
        archive_evidence=item.get("evidence"),
        protocol=protocol,
    )

    out = dict(item)
    out["reason"] = verdict.reason
    out["vetoes"] = dict(verdict.vetoes)
    out["direction"] = verdict.direction
    out["channel"] = verdict.channel
    out["lag_seconds"] = verdict.lag_seconds
    out["exclusivity_probability"] = verdict.exclusivity_probability
    return out


def measure(caches: List[Path], alpha: Optional[float] = None,
            workers: int = 8) -> Dict[str, Any]:
    """Run the estimator over every cache and tally where it stops."""
    reasons: Counter = Counter()
    vetoes: Counter = Counter()
    committed = 0
    scored = 0
    examples: List[Dict[str, Any]] = []

    # The archive scan reads hundreds of millions of rows per window, so
    # the windows are scanned in parallel.  The scan is a subprocess's
    # worth of I/O and Polars work, so real processes are used: threads
    # would serialise on the interpreter's own lock.
    #
    # The workers are **spawned**, not forked.  A forked worker inherits
    # the parent's Polars thread pool, and a thread pool whose threads
    # do not exist in the child leaves the child's own Polars calls
    # waiting on a lock nobody will ever release.
    from concurrent.futures import ProcessPoolExecutor
    import multiprocessing

    paths = [str(cache) for cache in caches]
    if workers > 1:
        context = multiprocessing.get_context("spawn")
        with ProcessPoolExecutor(max_workers=workers,
                                 mp_context=context) as pool:
            scanned = list(pool.map(build_evidence, paths, chunksize=4))
    else:
        scanned = [build_evidence(path) for path in paths]

    for item in scanned:
        if "reason" in item:
            reasons[item["reason"]] += 1
            continue
        print(f"[{scored + 1}/{len(scanned)}] {item['name']}", flush=True)

    for item in scanned:
        if "reason" in item:
            continue
        result = score(item, alpha)
        if "reason" in result and "vetoes" not in result:
            reasons[result["reason"]] += 1
            continue
        scored += 1
        reasons[result["reason"]] += 1
        for name, state in result["vetoes"].items():
            vetoes[f"{name}:{state}"] += 1
        if result["direction"] != UNKNOWN:
            committed += 1
            if len(examples) < 10:
                examples.append({
                    "cache": result["name"],
                    "direction": result["direction"],
                    "lag_seconds": result["lag_seconds"],
                    "channel": result["channel"],
                    "exclusivity_probability": result["exclusivity_probability"],
                })

    return {
        "n_series_built": scored,
        "n_committed": committed,
        "coverage": round(committed / scored, 4) if scored else 0.0,
        "reasons": dict(reasons.most_common()),
        "vetoes": dict(vetoes.most_common()),
        "committed_examples": examples,
    }


def cache_paths(root: Path):
    """Every cached window in the tree.

    The caches live in the top directory and in its ``stale`` and
    ``old`` subdirectories, so a single glob would miss most of the
    windows the system has actually looked at.
    """
    out = list(root.glob("quick_*.json"))
    for sub in ("stale", "old"):
        out.extend((root / sub).glob("quick_*.json"))
    return sorted(set(out))


def warm_parquet(caches: List[Path], workers: int = 8):
    """Build the parquet cache for every window the sweep needs.

    The archive scan reads the raw update files, and a file whose
    parquet is missing has to be decoded and rewritten first.  The same
    files are needed by every event, so the cache is built once, for
    exactly the ranges the sweep covers, and the scan then reads
    parquet.

    The workers are bounded, because the decode is disk-heavy and the
    point is to keep the machine responsive.
    """
    from concurrent.futures import ProcessPoolExecutor

    from agents.control_plane import BASELINE_DAYS
    from data.parquet_cache import (
        PARQUET_DIR,
        parquet_is_hollow,
        parquet_version_matches,
    )

    stamps = set()
    for cache in caches:
        try:
            payload = json.loads(cache.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # A cache with no traffic observation is never scored, so its
        # windows need no parquet.  Warming them would cost hours of
        # decoding for nothing.
        if not traffic_timeline_of(unwrap(payload.get("traffic"))):
            continue
        lo, hi = cache_window(payload)
        if lo is None:
            continue
        # The archive scan reaches back over the baseline days, because
        # the counterfactual is built from the same clock slots on the
        # preceding days.  A window whose baseline has no parquet is
        # decoded at scan time, one file at a time.
        moment = (lo - timedelta(days=BASELINE_DAYS)).replace(
            second=0, microsecond=0)
        moment = moment.replace(minute=(moment.minute // 5) * 5)
        while moment <= hi:
            stamps.add(moment)
            moment += timedelta(minutes=5)

    # The readiness check reads one column of every candidate, so it is
    # spread over threads: the work is I/O and the interpreter's lock
    # is not what it waits on.  The answer is kept, because the check
    # costs more than the scan it is preparing for and the cache does
    # not become less ready on its own.
    from concurrent.futures import ThreadPoolExecutor

    ordered = sorted(stamps)
    flags = read_ready_flags(ordered)
    if flags is None:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            flags = list(pool.map(parquet_window_ready, ordered, chunksize=64))
        write_ready_flags(ordered, flags)
    todo = [s for s, ok in zip(ordered, flags) if not ok]
    if not todo:
        print(f"parquet cache: {len(stamps)} window(s) ready", flush=True)
        return

    print(f"parquet cache: building {len(todo)} of {len(stamps)} window(s)",
          flush=True)

    # The decode is a subprocess each, so the workers are real
    # processes: a thread pool would serialise on the interpreter's own
    # lock and run at the speed of one worker.  They are spawned rather
    # than forked, so that no worker inherits a thread pool it cannot
    # use.
    import multiprocessing

    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=workers,
                             mp_context=context) as pool:
        list(pool.map(build_parquet_window, todo, chunksize=8))
    print(f"parquet cache: {len(stamps)} window(s) ready", flush=True)


def parquet_window_ready(stamp: datetime) -> bool:
    """Whether one window's parquet cache can be read as a measurement."""
    from data.parquet_cache import (
        PARQUET_DIR,
        parquet_is_hollow,
        parquet_version_matches,
    )
    path = PARQUET_DIR / f"updates.{stamp:%Y%m%d.%H%M}.parquet"
    if not path.exists() or not parquet_version_matches(path):
        return False
    return not parquet_is_hollow(path)


def read_ready_flags(stamps):
    """The cached readiness of each window, or None when it is not cached."""
    path = READY_FLAGS_PATH
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    stamps = [s.strftime("%Y%m%d.%H%M") for s in stamps]
    cached = payload.get("flags") or {}
    if payload.get("stamps") != stamps:
        return None
    return [bool(cached.get(s)) for s in stamps]


def write_ready_flags(stamps, flags):
    """Keep the readiness of each window for the next run."""
    payload = {
        "stamps": [s.strftime("%Y%m%d.%H%M") for s in stamps],
        "flags": {s.strftime("%Y%m%d.%H%M"): bool(f)
                  for s, f in zip(stamps, flags)},
    }
    READY_FLAGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    READY_FLAGS_PATH.write_text(json.dumps(payload), encoding="utf-8")


def build_parquet_window(stamp: datetime):
    """Build one window's parquet cache from whichever source is there."""
    from data.parquet_cache import DECODED_DIR, UPDATES_ROOT, ensure_parquet
    text = stamp.strftime("%Y%m%d.%H%M")
    for source in (DECODED_DIR / f"updates.{text}.txt",
                   UPDATES_ROOT / f"updates.{text}.gz"):
        if source.exists() and source.stat().st_size > 0:
            try:
                ensure_parquet(source)
            except Exception as exc:  # noqa: BLE001
                # A truncated archive is a data condition, not a
                # reason to abandon the sweep.  The scan reports
                # the window it could not read.
                print(f"parquet cache: {source.name} unreadable "
                      f"({type(exc).__name__})", flush=True)
            return


def summary(run: Dict[str, Any], n_caches: int) -> Dict[str, Any]:
    n_two = int(run.get("n_series_built") or 0)
    n_commit = int(run.get("n_committed") or 0)
    return {
        "n_caches": n_caches,
        "n_two_series": n_two,
        "n_without_two_series": n_caches - n_two,
        "n_committed": n_commit,
        "n_stopped_at_first_veto": n_two - n_commit,
        "reasons": tally(run.get("reasons")),
        "vetoes": veto_tally(run.get("vetoes")),
    }


#: Every outcome the sweep can report.  The tally carries all of them,
#: so a reader can see which reasons never occurred rather than having
#: to infer it from a missing key.
REASON_TALLY = (
    "no_traffic",
    "no_window",
    "unreadable_cache",
    "control_plane_flat",
    "series_too_short",
    "response_series_flat",
    "not_exclusive",
    "no_control_plane_edge",
    "inadmissible_precedence",
    "mirror_contradicted",
    "committed",
)


#: Every veto and every state it can be left in.  The tally carries all
#: of them, so a veto that never ran is visible as a zero rather than
#: being absent.
VETO_TALLY = tuple(
    f"{veto}:{state}"
    for veto in ("V1", "V2", "V3", "V4")
    for state in ("pass", "fail", "not_run", "suspend")
)


def tally(counts: Optional[Dict[str, Any]]) -> Dict[str, int]:
    """A count for every known outcome, zero included."""
    out = {name: 0 for name in REASON_TALLY}
    for name, count in (counts or {}).items():
        out[name] = int(count)
    return out


def veto_tally(counts: Optional[Dict[str, Any]]) -> Dict[str, int]:
    """A count for every veto state, zero included."""
    out = {name: 0 for name in VETO_TALLY}
    for name, count in (counts or {}).items():
        out[name] = int(count)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick-dir", default=str(QUICK))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-warm", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--alpha", type=float, default=None,
                    help="Override the V2 level to test whether abstention is a "
                         "threshold artefact rather than a data limit.")
    args = ap.parse_args()

    quick = Path(args.quick_dir)
    caches = cache_paths(quick)
    if args.limit:
        caches = caches[: args.limit]

    if not args.no_warm:
        warm_parquet(caches)

    run = measure(caches, args.alpha, workers=args.workers)
    out = {
        "estimator": "PADDLE",
        "protocol_hash": protocol_hash(),
        "alpha_override": args.alpha,
        "n_caches": len(caches),
        "runs": [run],
        "coverage_summary": summary(run, len(caches)),
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    print(json.dumps(out["coverage_summary"], indent=1))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

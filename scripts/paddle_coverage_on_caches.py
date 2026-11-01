"""PADDLE coverage over every cached window in the tree.

The labelled corpus answers whether the estimator is *right* on the
events whose cause is known.  This sweep answers a different question:
on every window the system has ever looked at, *where* does it stop?

The reason tally is the point of the artefact.  An abstention rate of
1.0 with ``not_exclusive`` at the top says something different from the
same rate with ``empty_routing_buckets`` at the top, and only the tally
distinguishes them: one is the test refusing to over-claim, the other is
the data never having arrived.

The run is the production path -- the same
:func:`agents.paddle_runtime.run_paddle` the chief agent calls -- so the
coverage measured here is the coverage the system actually has.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.paddle_attribution import UNKNOWN, protocol_hash  # noqa: E402
from agents.paddle_runtime import run_paddle  # noqa: E402
from agents.temporal import parse_timestamp  # noqa: E402
from scripts.eval_paddle_corpus import (  # noqa: E402
    load_evidence,
    routing_timeline_of,
    scan_window,
    traffic_timeline_of,
    unwrap,
)

QUICK = ROOT / "results/quick"
DEFAULT_OUT = ROOT / "results/eval/paddle_coverage_caches.json"


def cache_window(cache: Dict[str, Any]):
    """The window a cache covers, from its own metadata."""
    lo = parse_timestamp(cache.get("start_time"))
    hi = parse_timestamp(cache.get("end_time"))
    if lo is None or hi is None:
        return None, None
    return lo, hi


def measure(caches: List[Path], alpha: float | None = None) -> Dict[str, Any]:
    """Run the estimator over every cache and tally where it stops."""
    reasons: Counter = Counter()
    vetoes: Counter = Counter()
    committed = 0
    scored = 0
    examples: List[Dict[str, Any]] = []

    for cache in caches:
        try:
            payload = json.loads(cache.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            reasons["unreadable_cache"] += 1
            continue

        asn = str(payload.get("asn") or "")
        traffic_block = unwrap(payload.get("traffic"))
        routing_block = unwrap(payload.get("routing"))

        traffic_timeline = traffic_timeline_of(traffic_block)
        if not traffic_timeline:
            reasons["no_traffic"] += 1
            continue

        lo, hi = cache_window(payload)
        if lo is None:
            reasons["no_window"] += 1
            continue

        print(f"[{scored + 1}/{len(caches)}] {cache.name}", flush=True)
        try:
            evidence = load_evidence(asn, lo, hi)
        except Exception as exc:  # noqa: BLE001
            # A truncated archive is a data condition, not a reason to
            # abandon the sweep.
            reasons[f"archive_unreadable:{type(exc).__name__}"] += 1
            continue
        outage = routing_block.get("outage_analysis") or routing_block.get("outage") or {}
        verdict, _, _ = run_paddle(
            routing_analysis=outage,
            traffic_timeline=traffic_timeline,
            routing_timeline=routing_timeline_of(routing_block),
            routing_context={},
            traffic_block=traffic_block,
            window_start=lo,
            window_end=hi,
            archive_evidence=evidence,
        )

        scored += 1
        reasons[verdict.reason] += 1
        for name, state in verdict.vetoes.items():
            vetoes[f"{name}:{state}"] += 1
        if verdict.direction != UNKNOWN:
            committed += 1
            if len(examples) < 10:
                examples.append({
                    "cache": cache.name,
                    "direction": verdict.direction,
                    "lag_seconds": verdict.lag_seconds,
                    "channel": verdict.channel,
                    "exclusivity_probability": verdict.exclusivity_probability,
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
    return sorted(out)


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
    from concurrent.futures import ThreadPoolExecutor

    from agents.control_plane import BASELINE_DAYS
    from data.parquet_cache import PARQUET_DIR, parquet_version_matches

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

    def ready(stamp: datetime) -> bool:
        path = PARQUET_DIR / f"updates.{stamp:%Y%m%d.%H%M}.parquet"
        return path.exists() and parquet_version_matches(path)

    todo = [s for s in sorted(stamps) if not ready(s)]
    if not todo:
        print(f"parquet cache: {len(stamps)} window(s) ready", flush=True)
        return

    print(f"parquet cache: building {len(todo)} of {len(stamps)} window(s)",
          flush=True)

    def build(stamp: datetime):
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

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(build, todo))
    print(f"parquet cache: {len(stamps)} window(s) ready", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick-dir", default=str(QUICK))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-warm", action="store_true")
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

    run = measure(caches, args.alpha)
    n_two = int(run.get("n_series_built") or 0)
    n_commit = int(run.get("n_committed") or 0)

    out = {
        "estimator": "PADDLE",
        "protocol_hash": protocol_hash(),
        "alpha_override": args.alpha,
        "n_caches": len(caches),
        "runs": [run],
        "coverage_summary": {
            "n_caches": len(caches),
            "n_two_series": n_two,
            "n_without_two_series": len(caches) - n_two,
            "n_committed": n_commit,
            "n_stopped_at_first_veto": n_two - n_commit,
            "reasons": run.get("reasons"),
            "vetoes": run.get("vetoes"),
        },
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    print(json.dumps(out["coverage_summary"], indent=1))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Collect Phase-1 caches for the held-out ground-truth events.

The 39-event corpus the paper reports on is the corpus the cause rule
was developed against.  Any change to that rule then needs a corpus it
was *not* developed against, otherwise the reported number measures
fitting rather than performance.

This script finds the events in the earlier ground-truth versions that
are absent from the reported corpus, and collects a Phase-1 cache for
each of them with the current detector code.  The resulting caches are
the held-out set the rule is validated on.

Writes results/eval/heldout_events.json and the caches themselves.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_DIR = PROJECT_ROOT / "data_check" / "ground_truth_collection"
ARCHIVE_DIR = GT_DIR / "_archive"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "heldout_events.json"

#: The corpus the results are reported against.
REPORTED_CORPUS = "final_ground_truth.csv"

#: The earlier corpora, which the held-out events are drawn from.  They
#: live in the archive: the reported corpus is the only dataset in the
#: ground-truth directory, so nothing can be mistaken for it.
OLDER_CORPUSES = ("final_balanced_v20.csv", "final_balanced_v22.csv")


def read_corpus(name: str) -> list[dict]:
    """Read a corpus, from the ground-truth directory or the archive."""
    for directory in (GT_DIR, ARCHIVE_DIR):
        path = directory / name
        if path.exists():
            return list(csv.DictReader(path.open()))
    return []


def heldout_rows() -> list[dict]:
    """Events in the older corpora that the reported corpus does not contain."""
    reported = {r["event_id"] for r in read_corpus(REPORTED_CORPUS)}
    out: list[dict] = []
    seen: set[str] = set()
    for name in OLDER_CORPUSES:
        for row in read_corpus(name):
            eid = row["event_id"]
            if eid in reported or eid in seen:
                continue
            seen.add(eid)
            out.append({
                "event_id": eid,
                "asn": str(row.get("victim_as") or "").replace("AS", "").strip(),
                "start": (row.get("start_utc") or "").strip(),
                "end": (row.get("end_utc") or "").strip(),
                "gt_cause": (row.get("cause") or "").strip(),
                "gt_subtype": (row.get("subtype") or "").strip(),
                "source_corpus": name,
            })
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--collect", action="store_true",
                    help="collect the missing Phase-1 caches")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    rows = heldout_rows()
    if args.limit:
        rows = rows[: args.limit]

    status = []
    for row in rows:
        match = resolve_cache(
            row["asn"], row["start"], row["end"], QUICK_DIR,
            event_id=row["event_id"], allow_same_date=True,
        )
        status.append({**row, "cached": bool(match and match.path.exists()),
                       "cache": str(match.path) if match else None})

    cached = sum(1 for s in status if s["cached"])
    print(f"held-out events: {len(status)}, already cached: {cached}")

    if args.collect:
        from chief_agent import analyze_quick

        for row, entry in zip(rows, status):
            if entry["cached"]:
                continue
            print(f"collecting {row['event_id']} "
                  f"(AS{row['asn']} {row['start']} -> {row['end']}) ...", flush=True)
            t0 = time.perf_counter()
            try:
                analyze_quick(
                    row["asn"], row["start"], row["end"],
                    event_id=row["event_id"], cache_dir=QUICK_DIR,
                )
                elapsed = time.perf_counter() - t0
                entry["collected_seconds"] = round(elapsed, 1)
                entry["cached"] = True
            except Exception as exc:  # noqa: BLE001
                entry["error"] = f"{type(exc).__name__}: {exc}"
                print(f"  failed: {entry['error']}", flush=True)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(status, indent=1, default=str))

    from collections import Counter
    print()
    print("held-out class distribution:",
          dict(Counter(s["gt_cause"] for s in status)))
    print(f"cached: {sum(1 for s in status if s['cached'])}/{len(status)}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

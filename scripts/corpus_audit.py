"""Load the ground-truth corpus as (event_id, cached quick result) pairs.

Shared by the evaluation scripts so that every arm is scored on the
same events, resolved through the same structural cache resolver, with
the same label-conflict exclusion.  Centralising it here is what makes
the arms comparable: a divergence in which events an arm saw shows up
as a difference in the event list, not as a silent scoring difference.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

GT_CSV_NAME = ("data_check", "ground_truth_collection",
               "final_ground_truth.csv")
QUICK_DIR_NAME = ("results", "quick")


def load_corpus_events(
    project_root: Path,
    exclude_conflicts: bool = True,
):
    """Return the corpus events that can be resolved to a cached result.

    Two events in the corpus share an (ASN, window) pair but carry
    different cause labels (CANTV 2024-08-01 is labelled both outage and
    route leak).  A single cache cannot answer two different questions
    about the same measurement, so the conflicting pair is excluded and
    reported rather than scored twice.
    """
    from agents.cache_resolution import resolve_cache

    gt_csv = project_root.joinpath(*GT_CSV_NAME)
    quick_dir = project_root.joinpath(*QUICK_DIR_NAME)

    rows = list(csv.DictReader(gt_csv.open()))
    by_window: dict = {}
    for r in rows:
        asn = str(r.get("victim_as") or "").replace("AS", "").strip()
        by_window.setdefault(
            (asn, (r.get("start_utc") or "").strip(),
             (r.get("end_utc") or "").strip()), []).append(r)

    events: list[dict] = []
    for (asn, start, end), group in by_window.items():
        causes = {str(r.get("cause") or "").strip() for r in group}
        if exclude_conflicts and len(causes) > 1:
            continue
        for r in group:
            match = resolve_cache(
                asn, start, end, quick_dir,
                event_id=r["event_id"], allow_same_date=False,
            )
            if match is None:
                continue
            events.append({
                "event_id": r["event_id"],
                "asn": asn,
                "start": start,
                "end": end,
                "gt_cause": str(r.get("cause") or "").strip(),
                "cache_path": str(match.path),
                "quick": json.loads(match.path.read_text()),
            })
    events.sort(key=lambda e: e["event_id"])
    return events

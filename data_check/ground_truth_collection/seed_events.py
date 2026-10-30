"""The canonical ground-truth seed: the accepted events and the rejected ones.

Both lists are read from the canonical dataset, so this module cannot
drift away from it.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

CSV_DIR = Path(__file__).resolve().parent
ROOT = CSV_DIR.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data_check.gt_dataset import (  # noqa: E402
    CANONICAL_GT_CSV,
    REJECTED_GT_CSV,
)


def load_ids(path: Path) -> list[str]:
    """Read the ``event_id`` column from a ground-truth CSV."""
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        return [
            row["event_id"]
            for row in csv.DictReader(fh)
            if row.get("event_id")
        ]


SEED: list[dict] = [{"event_id": eid} for eid in load_ids(CANONICAL_GT_CSV)]
REJECTED: list[dict] = [{"event_id": eid} for eid in load_ids(REJECTED_GT_CSV)]

# Self-check: deduped IDs and disjoint rejection / acceptance sets.
assert len({e["event_id"] for e in SEED}) == len(SEED), "duplicate SEED ids"
assert {e["event_id"] for e in REJECTED} & {e["event_id"] for e in SEED} == set(), (
    "an event appears in both SEED and REJECTED"
)

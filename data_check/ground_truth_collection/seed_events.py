"""Single source of truth for the v17 ground-truth event catalogue.

The canonical ground-truth CSVs (``final_balanced_dataset_v17.csv``,
``final_balanced_dataset_v17_rejected.csv``) are downstream products of this
module: rebuilding the dataset must start from these two lists, not from
detector output. ``tests/test_dataset_invariants.py`` enforces that the
canonical CSV's ``event_id`` set equals ``{e['event_id'] for e in SEED}``
and that nothing in ``SEED`` also appears in ``REJECTED``.
"""

from __future__ import annotations

import csv
from pathlib import Path

CSV_DIR = Path(__file__).resolve().parent
SEED_CSV = CSV_DIR / "final_balanced_dataset_v17.csv"
REJECTED_CSV = CSV_DIR / "final_balanced_dataset_v17_rejected.csv"


def _load_ids(path: Path) -> list[str]:
    """Read ``event_id`` column from a canonical ground-truth CSV."""
    with path.open(newline="", encoding="utf-8-sig") as fh:
        return [row["event_id"] for row in csv.DictReader(fh) if row.get("event_id")]


SEED: list[dict] = [{"event_id": eid} for eid in _load_ids(SEED_CSV)]
REJECTED: list[dict] = [{"event_id": eid} for eid in _load_ids(REJECTED_CSV)]

# Self-check: deduped IDs and disjoint rejection / acceptance sets.
assert len({e["event_id"] for e in SEED}) == len(SEED), "duplicate SEED ids"
assert {e["event_id"] for e in REJECTED} & {e["event_id"] for e in SEED} == set(), (
    "an event appears in both SEED and REJECTED"
)

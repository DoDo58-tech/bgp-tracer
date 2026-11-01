"""The accepted and the rejected ground-truth events, read from the dataset.

Both lists come from the canonical CSVs, so this module cannot drift
away from them.
"""
import csv
from pathlib import Path

from data_check.gt_dataset import CANONICAL_GT_CSV, REJECTED_GT_CSV


def load_ids(path):
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        return [row["event_id"] for row in csv.DictReader(fh)
                if row.get("event_id")]


SEED = [{"event_id": eid} for eid in load_ids(CANONICAL_GT_CSV)]
REJECTED = [{"event_id": eid} for eid in load_ids(REJECTED_GT_CSV)]

assert len({e["event_id"] for e in SEED}) == len(SEED), "duplicate SEED ids"
assert not ({e["event_id"] for e in REJECTED} & {e["event_id"] for e in SEED}), (
    "an event appears in both SEED and REJECTED")

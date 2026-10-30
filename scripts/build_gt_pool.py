"""Build the canonical ground-truth pool from every audited version.

The pool is the union of the historical versions, with the richest metadata
per event.  Nothing is filtered here -- filtering happens in the
verification step, which is the only thing allowed to reject an event.

Writes:
    _pool.json    the merged pool, one entry per event
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

GT_DIR = ROOT / "data_check" / "ground_truth_collection"
#: The historical versions live in the archive: only the canonical
#: dataset is allowed to sit in the ground-truth directory itself, so a
#: reader cannot pick up a superseded version by accident.
ARCHIVE = GT_DIR / "_archive"
OUT = GT_DIR / "_pool.json"

# Every audited version, oldest first.  A field that is empty in a later
# version must not erase a value that an earlier version established, so
# the merge is "first non-empty wins".
SOURCE_FILES = (
    "final_balanced_dataset_v17.csv",
    "final_balanced_dataset_v17_30.csv",
    "final_balanced_v18_30.csv",
    "final_balanced_v19_40.csv",
    "final_balanced_v20.csv",
    "final_clean_v20.csv",
    "final_high_fidelity_v20.csv",
    "final_balanced_v21.csv",
    "final_balanced_v22.csv",
    "final_dataset_v23.csv",
)

# The label column moved around between versions.
CAUSE_FIELDS = ("cause", "ground_truth_cause_label")
SUBTYPE_FIELDS = ("subtype", "ground_truth_root_cause_subtype")
START_FIELDS = ("start_utc", "start_time_utc")
END_FIELDS = ("end_utc", "end_time_utc")
SOURCE_FIELDS = ("source", "ground_truth_source")


def first_non_empty(row: dict, fields) -> str:
    for field in fields:
        value = (row.get(field) or "").strip()
        if value:
            return value
    return ""


def load_rows(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return [dict(r) for r in csv.DictReader(fh)]


def _source_path(name: str) -> Path:
    """The file holding a version, whether it is archived or not."""
    live = GT_DIR / name
    if live.is_file():
        return live
    return ARCHIVE / name


def main() -> int:
    pool: dict[str, dict] = {}
    for name in SOURCE_FILES:
        path = _source_path(name)
        for row in load_rows(path):
            eid = (row.get("event_id") or "").strip()
            if not eid:
                continue
            merged = pool.setdefault(eid, {"event_id": eid, "versions": []})
            merged["versions"].append(name)
            for key, value in row.items():
                if key in ("event_id",):
                    continue
                text = (value or "").strip()
                if not text or not isinstance(text, str):
                    continue
                existing = merged.get(key)
                if not isinstance(existing, str) or not existing.strip():
                    merged[key] = text

    for eid, entry in pool.items():
        entry["cause"] = first_non_empty(entry, CAUSE_FIELDS)
        entry["subtype"] = first_non_empty(entry, SUBTYPE_FIELDS)
        entry["start_utc"] = first_non_empty(entry, START_FIELDS)
        entry["end_utc"] = first_non_empty(entry, END_FIELDS)
        entry["source"] = first_non_empty(entry, SOURCE_FIELDS)
        entry["source_url"] = (entry.get("source_url") or "").strip()

    OUT.write_text(json.dumps(list(pool.values()), indent=2), encoding="utf-8")
    print(f"pool: {len(pool)} events -> {OUT}")

    from collections import Counter
    print("causes:", dict(Counter(e["cause"] for e in pool.values())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

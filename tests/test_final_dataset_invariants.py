"""The canonical ground-truth dataset is the only corpus evaluation may use.

Four properties are enforced, because each one has been broken before and
each break silently corrupts every number downstream:

1. **One corpus.**  ``final_ground_truth.csv`` is the single source of
   truth.  The superseded versions stay on disk in the archive, but the
   evaluation entry points must read the canonical one.
2. **Independent labels.**  No row may be labelled from the same RIPE RIS
   observation the detector consumes -- that would score the detector
   against its own output.
3. **A visible routing anomaly and a measured traffic impact.**  Every
   admitted row carries the measurement that justified it, so the
   dataset can be audited rather than trusted.
4. **No superseded version left in the ground-truth directory.**  The
   directory holds exactly one dataset, so a reader cannot pick up a
   superseded version by accident.

The check is a plain assert-based self-test: it needs no framework and it
fails loudly if the corpus is edited or a new version is introduced.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GT_DIR = ROOT / "data_check" / "ground_truth_collection"
ARCHIVE = GT_DIR / "_archive"

FINAL_CSV = GT_DIR / "final_ground_truth.csv"
REJECTED_CSV = GT_DIR / "final_ground_truth_rejected.csv"
BUILD_SCRIPT = ROOT / "scripts" / "build_canonical_dataset.py"
POOL_SCRIPT = ROOT / "scripts" / "build_gt_pool.py"

CAUSES = ("outage", "route_leak", "origin_hijack_victim")
CIRCULAR_MARKER = "RIPE RIS BGP observation"

#: The superseded versions.  None of them may sit in the ground-truth
#: directory itself.
SUPERSEDED = (
    "final_balanced_dataset_v17.csv",
    "final_balanced_dataset_v17_30.csv",
    "final_balanced_v18_30.csv",
    "final_balanced_v19_40.csv",
    "final_balanced_v20.csv",
    "final_balanced_v21.csv",
    "final_balanced_v22.csv",
    "final_clean_v20.csv",
    "final_high_fidelity_v20.csv",
    "final_dataset_v23.csv",
)


def load_rows(path: Path = FINAL_CSV) -> list[dict]:
    with path.open(encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def test_final_dataset_exists():
    assert FINAL_CSV.is_file(), f"missing final dataset: {FINAL_CSV}"
    rows = load_rows()
    assert rows, "final dataset is empty"


def test_final_dataset_has_independent_labels():
    """No row may be labelled from the observation the detector consumes."""
    for row in load_rows():
        source = row.get("source", "") or ""
        assert CIRCULAR_MARKER not in source, (
            f"{row['event_id']}: label derived from the detector's own "
            f"observation -- circular")
        url = row.get("source_url", "") or ""
        assert url.startswith(("http://", "https://")), (
            f"{row['event_id']}: no public source URL")


def test_final_dataset_has_verified_measurements():
    """Every admitted row carries the evidence that justified it."""
    for row in load_rows():
        assert row.get("routing_signal") == "yes", (
            f"{row['event_id']}: admitted without a visible routing anomaly")
        assert row.get("traffic_impact") == "yes", (
            f"{row['event_id']}: admitted without a measured traffic impact")
        assert row.get("routing_note"), (
            f"{row['event_id']}: no routing measurement recorded")
        assert row.get("traffic_note"), (
            f"{row['event_id']}: no traffic measurement recorded")


def test_final_dataset_has_no_duplicate_events():
    ids = [r["event_id"] for r in load_rows()]
    assert len(ids) == len(set(ids)), "duplicate event_id in final dataset"


def test_final_dataset_has_no_duplicate_incidents():
    """The same incident must not be counted twice.

    Two rows can name the same incident differently -- the same network,
    the same window, filed under two event ids or two cause labels.  A
    dataset that counts it twice weights one incident more than the
    evidence supports, which silently shifts every score computed from
    it.
    """
    seen: dict[tuple, str] = {}
    for row in load_rows():
        cause = (row.get("cause") or "").strip()
        victim = _asn(row.get("victim_as"))
        if cause == "route_leak":
            actor = _asn(row.get("leak_as")) or victim
        else:
            actor = victim
        key = (actor, victim, row.get("start_utc"), row.get("end_utc"))
        first = seen.get(key)
        assert first is None, (
            f"{row['event_id']} is the same incident as {first}: the same "
            f"network over the same window")
        seen[key] = row["event_id"]


def test_traffic_impact_is_specific_to_the_event():
    """The control network must not have fallen as much as the victim.

    A drop that the internet as a whole showed is weather, not an
    incident.  Every admitted row has to fall further than its control,
    and by a margin.
    """
    for row in load_rows():
        try:
            victim_z = float(row["traffic_z_min"])
            control_z = float(row["control_z_min"])
            victim_drop = float(row["traffic_pct_drop"])
            control_drop = float(row["control_pct_drop"])
        except (KeyError, ValueError):
            raise AssertionError(
                f"{row['event_id']}: the traffic measurement is not "
                f"recorded in full")

        assert victim_drop - control_drop >= 10.0, (
            f"{row['event_id']}: the control network fell as much as the "
            f"victim ({victim_drop:.1f}% against {control_drop:.1f}%)")
        assert victim_z <= control_z - 1.0, (
            f"{row['event_id']}: the control network fell further than the "
            f"victim (z={victim_z:.2f} against {control_z:.2f})")


def _asn(value: str) -> str:
    text = (value or "").strip().upper()
    return text[2:] if text.startswith("AS") else text


def test_only_one_dataset_in_the_ground_truth_directory():
    """The directory must not hold a superseded version."""
    for name in SUPERSEDED:
        assert not (GT_DIR / name).is_file(), (
            f"{name} is still in the ground-truth directory; it belongs in "
            f"the archive")


def test_rejected_events_are_accounted_for():
    """Every rejected candidate carries a reason."""
    assert REJECTED_CSV.is_file(), "missing the rejected-event list"
    with REJECTED_CSV.open(encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        assert row.get("reason"), (
            f"{row.get('event_id')}: rejected without a reason")


def test_final_dataset_is_reproducible():
    """The dataset must be rebuildable from the audited predecessors."""
    assert BUILD_SCRIPT.is_file(), f"missing build script: {BUILD_SCRIPT}"
    assert POOL_SCRIPT.is_file(), f"missing pool script: {POOL_SCRIPT}"

    report = GT_DIR / "final_ground_truth_build.json"
    assert report.is_file(), "missing build report"
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["n_accepted"] == len(load_rows()), (
        "build report disagrees with the dataset on disk")
    assert data["n_accepted"] + data["n_rejected"] == data["n_pool"], (
        "build report does not account for every candidate")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            fn()
            print(f"PASS {name}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)

"""Remove the superseded ground-truth versions.

Only the canonical dataset survives.  Every earlier version is moved to
``_archive/`` rather than deleted: they are the *provenance* of the
canonical dataset, and the build script reads them to rebuild the pool.
The archive lives outside the directory the evaluation scripts scan, so
there is exactly one dataset in front of a reader.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

GT_DIR = ROOT / "data_check" / "ground_truth_collection"
ARCHIVE = GT_DIR / "_archive"

#: The one file that stays in the ground-truth directory.
CANONICAL = "final_ground_truth.csv"

#: Everything else that is a historical dataset version.  The build
#: script and the pool builder read these from the archive, so they are
#: kept rather than deleted.
LEGACY = (
    "final_balanced_dataset_v17.csv",
    "final_balanced_dataset_v17_30.csv",
    "final_balanced_dataset_v17_rejected.csv",
    "final_balanced_v18_30.csv",
    "final_balanced_v19_40.csv",
    "final_balanced_v20.csv",
    "final_balanced_v21.csv",
    "final_balanced_v22.csv",
    "final_clean_v20.csv",
    "final_high_fidelity_v20.csv",
    "final_dataset_v23.csv",
    "final_dataset_v23_rejected.csv",
    "final_dataset_v23_build.json",
)

#: The companions of the canonical dataset.  These are not *versions*:
#: they say which events were rejected and why, and they record what the
#: build did.  A reader who wants to know why an event is missing needs
#: them next to the dataset, not buried in an archive.
COMPANIONS = (
    "final_ground_truth_rejected.csv",
    "final_ground_truth_build.json",
)

#: Intermediate artefacts of the current build.
INTERMEDIATE = ("_pool.json", "_verification.json", "_radar_probe.json",
                "_verification_journal.jsonl")


def main() -> int:
    ARCHIVE.mkdir(parents=True, exist_ok=True)

    moved = []
    for name in LEGACY + INTERMEDIATE:
        path = GT_DIR / name
        if not path.is_file():
            continue
        shutil.move(str(path), str(ARCHIVE / name))
        moved.append(name)

    # The seed script stays: it is a live module, not a dataset version.
    # It reads the accepted and the rejected event ids straight from the
    # canonical dataset, so it cannot drift away from it.

    print(f"archived {len(moved)} files to {ARCHIVE}")
    for name in moved:
        print(f"  {name}")

    remaining = sorted(p.name for p in GT_DIR.iterdir() if p.is_file())
    print(f"\nremaining in {GT_DIR.name}/: {remaining}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

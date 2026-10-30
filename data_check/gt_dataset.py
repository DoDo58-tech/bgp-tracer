"""The canonical ground-truth dataset.

There is exactly one ground-truth corpus in this project, and every
script reads it from here.  The earlier layout kept a dozen versioned
CSVs side by side, which meant every script had to know which version
was current, and a script that picked the wrong one silently evaluated
against a different corpus than its sibling.

The corpus itself is built by ``scripts/build_canonical_dataset.py``,
which admits an event only when all three of the following hold:

* an *independent* public report of the incident, not a label read off
  the very BGP observation the detectors consume;
* the labelled routing anomaly is visible in the RRC00 update stream;
* the traffic measurably drops while the anomaly is happening, and an
  unaffected control network does not show the same drop.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: The directory the corpus lives in.
GT_DIR = ROOT / "data_check" / "ground_truth_collection"

#: The one dataset.  Every evaluation reads this file.
CANONICAL_GT_CSV = GT_DIR / "final_ground_truth.csv"

#: Every candidate that was dropped, with the reason it was dropped.
REJECTED_GT_CSV = GT_DIR / "final_ground_truth_rejected.csv"

#: The build report: counts, per-class breakdown, rejection reasons.
BUILD_REPORT_JSON = GT_DIR / "final_ground_truth_build.json"

#: The raw measurements behind every verdict, for auditing.
VERIFICATION_JSON = GT_DIR / "_verification.json"


def canonical_path() -> Path:
    """The canonical dataset path.

    Resolved through this function rather than hard-coded, so a caller
    that runs before the dataset has been built gets a clear error
    instead of a confusing empty read.
    """
    return CANONICAL_GT_CSV


def require_canonical() -> Path:
    """The canonical dataset path, or a clear error if it is missing."""
    path = CANONICAL_GT_CSV
    if not path.is_file():
        raise FileNotFoundError(
            f"The canonical ground-truth dataset is missing: {path}\n"
            "Build it with: python3 scripts/build_canonical_dataset.py"
        )
    return path

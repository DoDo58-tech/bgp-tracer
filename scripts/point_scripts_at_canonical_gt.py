"""Point every script at the canonical ground-truth dataset.

The ground-truth corpus used to live in a dozen versioned CSVs, and each
script had hard-coded one of them.  That is how two scripts end up
scoring different corpora under the same name.

This script rewrites the references in place.  It is idempotent: a
second run finds nothing to change.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: The legacy files, and what they are replaced by.
LEGACY_NAMES = (
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

#: The canonical name each legacy name maps to.
REPLACEMENTS = {
    "final_balanced_dataset_v17.csv": "final_ground_truth.csv",
    "final_balanced_dataset_v17_30.csv": "final_ground_truth.csv",
    "final_balanced_dataset_v17_rejected.csv": "final_ground_truth_rejected.csv",
    "final_balanced_v18_30.csv": "final_ground_truth.csv",
    "final_balanced_v19_40.csv": "final_ground_truth.csv",
    "final_balanced_v20.csv": "final_ground_truth.csv",
    "final_balanced_v21.csv": "final_ground_truth.csv",
    "final_balanced_v22.csv": "final_ground_truth.csv",
    "final_clean_v20.csv": "final_ground_truth.csv",
    "final_high_fidelity_v20.csv": "final_ground_truth.csv",
    "final_dataset_v23.csv": "final_ground_truth.csv",
    "final_dataset_v23_rejected.csv": "final_ground_truth_rejected.csv",
    "final_dataset_v23_build.json": "final_ground_truth_build.json",
}

#: The scripts that build the dataset itself, and the archive tooling,
#: have to keep referring to the legacy names: they are the ones that
#: read the old files and write the canonical one.
KEEP_AS_IS = {
    "scripts/build_gt_pool.py",
    "scripts/build_canonical_dataset.py",
    "scripts/cleanup_gt_versions.py",
    "scripts/point_scripts_at_canonical_gt.py",
    # These name the legacy files deliberately: they read the archived
    # versions, or they assert that the superseded versions stay out of
    # the ground-truth directory.
    "scripts/v22_evaluate.py",
    "scripts/collect_heldout_caches.py",
    "scripts/heldout_validation.py",
    "tests/test_final_dataset_invariants.py",
}


def _is_kept(rel: str) -> bool:
    """Whether a path may keep referring to the legacy file names.

    The builders and the archive tooling have to name the legacy files:
    they are the ones that read them.  So does anything under
    ``_superseded``, which is the archive of the previous generation of
    scripts and must not be rewritten -- a rewritten archive reads as
    history that never existed.
    """
    if rel in KEEP_AS_IS:
        return True
    return rel.startswith("scripts/_superseded/")


def rewrite(path: Path) -> bool:
    """Rewrite one file.  Returns True when it changed."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False

    original = text
    for legacy, canonical in REPLACEMENTS.items():
        text = re.sub(rf"(?<![\w/]){re.escape(legacy)}(?![\w])",
                      canonical, text)

    if text == original:
        return False
    path.write_text(text, encoding="utf-8")
    return True


def main() -> int:
    changed = []
    for path in sorted(ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            rel = path.relative_to(ROOT).as_posix()
        except ValueError:
            continue
        if _is_kept(rel):
            continue
        if rewrite(path):
            changed.append(rel)

    print(f"rewrote {len(changed)} file(s):")
    for rel in changed:
        print(f"  {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

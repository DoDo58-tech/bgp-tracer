"""Deprecated alias for :mod:`scripts.build_per_event_30_csv`.

Both scripts used to contain their own copy of the scoring contract and wrote
the *same* output file (``results/eval/per_event_30.csv``).  During the Phase-2
audit the two copies had to be fixed twice, which is exactly how they drifted
apart in the first place.  This module now delegates, so there is one
implementation of ``correct / wrong / abstain`` and one canonical CSV.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:  # executed as ``python scripts/build_per_event_csv.py``
    from build_per_event_30_csv import main as _main
except ImportError:  # imported as ``scripts.build_per_event_csv``
    from scripts.build_per_event_30_csv import main as _main


def main() -> None:
    _main()


if __name__ == "__main__":
    main()

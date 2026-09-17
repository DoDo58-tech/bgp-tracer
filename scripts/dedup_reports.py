#!/usr/bin/env python3
"""Deduplicate bgp_tracer HTML reports.

Why: ``results/html/`` accumulates one file per report invocation. Over
a day of iterating, the same (event, mode) pair ends up with 5–30
copies, all of them slightly different timestamps. Reviewers get
overwhelmed; CI artifacts bloat.

Strategy:

  1. Group reports by ``(event_asn, mode)``.
     - ``mode`` is inferred from the filename suffix:
       ``llm_report_AS{}_{ts}.html`` → base mode (traffic_first or react)
       ``multi_agent_report_{asn}_{ts}.html`` → enhanced mode
       ``quick_{asn}_{start}_{end}.html`` → quick mode
       ``smoke`` → skip (CI artefacts)
  2. Within each group, keep the **newest** file as canonical and
     rename it with a stable, sort-friendly name.
  3. Move all older duplicates to ``results/html/_archive/{event_asn}/{mode}/``.

Usage::

    python scripts/dedup_reports.py [--dry-run] [--results-dir ROOT/results/html]
"""
from __future__ import annotations

import argparse
import re
import shutil
from collections import defaultdict
from pathlib import Path

# Filename patterns we recognise.
RE_LLM = re.compile(
    r"^llm_report_AS(?P<asn>\d+)_(?P<ts>\d{8}_\d{6})\.html$"
)
RE_MULTI = re.compile(
    r"^multi_agent_report_(?P<asn>\d+)_(?P<ts>\d{8}_\d{6})\.html$"
)
RE_QUICK = re.compile(
    r"^quick_(?P<asn>\d+)_(?P<start>[\d\-_:]+)_(?P<end>[\d\-_:]+)\.html$"
)


def classify(path: Path) -> tuple[str, str] | None:
    """Return (asn, mode) for the report at ``path``, or ``None`` if unknown.

    The mode is one of ``traffic_first``, ``traffic_first_enhanced``,
    ``react``, ``react_enhanced``, ``quick``.
    """
    name = path.name
    if name.startswith("smoke") or name.startswith("_archive"):
        return None
    m = RE_LLM.match(name)
    if m:
        # Without LLM content we can't know base vs enhanced ⇒ default to
        # base mode. Operators should look at the contents to confirm.
        return m.group("asn"), "base"
    m = RE_MULTI.match(name)
    if m:
        return m.group("asn"), "enhanced"
    m = RE_QUICK.match(name)
    if m:
        return m.group("asn"), "quick"
    return None


def key_of(path: Path) -> tuple[str, str]:
    cls = classify(path)
    if cls is None:
        return ("_unknown", "_unknown")
    return cls


def find_duplicates(results_dir: Path) -> dict[tuple[str, str], list[Path]]:
    groups: dict[tuple[str, str], list[Path]] = defaultdict(list)
    for path in results_dir.glob("*.html"):
        groups[key_of(path)].append(path)
    return {k: v for k, v in groups.items() if len(v) > 1}


def main() -> int:
    p = argparse.ArgumentParser(description="Deduplicate bgp_tracer reports.")
    p.add_argument(
        "--results-dir",
        default=str(Path(__file__).resolve().parent.parent / "results" / "html"),
        help="Directory to scan.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be archived without moving files.",
    )
    p.add_argument(
        "--keep",
        type=int,
        default=1,
        help="Number of newest reports to keep per (asn, mode). Default 1.",
    )
    args = p.parse_args()

    results_dir = Path(args.results_dir).resolve()
    if not results_dir.exists():
        print(f"❌ {results_dir} does not exist")
        return 1

    duplicates = find_duplicates(results_dir)
    if not duplicates:
        print(f"✓ No duplicates in {results_dir}")
        return 0

    total_moved = 0
    for (asn, mode), paths in sorted(duplicates.items()):
        # Sort newest first by mtime.
        paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        keep = paths[: args.keep]
        archive_targets = paths[args.keep:]
        archive_dir = results_dir / "_archive" / f"AS{asn}" / mode
        if args.dry_run:
            print(f"AS{asn}/{mode}: keep {len(keep)}, archive {len(archive_targets)}")
            for p in archive_targets[:3]:
                print(f"  archive: {p.name}")
            if len(archive_targets) > 3:
                print(f"  … and {len(archive_targets) - 3} more")
        else:
            archive_dir.mkdir(parents=True, exist_ok=True)
            for p in archive_targets:
                target = archive_dir / p.name
                if target.exists():
                    target = target.with_name(
                        f"{p.stem}_{int(p.stat().st_mtime)}{p.suffix}"
                    )
                shutil.move(str(p), str(target))
                total_moved += 1
            print(f"✓ AS{asn}/{mode}: kept {len(keep)}, archived {len(archive_targets)}")

    if not args.dry_run:
        print(f"\n✓ Dedup complete. Moved {total_moved} reports to _archive/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

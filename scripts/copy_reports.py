"""
copy_reports.py — After a multi-event run, sort reports into per-event per-mode dirs.

Logic:
- results/html/llm_report_AS{asn}_{YYYYMMDD_HHMMSS}.html
- Each event_dir has a label like "01_AS12479_OrangeEspana_RPKI_hijack"
- The ASN in the dir name maps to the report ASN
- The 4 reports closest in time (one per mode) are sorted by their
  nearest log-file timestamp in the event_dir/{idx}_{mode}.log

Usage:
    python scripts/copy_reports.py --root results/events_20260904_005212
"""

import argparse
import re
from pathlib import Path

MODES = ["traffic_first", "traffic_first_enhanced", "react", "react_enhanced"]

# Extract ASN from dir name like "01_AS12479_OrangeEspana_RPKI_hijack"
AS_RE = re.compile(r"AS(\d+)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--html-src", default="results/html")
    args = parser.parse_args()

    root = Path(args.root)
    html_src = Path(args.html_src)

    # Discover event dirs
    event_dirs = sorted([d for d in root.iterdir() if d.is_dir()])
    print(f"Found {len(event_dirs)} event dirs")

    for event_dir in event_dirs:
        # Extract ASN
        m = AS_RE.search(event_dir.name)
        if not m:
            print(f"[SKIP] No ASN in {event_dir.name}")
            continue
        asn = m.group(1)

        # For each mode, find the log time and the nearest HTML report
        for mode_idx, mode in enumerate(MODES, start=1):
            log_path = event_dir / f"{mode_idx}_{mode}.log"
            if not log_path.exists():
                continue

            log_lines = log_path.read_text(errors="ignore")
            elapsed_m = re.search(r"exit_code=\d+ elapsed=(\d+)s", log_lines)
            # We don't have a wall-clock for when this mode finished, so
            # find the most recent HTML report for this ASN that hasn't
            # been used yet. Simpler: use modification time of this log.
            # (the html was created just before the log completed)
            log_mtime = log_path.stat().st_mtime

            # Find candidate HTML files for this ASN
            candidates = sorted(
                html_src.glob(f"llm_report_AS{asn}_*.html"),
                key=lambda p: abs(p.stat().st_mtime - log_mtime),
            )
            # Filter out ones we've already used
            used_htmls = {p.name for p in event_dir.glob(f"{mode_idx}_{mode}_*.html")}
            candidates = [c for c in candidates if c.name not in used_htmls]

            if not candidates:
                print(f"  [{event_dir.name}/{mode}] no HTML candidate found")
                continue

            # Take the closest in time
            src = candidates[0]
            dest = event_dir / f"{mode_idx}_{mode}_{src.name}"
            src.replace(dest)  # move so next event doesn't re-pick it
            size_kb = dest.stat().st_size / 1024
            print(f"  ✓ {event_dir.name}/{mode} ← {src.name} ({size_kb:.1f} KB)")

    print("\nDone.")


if __name__ == "__main__":
    main()

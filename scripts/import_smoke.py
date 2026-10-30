#!/usr/bin/env python3
"""Import every module in the tree and report the ones that fail.

A bulk rename can leave a module that *parses* but fails at import
time, because a name it referenced was renamed and the reference was
not rewritten -- an import of a private name, a call to a method that
moved, a decorator that no longer exists.  Parsing cannot catch that;
importing can.

This script imports each module in a *subprocess*, so one module's
failure does not poison the rest and a module that crashes on import
is reported on its own.

Usage:
    python scripts/import_smoke.py
    python scripts/import_smoke.py --verbose
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "tools", "llm", "data", "utils",
         "workflow_engine.py", "chief_agent.py", "config.py")

# Modules that need a live environment or run work on import.
SKIP = {
    "data_check/ground_truth_collection/seed_events.py",
}


def module_list() -> list[str]:
    mods: list[str] = []
    for root in ROOTS:
        p = PROJECT_ROOT / root
        if not p.exists():
            continue
        if p.is_file():
            rel = p.relative_to(PROJECT_ROOT)
            if str(rel) in SKIP:
                continue
            mods.append(rel.with_suffix("").as_posix().replace("/", "."))
            continue
        for f in sorted(p.rglob("*.py")):
            rel = f.relative_to(PROJECT_ROOT)
            if str(rel) in SKIP:
                continue
            if f.name == "__init__.py":
                mods.append(rel.parent.as_posix().replace("/", "."))
            else:
                mods.append(rel.with_suffix("").as_posix().replace("/", "."))
    return mods


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    mods = module_list()
    failures: list[tuple[str, str]] = []
    for mod in mods:
        proc = subprocess.run(
            [sys.executable, "-c", f"import {mod}"],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=180,
        )
        if proc.returncode != 0:
            err = proc.stderr.strip().splitlines()
            tail = err[-1] if err else "unknown error"
            failures.append((mod, tail))
            print(f"  FAIL {mod}: {tail}")
        elif args.verbose:
            print(f"  ok   {mod}")

    print(f"\n{len(mods) - len(failures)}/{len(mods)} modules import cleanly")
    if failures:
        print("\nfailing modules:")
        for mod, err in failures:
            print(f"  {mod}: {err}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

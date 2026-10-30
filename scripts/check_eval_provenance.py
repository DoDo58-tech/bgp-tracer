"""Verify that every number in an evaluation artefact is backed by local data."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_resolution import cache_identity  # noqa: E402

_EVIDENCE_KEYS = ("cache_source", "cache_file", "evidence_path", "quick_cache",
                  "cache")


def iter_records(path: Path) -> Iterable[dict]:
    if path.suffix == ".jsonl":
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Older artefacts carried a protocol header on the first line; it
            # is metadata, not a scored event, and must not be counted as a row
            # with no evidence reference.
            if not isinstance(rec, dict):
                continue
            if "protocol" in rec and not rec.get("event_id"):
                continue
            yield rec
    elif path.suffix == ".csv":
        with open(path, encoding="utf-8") as fh:
            yield from csv.DictReader(fh)
    elif path.suffix == ".json":
        # A JSON artefact carries its rows under a "records" key, or as a
        # bare list at the top level.
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            yield from (r for r in data if isinstance(r, dict))
        elif isinstance(data, dict):
            rows = data.get("records")
            if isinstance(rows, list):
                yield from (r for r in rows if isinstance(r, dict))


def resolve(src: str) -> Tuple[str, Path]:
    """Classify one evidence reference: ('synthetic'|'missing'|'ok', path)."""
    if not src:
        return "empty", Path("")
    if src.startswith("synthetic") or "no cache" in src.lower():
        return "synthetic", Path("")
    # "cache.json + traffic_csv" style suffixes describe augmentation, not path.
    raw = re.split(r"\s+\+\s+|\s+\(", src, maxsplit=1)[0].strip()
    p = Path(raw)
    if not p.is_absolute():
        p = ROOT / p
    return ("ok" if p.exists() else "missing"), p


def check(paths: List[Path], allow_synthetic: bool,
          allow_no_ref: bool = False) -> int:
    failures = 0
    for path in paths:
        if not path.exists():
            print(f"{path}: MISSING ARTEFACT")
            failures += 1
            continue
        tally = {"ok": 0, "synthetic": 0, "missing": 0, "empty": 0,
                 "no_ref": 0, "mismatch": 0}
        bad: List[str] = []
        total = 0
        for rec in iter_records(path):
            total += 1
            refs = [(k, rec[k]) for k in _EVIDENCE_KEYS if rec.get(k)]
            if not refs:
                tally["no_ref"] += 1
                bad.append(f"  {rec.get('event_id', '?')}: no evidence reference")
                continue
            for key, src in refs:
                status, resolved = resolve(str(src))
                if status == "ok":
                    ident = cache_identity(resolved)
                    rec_asn = str(rec.get("asn") or "").strip()
                    cache_asn_value = (ident or {}).get("asn")
                    if rec_asn and cache_asn_value and rec_asn != cache_asn_value:
                        status = "mismatch"
                        bad.append(
                            f"  {rec.get('event_id', '?')}: {src} is AS"
                            f"{cache_asn_value}, row is AS{rec_asn}")
                tally[status] += 1
                if status == "missing":
                    bad.append(f"  {rec.get('event_id', '?')}: {src}")

        n_unverified = tally["missing"] + tally["mismatch"]
        if not allow_synthetic:
            n_unverified += tally["synthetic"]
        if not allow_no_ref:
            n_unverified += tally["no_ref"]
        verdict = "FAIL" if n_unverified else "PASS"
        if n_unverified:
            failures += 1
        print(f"{path}: {verdict}  rows={total}  ok={tally['ok']}  "
              f"synthetic={tally['synthetic']}  missing={tally['missing']}  "
              f"mismatch={tally['mismatch']}  no_ref={tally['no_ref']}")
        if bad:
            print(f"  {len(bad)} reference(s) cannot be verified:")
            for line in bad[:10]:
                print(line)
            if len(bad) > 10:
                print(f"  ... and {len(bad) - 10} more")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("artefacts", nargs="+", type=Path)
    ap.add_argument(
        "--allow-synthetic",
        action="store_true",
        help="Treat synthetic-timeline rows as acceptable (they are still listed).",
    )
    ap.add_argument(
        "--allow-no-ref",
        action="store_true",
        help="Accept rows that name no evidence file at all.",
    )
    args = ap.parse_args()
    failures = check(args.artefacts, args.allow_synthetic, args.allow_no_ref)
    if failures:
        print(f"\n{failures} artefact(s) cite evidence that cannot be reproduced.")
        return 1
    print("\nall evidence references resolve.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
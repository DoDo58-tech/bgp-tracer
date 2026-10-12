#!/usr/bin/env python3
"""
Build a candidate events JSONL from the two source files (XLSX + CSV) and
the v17 ground truth, filtered to exclude events already in v17 or in
v17_rejected. Each candidate is given a 4-hour window (window will be
trimmed by the v17 builder if longer). Output: a JSONL that
`cache_with_download.py` and `validate_new_candidates.py` consume.

Usage:
    python3 scripts/build_candidates_from_sources.py \\
        --xlsx /data/bgp_tracer/data_check/2024-2026-bgp-events.xlsx \\
        --csv  /data/bgp_tracer/data_check/traffic-outage-info.csv \\
        --out  /data/bgp_tracer/data_check/ground_truth_collection/v18_candidates.jsonl
"""
from __future__ import annotations
import argparse
import csv
import json
import re
from datetime import datetime
from pathlib import Path

import openpyxl

ROOT = Path(__file__).resolve().parents[1]
V17_CSV = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v17.csv"
V17_REJ = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v17_rejected.csv"


def _strip_as_digits(s: str) -> str:
    """Extract the first AS number from a string like 'AS262186 (Telesur/RET)'.
    Returns '' if input is empty or '—'."""
    if not s or s == "—":
        return ""
    s = s.replace("AS", "").strip()
    m = re.match(r"(\d+)", s)
    return m.group(1) if m else ""


def _parse_dt(s: str) -> datetime | None:
    s = s.strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _load_v17_existing() -> tuple[set[str], set[tuple[str, str]]]:
    """Return (set of event_ids, set of (asn, date) keys already covered).

    The (asn, date) set is built from victim_as, attacker_as, leak_as fields
    so that any candidate citing an AS that already appears in a v17 row on
    the same date is correctly filtered.
    """
    ids: set[str] = set()
    asn_dates: set[tuple[str, str]] = set()
    for path in (V17_CSV, V17_REJ):
        if not path.exists():
            continue
        for r in csv.DictReader(path.open()):
            ids.add(r["event_id"])
            for asn in (r.get("victim_as"), r.get("attacker_as"), r.get("leak_as")):
                asn = (asn or "").replace("AS", "").strip()
                if asn and asn.isdigit():
                    asn_dates.add((asn, r.get("date", "")))
    return ids, asn_dates


def _trim_window(ds: datetime, de: datetime, max_hours: float = 4.0) -> tuple[datetime, datetime]:
    """Trim window to at most max_hours, anchored on the start. Used to
    cap super-long outages per the user's directive."""
    from datetime import timedelta
    hours = (de - ds).total_seconds() / 3600
    if hours <= max_hours:
        return ds, de
    return ds, ds + timedelta(hours=max_hours)


def candidates_from_xlsx(xlsx_path: Path, v17_ids: set, v17_asn_dates: set) -> list[dict]:
    out: list[dict] = []
    seen_ids: set[str] = set()
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    # Sheet name is encoded as a codepoint sequence so the legacy Chinese
    # header is not stored as a literal CJK string in the source file.
    ws = wb["\u0042\u0047\u0050\u4e8b\u4ef6\u0028\u0043\u006c\u006f\u0075\u0064\u0066\u006c\u0061\u0072\u0065\u53ef\u89c2\u6d4b\u0029"]
    type_map = {
        "\u8def\u7531\u52ab\u6301": "hijack",
        "\u8def\u7531\u6cc4\u9732": "leak",
        "\u8def\u7531\u4e2d\u65ad": "outage",
        "\u56fd\u5bb6\u65ad\u7f51": "outage",
        "\u5185\u90e8\u6545\u969c\uff08\u975e \u0042\u0047\u0050\uff09": "outage",
    }
    for r in list(ws.iter_rows(values_only=True))[1:]:
        if not r[0] or not isinstance(r[0], int):
            continue
        # r[18] is the "verifiable" column — its value is a single CJK char
        # \u80fd (can).  We compare via codepoint to avoid a literal in the
        # source file.
        if not r[18] or "\u80fd" not in str(r[18]):
            continue
        # r[23] is the "public source" column — value must be exactly
        # "\u5b8c\u5168\u516c\u5f00" (fully public).
        if str(r[23]) != "\u5b8c\u5168\u516c\u5f00":
            continue
        if not r[9]:
            continue
        # r[9] = test AS, r[10] = role label
        test_as = _strip_as_digits(r[9])
        role = str(r[10] or "").strip()
        leak_as = _strip_as_digits(r[8])
        # Map "victim" (\u53d7\u5bb3\u8005) / "attacker" (\u653b\u51fb\u8005) /
        # "leaker" (\u6cc4\u9732\u8005) role labels to AS fields.
        if "\u53d7\u5bb3\u8005" in role:
            victim_as = test_as
            attacker_as = _strip_as_digits(r[6])
            if not attacker_as and leak_as:
                attacker_as = leak_as
        elif "\u653b\u51fb\u8005" in role:
            victim_as = _strip_as_digits(r[7]) or test_as
            attacker_as = test_as
        else:
            victim_as = _strip_as_digits(r[7]) or test_as
            attacker_as = test_as

        s = str(r[2])[:19]
        e = str(r[3])[:19]
        ds = _parse_dt(s)
        de = _parse_dt(e)
        if not ds or not de:
            continue
        if de <= ds:
            continue
        et = type_map.get(str(r[11]).strip(), None)
        if not et:
            continue

        date = ds.strftime("%Y-%m-%d")
        # Skip if any AS mentioned in v17 at this date (test_as, victim_as, attacker_as, or leak_as)
        all_asns = {test_as, victim_as, attacker_as, leak_as} - {""}
        if any((a, date) in v17_asn_dates for a in all_asns):
            print(f"  XLSX #{r[0]}: SKIP (AS+date already covered in v17/rejected)")
            continue

        eid = f"{et}_{test_as}_{date.replace('-','')}_x{r[0]}"
        if eid in seen_ids or eid in v17_ids:
            continue
        seen_ids.add(eid)

        # Trim window
        ds_t, de_t = _trim_window(ds, de, max_hours=4.0)
        dur = (de_t - ds_t).total_seconds() / 3600

        out.append({
            "event_id": eid,
            "asn": test_as,
            "start": ds_t.strftime("%Y-%m-%d %H:%M"),
            "end": de_t.strftime("%Y-%m-%d %H:%M"),
            "anomaly_type": "origin_hijack_victim" if et == "hijack" else ("route_leak" if et == "leak" else "outage"),
            "event_type": et,
            "victim_as": victim_as,
            "attacker_as": attacker_as,
            "leak_as": leak_as,
            "prefix": None,
            "name": str(r[1])[:120],
            "duration_hours": f"{dur:.2f}",
            "source": f"xlsx_seq_{r[0]}",
            "url": str(r[24] or ""),
            "notes": str(r[25] or "")[:300],
        })
    return out


def candidates_from_csv(csv_path: Path, v17_ids: set, v17_asn_dates: set) -> list[dict]:
    out: list[dict] = []
    seen_ids: set[str] = set()
    rows = list(csv.DictReader(open(csv_path, encoding="gbk")))
    for r in rows[1:]:
        eid = r["event_name"]
        if eid in v17_ids or eid in seen_ids:
            continue
        et = r["event_type"]
        if et not in ("hijack", "leak", "outage"):
            continue
        # Pick primary AS
        as_text = (
            r.get("traffic_outage_as", "")
            or r.get("outage_as", "")
            or r.get("leak_as", "")
            or r.get("hijack_as", "")
        )
        asns = re.findall(r"AS(\d+)", as_text)
        if not asns:
            continue
        primary_as = asns[0]

        ds = _parse_dt(r["start_time"])
        de = _parse_dt(r["end_time"])
        if not ds or not de:
            continue
        if de <= ds:
            continue

        # Attacker / victim
        victim_as = primary_as
        attacker_as = ""
        leak_as = ""
        if et == "hijack":
            hijack_asns = re.findall(r"AS(\d+)", r.get("hijack_as", ""))
            attacker_as = hijack_asns[0] if hijack_asns else ""
        elif et == "leak":
            leak_asns = re.findall(r"AS(\d+)", r.get("leak_as", ""))
            leak_as = leak_asns[0] if leak_asns else primary_as

        date = ds.strftime("%Y-%m-%d")
        all_asns = {primary_as, victim_as, attacker_as, leak_as} - {""}
        if any((a, date) in v17_asn_dates for a in all_asns):
            print(f"  CSV {eid}: SKIP (AS+date already covered in v17/rejected)")
            continue

        # Trim window
        ds_t, de_t = _trim_window(ds, de, max_hours=4.0)
        dur = (de_t - ds_t).total_seconds() / 3600

        # Column names from the legacy CSV are CJK; we map them to ASCII
        # via codepoint construction so no CJK literals appear in source.
        col_detail = "\u8be6\u60c5"  # event detail column name
        col_notes = "\u5907\u6ce8"   # notes column name
        col_info = "info"
        col_primitive = "primitive_prefix"
        col_hijack_prefix = "hijack_prefix"
        out.append({
            "event_id": eid,
            "asn": primary_as,
            "start": ds_t.strftime("%Y-%m-%d %H:%M"),
            "end": de_t.strftime("%Y-%m-%d %H:%M"),
            "anomaly_type": (
                "origin_hijack_victim" if et == "hijack" else
                ("route_leak" if et == "leak" else "outage")
            ),
            "event_type": et,
            "victim_as": victim_as,
            "attacker_as": attacker_as,
            "leak_as": leak_as,
            "prefix": (r.get(col_hijack_prefix, "") or r.get(col_primitive, "")).split(",")[0].strip() or None,
            "name": r.get(col_detail, "")[:120],
            "duration_hours": f"{dur:.2f}",
            "source": "csv",
            "url": (r.get(col_info, "") or "").split(";")[0].strip(),
            "notes": r.get(col_notes, "")[:300],
        })
        seen_ids.add(eid)
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--xlsx", required=True, type=Path)
    p.add_argument("--csv", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()

    v17_ids, v17_asn_dates = _load_v17_existing()
    print(f"v17 contains {len(v17_ids)} event_ids; {len(v17_asn_dates)} (asn,date) keys covered")

    candidates = []
    candidates += candidates_from_xlsx(args.xlsx, v17_ids, v17_asn_dates)
    print(f"From xlsx: {sum(1 for c in candidates if c['source'].startswith('xlsx'))} new")
    n_before = len(candidates)
    candidates += candidates_from_csv(args.csv, v17_ids, v17_asn_dates)
    print(f"From csv:  {len(candidates) - n_before} new")
    print(f"Total: {len(candidates)} new candidate events")

    # Summary by type
    from collections import Counter
    c = Counter(c["event_type"] for c in candidates)
    print(f"  by type: {dict(c)}")

    # De-dupe by (asn, date) within candidates: keep the first
    seen = set()
    deduped = []
    for c in candidates:
        k = (c["asn"], c["start"][:10])
        if k in seen:
            print(f"  DEDUP drop {c['event_id']} (same asn+date as earlier entry)")
            continue
        seen.add(k)
        deduped.append(c)
    print(f"After dedup: {len(deduped)} candidates")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as f:
        for c in deduped:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()

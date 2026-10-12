"""
Robust cache builder for new candidate events.

For each event:
  1. Computes 5-minute buckets in [start - pre_days, end + post_days]
  2. Downloads missing .gz from RIPE RIS RRC00
  3. Decodes each .gz -> decoded/*.txt using bgpdump (BEFORE parquet_cache
     touches it, so the parquet is built from text, not from raw binary)
  4. Removes any stale .parquet / .meta.json so iter_window_chunks re-builds
  5. Calls chief_agent.analyze_quick(asn, start, end)

Why this exists:
  iter_window_chunks auto-downloads .gz and lazily calls _ensure_parquet
  which tries to read the binary MRT .gz as if it were bgpdump-decoded
  text. That produces a 0-row parquet and silently breaks detection.
  This script does the decode step explicitly so the parquet is correct.
"""

from __future__ import annotations
import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("BGPT_RUN_LEAK", "1")
os.environ.setdefault("BGPT_RUN_OUTAGE", "0")

from data.updates_loader import download_data, decode_gz_to_txt
from config import RIPE_RIS_URL
from chief_agent import analyze_quick

UPDATES_ROOT = ROOT / "data" / "updates_rrc00"
DECODED_DIR = UPDATES_ROOT / "decoded"
PARQUET_DIR = UPDATES_ROOT / "parquet"


def parse_dt(s: str) -> datetime:
    s = s.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    raise ValueError(f"Cannot parse datetime: {s!r}")


def bucket_stamps(start: datetime, end: datetime) -> list[str]:
    aligned = start.replace(minute=(start.minute // 5) * 5, second=0, microsecond=0)
    out = []
    cur = aligned
    while cur <= end:
        out.append(cur.strftime("%Y%m%d.%H%M"))
        cur += timedelta(minutes=5)
    return out


def pre_stage_buckets(start: datetime, end: datetime, skip_download: bool = False) -> dict:
    UPDATES_ROOT.mkdir(parents=True, exist_ok=True)
    DECODED_DIR.mkdir(parents=True, exist_ok=True)
    PARQUET_DIR.mkdir(parents=True, exist_ok=True)

    stamps = bucket_stamps(start, end)
    downloaded = decoded = skipped_gz = skipped_decode = 0
    failed = []

    for stamp in stamps:
        gz_path = UPDATES_ROOT / f"updates.{stamp}.gz"
        txt_path = DECODED_DIR / f"updates.{stamp}.txt"
        for stale in PARQUET_DIR.glob(f"updates.{stamp}.parquet*"):
            try:
                stale.unlink()
            except OSError:
                pass

        if not gz_path.exists() or gz_path.stat().st_size < 1000:
            if skip_download:
                failed.append((stamp, "skip_download enabled"))
                continue
            ym = datetime.strptime(stamp.replace(".", ""), "%Y%m%d%H%M").strftime("%Y.%m")
            url = f"{RIPE_RIS_URL}{ym}/updates.{stamp}.gz"
            try:
                download_data(url)
                downloaded += 1
            except Exception as exc:
                failed.append((stamp, f"download: {exc}"))
                continue

        if not txt_path.exists() or txt_path.stat().st_size < 1000:
            if decode_gz_to_txt(gz_path, txt_path):
                decoded += 1
            else:
                failed.append((stamp, "decode_gz_to_txt"))
        else:
            skipped_decode += 1

    return {
        "n_buckets": len(stamps),
        "downloaded": downloaded,
        "decoded": decoded,
        "skipped_decode": skipped_decode,
        "failed": failed,
    }


def cache_for_event(asn: str, start: str, end: str,
                    skip_download: bool = False,
                    run_leak: bool = True,
                    run_outage: bool = False) -> dict:
    start_dt = parse_dt(start)
    end_dt = parse_dt(end)
    out: dict = {
        "asn": asn,
        "start": start,
        "end": end,
    }

    t0 = time.time()
    stage = pre_stage_buckets(start_dt, end_dt, skip_download=skip_download)
    out["stage_elapsed_s"] = round(time.time() - t0, 1)
    out["n_buckets"] = stage["n_buckets"]
    out["downloaded"] = stage["downloaded"]
    out["decoded"] = stage["decoded"]
    out["skipped_decode"] = stage["skipped_decode"]
    if stage["failed"]:
        out["stage_failed"] = stage["failed"][:3]

    if stage["failed"] and stage["decoded"] == 0 and stage["skipped_decode"] == 0:
        out["skipped_analyze"] = "all buckets failed to decode"
        return out

    # Per-call env override
    os.environ["BGPT_RUN_LEAK"] = "1" if run_leak else "0"
    os.environ["BGPT_RUN_OUTAGE"] = "1" if run_outage else "0"

    t1 = time.time()
    try:
        result = analyze_quick(asn, start, end, enable_mitm=False)
        out["elapsed_s"] = round(time.time() - t1, 1)
        out["success"] = bool(result.get("success", False))
        out["traffic_signal_present"] = bool(result.get("traffic_signal_present", False))
        rt = result.get("routing", {}) or {}
        if isinstance(rt, dict):
            for k in ("origin_hijacked", "origin_hijacking",
                      "forge_hijacked", "forge_hijacking", "route_leaks"):
                v = rt.get(k, [])
                if isinstance(v, list):
                    out[f"n_{k}"] = len(v)
        out["cache_path"] = result.get("cache_path")
        if result.get("warnings"):
            out["warnings"] = result["warnings"][:3]
    except Exception as e:
        out["analyze_error"] = repr(e)
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("events_jsonl", help="JSONL with {asn, start, end, event_id} per line")
    parser.add_argument("--out", help="Write results to this JSONL", default=None)
    parser.add_argument("--skip-download", action="store_true",
                        help="Use only locally-staged gz/txt; don't fetch from RIPE RIS")
    parser.add_argument("--run-leak", type=int, default=1)
    parser.add_argument("--run-outage", type=int, default=0)
    args = parser.parse_args()

    in_path = Path(args.events_jsonl)
    if not in_path.exists():
        print(f"Input not found: {in_path}", file=sys.stderr)
        sys.exit(1)
    events = []
    with in_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    print(f"Loaded {len(events)} events from {in_path}")

    out_path = Path(args.out) if args.out else in_path.with_suffix(".results.jsonl")
    with out_path.open("w") as fout:
        for ev in events:
            eid = ev.get("event_id", "?")
            print(f"\n=== {eid} AS{ev['asn']} {ev['start']} -> {ev['end']} ===", flush=True)
            res = cache_for_event(
                ev["asn"], ev["start"], ev["end"],
                skip_download=args.skip_download,
                run_leak=bool(args.run_leak),
                run_outage=bool(args.run_outage),
            )
            res["event_id"] = eid
            print(json.dumps({k: v for k, v in res.items() if k != "warnings"}, ensure_ascii=False), flush=True)
            fout.write(json.dumps(res, ensure_ascii=False) + "\n")
            fout.flush()

    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
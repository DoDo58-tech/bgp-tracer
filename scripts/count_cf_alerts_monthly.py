#!/usr/bin/env python3
"""Count Cloudflare Radar alerts per month for hijack / leak / outage.

Window: 2025-09 .. 2026-09 (13 months), configurable.

API notes (verified empirically, 2026-10-22):
  * ``dateStart`` MUST be paired with ``dateEnd`` on the BGP streams. Passing
    ``dateStart`` alone silently falls back to "most recent" data.
  * ``page`` is the working pagination parameter for the BGP streams; ``offset``
    is the working one for ``/radar/annotations``.
  * ``leaks``/``hijacks`` expose no total count, so we must page until a short
    page comes back. That is why this script is resumable and caches per
    (month, category).

Filters are intentionally NOT applied: we want the platform's own raw alert
count, i.e. what a NOC would have received. The repo's operational script
(``scripts/cloudflare_alerts/fetch_cloudflare_alerts.py``) applies
``confidenceScoreMin``/``prefixCountMin`` because it wants *actionable*
candidates; that is a different question and is not used here.

Outage = ``/radar/annotations`` rows with ``eventType == OUTAGE``.

Usage:
    python3 scripts/count_cf_alerts_monthly.py
    python3 scripts/count_cf_alerts_monthly.py --start 2025-09 --end 2026-09
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("ERROR: requests is required (pip install requests)", file=sys.stderr)
    sys.exit(1)

API = "https://api.cloudflare.com/client/v4"
RADAR = f"{API}/radar"
LEAKS_URL = f"{RADAR}/bgp/leaks/events"
HIJACKS_URL = f"{RADAR}/bgp/hijacks/events"
ANNOTATIONS_URL = f"{RADAR}/annotations"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = PROJECT_ROOT / "results" / "cf_alert_monthly"
OUT_CSV = PROJECT_ROOT / "results" / "cf_alert_monthly" / "monthly_counts.csv"

PAGE_SIZE = 50
REQUEST_TIMEOUT = 40
MAX_RETRIES = 6
# Cloudflare Radar rate limit: 1200 requests / 5 min per token.
MIN_INTERVAL_S = 0.30


# ── auth ────────────────────────────────────────────────────────────────
def load_token() -> str:
    for cand in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY"):
        v = os.environ.get(cand, "").strip()
        if v:
            return v
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith(("CLOUDFLARE_API_TOKEN=", "CLOUDFLARE_API_KEY=")):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("ERROR: no Cloudflare API token found (env or .env)")


# ── http ────────────────────────────────────────────────────────────────
class Fetcher:
    def __init__(self, token: str) -> None:
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "User-Agent": "bgp-tracer/alert-monthly",
        })
        self._last = 0.0

    def get(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        for attempt in range(MAX_RETRIES):
            gap = time.monotonic() - self._last
            if gap < MIN_INTERVAL_S:
                time.sleep(MIN_INTERVAL_S - gap)
            self._last = time.monotonic()
            try:
                r = self.s.get(url, params=params, timeout=REQUEST_TIMEOUT)
            except requests.RequestException as e:
                wait = min(2 ** attempt, 30)
                print(f"    [retry {attempt+1}] {e}; sleep {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            if r.status_code == 429:
                wait = min(2 ** attempt, 60)
                print(f"    [429] sleep {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            if r.status_code >= 500:
                wait = min(2 ** attempt, 30)
                print(f"    [{r.status_code}] sleep {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            if not r.ok:
                raise RuntimeError(f"GET {url} → HTTP {r.status_code}: {r.text[:300]}")
            return r.json()
        raise RuntimeError(f"GET {url}: exhausted retries")

    def get_safe(self, url: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            return self.get(url, params)
        except Exception as e:  # noqa: BLE001
            print(f"    [ERROR] {e}", file=sys.stderr)
            return None


# ── month helpers ───────────────────────────────────────────────────────
def month_range(start: str, end: str) -> List[Tuple[str, str, str]]:
    """[(YYYY-MM, start_iso, end_iso)] inclusive of both end months."""
    sy, sm = int(start[:4]), int(start[5:7])
    ey, em = int(end[:4]), int(end[5:7])
    out = []
    y, m = sy, sm
    while (y, m) <= (ey, em):
        ny, nm = (y + 1, 1) if m == 12 else (y, m + 1)
        s = datetime(y, m, 1, tzinfo=timezone.utc)
        e = datetime(ny, nm, 1, tzinfo=timezone.utc) - timedelta(seconds=1)
        out.append((f"{y:04d}-{m:02d}",
                    s.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    e.strftime("%Y-%m-%dT%H:%M:%SZ")))
        y, m = ny, nm
    return out


# ── counting per category ───────────────────────────────────────────────
def count_bgp_stream(f: Fetcher, url: str, month: str, s_iso: str, e_iso: str,
                      cache_path: Path) -> Tuple[int, str]:
    """Page through a BGP event stream for one month. Returns (count, note)."""
    if cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text())
            return int(cached["count"]), "cached"
        except Exception:  # noqa: BLE001
            pass

    ids: set = set()
    page = 1
    note = ""
    while True:
        data = f.get_safe(url, {
            "format": "json", "limit": PAGE_SIZE, "page": page,
            "dateStart": s_iso, "dateEnd": e_iso,
        })
        if data is None:
            note = "ERROR: stream fetch failed"
            break
        res = data.get("result") or {}
        events = res.get("events") or []
        if not events:
            break
        for ev in events:
            ids.add(ev.get("id"))
        if page % 20 == 0:
            print(f"    page={page} unique={len(ids)}", file=sys.stderr)
        if len(events) < PAGE_SIZE:
            break
        page += 1
        if page > 4000:  # safety valve
            note = "TRUNCATED: hit page cap"
            break

    count = len(ids)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(
        {"month": month, "count": count, "note": note, "pages": page},
        indent=2))
    return count, note


def count_outages(f: Fetcher, month: str, s_iso: str, e_iso: str,
                  cache_path: Path) -> Tuple[int, str]:
    """Annotations with eventType == OUTAGE, via the working `offset` pager."""
    if cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text())
            return int(cached["count"]), "cached"
        except Exception:  # noqa: BLE001
            pass

    ids: set = set()
    offset = 0
    note = ""
    while True:
        data = f.get_safe(ANNOTATIONS_URL, {
            "format": "json", "limit": PAGE_SIZE, "offset": offset,
            "dateStart": s_iso, "dateEnd": e_iso,
        })
        if data is None:
            note = "ERROR: annotations fetch failed"
            break
        res = data.get("result") or {}
        batch = res.get("annotations") or []
        if not batch:
            break
        n_out = 0
        for ann in batch:
            if (ann.get("eventType") or "").upper() == "OUTAGE":
                ids.add(ann.get("id"))
                n_out += 1
        if offset % 1000 == 0:
            print(f"    offset={offset} outages={len(ids)} (batch_outage={n_out})",
                  file=sys.stderr)
        if len(batch) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
        if offset > 20000:
            note = "TRUNCATED: hit offset cap"
            break

    count = len(ids)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(
        {"month": month, "count": count, "note": note, "offset": offset},
        indent=2))
    return count, note


# ── main ────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="2025-09")
    ap.add_argument("--end", default="2026-09")
    ap.add_argument("--out", default=str(OUT_CSV))
    args = ap.parse_args()

    token = load_token()
    f = Fetcher(token)
    months = month_range(args.start, args.end)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    rows = []
    totals = {"hijack": 0, "leak": 0, "outage": 0}
    for month, s_iso, e_iso in months:
        print(f"[{month}] {s_iso} .. {e_iso}", flush=True)

        hj, hj_note = count_bgp_stream(
            f, HIJACKS_URL, month, s_iso, e_iso, CACHE_DIR / f"hijack_{month}.json")
        print(f"  hijack = {hj} ({hj_note})", flush=True)

        lk, lk_note = count_bgp_stream(
            f, LEAKS_URL, month, s_iso, e_iso, CACHE_DIR / f"leak_{month}.json")
        print(f"  leak   = {lk} ({lk_note})", flush=True)

        og, og_note = count_outages(
            f, month, s_iso, e_iso, CACHE_DIR / f"outage_{month}.json")
        print(f"  outage = {og} ({og_note})", flush=True)

        totals["hijack"] += hj
        totals["leak"] += lk
        totals["outage"] += og
        rows.append({"month": month, "hijack": hj, "leak": lk, "outage": og,
                     "total": hj + lk + og})

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["month", "hijack", "leak", "outage", "total"])
        w.writeheader()
        w.writerows(rows)
        w.writerow({"month": "TOTAL", **totals,
                     "total": totals["hijack"] + totals["leak"] + totals["outage"]})

    grand = totals["hijack"] + totals["leak"] + totals["outage"]
    print("\n===== Cloudflare Radar alert counts =====")
    print(f"window: {args.start} .. {args.end}")
    for r in rows:
        print(f"  {r['month']}  hijack={r['hijack']:>7}  leak={r['leak']:>7}  "
              f"outage={r['outage']:>5}  total={r['total']:>7}")
    print(f"  {'TOTAL':<7} hijack={totals['hijack']:>7}  leak={totals['leak']:>7}  "
          f"outage={totals['outage']:>5}  total={grand:>7}")
    print(f"\nCSV: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

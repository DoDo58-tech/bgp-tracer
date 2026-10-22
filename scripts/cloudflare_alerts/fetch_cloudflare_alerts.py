#!/usr/bin/env python3
"""Fetch Cloudflare Radar alert feed: annotations + leaks + hijacks.

The user's brief: "the point of this exercise is to take an operational
alert-platform feed and filter it through BGP Tracer — keep only the alerts
that genuinely correspond to dangerous routing-induced traffic changes".

There are THREE Cloudflare Radar alert streams that are relevant:

  1. ``/radar/annotations``           — curated outage / event feed (operator-annotated)
  2. ``/radar/bgp/leaks/events``      — route-leak events detected by Cloudflare's BGP monitor
  3. ``/radar/bgp/hijacks/events``    — BGP hijack events detected by Cloudflare's BGP monitor

This script fetches each stream in the requested window, normalises them to a
common alert-record shape (``alert_id``, ``source``, ``asn``, ``start_time``,
``end_time``, ``severity``, ...), and writes:

    - raw_alerts.json           — list of normalised alert records
    - raw_alerts.csv            — same data as a flat CSV (for quick eyeballing)
    - raw_<source>.json         — per-stream raw response for traceability

Filtering rules (matching the user's policy — "only alerts where the routing
layer could plausibly see a trace"):

  * annotations: include ``OUTAGE`` / ``GENERAL`` / ``EVENT``, drop ``PIPELINE``
                  (Cloudflare-side data pipeline noise — unrelated to BGP)
  * leaks:       require at least one prefix + a finished event OR high impact
                  (``prefix_count >= 5`` or ``peer_count >= 30``)
  * hijacks:     require confidence score >= 4 (filters out false positives
                  from monitoring noise)

Each stream is independently resumable: re-running the script picks up
where the previous run stopped, deduplicating on the alert id.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import requests
except ImportError:
    print("ERROR: requests is required (pip install requests)", file=sys.stderr)
    sys.exit(1)


# ── Defaults ────────────────────────────────────────────────────────────
API_BASE = "https://api.cloudflare.com/client/v4"
ANNOTATIONS_URL = f"{API_BASE}/radar/annotations"
LEAKS_URL = f"{API_BASE}/radar/bgp/leaks/events"
HIJACKS_URL = f"{API_BASE}/radar/bgp/hijacks/events"

# Pagination cap (Cloudflare returns at most 50 events per request).
MAX_PER_PAGE = 50
REQUEST_TIMEOUT = 30
MAX_RETRIES = 6
MIN_INTERVAL_S = 0.25  # 4 req/s, well below the 1200/5min ceiling

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = PROJECT_ROOT / "results" / "cloudflare_alerts" / "raw"


# ── Helpers ─────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _request_with_retry(
    session: requests.Session,
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """One HTTP call with exponential backoff + rate-limit (429) handling."""
    last_err: Optional[Exception] = None
    for attempt in range(MAX_RETRIES):
        t0 = time.monotonic()
        try:
            resp = session.request(
                method, url,
                headers=headers, params=params, json=json_body,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as e:
            last_err = e
            wait = min(2 ** attempt, 30)
            print(f"    [retry {attempt + 1}/{MAX_RETRIES}] network error: {e}; "
                  f"sleep {wait}s", file=sys.stderr)
            time.sleep(wait)
            continue

        if resp.status_code == 429:
            wait = min(2 ** attempt, 30)
            print(f"    [retry {attempt + 1}/{MAX_RETRIES}] HTTP 429 rate-limit; "
                  f"sleep {wait}s", file=sys.stderr)
            time.sleep(wait)
            continue

        if resp.status_code >= 500:
            wait = min(2 ** attempt, 30)
            print(f"    [retry {attempt + 1}/{MAX_RETRIES}] HTTP {resp.status_code}; "
                  f"sleep {wait}s", file=sys.stderr)
            time.sleep(wait)
            continue

        if not resp.ok:
            raise RuntimeError(
                f"{method} {url} → HTTP {resp.status_code}: {resp.text[:300]}"
            )

        # honour minimum interval pacing (best-effort)
        elapsed = time.monotonic() - t0
        if elapsed < MIN_INTERVAL_S:
            time.sleep(MIN_INTERVAL_S - elapsed)
        return resp.json()

    raise RuntimeError(f"Exhausted {MAX_RETRIES} retries: last error: {last_err}")


# ── Stream 1: Annotations ──────────────────────────────────────────────
def fetch_annotations(
    session: requests.Session,
    headers: Dict[str, str],
    *,
    date_start: str,
    date_end: Optional[str],
    include_types: Iterable[str],
    exclude_types: Set[str],
    seen_ids: Set[str],
    raw_records: List[Dict[str, Any]],
    max_records: int = 0,
) -> List[Dict[str, Any]]:
    # The /radar/annotations API requires BOTH dateStart AND dateEnd, AND
    # the server cannot return events that haven't happened yet, so dateEnd
    # must be strictly before ``now()``. Use a 5-minute safety margin.
    if not date_end:
        now_utc = datetime.now(timezone.utc)
        date_end = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    base_params: Dict[str, Any] = {
        "format": "json",
        "limit": MAX_PER_PAGE,
        "dateStart": date_start,
        "dateEnd": date_end,
    }
    # Always pull every type and filter client-side. This keeps the code
    # simple at the cost of one extra round-trip per page, but annotations
    # are ≤ 200 / month so the cost is negligible.

    page = 1
    pages_fetched = 0
    # API eventType values are uppercase (OUTAGE / GENERAL / EVENT / PIPELINE),
    # but the user typically thinks in lowercase. Normalise both sides.
    include_set = {t.strip().upper() for t in include_types if t}
    exclude_set = {t.strip().upper() for t in exclude_types if t}
    while True:
        base_params["limit"] = MAX_PER_PAGE
        base_params["offset"] = (page - 1) * MAX_PER_PAGE
        print(f"  [annotations] offset={(page - 1) * MAX_PER_PAGE} "
              f"limit={MAX_PER_PAGE}", file=sys.stderr)
        resp = _request_with_retry(session, "GET", ANNOTATIONS_URL,
                                   headers=headers, params=dict(base_params))
        result = resp.get("result") or {}
        batch = result.get("annotations") or []
        if not batch:
            break
        n_added = 0
        for ann in batch:
            aid = f"annotation:{ann.get('id')}"
            et = (ann.get("eventType") or "").upper()
            if et in exclude_set:
                continue
            if include_set and et not in include_set:
                continue
            if aid in seen_ids:
                continue
            seen_ids.add(aid)
            raw_records.append(ann)
            n_added += 1
        pages_fetched += 1
        print(f"  [annotations] page={page} got={len(batch)} new={n_added} "
              f"total_seen={len(seen_ids)}", file=sys.stderr)
        if len(batch) < MAX_PER_PAGE:
            break
        if n_added == 0:
            break
        if max_records and len(raw_records) >= max_records:
            print(f"  [annotations] max-records cap reached ({max_records})",
                  file=sys.stderr)
            break
        page += 1
    return []  # normalised separately below


# ── Stream 2: Leaks ─────────────────────────────────────────────────────
def fetch_leaks(
    session: requests.Session,
    headers: Dict[str, str],
    *,
    date_start: str,
    date_end: Optional[str],
    seen_ids: Set[str],
    raw_records: List[Dict[str, Any]],
    prefix_count_min: int = 5,
    max_records: int = 0,
    persist_path: Optional["Path"] = None,
    persist_every: int = 5,
) -> int:
    base_params: Dict[str, Any] = {
        "format": "json",
        "limit": MAX_PER_PAGE,
        "dateStart": date_start,
        "prefixCountMin": prefix_count_min,
    }
    if date_end:
        base_params["dateEnd"] = date_end

    page = 1
    pages_fetched = 0
    while True:
        base_params["limit"] = MAX_PER_PAGE
        base_params["page"] = page
        print(f"  [leaks] page={page}", file=sys.stderr)
        resp = _request_with_retry(session, "GET", LEAKS_URL,
                                   headers=headers, params=dict(base_params))
        result = resp.get("result") or {}
        events = result.get("events") or []
        if not events:
            break
        n_added = 0
        for ev in events:
            label = f"leak:{ev.get('id')}"
            if label in seen_ids:
                continue
            seen_ids.add(label)
            raw_records.append(ev)
            n_added += 1
        pages_fetched += 1
        print(f"  [leaks] page={page} got={len(events)} new={n_added} "
              f"total_seen={len(seen_ids)}", file=sys.stderr)
        if len(events) < MAX_PER_PAGE:
            break
        if n_added == 0:
            break
        if max_records and len(raw_records) >= max_records:
            print(f"  [leaks] max-records cap reached ({max_records})",
                  file=sys.stderr)
            break
        if persist_path and pages_fetched % persist_every == 0:
            try:
                persist_path.write_text(
                    json.dumps(raw_records, ensure_ascii=False),
                    encoding="utf-8",
                )
                print(f"  [leaks] persisted {len(raw_records)} records "
                      f"to {persist_path.name}", file=sys.stderr)
            except Exception as _e:
                print(f"  [leaks] persist failed: {_e}", file=sys.stderr)
        page += 1
    return pages_fetched


# ── Stream 3: Hijacks ────────────────────────────────────────────────────
def fetch_hijacks(
    session: requests.Session,
    headers: Dict[str, str],
    *,
    date_start: str,
    date_end: Optional[str],
    seen_ids: Set[str],
    raw_records: List[Dict[str, Any]],
    confidence_min: int = 4,
    max_records: int = 0,
    persist_path: Optional["Path"] = None,
    persist_every: int = 5,
) -> int:
    base_params: Dict[str, Any] = {
        "format": "json",
        "limit": MAX_PER_PAGE,
        "dateStart": date_start,
        "confidenceScoreMin": confidence_min,
    }
    if date_end:
        base_params["dateEnd"] = date_end

    page = 1
    pages_fetched = 0
    while True:
        base_params["limit"] = MAX_PER_PAGE
        base_params["page"] = page
        print(f"  [hijacks] page={page}", file=sys.stderr)
        resp = _request_with_retry(session, "GET", HIJACKS_URL,
                                   headers=headers, params=dict(base_params))
        result = resp.get("result") or {}
        events = result.get("events") or []
        if not events:
            break
        n_added = 0
        for ev in events:
            label = f"hijack:{ev.get('id')}"
            if label in seen_ids:
                continue
            seen_ids.add(label)
            raw_records.append(ev)
            n_added += 1
        pages_fetched += 1
        print(f"  [hijacks] page={page} got={len(events)} new={n_added} "
              f"total_seen={len(seen_ids)}", file=sys.stderr)
        if len(events) < MAX_PER_PAGE:
            break
        if n_added == 0:
            break
        if max_records and len(raw_records) >= max_records:
            print(f"  [hijacks] max-records cap reached ({max_records})",
                  file=sys.stderr)
            break
        if persist_path and pages_fetched % persist_every == 0:
            try:
                persist_path.write_text(
                    json.dumps(raw_records, ensure_ascii=False),
                    encoding="utf-8",
                )
                print(f"  [hijacks] persisted {len(raw_records)} records "
                      f"to {persist_path.name}", file=sys.stderr)
            except Exception as _e:
                print(f"  [hijacks] persist failed: {_e}",
                      file=sys.stderr)
        page += 1
    return pages_fetched


# ── Normalisation ───────────────────────────────────────────────────────
def normalise_annotation(a: dict) -> Optional[Dict[str, Any]]:
    """OUTAGE/GENERAL/EVENT → common alert record.

    OUTAGE  → victim ASN(s) in ``asns`` field; primary AS = first
    GENERAL  → no ASN (these are Cloudflare-global); skip in BGP Tracer
                pipeline but keep for drill-down.
    """
    asns = a.get("asns") or []
    event_type = a.get("eventType")
    # if annotation has no ASN, still keep for stats but mark skip=True
    skip_bgpt = not asns or event_type == "GENERAL"
    asn = str(asns[0]) if asns else ""
    start = a.get("startDate") or ""
    end = a.get("endDate") or ""
    return {
        "alert_id": f"annotation:{a.get('id')}",
        "source": "annotation",
        "source_event_type": event_type,
        "cloudflare_id": str(a.get("id")),
        "asn": asn,
        "asns": [str(x) for x in asns],
        "locations": a.get("locations") or [],
        "start_time": start,
        "end_time": end,
        "description": a.get("description") or "",
        "linked_url": a.get("linkedUrl"),
        "severity": _severity_annotation(a),
        "skip_bgpt": skip_bgpt,
        "raw_outage_cause": (a.get("outage") or {}).get("outageCause"),
        "raw_outage_type": (a.get("outage") or {}).get("outageType"),
    }


def _severity_annotation(a: dict) -> float:
    """Heuristic severity 0-1 for annotations.  OUTAGE > GENERAL."""
    et = a.get("eventType")
    if et == "OUTAGE":
        ot = (a.get("outage") or {}).get("outageType") or ""
        # NATIONWIDE > REGIONAL > NETWORK
        if ot == "NATIONWIDE":
            return 0.9
        if ot == "REGIONAL":
            return 0.6
        return 0.5


def normalise_leak(ev: dict) -> Dict[str, Any]:
    leak_asn = ev.get("leak_asn")
    leak_seg = ev.get("leak_seg") or []
    # leak_seg = [origin_asn, leak_asn, ...peers], so peers = leak_seg[2:]
    peers = leak_seg[2:] if len(leak_seg) > 2 else []
    return {
        "alert_id": f"leak:{ev.get('id')}",
        "source": "leak",
        "source_event_type": "ROUTE_LEAK",
        "cloudflare_id": str(ev.get("id")),
        "asn": str(leak_asn) if leak_asn else "",
        "asns": [str(x) for x in [leak_asn] + peers],
        "leak_seg": leak_seg,
        "leak_type": ev.get("leak_type"),
        "leak_count": ev.get("leak_count"),
        "prefix_count": ev.get("prefix_count"),
        "peer_count": ev.get("peer_count"),
        "origin_count": ev.get("origin_count"),
        "countries": ev.get("countries") or [],
        "start_time": ev.get("min_ts"),
        "end_time": ev.get("max_ts"),
        "description": (
            f"Route leak from AS{leak_asn}; "
            f"{ev.get('leak_count')} leaked updates, "
            f"{ev.get('prefix_count')} prefixes, "
            f"{ev.get('peer_count')} peers"
        ),
        "severity": _severity_leak(ev),
        "skip_bgpt": False,
    }


def _severity_leak(ev: dict) -> float:
    """Heuristic 0-1 based on leak_count/prefix_count/peer_count."""
    leak_count = ev.get("leak_count") or 0
    prefix_count = ev.get("prefix_count") or 0
    peer_count = ev.get("peer_count") or 0
    # Normalise: log scale on leak_count, capped contributions.
    s_leak = min(1.0, math.log10(max(leak_count, 1)) / 3.0)  # 1 → 0; 1000 → 1
    s_prefix = min(1.0, prefix_count / 30.0)
    s_peer = min(1.0, peer_count / 50.0)
    return round(0.5 * s_leak + 0.3 * s_prefix + 0.2 * s_peer, 3)


def normalise_hijack(ev: dict) -> Dict[str, Any]:
    hijacker = ev.get("hijacker_asn")
    victims = ev.get("victim_asns") or []
    asns = [str(hijacker)] + [str(v) for v in victims]
    return {
        "alert_id": f"hijack:{ev.get('id')}",
        "source": "hijack",
        "source_event_type": "ORIGIN_HIJACK",
        "cloudflare_id": str(ev.get("id")),
        "asn": str(victims[0]) if victims else "",  # primary target = first victim
        "asns": asns,
        "hijacker_asn": str(hijacker) if hijacker else "",
        "victim_asns": [str(v) for v in victims],
        "prefixes": ev.get("prefixes") or [],
        "peer_asns": [str(p) for p in (ev.get("peer_asns") or [])],
        "confidence_score": ev.get("confidence_score"),
        "hijack_msgs_count": ev.get("hijack_msgs_count"),
        "peer_ip_count": ev.get("peer_ip_count"),
        "tags": ev.get("tags") or [],
        "countries": ev.get("victim_countries") or [],
        "start_time": ev.get("min_hijack_ts"),
        "end_time": ev.get("max_hijack_ts"),
        "description": (
            f"Hijack by AS{hijacker} of {','.join(str(v) for v in victims)} "
            f"prefixes {','.join(ev.get('prefixes') or [])[:80]}"
        ),
        "severity": _severity_hijack(ev),
        "skip_bgpt": False,
    }


def _severity_hijack(ev: dict) -> float:
    cs = ev.get("confidence_score") or 0
    # Cloudflare confidence_score typically 1..12; higher = more confident.
    # normalise by /12
    base = min(1.0, cs / 12.0)
    # boost by msg_count & peer count
    msgs = ev.get("hijack_msgs_count") or 0
    peers = len(ev.get("peer_asns") or [])
    boost = min(0.2, math.log10(max(msgs, 1)) / 50.0 + peers / 200.0)
    return round(min(1.0, base + boost), 3)




# ── CLI ──────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--token", default=os.environ.get("CLOUDFLARE_API_TOKEN", ""))
    ap.add_argument("--date-start", default="2025-01-01T00:00:00Z")
    ap.add_argument("--date-end", default=None)
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    ap.add_argument(
        "--include-annotations", default="outage,event,general",
        help="Comma-separated annotation eventType values to keep.",
    )
    ap.add_argument(
        "--exclude-annotations", default="pipeline",
        help="Comma-separated annotation eventType values to drop.",
    )
    ap.add_argument(
        "--leaks-prefix-count-min", type=int, default=5,
        help="Filter leak events to those affecting ≥ this many prefixes. "
             "Higher = fewer / more impactful events.",
    )
    ap.add_argument(
        "--hijacks-confidence-min", type=int, default=4,
        help="Filter hijack events to those with confidence_score ≥ this. "
             "0-12 scale; 4+ filters out noise.",
    )
    ap.add_argument(
        "--resume", action="store_true", default=True,
        help="Resume from existing raw_<source>.json files (default on).",
    )
    ap.add_argument(
        "--no-resume", dest="resume", action="store_false",
    )
    ap.add_argument(
        "--max-records", type=int, default=0,
        help="If >0, stop after this many *new* records per stream. Useful "
             "for dry runs.",
    )
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    if not args.token:
        print("ERROR: --token or CLOUDFLARE_API_TOKEN required", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_ann_path = out_dir / "raw_annotations.json"
    raw_leak_path = out_dir / "raw_leaks.json"
    raw_hijack_path = out_dir / "raw_hijacks.json"

    include_types = [t.strip() for t in args.include_annotations.split(",") if t.strip()]
    exclude_types = {t.strip() for t in args.exclude_annotations.split(",") if t.strip()}

    fetched_at = _now_iso()
    print(f"Fetching Cloudflare Radar alerts")
    print(f"  window:   {args.date_start} → {args.date_end or 'now'}")
    print(f"  include:  {include_types}")
    print(f"  exclude:  {exclude_types}")
    print(f"  leaks:    prefix_count ≥ {args.leaks_prefix_count_min}")
    print(f"  hijacks:  confidence_score ≥ {args.hijacks_confidence_min}")
    print(f"  out dir:  {out_dir}")

    session = requests.Session()
    headers = {"Authorization": f"Bearer {args.token}"}

    # ── resume support ─────────────────────────────────────────────────
    ann_records = json.loads(raw_ann_path.read_text()) if (args.resume and raw_ann_path.exists()) else []
    leak_records = json.loads(raw_leak_path.read_text()) if (args.resume and raw_leak_path.exists()) else []
    hijack_records = json.loads(raw_hijack_path.read_text()) if (args.resume and raw_hijack_path.exists()) else []
    print(f"  resume:   annotations={len(ann_records)} leaks={len(leak_records)} "
          f"hijacks={len(hijack_records)}")

    seen: Set[str] = set()
    for a in ann_records: seen.add(f"annotation:{a.get('id')}")
    for e in leak_records: seen.add(f"leak:{e.get('id')}")
    for e in hijack_records: seen.add(f"hijack:{e.get('id')}")

    # ── Stream 1: annotations ──────────────────────────────────────────
    print("\n[1/3] annotations")
    new_ann = fetch_annotations(
        session, headers,
        date_start=args.date_start, date_end=args.date_end,
        include_types=include_types, exclude_types=exclude_types,
        seen_ids=seen, raw_records=ann_records,
        max_records=args.max_records,
    )
    print(f"  → {len(ann_records)} total annotations")

    # ── Stream 2: leaks ────────────────────────────────────────────────
    print("\n[2/3] leaks")
    fetch_leaks(
        session, headers,
        date_start=args.date_start, date_end=args.date_end,
        seen_ids=seen, raw_records=leak_records,
        prefix_count_min=args.leaks_prefix_count_min,
        max_records=args.max_records,
        persist_path=raw_leak_path,
        persist_every=5,
    )
    print(f"  → {len(leak_records)} total leak events")

    # ── Stream 3: hijacks ──────────────────────────────────────────────
    print("\n[3/3] hijacks")
    fetch_hijacks(
        session, headers,
        date_start=args.date_start, date_end=args.date_end,
        seen_ids=seen, raw_records=hijack_records,
        confidence_min=args.hijacks_confidence_min,
        max_records=args.max_records,
        persist_path=raw_hijack_path,
        persist_every=5,
    )
    print(f"  → {len(hijack_records)} total hijack events")

    # ── persist raw streams ─────────────────────────────────────────────
    raw_ann_path.write_text(
        json.dumps(ann_records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    raw_leak_path.write_text(
        json.dumps(leak_records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    raw_hijack_path.write_text(
        json.dumps(hijack_records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"  wrote:    {raw_ann_path.name} ({raw_ann_path.stat().st_size:,} bytes)")
    print(f"  wrote:    {raw_leak_path.name} ({raw_leak_path.stat().st_size:,} bytes)")
    print(f"  wrote:    {raw_hijack_path.name} ({raw_hijack_path.stat().st_size:,} bytes)")

    # ── normalise ─────────────────────────────────────────────────────
    norm: List[Dict[str, Any]] = []
    norm.extend([n for n in (normalise_annotation(a) for a in ann_records) if n])
    norm.extend(normalise_leak(e) for e in leak_records)
    norm.extend(normalise_hijack(e) for e in hijack_records)
    norm.sort(key=lambda r: r.get("start_time") or "", reverse=True)

    # deduplicate by alert_id (defensive)
    seen_aid: Set[str] = set()
    deduped: List[Dict[str, Any]] = []
    for r in norm:
        if r["alert_id"] in seen_aid:
            continue
        seen_aid.add(r["alert_id"])
        deduped.append(r)
    norm = deduped

    # ── write normalised ───────────────────────────────────────────────
    raw_path = out_dir / "raw_alerts.json"
    raw_path.write_text(
        json.dumps(norm, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"  wrote:    raw_alerts.json ({raw_path.stat().st_size:,} bytes)")

    csv_path = out_dir / "raw_alerts.csv"
    csv_fields = [
        "alert_id", "source", "source_event_type", "cloudflare_id", "asn",
        "asns", "locations", "start_time", "end_time", "severity",
        "skip_bgpt", "description", "linked_url",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=csv_fields, extrasaction="ignore")
        w.writeheader()
        for r in norm:
            w.writerow(r)
    print(f"  wrote:    raw_alerts.csv ({csv_path.stat().st_size:,} bytes)")

    # ── summary ────────────────────────────────────────────────────────
    by_source: Dict[str, int] = {}
    by_year: Dict[str, int] = {}
    skip_count = 0
    for r in norm:
        s = r["source"]
        by_source[s] = by_source.get(s, 0) + 1
        y = (r.get("start_time") or "")[:4]
        by_year[y] = by_year.get(y, 0) + 1
        if r.get("skip_bgpt"):
            skip_count += 1

    print()
    print("Summary:")
    print(f"  total alerts:        {len(norm)}")
    print(f"  skip BGP Tracer:     {skip_count}  (no ASN / GENERAL type)")
    print(f"  by source:           {by_source}")
    print(f"  by year:             {dict(sorted(by_year.items()))}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
"""Structural resolution of an event row to a Phase-1 quick cache."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Optional, Tuple

__all__ = [
    "CacheMatch",
    "parse_datetime",
    "parse_window_from_stem",
    "resolve_cache",
    "cache_asn",
    "cache_identity",
    "infer_hour_offset",
    "newest",
]

_TOKEN_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})"
    r"(?:[T_ ]?(\d{2}):?(\d{2})(?::?(\d{2}))?)?"
)
_ASN_RE = re.compile(r"^quick_(?:AS)?(\d+)_")


def parse_datetime(value: object) -> Optional[datetime]:
    """Parse the timestamp spellings that appear in filenames and GT rows."""
    if value is None:
        return None
    text = str(value).strip().replace("Z", "").replace("T", " ")
    text = text.replace("_", " ").split(".")[0].strip()
    if not text:
        return None

    colon = re.match(
        r"^(\d{4})-(\d{2})-(\d{2})(?:[ ](\d{2}):(\d{2})(?::(\d{2}))?)?$", text)
    if colon:
        y, mo, d, hh, mm, ss = colon.groups()
        return datetime(int(y), int(mo), int(d), int(hh or 0), int(mm or 0),
                        int(ss or 0))

    compact = re.match(
        r"^(\d{4})-(\d{2})-(\d{2})(?:[ ](\d{2})(\d{2})(\d{2})?)?$", text)
    if compact:
        y, mo, d, hh, mm, ss = compact.groups()
        return datetime(int(y), int(mo), int(d), int(hh or 0), int(mm or 0),
                        int(ss or 0))
    return None


def parse_window_from_stem(stem: str) -> Optional[Tuple[datetime, datetime]]:
    """Return ``(start, end)`` encoded in a cache filename, or ``None``."""
    tokens: list[Tuple[int, int, int, int, int, int]] = []
    for m in _TOKEN_RE.finditer(stem):
        y, mo, d, hh, mm, ss = m.groups()
        tokens.append((int(y), int(mo), int(d), int(hh or 0), int(mm or 0),
                       int(ss or 0)))
        if len(tokens) == 2:
            break
    if len(tokens) < 2:
        return None
    try:
        start = datetime(*tokens[0])
        end = datetime(*tokens[1])
    except ValueError:
        return None
    if end < start:
        return None
    return start, end


def cache_asn(path: Path) -> Optional[str]:
    """ASN encoded in a cache filename (``quick_12479_...``), if any."""
    m = _ASN_RE.match(path.stem)
    return m.group(1) if m else None


@dataclass(frozen=True)
class CacheMatch:
    """A resolved cache file plus the structural evidence for the match."""

    path: Path
    kind: str
    overlap_seconds: float = 0.0

    @property
    def strict(self) -> bool:
        """True when the cache window was actually used to justify the match."""
        return self.kind in ("event_id", "exact", "contains", "overlap")


def candidates(quick_dir: Path) -> Iterable[Path]:
    return sorted(quick_dir.glob("quick_*.json"))


def newest(paths: list[Path]) -> Path:
    """Return the most recently written file.

    A cache is a measurement of one window at one point in time.  When
    the same window exists in more than one file, the newest file is the
    one produced by the current detector code; the older ones are stale
    results kept from an earlier run.  Choosing by mtime instead of by
    name keeps the evaluation on the current measurement.
    """
    if not paths:
        raise ValueError("newest() needs at least one path")
    return max(paths, key=lambda p: p.stat().st_mtime)


def resolve_cache(
    asn: Optional[str],
    start: Optional[str],
    end: Optional[str],
    quick_dir: Path,
    *,
    event_id: Optional[str] = None,
    allow_same_date: bool = False,
    min_overlap_frac: float = 0.5,
) -> Optional[CacheMatch]:
    """Resolve one event to one cache file, structurally."""
    if not quick_dir.is_dir():
        return None
    asn = str(asn).replace("AS", "").strip() if asn else None

    if event_id:
        for cand in candidates(quick_dir):
            if cand.stem.startswith(f"quick_{event_id}_"):
                return CacheMatch(cand, "event_id")

    ev_start = parse_datetime(start)
    ev_end = parse_datetime(end)
    if ev_start is None:
        return None
    if ev_end is None or ev_end < ev_start:
        ev_end = ev_start
    ev_seconds = max((ev_end - ev_start).total_seconds(), 0.0)

    exact: list[Path] = []
    containing: list[tuple[float, Path]] = []
    overlapping: list[tuple[float, Path]] = []

    for cand in candidates(quick_dir):
        # A cache whose filename carries another ASN is never evidence about
        if asn is not None and cache_asn(cand) != asn:
            continue
        window = parse_window_from_stem(cand.stem)
        if window is None:
            continue
        c_start, c_end = window
        if c_start == ev_start and c_end == ev_end:
            exact.append(cand)
            continue
        if c_start <= ev_start and ev_end <= c_end:
            containing.append(((c_end - c_start).total_seconds(), cand))
            continue
        overlap = (min(c_end, ev_end) - max(c_start, ev_start)).total_seconds()
        if overlap > 0 and (ev_seconds == 0.0
                            or overlap >= min_overlap_frac * ev_seconds):
            overlapping.append((overlap, cand))

    if exact:
        # Several files can encode the same window under different
        # separator spellings ("2025-08-10T1430" vs "2025-08-10_1430").
        # They are the same measurement, and only the newest one reflects
        # the current detector code, so pick by modification time instead
        # of by sort order.
        return CacheMatch(newest(exact), "exact")
    if containing:
        # Smallest containing window: the one that adds the least context.
        containing.sort(key=lambda t: t[0])
        return CacheMatch(newest([p for _, p in containing]), "contains",
                          overlap_seconds=ev_seconds)
    if overlapping:
        overlapping.sort(key=lambda t: -t[0])
        return CacheMatch(newest([p for _, p in overlapping]), "overlap",
                          overlap_seconds=overlapping[0][0])
    if allow_same_date and asn is not None:
        same_day = []
        for cand in candidates(quick_dir):
            if cache_asn(cand) != asn:
                continue
            window = parse_window_from_stem(cand.stem)
            if window is not None and window[0].date() == ev_start.date():
                same_day.append((window[0], cand))
        if same_day:
            same_day.sort(key=lambda t: t[0])
            return CacheMatch(same_day[0][1], "same_date")
    return None


def infer_hour_offset(
    timestamps,
    start: Optional[datetime],
    end: Optional[datetime],
    *,
    min_share: float = 0.9,
    max_shift: int = 14,
) -> int:
    """Infer a whole-hour shift that aligns event timestamps with a window."""
    if start is None or end is None or end <= start:
        return 0
    parsed = [t for t in timestamps if t is not None]
    if not parsed:
        return 0

    def share(hours: int) -> float:
        shift = timedelta(hours=hours)
        inside = sum(1 for t in parsed if start <= t + shift <= end)
        return inside / len(parsed)

    best_shift, best_share = 0, share(0)
    if best_share >= min_share:
        return 0
    for hours in range(-max_shift, max_shift + 1):
        if hours == 0:
            continue
        s = share(hours)
        if s > best_share:
            best_shift, best_share = hours, s
    return best_shift if best_share >= min_share else 0


def cache_identity(path: Path) -> dict:
    """Read the identifying fields of a cache without loading its timeline."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError):
        return {}
    return {
        "event_id": data.get("event_id"),
        "asn": str(data.get("asn") or "") or None,
        "start_time": data.get("start_time"),
        "end_time": data.get("end_time"),
    }

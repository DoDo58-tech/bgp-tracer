"""Time-string parsing shared across the traffic pipeline.

The traffic detector, the plotting module and the cache writers all
read timestamps that come from three different places: the Cloudflare
Radar API (ISO 8601 with a ``Z`` suffix), the cache files written by
the detector itself (``%Y-%m-%dT%H:%M``), and the command line
(``%Y-%m-%d %H:%M:%S``).  Each module used to carry its own copy of
the format list, and the copies drifted: the plotting module kept only
the two space-separated formats, so an ISO timestamp from a cache file
raised ``ValueError: time data '2025-03-01T16:00' does not match
format '%Y-%m-%d %H:%M:%S'`` and the plot -- and the whole traffic
stage -- failed.

One parser, used everywhere, removes that class of bug.
"""
from __future__ import annotations

from datetime import datetime

#: Formats accepted by :func:`parse_iso`, tried in order.
ISO_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
)


def parse_iso(s) -> datetime:
    """Parse a time string in any of the supported formats.

    Raises ``ValueError`` when the string matches none of them.
    """
    if not s:
        raise ValueError("empty time string")
    text = str(s).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+0000"
    for fmt in ISO_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"time data {s!r} does not match any supported format"
        ) from exc


def parse_iso_utc(s) -> datetime | None:
    """Parse a UTC time string, returning ``None`` when it does not parse."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(
            str(s).strip().replace("Z", "+00:00")
        ).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None

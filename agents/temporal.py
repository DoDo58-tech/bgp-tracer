"""One place where every timestamp spelling the system sees is parsed.

Three producers write timestamps into the same pipeline and they do
not agree on a spelling:

* the traffic provider writes ISO-8601, sometimes with a ``Z`` suffix
  and sometimes with an explicit offset;
* the cache writer writes ISO-8601 without a suffix;
* the **routing detectors** write ``MM/DD/YY HH:MM:SS`` -- for example
  ``10/01/24 11:10:51``.

The last spelling is the dangerous one.  A parser that does not know it
does not raise: it returns ``None``, and the caller treats the record
as if it had no timestamp.  A whole event's routing evidence then
disappears from the analysis and the estimator abstains, which looks
like a modelling result and is actually a parsing failure.  Every
timestamp therefore goes through this module, and a value that cannot
be parsed is reported as such rather than dropped.

All parsed values are timezone-naive UTC.  The pipeline compares a
routing observation with a traffic observation, and one of them
carrying an offset while the other does not makes the subtraction
raise; normalising at the boundary keeps the arithmetic total.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

__all__ = ["parse_timestamp", "parse_timestamp_strict", "as_utc_naive"]

#: The spellings that are tried, in order.  ISO first because it is the
#: most common and the least ambiguous.
_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d",
    # The routing detectors' spelling.  ``%y`` maps 24 to 2024, which
    # is what the detector meant.
    "%m/%d/%y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%y %H:%M",
    "%m/%d/%Y %H:%M",
    "%m/%d/%y",
    "%m/%d/%Y",
    # A few producers write the date with dashes and the time with
    # colons but no separator at all.
    "%Y%m%d%H%M%S",
    "%Y%m%d",
)


def as_utc_naive(value: datetime) -> datetime:
    """Return ``value`` as a naive UTC datetime."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def try_iso(text: str) -> Optional[datetime]:
    candidate = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def parse_timestamp_strict(value: object) -> Optional[datetime]:
    """Parse a timestamp, or return ``None`` if it cannot be read.

    The function is strict about *not* guessing: an unreadable value is
    ``None``, and the caller decides whether that is acceptable.
    """
    if isinstance(value, datetime):
        return as_utc_naive(value)
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    iso = try_iso(text)
    if iso is not None:
        return as_utc_naive(iso)

    # A trailing offset that ISO rejected (for example ``+0000``) is
    # normalised before the format table is tried.
    normalised = text.replace("/", "-")
    if normalised != text:
        iso = try_iso(normalised)
        if iso is not None:
            return as_utc_naive(iso)

    for fmt in _FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse_timestamp(value: object) -> Optional[datetime]:
    """Parse the timestamp spellings that reach the engine.

    Kept as the public name because the rest of the pipeline already
    imports it; the behaviour lives in this module.
    """
    return parse_timestamp_strict(value)

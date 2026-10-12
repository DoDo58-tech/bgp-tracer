"""
Detector input validation.

Every detector entry point takes a target AS plus a time window. Before the
2026-10-05 audit these were accepted unvalidated, which let two silent-failure
modes reach the pipeline:

1. **Argument mis-binding.** ``detect_hijacks`` is
 ``(start_time, end_time, target_as)`` while ``analyze_leak_surface`` is
 ``(asn, start_time, end_time)``. Passing the AS in the wrong slot did not
 raise - it was parsed as a timestamp, the run proceeded, and a results file
 was written with an inverted window and ``total_alerts: 0``. That is a
 false negative wearing the costume of a finding.

2. **Inverted windows.** Nothing anywhere checked ``start <= end``. A typo or
 timezone slip in an input CSV yields a clean empty result instead of an
 error.

``validate_detection_request`` is the single gate. It raises
``InputValidationError`` (a ``ValueError`` subclass, so existing
``except ValueError`` handlers still catch it) rather than returning a result
dict, because a validation failure must not be shaped like a detection.
Callers that want a result dict instead should use ``as_result_dict``.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Tuple

__all__ = [
    "InputValidationError",
    "validate_detection_request",
    "validate_time_window",
    "parse_timestamp",
    "looks_like_asn",
    "looks_like_timestamp",
]


class InputValidationError(ValueError):
    """Raised when a detector request is malformed before any work starts."""


# ASNs are 1..4294967295 (32-bit, per RFC 6793). 0 is reserved.
_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
_ASN_MAX = 4294967295

# Formats already accepted by the pipeline, kept in one place so the
# detectors and the batch runners cannot drift apart again.
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y/%m/%d %H:%M:%S",
)


def _looks_timestampy(value_text: str) -> bool:
    """True for strings that are clearly datetimes, not ASNs.

 Used only to produce a *better error message* when the AS slot received a
 timestamp (the mis-binding case). A bare number is ambiguous by design:
 ``AS1234`` and ``1234`` are both valid, so it is accepted as an ASN.
 """
    v = value.strip()
    if "-" in v or ":" in v or "/" in v:
        return True
    return False


def looks_like_asn(value: Any) -> bool:
    """True if `value` is a syntactically valid ASN string or int."""
    if isinstance(value, bool):  # bool is an int subclass; reject explicitly
        return False
    if isinstance(value, int):
        return 0 < value <= _ASN_MAX
    if not isinstance(value, str):
        return False
    m = _ASN_RE.match(value.strip())
    if not m:
        return False
    n = int(m.group(1))
    return 0 < n <= _ASN_MAX


def looks_like_timestamp(value: Any) -> bool:
    """True if `value` parses as one of the supported timestamp formats."""
    if isinstance(value, datetime):
        return True
    if not isinstance(value, str):
        return False
    try:
        parse_timestamp(value)
        return True
    except InputValidationError:
        return False


def parse_timestamp(value: Any, label: str = "timestamp") -> datetime:
    """Parse a timestamp string into a naive datetime.

 Raises InputValidationError with an actionable message, including a hint
 when a timestamp was passed where an ASN was expected.
 """
    if isinstance(value, datetime):
        return value
    if value is None:
        raise InputValidationError(f"{label} is required but was None")
    if not isinstance(value, str):
        raise InputValidationError(
            f"{label} must be a str or datetime, got {type(value).__name__}: {value!r}"
        )

    s = value.strip()
    if not s:
        raise InputValidationError(f"{label} is required but was empty")

    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        pass

    # If it looks like an ASN, the caller almost certainly swapped arguments.
    if looks_like_asn(s):
        raise InputValidationError(
            f"{label}={s!r} is an AS number, not a timestamp. "
            "Arguments are very likely swapped: the AS and the time window "
            "must not be mixed up."
        )
    raise InputValidationError(
        f"{label}={s!r} is not a recognised timestamp. "
        f"Expected one of: {' '.join(_TS_FORMATS)}, or ISO 8601."
    )


def _validate_asn(value: Any, label: str = "asn") -> str:
    """Return the bare digits for an ASN, raising if it is not one."""
    if isinstance(value, bool) or value is None:
        raise InputValidationError(f"{label} is required, got {value!r}")
    if isinstance(value, int):
        if not (0 < value <= _ASN_MAX):
            raise InputValidationError(f"{label}={value} out of range (1..{_ASN_MAX})")
        return str(value)
    if not isinstance(value, str):
        raise InputValidationError(
            f"{label} must be a str or int, got {type(value).__name__}: {value!r}"
        )
    s = value.strip()
    if not s:
        raise InputValidationError(f"{label} is required but was empty")

    m = _ASN_RE.match(s)
    if not m:
        if _looks_timestampy(s):
            raise InputValidationError(
                f"{label}={s!r} looks like a timestamp, not an AS number. "
                "Arguments are very likely swapped (check the parameter order "
                "of the detector entry point)."
            )
        raise InputValidationError(
            f"{label}={s!r} is not a valid AS number "
            "(expected digits, optionally prefixed with 'AS')."
        )
    n = int(m.group(1))
    if not (0 < n <= _ASN_MAX):
        raise InputValidationError(f"{label}={s!r} out of range (1..{_ASN_MAX})")
    return str(n)


def validate_time_window(
    start_time: Any,
    end_time: Any,
    *,
    start_label: str = "start_time",
    end_label: str = "end_time",
    min_duration_seconds: int = 0,
) -> Tuple[datetime, datetime]:
    """Parse and sanity-check a window. Returns (start, end) as datetimes.

 Rejects inverted windows outright. An inverted window is never a valid
 query, and the old behaviour (proceed, scan nothing, report zero findings)
 is indistinguishable from a genuine miss.
 """
    start = parse_timestamp(start_time, start_label)
    end = parse_timestamp(end_time, end_label)

    if end < start:
        raise InputValidationError(
            f"{end_label} ({end_time!r}) is before {start_label} ({start_time!r}). "
            "The window is inverted; refusing to run because an inverted "
            "window yields a clean empty result rather than an error."
        )
    if end == start and min_duration_seconds > 0:
        raise InputValidationError(
            f"Window is zero-length ({start_time!r} == {end_time!r}); "
            f"minimum duration is {min_duration_seconds}s."
        )
    return start, end


def validate_detection_request(
    asn: Any,
    start_time: Any,
    end_time: Any,
    *,
    asn_label: str = "asn",
    start_label: str = "start_time",
    end_label: str = "end_time",
    min_duration_seconds: int = 0,
) -> Tuple[str, datetime, datetime]:
    """Validate (asn, start, end) and return (asn_digits, start, end).

 This is the single entry point every detector should call first. It is
 deliberately strict and raises, so a malformed request can never be
 mistaken for a negative detection.
 """
    clean_asn = _validate_asn(asn, asn_label)
    start, end = validate_time_window(
        start_time,
        end_time,
        start_label=start_label,
        end_label=end_label,
        min_duration_seconds=min_duration_seconds,
    )
    return clean_asn, start, end
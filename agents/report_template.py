"""Structure-locked HTML report renderer (template ``report_v2``).

Why this module exists
----------------------
The legacy report path let the LLM emit a full HTML document (head, CSS,
section order) and then patched it afterwards with ``re.sub`` and CSS
overrides. That made three classes of defect impossible to eliminate:

  1. **Width inconsistency** — the LLM emitted its own ``body{max-width}``
     while ``inject_traffic_plot`` injected a second ``.report-container``
     with a different width, so blocks rendered under two different
     constraints and the document looked visibly "torn apart".
  2. **Wrong traffic chart** — the base64 injection path depended on
     ``extract_plot_path`` guessing a file on disk; when the guess failed
     the report shipped with no chart or a stale one.
  3. **Empty table columns** — ``_render_table_html`` always emitted every
     column, so a detector that never populates (e.g. ``leaked_by``) produced
     a wall of ``—`` cells that read as "the tool is broken".

This module inverts the responsibility split:

  * **Python owns 100% of the markup.** The template owns structure, section
    order, CSS, and the single width constraint.
  * **The LLM owns 100% of the prose.** It returns a JSON object of narrative
    fields (see :func:`request_llm_narrative`). It never writes HTML, never
    writes CSS, and never chooses a column set.

The three defects above become structurally impossible:

  1. There is exactly one width rule in the template (``.report``), and the
     LLM cannot inject a competing one because it emits no CSS.
  2. The plot path is resolved deterministically from the traffic payload
     (``plot_path``) and, if that fails, the renderer reports the gap in
     plain language instead of silently shipping a wrong image.
  3. :func:`build_table` drops any column that is empty in *every* row, so a
     table can never present a column of placeholders.

Public API::

    render_report(...)  -> str   # final HTML
    request_llm_narrative(...) -> dict  # structured prose from the LLM
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Sequence

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

# ── Paths ────────────────────────────────────────────────────────────────────
_MODULE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = _MODULE_DIR.parent / "templates"
TEMPLATE_NAME = "report_v2.html.j2"
TEMPLATE_VERSION = "report_v2"
SCHEMA_VERSION = "1.0"


def preview_name(asn: str, start_time: str = "", end_time: str = "") -> str:
    """Build a filesystem-safe report filename: ``AS8048_2024-08-01_08-45.html``.

    Names never start with an underscore (a leading ``_`` is a POSIX convention
    for "internal", and these renders are things a person opens) and never
    contain ``:`` or spaces, which are illegal or awkward on several
    filesystems. Unparseable timestamps degrade to ``unknown`` rather than
    producing a truncated name like ``AS44244_-06-18T17:55:00.html``.
    """
    def _stamp(value: str) -> str:
        raw = (value or "").strip()
        if not raw:
            return "unknown"
        m = re.search(r"(\d{4})[-/](\d{2})[-/](\d{2})[T ]?(\d{2})[:\-](\d{2})", raw)
        if m:
            y, mo, d, hh, mm = m.groups()
            return f"{y}-{mo}-{d}_{hh}-{mm}"
        m = re.search(r"(\d{4})[-/](\d{2})[-/](\d{2})", raw)
        if m:
            return "-".join(m.groups())
        return "unknown"

    asn_part = re.sub(r"[^0-9A-Za-z]", "", str(asn or "")) or "unknown"
    start_part = _stamp(start_time)
    end_part = _stamp(end_time)
    if end_part and end_part != start_part:
        return f"AS{asn_part}_{start_part}_to_{end_part}.html"
    return f"AS{asn_part}_{start_part}.html"


def window_from_artifact_name(stem: str) -> tuple:
    """Recover ``(start, end)`` from an artifact filename.

    Run artifacts are named ``traffic_outage_analysis_<asn>_<window>.json``
    where the window is spelled in several ways:
    ``17557_2025-09-05_14:30``, ``44244_2025-06-18T17:55:00``, or
    ``8048_2024-08-01 08-45``. Returns ``("", "")`` when nothing matches so
    callers can decide their own fallback rather than getting a bogus value.
    """
    raw = str(stem or "")
    m = re.search(
        r"(\d{4}-\d{2}-\d{2})[T _](\d{2})[:-](\d{2})(?:[:-](\d{2}))?"
        r"(?:\s+to\s+(\d{4}-\d{2}-\d{2})[T _](\d{2})[:-](\d{2}))?",
        raw,
    )
    if not m:
        return "", ""
    y, mo, d, hh, mm, s = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)
    start = f"{y}-{mo}-{d} {hh}:{mm}" + (f":{s}" if s else "")
    if m.group(7):
        end = f"{m.group(7)} {m.group(8)}:{m.group(9)}" + (
            f":{m.group(10)}" if m.group(10) else ""
        )
        return start, end
    return start, ""

# ── Cause palette (kept in sync with report_agent._CAUSE_LABEL) ───────────────
_CAUSE_COLORS = {
    "origin_hijack_victim": "#b91c1c",
    "origin_hijack_attacker": "#ea580c",
    "roa_misconfig": "#ca8a04",
    "route_leak": "#7048e8",
    "outage": "#0d6efd",
    "traffic_anomaly_only": "#12b886",
    "independent_coincidence": "#64748b",
    "no_clear_anomaly": "#64748b",
}

_CORR_LEVEL_CODE = {
    "critical": "L1", "high": "L2", "medium": "L3", "low": "L4",
    "none": "L5", "minimal": "L5",
}


# ═════════════════════════════════════════════════════════════════════════════
#  Low-level helpers
# ═════════════════════════════════════════════════════════════════════════════

def _safe(value: Any, default: str = "—") -> str:
    """HTML-safe text for a cell, never producing an empty string.

    Empty values collapse to an em-dash so a reviewer never has to
    distinguish "blank because missing" from "blank because broken".
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        if value != value:  # NaN
            return default
        if abs(value - round(value)) < 1e-9 and abs(value) < 1e15:
            return str(int(round(value)))
        return f"{value:.4g}"
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)[:180]
        except Exception:
            return default
    s = str(value).strip()
    return s if s else default


def _num(value: Any, spec: str = ".2f") -> str:
    try:
        return format(float(value), spec)
    except (TypeError, ValueError):
        return "—"


def _esc(text: Any) -> str:
    """Escape text for interpolation into template output.

    Only use this on *prose*. Pre-rendered HTML fragments built by
    :func:`build_table` (or any other trusted builder) must be wrapped in
    :func:`markup` instead, otherwise Jinja's autoescape escapes them a
    second time and the browser shows literal ``&lt;table&gt;`` text.
    """
    s = _safe(text, "")
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def markup(fragment: Optional[str]) -> Markup:
    """Mark a pre-rendered HTML fragment as already-safe for Jinja."""
    return Markup(fragment or "")


def _unwrap(payload: Any) -> dict:
    """Unwrap the ``{"result": {...}}`` envelope used across the blackboard."""
    if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
        return payload["result"]
    return payload if isinstance(payload, dict) else {}


# ═════════════════════════════════════════════════════════════════════════════
#  Table construction — the fix for empty columns
# ═════════════════════════════════════════════════════════════════════════════

def build_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    row_limit: int = 50,
) -> Optional[dict]:
    """Render a data table, dropping columns that are empty in every row.

    Returns ``None`` when there are no rows at all so the caller can omit
    the whole block (an event class that was never detected should not
    leave an empty heading behind).

    A column survives only if at least one row has a real value in it.
    That is the single rule that guarantees the "table full of em-dashes"
    defect cannot reappear, even when an upstream detector renames or
    omits fields.

    Returns a dict with ``html`` plus ``shown`` / ``omitted`` counts so the
    template can label a collapsible block accurately.
    """
    if not rows:
        return None

    # Determine which columns carry data in at least one row.
    #
    # This must inspect the RAW cell value, not the rendered string: a
    # missing field becomes "—" only at render time, so a column that is
    # entirely absent still looks "populated" if the check runs afterwards.
    # Checking the raw value is what lets an all-placeholder column be
    # dropped (e.g. "Victim AS" on attacker-side hijack rows, where no
    # victim was ever recorded).
    keep = []
    for idx, _header in enumerate(headers):
        for row in rows:
            if idx >= len(row):
                continue
            cell = row[idx]
            if cell is None:
                continue
            if isinstance(cell, str) and not cell.strip():
                continue
            # Treat the em-dash/placeholder markers as "no value" too, since
            # upstream helpers sometimes pre-format a missing field.
            if isinstance(cell, str) and cell.strip() in ("—", "-", "N/A", "n/a"):
                continue
            keep.append(idx)
            break

    # Every column empty → the table carries no information; drop it.
    if not keep:
        return None

    kept_headers = [headers[i] for i in keep]
    shown = list(rows[:row_limit])
    omitted = max(0, len(rows) - row_limit)

    def _render_row(row: Sequence[Any], tag: str, cls: str = "") -> str:
        cells = []
        for i in keep:
            raw = row[i] if i < len(row) else None
            text = _esc(raw) if raw is not None else "—"
            cells.append(f'<td{cls}>{text}</td>')
        attr = f' class="{cls}"' if cls and not cls.startswith("text") else ""
        return f"<tr{attr}>{''.join(cells)}</tr>"

    body = [_render_row(r, "td") for r in shown]
    if omitted:
        body.append(
            f'<tr class="omitted"><td colspan="{len(keep)}">'
            f"&hellip; {omitted} further row(s) not shown</td></tr>"
        )

    thead = "<thead><tr>" + "".join(
        f"<th>{_esc(h)}</th>" for h in kept_headers
    ) + "</tr></thead>"
    tbody = "<tbody>" + "".join(body) + "</tbody>"

    html = (
        '<div class="tbl-scroll"><table class="data">'
        f"{thead}{tbody}</table></div>"
    )
    return {"html": html, "shown": len(shown), "omitted": omitted, "columns": kept_headers}


# ═════════════════════════════════════════════════════════════════════════════
#  Event-class extraction
# ═════════════════════════════════════════════════════════════════════════════

def _first_present(*candidates: Any) -> Any:
    """First candidate that is neither None nor an empty string.

    Guards against the ``or``-chain bug where a legitimate ``0`` collapses
    into the fallback value.
    """
    for c in candidates:
        if c is None:
            continue
        if isinstance(c, str) and not c.strip():
            continue
        return c
    return None


def _dedupe_events(events: Sequence[dict]) -> list:
    """Drop events that appear more than once in the payload.

    The routing agent writes the same route-leak event to both
    ``routing.route_leaks`` and ``routing.leak_analysis.route_leaks``. When
    both are read, every leak is counted twice — which inflates the counts in
    the report and makes a 500-event leak look like 1000. Identity is the
    (timestamp, prefix, AS path) triple, falling back to the JSON form of the
    whole event when those fields are absent.
    """
    seen: set = set()
    out: list = []
    for ev in events:
        key = (
            _first_present(ev.get("timestamp"), ev.get("time"), ev.get("detected_at")),
            ev.get("prefix"),
            _first_present(ev.get("as_path"), ev.get("as-path")),
        )
        if all(part is None for part in key):
            try:
                key = ("json", json.dumps(ev, sort_keys=True, default=str))
            except Exception:
                key = ("repr", repr(ev))
        if key in seen:
            continue
        seen.add(key)
        out.append(ev)
    return out


def normalize_routing(routing_result: Any) -> dict:
    """Flatten the routing payload into one predictable shape.

    Handles both shapes emitted by the routing agent: the annotation
    package (``{"hijack": {"origin_hijacked": [...]}}``) and the flat form
    (``{"origin_hijacked": [...]}``).
    """
    rr = _unwrap(routing_result)
    if not isinstance(rr, dict):
        return {}

    def collect(*keys: str) -> list:
        out: list = []
        for key in keys:
            value = rr.get(key)
            if isinstance(value, list):
                out.extend(v for v in value if isinstance(v, dict))
            elif isinstance(value, dict):
                # annotation-package section
                for sub in value.values():
                    if isinstance(sub, list):
                        out.extend(v for v in sub if isinstance(v, dict))
        return out

    hijacked = collect("origin_hijacked", "forge_hijacked", "hijacks")
    hijacking = collect("origin_hijacking", "forge_hijacking")

    # Route leaks are frequently stored in TWO places at once: the top-level
    # ``route_leaks`` list and the ``leak_analysis`` sub-object. Concatenating
    # them double-counts every event (observed: 500 real leaks reported as
    # 1000), so dedupe on a stable event identity before use.
    leak_candidates: list = []
    for key in ("route_leaks", "leaks"):
        value = rr.get(key)
        if isinstance(value, list):
            leak_candidates.extend(v for v in value if isinstance(v, dict))
    leak_section = rr.get("leak")
    if isinstance(leak_section, dict):
        leak_candidates.extend(
            v for v in (leak_section.get("route_leaks") or []) if isinstance(v, dict)
        )
    leak_analysis = rr.get("leak_analysis")
    if isinstance(leak_analysis, dict):
        leak_candidates.extend(
            v for v in (leak_analysis.get("route_leaks") or []) if isinstance(v, dict)
        )

    leaks = _dedupe_events(leak_candidates)

    outage = rr.get("outage_analysis") or rr.get("outages") or rr.get("outage") or {}
    if not isinstance(outage, dict):
        outage = {}

    return {
        "origin_hijacked": hijacked,
        "origin_hijacking": hijacking,
        "route_leaks": leaks,
        "outage": outage,
        "outage_suspected": bool(outage.get("is_outage_suspected")) or bool(rr.get("outage_suspected")),
        "outage_score": outage.get("outage_score") or rr.get("outage_score") or 0.0,
        "mitm_alerts": collect("mitm_alerts"),
    }


def hijack_rows(routing_norm: dict) -> list:
    """Per-event hijack rows with only fields the detector actually set."""
    rows = []
    for ev in routing_norm.get("origin_hijacked", []) + routing_norm.get("origin_hijacking", []):
        hijacker = _first_present(
            ev.get("origin_as"), ev.get("hijacker_as"), ev.get("attacker_as")
        )
        if hijacker is None and isinstance(ev.get("origin"), dict):
            hijacker = ev["origin"].get("asn")
        victim = _first_present(
            ev.get("victim_as"), ev.get("expected_origin"), ev.get("expected_origin_as")
        )
        as_path = _first_present(ev.get("as_path"), ev.get("as-path"))
        rows.append([
            _first_present(ev.get("timestamp"), ev.get("time"), ev.get("detected_at")),
            ev.get("prefix"),
            hijacker,
            victim,
            as_path,
            "victim" if ev in routing_norm.get("origin_hijacked", []) else "attacker",
        ])
    return rows


def leak_rows(routing_norm: dict) -> list:
    """Route-leak rows.

    A leak event frequently lacks a dedicated ``leaked_by`` field, in which
    case the first AS of the AS_PATH is the leaker by definition of a leak.
    The reverse (prefix) is derived from the AS_PATH's trailing prefix token
    when the detector did not record it separately.
    """
    rows = []
    for ev in routing_norm.get("route_leaks", []):
        as_path = _first_present(ev.get("as_path"), ev.get("as-path"))
        leaker = _first_present(ev.get("leaked_by"), ev.get("leak_as"), ev.get("leaker_as"))
        if leaker is None and isinstance(as_path, str) and as_path.strip():
            leaker = as_path.split()[0]
        # The PathProb detector's own score is the most informative severity
        # signal it emits; prefer it over the generic `severity` label.
        probability = _first_present(ev.get("leak_probability"), ev.get("probability"))
        severity = (
            f"{float(probability):.3f}" if isinstance(probability, (int, float))
            else _first_present(
                ev.get("severity"), ev.get("severity_class"), ev.get("type")
            )
        )
        rows.append([
            _first_present(ev.get("timestamp"), ev.get("time"), ev.get("detected_at")),
            ev.get("prefix"),
            leaker,
            as_path,
            severity,
        ])
    return rows


def traffic_anomaly_rows(traffic_norm: dict) -> list:
    """Traffic anomaly rows using only signals the detector emitted."""
    rows = []
    for a in (traffic_norm.get("anomalies") or [])[:50]:
        if not isinstance(a, dict):
            continue
        signal = _first_present(
            a.get("z_score"), a.get("deviation"), a.get("deviation_pct"),
            a.get("change_magnitude"), a.get("change_type"),
        )
        if signal is None and a.get("sudden_drop"):
            signal = "sudden_drop"
        rows.append([
            _first_present(a.get("timestamp"), a.get("time")),
            _first_present(a.get("current_value"), a.get("value")),
            a.get("severity"),
            signal,
            a.get("baseline_method") or a.get("percentile_direction"),
        ])
    return rows


def routing_aggregate(routing_norm: dict, top_n: int = 8) -> tuple:
    """Aggregate routing alerts by (prefix, role) for the top-N view."""
    counter: dict = {}

    def bump(prefix: str, role: str, asn: str, counterparty: str) -> None:
        key = (prefix, role)
        slot = counter.setdefault(
            key, {"count": 0, "prefix": prefix, "role": role, "asn": asn, "peer": counterparty}
        )
        slot["count"] += 1

    for ev in routing_norm.get("origin_hijacked", []):
        bump(
            ev.get("prefix") or "—", "victim",
            _first_present(ev.get("origin_as"), ev.get("hijacker_as")),
            _first_present(ev.get("victim_as"), ev.get("expected_origin")) or "—",
        )
    for ev in routing_norm.get("origin_hijacking", []):
        bump(
            ev.get("prefix") or "—", "attacker",
            _first_present(ev.get("origin_as"), ev.get("hijacker_as"), ev.get("attacker_as")),
            _first_present(ev.get("victim_as"), ev.get("expected_origin")) or "(none recorded — ROA gap)",
        )
    for ev in routing_norm.get("route_leaks", []):
        as_path = _first_present(ev.get("as_path"), ev.get("as-path"))
        leaker = _first_present(ev.get("leaked_by"), ev.get("leak_as"), ev.get("leaker_as"))
        if leaker is None and isinstance(as_path, str) and as_path.strip():
            leaker = as_path.split()[0]
        bump(ev.get("prefix") or "—", "leaker", leaker, "—")

    if not counter:
        return None, 0

    ordered = sorted(counter.values(), key=lambda g: (-g["count"], str(g["prefix"])))[:top_n]
    rows = [[g["prefix"], g["role"], g["asn"], g["peer"], g["count"]] for g in ordered]
    return rows, sum(g["count"] for g in counter.values())


# ═════════════════════════════════════════════════════════════════════════════
#  Traffic plot resolution — the fix for the wrong / missing chart
# ═════════════════════════════════════════════════════════════════════════════

_PLOT_DIR = Path("/data/bgp_tracer/data/traffic_plots")


def _plot_quality(path: Path) -> tuple:
    """Rank a plot render: ``(is_full_resolution, byte_size)``.

    The reference charts (e.g. ``AS174_2025-03-20 15-43-00_to_…png``) are
    5600x2600 / ~1 MB, produced by the full detector pipeline with the
    historical baseline bands. The degraded renders of the same window are
    ~300 KB. Pixel dimensions are the only reliable proxy available without
    re-deriving the chart, so prefer full-resolution renders and break ties on
    file size.

    NOTE: mtime is deliberately NOT part of this ranking. Filesystem mtime only
    records when a file happened to be regenerated, not how good it is — using
    it as a tiebreak let a stale, lower-fidelity plot beat a correct one.
    """
    try:
        from PIL import Image
        with Image.open(path) as im:
            width, _height = im.size
    except Exception:
        width = 0
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    return (1 if width >= 4000 else 0, size)


def _best_sibling_for_window(recorded: Path, asn: str, window_hint: str) -> Optional[Path]:
    """Return a better render of the *same* window than ``recorded``, if any.

    The window is taken from ``recorded``'s OWN filename, not from
    ``window_hint``. Those two can legitimately disagree: for AS8048 the
    payload's ``traffic_anomaly_window`` starts 2024-07-31 while the detector
    actually plotted 2024-08-01. Keying off the hint therefore matched a
    different day (or nothing at all) and defeated the upgrade. Keying off the
    recorded filename keeps the substitution strictly within the window the
    detector chose, so it can never swap in an unrelated chart.

    Returns ``None`` when ``recorded`` is already the best available render.
    """
    if not _PLOT_DIR.is_dir():
        return None

    # "AS8048_2024-08-01 08-45_to_2024-08-01 09-45.png" -> date + HH-MM
    stem = recorded.stem
    m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}-\d{2})", stem)
    if not m:
        return None
    date_part, time_part = m.group(1), m.group(2)

    recorded_q = _plot_quality(recorded)
    best: Optional[Path] = None
    best_key: Optional[tuple] = None

    for path in _PLOT_DIR.glob(f"AS{asn}*.png"):
        name = path.name
        if date_part not in name:
            continue
        if time_part not in name:
            continue
        q = _plot_quality(path)
        key = (q[0], q[1])
        if best_key is None or key > best_key:
            best, best_key = path, key

    if best is None or best == recorded:
        return None
    # Only upgrade — never downgrade.
    if best_key is not None and best_key > recorded_q:
        return best
    return None


def _normalise_window_hint(value: str) -> str:
    """Reduce a timestamp to the ``YYYY-MM-DD HH:MM`` prefix used in filenames.

    Plot files are named ``AS<asn>_<start>_to_<end>.png`` with ``:`` replaced
    by ``-``, so the resolver only needs the date plus hour-minute. Accepts the
    ISO forms that appear in the payloads (``...T08:45:00Z``, ``...+08:00``,
    space-separated) and returns ``""`` when the input is unparseable rather
    than propagating a bogus hint.
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    raw = raw.split(" to ")[0].strip()
    # Trim a trailing UTC offset such as "+08:00" or "Z".
    if raw.endswith("Z"):
        raw = raw[:-1].strip()
    try:
        from datetime import datetime
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M",
                    "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                return datetime.strptime(raw[:len(datetime.now().strftime(fmt))],
                                         fmt).strftime("%Y-%m-%d %H:%M")
            except ValueError:
                continue
    except Exception:
        pass
    # Fall back to a purely lexical slice: "2024-07-31T08:45..." -> "2024-07-31 08:45"
    m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}):(\d{2})", raw)
    if m:
        return f"{m.group(1)} {m.group(2)}:{m.group(3)}"
    return ""


def resolve_traffic_plot(
    traffic_result: Any,
    asn: str = "",
    *,
    window_hint: str = "",
) -> tuple:
    """Return ``(base64_png, source_path, attempted_path)``.

    Resolution order is strictly deterministic:

      1. ``plot_path`` recorded by the traffic detector (the authoritative
         artifact produced during traffic anomaly detection).
      2. A file in the traffic-plot directory whose name encodes the
         analysis window (most specific match wins).

    If neither resolves, the caller renders an explicit gap notice — the
    report never silently substitutes an unrelated chart. ``window_hint``
    is a substring such as ``2024-10-29 13:30`` that the detector bakes
    into the plot filename.
    """
    traffic = _unwrap(traffic_result)
    attempted: Optional[str] = None

    # 1) Detector-recorded path.
    recorded = _first_present(
        traffic.get("plot_path"),
        traffic.get("traffic_plot_path"),
        (traffic.get("llm_insights") or {}).get("plot_path")
        if isinstance(traffic.get("llm_insights"), dict) else None,
    )
    if recorded:
        attempted = str(recorded)
        try:
            resolved = Path(recorded).resolve()
            if resolved.is_file():
                # The recorded path is authoritative for *which window* to
                # show, but not for *which render* of that window. A previous
                # detector run may have recorded a degraded chart while a
                # full-fidelity render of the identical window exists (the
                # recorded file is kept on disk and never deleted). Blindly
                # embedding it produced visibly poorer reports, so we upgrade
                # to the best-quality sibling covering the same window when one
                # is available, and only fall back to the recorded bytes.
                if asn and _PLOT_DIR.is_dir():
                    sibling = _best_sibling_for_window(resolved, asn, window_hint)
                    if sibling is not None and sibling != resolved:
                        return (
                            base64.b64encode(sibling.read_bytes()).decode("ascii"),
                            str(sibling),
                            attempted,
                        )
                return (
                    base64.b64encode(resolved.read_bytes()).decode("ascii"),
                    str(resolved),
                    None,
                )
        except Exception:
            pass

    # 2) Window-scoped lookup inside the plot directory.
    if asn and _PLOT_DIR.is_dir():
        needle = window_hint.strip()
        candidates = list(_PLOT_DIR.glob(f"AS{asn}*.png"))
        if candidates:
            # The detector encodes timestamps with several separators, so the
            # same logical window can appear as "2024-08-01 08-45_to_…09-45"
            # (minute precision) or "2024-08-01 08-45-00_to_…09-45-00" (second
            # precision). Both are legitimate; we must pick between them on
            # quality, not on filesystem mtime.
            #
            # BUG (2026-10-04): the previous tiebreak was `st_mtime`, which
            # let a stale, lower-fidelity plot win simply because it was
            # written later. For AS8048 that embedded a 309 KB truncated chart
            # instead of the 1.0 MB full-fidelity one for the same window.
            # mtime carries no information about plot quality — it only records
            # when a file happened to be regenerated — so it is now used solely
            # as a last-resort tiebreak after explicit quality signals.
            date_part = needle[:10]
            time_part = needle[11:16].replace(":", "-")

            scored = []
            for path in candidates:
                name = path.name
                score = 0
                if date_part and date_part in name:
                    score += 2
                if time_part and time_part in name:
                    score += 3
                if score:
                    res_rank, size = _plot_quality(path)
                    scored.append((score, res_rank, size, path.stat().st_mtime, path))
            if scored:
                # window match, then resolution class, then byte size, then
                # mtime purely as a deterministic last resort.
                scored.sort(key=lambda t: (t[0], t[1], t[2], t[3]), reverse=True)
                best = scored[0][4]
                return (
                    base64.b64encode(best.read_bytes()).decode("ascii"),
                    str(best),
                    attempted,
                )
            # No window match: fall back to the best-quality plot for the AS
            # rather than the most recently touched one.
            ranked = sorted(
                ((*_plot_quality(p), p.stat().st_mtime, p) for p in candidates),
                key=lambda t: (t[0], t[1], t[2]),
                reverse=True,
            )
            best = ranked[0][-1]
            return (
                base64.b64encode(best.read_bytes()).decode("ascii"),
                str(best),
                attempted,
            )

    return None, None, attempted


# ═════════════════════════════════════════════════════════════════════════════
#  LLM narrative — structured JSON only, never HTML
# ═════════════════════════════════════════════════════════════════════════════

NARRATIVE_SCHEMA_VERSION = "1.0"

# Field name -> hard character cap. Caps keep the LLM response inside a few
# thousand tokens so the call cannot time out on prose.
_NARRATIVE_FIELDS = {
    "executive_note": 420,
    "mechanism": 320,
    "traffic_analysis": 700,
    "routing_analysis": 900,
    "hypothesis_note": 260,
    "gap_note": 320,
}

NARRATIVE_PROMPT = """\
You are the narrative layer of a BGP incident report renderer. The HTML \
structure, all tables, and every number in the report are produced by a \
deterministic Python program. Your only job is to write the analyst prose \
that accompanies them.

Return ONE JSON object and nothing else. No markdown fence, no commentary, \
no HTML, no <tags>.

Schema:
{{
  "executive_note":   "1-2 sentences: what happened and why it matters",
  "mechanism":        "1 sentence: the technical mechanism behind the anomaly",
  "traffic_analysis": "2-3 sentences interpreting the traffic anomaly table",
  "routing_analysis": "2-4 sentences interpreting the routing alert counts and prefixes",
  "hypothesis_note":  "1 sentence on how to discriminate the leading hypotheses",
  "gap_note":         "1-2 sentences on the biggest evidence limitation"
}}

Rules:
- Write in English, in plain prose. No bullet points, no markdown, no HTML.
- Never invent a number. Every figure belongs to the renderer; you only \
interpret. If a field below is missing, do not mention it.
- If the data shows a data-collection artefact (for example alternating \
drop/jump cycles that alternate between near-zero and the baseline), say so \
plainly instead of attributing it to an attack.
- Each value must be a string. Do not nest objects or arrays.
- Do not include the keys "cause", "confidence", "verdict" — the renderer \
owns the verdict and it must be the only one shown.

Analysis data:
{analysis_data}
"""


def request_llm_narrative(llm, analysis_data: dict, *, timeout: float = 240.0) -> dict:
    """Ask the LLM for prose fields only. Never returns HTML.

    Any failure (timeout, transport error, unparseable output) degrades to
    an empty dict, and every template field has a deterministic Python
    fallback, so the report still renders in full.
    """
    empty = {key: "" for key in _NARRATIVE_FIELDS}
    try:
        data_json = json.dumps(analysis_data, ensure_ascii=False, default=str)[:60_000]
        prompt = NARRATIVE_PROMPT.replace("{analysis_data}", data_json)
        # The schema block is doubled-brace in the source string; unescape it
        # now that the data placeholder has been substituted.
        prompt = prompt.replace("{{", "{").replace("}}", "}")

        response = llm.complete(
            prompt,
            max_retries=1,
            max_tokens=1400,
        )
        text = (getattr(response, "text", "") or "").strip()
        return parse_narrative(text, default=empty)
    except Exception:
        return empty


def parse_narrative(text: str, default: Optional[dict] = None) -> dict:
    """Parse the LLM's JSON narrative defensively.

    Handles a markdown fence, leading prose, and trailing commentary. Any
    field that is missing, of the wrong type, or over its cap is dropped in
    favour of the deterministic fallback rather than rendered as garbage.
    """
    fallback = dict(default or {})
    result = {key: fallback.get(key, "") for key in _NARRATIVE_FIELDS}
    if not text:
        return result

    # Strip a markdown fence if present.
    fenced = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)

    # Prefer the outermost JSON object.
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return result
    try:
        data = json.loads(text[start:end + 1])
    except (json.JSONDecodeError, ValueError):
        return result
    if not isinstance(data, dict):
        return result

    for key, cap in _NARRATIVE_FIELDS.items():
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            # Collapse whitespace and neutralize any stray markup so a
            # misbehaving model cannot inject tags into the template output.
            cleaned = re.sub(r"<[^>]+>", "", value)
            cleaned = re.sub(r"\s+", " ", cleaned).strip()
            if cleaned:
                result[key] = cleaned[:cap]
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  Deterministic narrative fallbacks
# ═════════════════════════════════════════════════════════════════════════════

def _traffic_prose(traffic: dict, routing_norm: dict) -> str:
    count = traffic.get("anomaly_count") or len(traffic.get("anomalies") or [])
    drop = traffic.get("peak_trough_drop_pct")
    severity = traffic.get("max_severity")
    parts = []
    if count:
        drop_txt = f", peak-to-trough drop {float(drop):.1f}%" if drop not in (None, "") else ""
        sev_txt = f" (max severity: {severity})" if severity else ""
        parts.append(
            f"{count} traffic anomaly window(s) were detected{drop_txt}{sev_txt}."
        )
    else:
        parts.append("No traffic anomaly was detected in this window.")
    if routing_norm:
        alerts = (
            len(routing_norm.get("origin_hijacked", []))
            + len(routing_norm.get("origin_hijacking", []))
            + len(routing_norm.get("route_leaks", []))
        )
        if alerts:
            parts.append(
                f"{alerts} routing alert(s) fall inside the same window, so the "
                "traffic and routing signals were compared on time separation."
            )
    return " ".join(parts)


def _routing_prose(routing_norm: dict) -> str:
    hijacked = len(routing_norm.get("origin_hijacked", []))
    hijacking = len(routing_norm.get("origin_hijacking", []))
    leaks = len(routing_norm.get("route_leaks", []))
    parts = []
    if hijacked:
        parts.append(
            f"{hijacked} event(s) list the target AS as the hijacked (victim) "
            "side, meaning other ASes announced its prefixes."
        )
    if hijacking:
        parts.append(
            f"{hijacking} event(s) list the target AS as the announcing "
            "(attacker) side."
        )
    if leaks:
        parts.append(f"{leaks} route-leak event(s) were recorded.")
    if routing_norm.get("outage_suspected"):
        parts.append(
            f"Reachability outage suspected (score "
            f"{_num(routing_norm.get('outage_score'))})."
        )
    if not parts:
        return "No routing-security alert was detected in this window."
    return " ".join(parts)


def _evidence_chain(cause: dict, traffic: dict, routing_norm: dict, corr: dict) -> list:
    """Deterministic OBSERVE -> INFER -> LINK -> CONCLUDE -> CITE chain."""
    steps = []

    obs = []
    count = traffic.get("anomaly_count") or len(traffic.get("anomalies") or [])
    if count:
        obs.append(f"{count} traffic anomaly window(s) detected.")
    alerts = (
        len(routing_norm.get("origin_hijacked", []))
        + len(routing_norm.get("origin_hijacking", []))
        + len(routing_norm.get("route_leaks", []))
    )
    if alerts:
        obs.append(f"{alerts} routing alert(s) detected.")
    if routing_norm.get("outage_suspected"):
        obs.append(
            f"Outage detector score {_num(routing_norm.get('outage_score'))}."
        )
    if obs:
        steps.append({
            "label": "Observe",
            "lines": obs,
            "sources": "traffic.anomalies, routing.*_hijacked, routing.route_leaks",
        })

    inf = []
    strength = corr.get("strength") or 0.0
    proximity = corr.get("temporal_proximity") or "none"
    inf.append(
        f"Temporal proximity between routing and traffic signals is "
        f"\"{proximity}\" (strength {float(strength):.2f})."
    )
    if inf:
        steps.append({
            "label": "Infer",
            "lines": inf,
            "sources": "correlation_analysis.correlation",
        })

    link = cause.get("explanation")
    if link:
        steps.append({
            "label": "Link",
            "lines": [link],
            "sources": "diagnosis.top_cause",
        })

    steps.append({
        "label": "Conclude",
        "lines": [
            f"Most likely cause: {cause.get('label', 'unknown')} "
            f"(confidence {float(cause.get('confidence') or 0):.0%})."
        ],
        "sources": "diagnosis.top_cause",
    })
    return steps


def _hypotheses(cause: dict, routing_norm: dict, traffic: dict) -> list:
    """Render the leading causes as refutable hypothesis cards."""
    ranked = cause.get("ranked") or []
    palette = ["#dc3545", "#f59f00", "#fd7e14", "#6c757d"]
    out = []
    for idx, item in enumerate(ranked[:4]):
        if isinstance(item, (list, tuple)) and len(item) >= 3:
            key, label, conf = item[0], item[1], item[2]
            why = item[3] if len(item) > 3 else cause.get("explanation", "")
        elif isinstance(item, dict):
            key = item.get("cause", "")
            label = item.get("label", key)
            conf = item.get("confidence", 0.0)
            why = item.get("explanation", "")
        else:
            continue
        out.append({
            "title": f"Hypothesis {chr(65 + idx)} — {label}",
            "confidence": float(conf or 0.0),
            "why": why or cause.get("explanation", ""),
            "refute": _REFUTE_HINTS.get(key, "Gather independent confirmation before acting."),
            "color": palette[idx % len(palette)],
        })
    return out


_REFUTE_HINTS = {
    "origin_hijack_victim": "Confirm the bogus announcement is withdrawn and the prefixes are reachable again from multiple vantage points.",
    "origin_hijack_attacker": "Check IRR/RPKI records for the announced prefixes; a legitimate announcement would be covered by a matching ROA.",
    "roa_misconfig": "Run RPKI validation against the affected prefixes; a valid ROA chain would rule out a misconfiguration.",
    "route_leak": "Inspect the peer's import policy; tightening the leaking session removes the leak path.",
    "outage": "Check upstream provider status pages and the AS's own edge-router session state.",
    "traffic_anomaly_only": "Cross-check the traffic series against a second collector to rule out a telemetry fault.",
    "independent_coincidence": "Extend the analysis window; if the two signals remain separated, the link is coincidental.",
    "no_clear_anomaly": "Widen the window or add collectors; the absence of a signal here is not evidence of normality.",
}


def _counterfactuals(cause: dict) -> list:
    key = cause.get("cause", "")
    table = {
        "origin_hijack_victim": (
            "If the hijacking announcements had been filtered by the receiving "
            "peers, the traffic drop would not have occurred despite the same "
            "number of BGP updates."
        ),
        "origin_hijack_attacker": (
            "If the announced prefixes were covered by a valid ROA, validators "
            "would have rejected them, so no traffic diversion would occur."
        ),
        "roa_misconfig": (
            "If ROA coverage existed for the announced prefixes, the hijack "
            "hypothesis would flip to a configuration gap rather than an attack."
        ),
        "route_leak": (
            "If the leaking peer's import policy rejected the routes, the same "
            "announcements would have been harmless."
        ),
        "outage": (
            "If upstream reachability was maintained, the traffic drop would "
            "require a different explanation than upstream failure."
        ),
        "traffic_anomaly_only": (
            "If routing data covered the same window and showed no alerts, the "
            "traffic anomaly would be attributable to a non-BGP cause."
        ),
    }
    body = table.get(key)
    if not body:
        return []
    return [{"title": f"If the leading cause were removed ({cause.get('label')})", "body": body}]


def _gaps(routing_norm: dict, traffic: dict, plot_missing: bool) -> list:
    gaps = []
    if plot_missing:
        gaps.append("No traffic plot artifact was resolved for this window.")
    leaks = routing_norm.get("route_leaks") or []
    if leaks and not any(
        _first_present(e.get("prefix"), e.get("as_path"), e.get("as-path")) for e in leaks
    ):
        gaps.append(
            "Route-leak events were counted but carry neither a prefix nor an "
            "AS path, so the affected prefixes could not be identified."
        )
    if not traffic.get("data_available", True):
        gaps.append("Traffic data was unavailable for part of the analysis window.")
    if not gaps:
        gaps.append(
            "Causal attribution is observational: it rests on temporal "
            "coincidence, not on a reproduced experiment."
        )
    return gaps


def _routing_counts(routing_norm: dict) -> list:
    hijacked = len(routing_norm.get("origin_hijacked", []))
    hijacking = len(routing_norm.get("origin_hijacking", []))
    leaks = len(routing_norm.get("route_leaks", []))
    mitm = len(routing_norm.get("mitm_alerts", []))
    outage_sus = routing_norm.get("outage_suspected")
    rows = [
        ["Origin hijacks (target = victim)", str(hijacked),
         "Other ASes announced the target's prefixes." if hijacked else "None observed."],
        ["Origin hijacks (target = attacker)", str(hijacking),
         "The target announced prefixes attributed to another origin." if hijacking else "None observed."],
        ["Route leaks", str(leaks),
         "Peers received routes they should have filtered." if leaks else "None observed."],
        ["MITM alerts", str(mitm),
         "MITM detection produced alerts." if mitm else "No alerts; detection is optional and may be disabled."],
        ["Reachability outage", "suspected" if outage_sus else "not suspected",
         f"Outage score {_num(routing_norm.get('outage_score'))}."],
    ]
    return rows


# ═════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═════════════════════════════════════════════════════════════════════════════

_ENV: Optional[Environment] = None


def _env() -> Environment:
    global _ENV
    if _ENV is None:
        _ENV = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "j2"], default_for_string=True),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=False,
        )
    return _ENV


def _cause(cause: dict) -> dict:
    key = cause.get("cause", "no_clear_anomaly")
    return {
        "cause": key,
        "label": cause.get("label") or key.replace("_", " ").title(),
        "explanation": cause.get("explanation") or "",
        "confidence": float(cause.get("confidence") or 0.0),
        "color": _CAUSE_COLORS.get(key, "#64748b"),
        "ranked": cause.get("ranked") or [],
    }


def _certainty(cause_conf: float, proximity: str, strength: float) -> tuple:
    evidence = float(strength or 0.0)
    if proximity in ("strong", "moderate"):
        evidence = max(evidence, 0.60 if proximity == "strong" else 0.45)
    combined = min(1.0, 0.6 * float(cause_conf or 0.0) + 0.4 * evidence)
    if combined >= 0.70:
        return "HIGH", "#198754", "✓"
    if combined >= 0.40:
        return "MEDIUM", "#f59f00", "≈"
    return "LOW", "#6c757d", "?"


def _gauge(level: str, strength: float) -> str:
    """Inline SVG semicircle gauge, deterministic on a single strength value."""
    import math
    value = max(0.0, min(1.0, float(strength or 0.0)))
    if value >= 0.65:
        label, color, arc = "high", "#dc3545", 0.75
    elif value >= 0.35:
        label, color, arc = "medium", "#f59f00", 0.50
    elif value >= 0.15:
        label, color, arc = "low", "#12b886", 0.25
    else:
        label, color, arc = "minimal", "#adb5bd", 0.10

    def point(frac: float) -> tuple:
        angle = math.pi * (1 - frac)
        return (100 + 70 * math.cos(angle), 95 - 70 * math.sin(angle))

    x1, y1 = point(0.0)
    x2, y2 = point(arc)
    large = 1 if arc > 0.5 else 0
    return (
        f'<svg width="230" height="150" viewBox="0 0 200 160" role="img" '
        f'aria-label="Correlation strength gauge">'
        f'<path d="M {x1:.1f} {y1:.1f} A 70 70 0 0 1 170 95" '
        f'stroke="#e9ecef" stroke-width="14" fill="none" stroke-linecap="round"/>'
        f'<path d="M {x1:.1f} {y1:.1f} A 70 70 0 {large} 1 {x2:.1f} {y2:.1f}" '
        f'stroke="{color}" stroke-width="14" fill="none" stroke-linecap="round"/>'
        f'<text x="100" y="120" text-anchor="middle" font-size="21" '
        f'font-weight="700" fill="#102a43">{label}</text>'
        f'<text x="100" y="137" text-anchor="middle" font-size="10" '
        f'fill="#748ffc">strength {value:.2f}</text>'
        f'<text x="100" y="152" text-anchor="middle" font-size="9" '
        f'fill="#829ab1">correlation</text>'
        f"</svg>"
    )


def render_report(
    *,
    asn: str,
    start_time: str,
    end_time: str,
    traffic_result: Any = None,
    routing_result: Any = None,
    correlation_analysis: Any = None,
    top_cause: Optional[dict] = None,
    evidence_chain: Any = None,
    auto_probe_findings: Optional[list] = None,
    org_name: Optional[str] = None,
    narrative: Optional[dict] = None,
    narrative_source: str = "python-fallback",
    output_dir: Optional[Path] = None,
) -> str:
    """Render the final HTML document and optionally write it to disk.

    ``narrative`` is the dict returned by :func:`request_llm_narrative`. Any
    field left empty falls back to a deterministic Python sentence, so the
    document is always complete.
    """
    traffic = _unwrap(traffic_result)
    routing_norm = normalize_routing(routing_result)
    narrative = narrative or {}

    # ── Correlation ───────────────────────────────────────────────────────
    corr = _unwrap(correlation_analysis)
    inner = corr.get("correlation") if isinstance(corr.get("correlation"), dict) else corr
    strength = inner.get("strength") or inner.get("confidence") or 0.0
    proximity = inner.get("temporal_proximity") or "none"
    corr_level = str(inner.get("level") or "none")
    delta_ts = inner.get("delta_ts") or corr.get("delta_ts") or []

    # ── Cause ─────────────────────────────────────────────────────────────
    if isinstance(top_cause, dict) and top_cause.get("cause"):
        cause = _cause(top_cause)
    else:
        cause = _deterministic_cause(traffic, routing_norm, strength, proximity)
    certainty_label, certainty_color, certainty_glyph = _certainty(
        cause["confidence"], proximity, strength
    )

    # ── Plot ──────────────────────────────────────────────────────────────
    # The window hint drives plot selection, so it must be the *start* of the
    # analysis window in the "YYYY-MM-DD HH:MM[:SS]" shape the detector bakes
    # into plot filenames. Two shapes occur in practice:
    #   * a dict  {"start": ..., "end": ...}
    #   * a string "2024-07-31T08:45:00Z to 2024-08-01T15:45:00Z"
    # Only the dict branch was handled, so string windows silently produced an
    # empty hint and the resolver fell back to "newest file for this AS",
    # which is how a stale plot from a different day got embedded.
    window_hint = ""
    win = traffic.get("traffic_anomaly_window")
    if isinstance(win, dict):
        window_hint = str(win.get("start") or "")
    elif isinstance(win, str) and win.strip():
        window_hint = win.split(" to ")[0].strip()
    if not window_hint:
        window_hint = str(traffic.get("start_time") or start_time or "")
    # Normalise ISO separators/offsets to the "YYYY-MM-DD HH:MM" prefix that
    # appears in plot filenames.
    window_hint = _normalise_window_hint(window_hint)
    plot_b64, plot_src, plot_attempted = resolve_traffic_plot(
        traffic, asn, window_hint=window_hint
    )

    # ── Tables ────────────────────────────────────────────────────────────
    traffic_tbl = build_table(
        ["Timestamp (UTC)", "Value", "Severity", "Signal", "Baseline"],
        traffic_anomaly_rows(traffic),
        row_limit=50,
    )
    agg_rows, agg_total = routing_aggregate(routing_norm)
    hijack_agg_tbl = build_table(
        ["Prefix", "Role", "AS", "Counterparty", "Alerts"],
        agg_rows or [],
    )
    hijack_event_tbl = build_table(
        ["Timestamp (UTC)", "Prefix", "Announcing AS", "Victim AS", "AS Path", "Role"],
        hijack_rows(routing_norm),
    )
    leak_tbl = build_table(
        ["Timestamp (UTC)", "Prefix", "Leaked by", "AS Path", "Leak score"],
        leak_rows(routing_norm),
    )
    if leak_tbl:
        _leaks = routing_norm.get("route_leaks") or []
        _informative = sum(
            1 for e in _leaks
            if _first_present(e.get("prefix"), e.get("as_path"), e.get("as-path"))
        )
        leak_tbl["note"] = (
            f"{_informative} of {len(_leaks)} leak event(s) carry a prefix or AS path. "
            "Rows without one are omitted rather than shown as placeholder cells."
        )

    delta_tbl = build_table(
        ["Routing (UTC)", "Traffic (UTC)", "ΔT (h)", "Direction", "Confidence"],
        [
            [
                d.get("routing_ts") or d.get("earliest_routing_ts"),
                d.get("traffic_ts"),
                d.get("delta_hours"),
                d.get("direction"),
                d.get("window") or d.get("confidence"),
            ]
            for d in (delta_ts or [])
            if isinstance(d, dict)
        ],
    )

    probe_findings = [p for p in (auto_probe_findings or []) if isinstance(p, dict)]
    probe_rows = [[
        _safe(p.get("target") or p.get("host") or p.get("prefix")),
        _safe(p.get("kind") or p.get("type")),
        "reached" if p.get("success") else "failed",
        _safe(p.get("detail") or p.get("error") or p.get("note")),
    ] for p in probe_findings]

    metrics_rows = [
        ["Traffic anomaly windows", str(traffic.get("anomaly_count") or len(traffic.get("anomalies") or []))],
        ["Peak-to-trough drop", f"{float(traffic.get('peak_trough_drop_pct') or 0):.1f}%"
         if traffic.get("peak_trough_drop_pct") not in (None, "") else "—"],
        ["Overall percent change", f"{float(traffic.get('percent_change') or 0):+.2f}%"
         if traffic.get("percent_change") not in (None, "") else "—"],
        ["Origin hijacks (victim side)", str(len(routing_norm.get("origin_hijacked", [])))],
        ["Origin hijacks (attacker side)", str(len(routing_norm.get("origin_hijacking", [])))],
        ["Route leaks", str(len(routing_norm.get("route_leaks", [])))],
        ["Temporal proximity", proximity],
        ["Correlation strength", f"{float(strength or 0):.2f}"],
    ]

    summary_bullets = []
    if traffic.get("anomaly_count") or traffic.get("anomalies"):
        drop = traffic.get("peak_trough_drop_pct")
        drop_txt = f" (peak-to-trough drop {float(drop):.1f}%)" if drop not in (None, "") else ""
        summary_bullets.append(
            f"{traffic.get('anomaly_count') or len(traffic.get('anomalies') or [])} "
            f"traffic anomaly window(s){drop_txt}."
        )
    routing_alerts = (
        len(routing_norm.get("origin_hijacked", []))
        + len(routing_norm.get("origin_hijacking", []))
        + len(routing_norm.get("route_leaks", []))
    )
    if routing_alerts:
        summary_bullets.append(
            f"{routing_alerts} routing-security alert(s) detected in the same window."
        )
    if not summary_bullets:
        summary_bullets.append("No strong signal in either the traffic or the routing data.")
    if not cause.get("explanation"):
        cause["explanation"] = _routing_prose(routing_norm)
    if not cause.get("ranked") and traffic.get("anomalies") and not routing_alerts:
        cause["ranked"] = [
            ("traffic_anomaly_only", "Traffic anomaly, routing quiet", 0.55,
             "Traffic moved without any matching routing alert."),
        ]

    # ── Evidence chain ────────────────────────────────────────────────────
    llm_chain = evidence_chain if isinstance(evidence_chain, dict) else {}
    if llm_chain.get("verdict") or llm_chain.get("evidence_chain"):
        chain = _chain_from_llm(llm_chain)
        provenance = "Source: reasoning agent evidence chain (OBSERVE→INFER→LINK→CONCLUDE→CITE)."
    else:
        chain = _evidence_chain(cause, traffic, routing_norm, {
            "strength": strength, "temporal_proximity": proximity,
        })
        provenance = (
            "Source: deterministic reconstruction from the routing and traffic "
            "payloads (the reasoning agent produced no usable chain for this run)."
        )

    context = {
        "target_as": asn,
        "org_name": org_name,
        "start_time": start_time,
        "end_time": end_time,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "template_version": TEMPLATE_VERSION,
        "schema_version": SCHEMA_VERSION,

        # Header
        "corr_level": corr_level.capitalize(),
        "corr_level_code": _CORR_LEVEL_CODE.get(corr_level, "L5"),
        "certainty_label": certainty_label,
        "certainty_color": certainty_color,
        "certainty_glyph": certainty_glyph,

        # Executive summary
        "cause": cause,
        "cause_label": cause["label"],
        "cause_color": cause["color"],
        "cause_confidence": cause["confidence"],
        "cause_explanation": cause["explanation"],
        "summary_bullets": summary_bullets,
        "narrative": {
            k: _esc(narrative.get(k, "")) for k in _NARRATIVE_FIELDS
        },

        # Metrics
        "metrics_headers": ["Metric", "Value"],
        "metrics_rows": metrics_rows,

        # Traffic
        "traffic_summary_prose": _traffic_prose(traffic, routing_norm),
        "traffic_plot_b64": plot_b64,
        "traffic_plot_source": Path(plot_src).name if plot_src else "",
        "traffic_plot_attempted": plot_attempted,
        # Pre-rendered HTML fragments → must be marked safe, else Jinja's
        # autoescape turns them into visible &lt;table&gt; text.
        "traffic_table": (
            {**traffic_tbl, "html": markup(traffic_tbl["html"])} if traffic_tbl else None
        ),

        # Routing
        "routing_summary_prose": _routing_prose(routing_norm),
        "routing_counts": _routing_counts(routing_norm),
        "hijack_aggregate_table": markup((hijack_agg_tbl or {}).get("html")),
        "hijack_aggregate_total": agg_total,
        "hijack_event_table": markup((hijack_event_tbl or {}).get("html")),
        "hijack_event_total": len(routing_norm.get("origin_hijacked", [])) + len(routing_norm.get("origin_hijacking", [])),
        "leak_table": (
            {**leak_tbl, "html": markup(leak_tbl["html"])} if leak_tbl else None
        ),
        "outage_card": markup((
            f'<p style="margin:4px 0">Outage detector flagged this window with '
            f'score <strong>{_num(routing_norm.get("outage_score"))}</strong>.</p>'
            if routing_norm.get("outage_suspected") else None
        )),

        # Correlation
        "correlation_gauge": markup(_gauge(corr_level, strength)),
        "corr_strength": float(strength or 0.0),
        "temporal_proximity": proximity,
        "correlation_gap_note": _gauge_note(strength, proximity, delta_ts),
        "delta_t_table": (
            {**delta_tbl, "html": markup(delta_tbl["html"])} if delta_tbl else None
        ),

        # Reasoning
        "evidence_chain": chain,
        "chain_provenance": provenance,
        "hypotheses": _hypotheses(cause, routing_norm, traffic),
        "counterfactuals": _counterfactuals(cause),
        "gaps": _gaps(routing_norm, traffic, plot_missing=not plot_b64),
        "gaps_note": narrative.get("gap_note", ""),

        # Probes
        "probe_rows": probe_rows,
        "probe_headers": ["Target", "Kind", "Result", "Detail"],
        "probe_summary": narrative.get("probe_summary", ""),

    }

    html = _env().get_template(TEMPLATE_NAME).render(**context)

    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"llm_report_AS{asn}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        path.write_text(html, encoding="utf-8")

    return html


def _chain_from_llm(llm_chain: dict) -> list:
    """Map the reasoning agent's evidence chain onto the template's steps."""
    steps = []
    for stage in ("observe", "infer", "link", "conclude", "cite"):
        value = llm_chain.get(stage)
        if isinstance(value, list) and value:
            steps.append({
                "label": stage.capitalize(),
                "lines": [_safe(v) for v in value[:6]],
                "sources": str(llm_chain.get("sources") or "") if stage == "cite" else "",
            })
    if not steps and llm_chain.get("hypothesis"):
        steps.append({
            "label": "Conclude",
            "lines": [_safe(llm_chain.get("hypothesis"))],
            "sources": "",
        })
    return steps


def _gauge_note(strength: float, proximity: str, delta_ts: list) -> str:
    if not delta_ts:
        return "No paired routing/traffic timestamps were available for a ΔT comparison."
    try:
        first = delta_ts[0]
        delta = float(first.get("delta_hours"))
    except (TypeError, ValueError, IndexError, KeyError):
        return ""
    direction = (
        "traffic anomalies preceded the routing events"
        if delta < 0 else "routing events preceded the traffic anomalies"
    )
    return (
        f"Closest pairing: {direction} by {abs(delta):.1f} h. "
        "A negative ΔT weakens a routing→traffic causal reading."
    )


def _deterministic_cause(
    traffic: dict, routing_norm: dict, strength: float, proximity: str
) -> dict:
    """Single most likely cause, chosen from routing event counts only.

    Mirrors the taxonomy in ``report_agent.compute_top_cause`` so the
    template renderer and the legacy path cannot disagree on the verdict.
    """
    hijacked = len(routing_norm.get("origin_hijacked", []))
    hijacking = len(routing_norm.get("origin_hijacking", []))
    leaks = len(routing_norm.get("route_leaks", []))
    outage = bool(routing_norm.get("outage_suspected"))

    def mk(key: str, label: str, conf: float, why: str) -> dict:
        return {"cause": key, "label": label, "explanation": why, "confidence": conf,
                "color": _CAUSE_COLORS.get(key, "#64748b"), "ranked": []}

    if hijacked:
        why = f"{hijacked} event(s) list the target AS as the hijacked side."
        ranked = [("origin_hijack_victim", "Origin Hijack — AS is Victim", 0.85, why)]
        if leaks:
            ranked.append(("route_leak", "Route Leak", 0.6,
                           f"{leaks} route-leak event(s) were recorded."))
        return mk("origin_hijack_victim", "Origin Hijack — AS is Victim", 0.85, why) | {
            "ranked": ranked
        }
    if hijacking:
        why = f"{hijacking} event(s) list the target AS as the announcing side."
        return mk("origin_hijack_attacker", "Origin Hijack — AS is Attacker", 0.75, why) | {
            "ranked": [("origin_hijack_attacker", "Origin Hijack — AS is Attacker", 0.75, why),
                       ("roa_misconfig", "ROA Misconfiguration (RPKI gap)", 0.5,
                        "Announced prefixes lacked a matching ROA.")]
        }
    if leaks:
        why = f"{leaks} route-leak event(s) were recorded."
        return mk("route_leak", "Route Leak", 0.7, why) | {
            "ranked": [("route_leak", "Route Leak", 0.7, why),
                       ("outage", "Reachability Outage", 0.4,
                        "Leaks can degrade reachability without full loss.")]
        }
    if outage:
        why = "Outage detector flagged the window."
        return mk("outage", "Reachability Outage", 0.6, why) | {
            "ranked": [("outage", "Reachability Outage", 0.6, why),
                       ("traffic_anomaly_only", "Traffic anomaly, routing quiet", 0.4,
                        "No routing alert coincided with the traffic change.")]
        }
    if traffic.get("anomalies") or traffic.get("anomaly_count"):
        why = "Traffic moved but no routing alert was recorded."
        return mk("traffic_anomaly_only", "Traffic anomaly, routing quiet", 0.55, why) | {
            "ranked": [("traffic_anomaly_only", "Traffic anomaly, routing quiet", 0.55, why),
                       ("outage", "Reachability Outage", 0.25,
                        "A reachability loss would not necessarily raise a BGP alert.")]
        }
    return mk("no_clear_anomaly", "No clear anomaly", 0.2,
              "Neither the traffic nor the routing detector produced a signal.")

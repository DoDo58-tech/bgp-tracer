"""
Phase 1 (quick) HTML report renderer.

Generates a *preliminary* HTML report directly from the Phase-1 verdict +
anomaly summary.  No LLM call, no waiting: produced in < 2 seconds.  The
output is intentionally compact, evidence-rich and clearly marked as a
"Phase 1 preliminary" report so the user understands the deeper LLM-driven
analysis is still running (or will run next in auto mode).

The Phase-2 LLM-generated report (chief_agent.analyze_deep_from_quick) is
designed to overwrite this file at the SAME path, so an external dashboard
just needs to point at ``<report_path>`` and refresh.
"""
from __future__ import annotations

import html as _html
import os as _os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


# ── Verdict → human label / severity / colour mapping ─────────────────────
_VERDICT_META: Dict[str, Dict[str, str]] = {
    "real_incident": {
        "label": "Confirmed BGP Incident",
        "severity": "critical",
        "tone": "#b91c1c",
        "icon": "⚠️",
        "blurb": (
            "Both routing (BGP) and traffic signals detected a correlated anomaly. "
            "Likely a real BGP security event with measurable user impact."
        ),
    },
    "silent_alert": {
        "label": "Silent Routing Alert",
        "severity": "medium",
        "tone": "#c2410c",
        "icon": "🟧",
        "blurb": (
            "BGP detected an anomaly (hijack / leak / outage) but traffic is "
            "unchanged. The event has not yet affected end users; monitor closely."
        ),
    },
    "traffic_only": {
        "label": "Traffic Anomaly Only",
        "severity": "medium",
        "tone": "#1d4ed8",
        "icon": "🔍",
        "blurb": (
            "Traffic looks abnormal but routing is calm. The root cause is "
            "likely outside BGP scope (e.g. application / CDN / network capacity)."
        ),
    },
    "correlation_uncertain": {
        "label": "Uncertain Correlation",
        "severity": "medium",
        "tone": "#a16207",
        "icon": "❓",
        "blurb": (
            "Both BGP and traffic show anomalies, but they do NOT overlap in "
            "time. Could be a coincidence or a delayed effect — Phase-2 LLM "
            "analysis will resolve."
        ),
    },
    "no_clear_anomaly": {
        "label": "No Clear Anomaly",
        "severity": "info",
        "tone": "#15803d",
        "icon": "✅",
        "blurb": "Neither BGP nor traffic show notable anomalies in this window.",
    },
    "unknown": {
        "label": "Inconclusive",
        "severity": "info",
        "tone": "#475569",
        "icon": "ℹ️",
        "blurb": (
            "Phase-1 ran but the data was insufficient to issue a verdict. "
            "Phase-2 LLM analysis is required."
        ),
    },
}


def _esc(value):
    """HTML-escape any value, coercing None → '—'."""
    if value is None or value == "":
        return "—"
    return _html.escape(str(value), quote=False)


def _row(label, value, *, mono=False):
    val_cls = "kv-value mono" if mono else "kv-value"
    return (
        f'<tr><td class="kv-label">{_esc(label)}</td>'
        f'<td class="{val_cls}">{_esc(value)}</td></tr>'
    )


def _kv_table(rows):
    return f'<table class="kv-table"><tbody>{rows}</tbody></table>'


def _render_traffic_card(summary: Dict[str, Any]):
    rows = (
        _row("Anomaly count", summary.get("traffic_anomaly_count"))
        + _row("Signal present", summary.get("traffic_signal_present"))
        + _row("Data points", summary.get("traffic_data_points"))
        + _row("Anomaly window", summary.get("traffic_anomaly_window"), mono=True)
    )
    return _section("Traffic Signal", _kv_table(rows))


def _render_routing_card(summary: Dict[str, Any]):
    rows = (
        _row("Hijack events", summary.get("routing_hijack_count"))
        + _row("Route leaks", summary.get("routing_leak_count"))
        + _row("Outage score", summary.get("routing_outage_score"))
        + _row("Outage suspect", summary.get("routing_outage_suspect"))
    )
    return _section("Routing Signal", _kv_table(rows))


def _render_correlation_card(summary: Dict[str, Any]):
    rows = (
        _row("Level", summary.get("correlation_level"))
        + _row("Strength", summary.get("correlation_strength"))
        + _row("Method", summary.get("correlation_method"))
    )
    return _section("Correlation", _kv_table(rows))


def _section(title, body_html):
    return (
        f'<section class="card"><h2>{_esc(title)}</h2>{body_html}</section>'
    )


def render_quick_html(
    quick_result: Dict[str, Any],
    *,
    report_path: Optional[Path] = None,
    phase2_pending: bool = True,
) -> Path:
    """Render the Phase-1 preliminary HTML report.

    Args:
        quick_result: dict produced by ``analyze_quick()``.
        report_path: optional explicit destination.  Defaults to
            ``PROJECT_ROOT/results/html/quick_<asn>_<start>_<end>.html``.
        phase2_pending: if True, the banner advertises an upcoming Phase-2
            detailed LLM report.  Set False for a stand-alone quick run.

    Returns:
        Absolute Path of the written HTML file.
    """
    # Always render through this template so failure cases still produce
    # a useful HTML page instead of a blank file or stack trace.
    asn = _esc((quick_result or {}).get("asn", "?"))
    start = _esc((quick_result or {}).get("start_time", "?"))
    end = _esc((quick_result or {}).get("end_time", "?"))
    verdict = (quick_result or {}).get("quick_verdict", "unknown")
    summary = (quick_result or {}).get("anomaly_summary") or {}
    meta = _VERDICT_META.get(verdict, _VERDICT_META["unknown"])
    elapsed = (quick_result or {}).get("elapsed_seconds", 0.0)
    cache_path = (quick_result or {}).get("cache_path", "")
    ok = bool((quick_result or {}).get("success"))
    cache_hit = bool((quick_result or {}).get("cache_hit"))

    # If cache hit, show "instant" badge instead of elapsed time which would
    elapsed_label = (
        "<code>instant (cache hit)</code>" if cache_hit
        else (
            f'<code>{elapsed:.1f}s</code>'
            if isinstance(elapsed, (int, float)) else f'<code>{_esc(elapsed)}</code>'
        )
    )

    if ok:
        traffic_card = _render_traffic_card(summary)
        routing_card = _render_routing_card(summary)
        corr_card = _render_correlation_card(summary)
        verdict_blurb = meta["blurb"]
        banner_text = (
            '<strong>⏳ Phase-2 detailed LLM analysis is in progress.</strong> '
            'This preliminary report will be replaced automatically once the '
            'deep report finishes.'
            if phase2_pending
            else '<strong>ℹ️ Preliminary report only.</strong> '
                 'A Phase-2 LLM report was not requested for this run.'
        )
        banner_class = "" if phase2_pending else "done"
    else:
        traffic_card = _section(
            "Traffic Signal", '<p class="muted">Phase-1 failed; no data.</p>'
        )
        routing_card = _section(
            "Routing Signal", '<p class="muted">Phase-1 failed; no data.</p>'
        )
        corr_card = _section(
            "Correlation", '<p class="muted">Phase-1 failed; no data.</p>'
        )
        err = (quick_result or {}).get("error", "Unknown Phase-1 error")
        verdict_blurb = f"Phase-1 quick analysis failed: {_esc(err)}"
        banner_text = '<strong>Phase-1 failed.</strong> Detailed analysis is unavailable.'
        banner_class = "done"
        meta = dict(meta)
        meta["label"] = "Phase-1 Failed"
        meta["tone"] = "#7f1d1d"
        meta["icon"] = "❌"

    html_doc = _HTML_DOC_TEMPLATE.format(
        asn=asn,
        start_time=start,
        end_time=end,
        generated_at=_esc(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        verdict_label=_esc(meta["label"]),
        verdict_tone=meta["tone"],
        verdict_icon=_esc(meta["icon"]),
        verdict_blurb=verdict_blurb,
        traffic_card=traffic_card,
        routing_card=routing_card,
        correlation_card=corr_card,
        banner_text=banner_text,
        banner_class=banner_class,
        elapsed_label=elapsed_label,
        cache_path=_esc(cache_path),
        verdict=_esc(verdict),
        cache_path_line=(
            f'&middot; quick cache: <code>{_esc(cache_path)}</code>' if cache_path else ""
        ),
    )

    # Default output path
    if report_path is None:
        asn_raw = (quick_result or {}).get("asn", "?")
        start_raw = str((quick_result or {}).get("start_time", "?"))
        end_raw = str((quick_result or {}).get("end_time", "?"))
        safe_start = start_raw.replace(" ", "_").replace(":", "")
        safe_end = end_raw.replace(" ", "_").replace(":", "")
        report_path = Path(
            f"/data/bgp_tracer/results/html/quick_{asn_raw}_{safe_start}_{safe_end}.html"
        )
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write to avoid leaving a half-written HTML on crash
    tmp_path = report_path.with_suffix(report_path.suffix + ".tmp")
    tmp_path.write_text(html_doc, encoding="utf-8")
    try:
        _os.replace(tmp_path, report_path)
    except OSError:
        report_path.write_text(html_doc, encoding="utf-8")
        try:
            tmp_path.unlink()
        except OSError:
            pass
    return report_path


# ── Styling ────────────────────────────────────────────────────────────────
_HTML_DOC_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>BGP Quick Assessment — AS{asn}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{
    --bg: #f8fafc; --card: #ffffff; --ink: #0f172a; --muted: #64748b;
    --line: #e2e8f0; --accent: #2563eb;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 28px; background: var(--bg); color: var(--ink);
    font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei",
                 Helvetica, Arial, sans-serif;
    line-height: 1.5;
  }}
  .container {{ max-width: 980px; margin: 0 auto; }}
  h1 {{ margin: 0 0 4px 0; font-size: 26px; }}
  .meta {{ color: var(--muted); font-size: 13px; margin-bottom: 16px; }}
  .verdict-banner {{
    background: var(--card); border: 1px solid var(--line);
    border-left: 6px solid {verdict_tone};
    border-radius: 8px; padding: 16px 20px; margin: 16px 0 24px 0;
    display: flex; align-items: center; gap: 14px;
  }}
  .verdict-banner .icon {{ font-size: 32px; }}
  .verdict-banner .label {{ font-size: 19px; font-weight: 600; color: {verdict_tone}; }}
  .verdict-banner .blurb {{ margin-top: 4px; color: var(--ink); font-size: 14px; }}
  .phase-banner {{
    background: #fef9c3; border: 1px solid #fde047; color: #713f12;
    padding: 10px 14px; border-radius: 6px; margin: 12px 0 18px 0;
    font-size: 13px;
  }}
  .phase-banner.done {{ background: #f1f5f9; border-color: #cbd5e1; color: #334155; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
  .card {{
    background: var(--card); border: 1px solid var(--line); border-radius: 8px;
    padding: 16px 18px;
  }}
  .card h2 {{
    margin: 0 0 10px 0; font-size: 15px; text-transform: uppercase;
    letter-spacing: 0.04em; color: var(--muted);
  }}
  .kv-table {{ width: 100%; border-collapse: collapse; }}
  .kv-table td {{ padding: 6px 8px; vertical-align: top; border-bottom: 1px solid var(--line); font-size: 14px; }}
  .kv-table tr:last-child td {{ border-bottom: 0; }}
  .kv-label {{ color: var(--muted); width: 38%; }}
  .kv-value {{ color: var(--ink); font-weight: 500; }}
  .kv-value.mono {{ font-family: "JetBrains Mono", Menlo, Consolas, monospace; font-size: 13px; }}
  .muted {{ color: var(--muted); font-size: 13px; margin: 0; }}
  footer {{
    margin-top: 28px; color: var(--muted); font-size: 12px; text-align: center;
  }}
  code {{ background: #f1f5f9; padding: 1px 6px; border-radius: 4px; }}
</style>
</head>
<body>
<div class="container">
  <h1>BGP Quick Assessment — AS{asn}</h1>
  <div class="meta">
    Analysis window: <code>{start_time}</code> → <code>{end_time}</code>
    &nbsp;|&nbsp; generated at <code>{generated_at}</code>
    &nbsp;|&nbsp; elapsed {elapsed_label}
  </div>

  <div class="verdict-banner">
    <div class="icon">{verdict_icon}</div>
    <div>
      <div class="label">{verdict_label}</div>
      <div class="blurb">{verdict_blurb}</div>
    </div>
  </div>

  <div class="phase-banner {banner_class}">{banner_text}</div>

  <div class="cards">
    {traffic_card}
    {routing_card}
    {correlation_card}
  </div>

  <footer>
    Phase-1 preliminary report &middot; no LLM was invoked &middot;
    verdict code: <code>{verdict}</code>
    {cache_path_line}
  </footer>
</div>
</body>
</html>
"""

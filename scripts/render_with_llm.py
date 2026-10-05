"""End-to-end test: real LLM narrative → structure-locked template.

This exercises the NEW path exactly as production will:

    analysis payload
        → build a compact LLM context
        → LLM returns JSON prose (never HTML)
        → parse defensively
        → render the fixed template
        → audit the three production defects

It also reports what the LLM actually returned, so a regression in the JSON
contract is visible rather than silently falling back to Python prose.

Usage::

    python scripts/render_with_llm.py [max_events]
"""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.report_template import (  # noqa: E402
    normalize_routing,
    preview_name,
    render_report,
    request_llm_narrative,
    window_from_artifact_name,
)

JSON_DIR = ROOT / "results" / "json"
OUT = ROOT / "results" / "template_preview"
OUT.mkdir(parents=True, exist_ok=True)

MAX_EVENTS = int(sys.argv[1]) if len(sys.argv) > 1 else 3


def _extract(doc: dict) -> tuple:
    reasoning = doc.get("reasoning_result") or {}
    evidence = reasoning.get("evidence_summary") or {}
    traffic = evidence.get("traffic_data") or {}
    routing = evidence.get("routing_data") or {}
    if isinstance(traffic, dict) and isinstance(traffic.get("result"), dict):
        traffic = traffic["result"]
    if isinstance(routing, dict) and isinstance(routing.get("result"), dict):
        routing = routing["result"]
    asn = str(traffic.get("asn") or routing.get("asn") or reasoning.get("asn") or "unknown")
    correlation = doc.get("causal_analysis") if isinstance(doc.get("causal_analysis"), dict) else {}
    for holder in (reasoning, doc):
        for key in ("correlation_analysis", "correlation"):
            if isinstance(holder.get(key), dict) and holder[key]:
                correlation = holder[key]
                break
    # The timestamps live in several places depending on which detector wrote
    # the artifact: traffic.start_time / end_time, the anomaly window, or the
    # routing payload. Probe them in order and fall back to the artifact
    # filename (which always embeds the window) so the preview filename never
    # degrades to "unknown".
    start = str(traffic.get("start_time") or traffic.get("start") or "")
    end = str(traffic.get("end_time") or traffic.get("end") or "")
    win = traffic.get("traffic_anomaly_window")
    if isinstance(win, dict):
        start = start or str(win.get("start") or "")
        end = end or str(win.get("end") or "")
    elif isinstance(win, str) and " to " in win:
        left, _, right = win.partition(" to ")
        start = start or left.strip()
        end = end or right.strip()
    if not start:
        start = str(routing.get("start_time") or routing.get("analysis_start") or "")
    if not start:
        m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2})[:-](\d{2})", str(doc.get("analysis_window") or ""))
        if m:
            start = f"{m.group(1)} {m.group(2)}:{m.group(3)}"
    return asn, start or "unknown", end or start or "unknown", traffic, routing, correlation


def build_llm_context(asn: str, traffic: dict, routing_norm: dict) -> dict:
    """Compact, LLM-friendly summary of the facts.

    Only derived facts go in — never raw event lists. This keeps the prompt
    small (so the call cannot time out) and stops the model from having to
    do arithmetic that Python already did.
    """
    hijacked = len(routing_norm.get("origin_hijacked", []))
    hijacking = len(routing_norm.get("origin_hijacking", []))
    leaks = len(routing_norm.get("route_leaks", []))
    sample_leaks = [
        {
            "prefix": e.get("prefix"),
            "leak_score": e.get("leak_probability"),
        }
        for e in (routing_norm.get("route_leaks") or [])[:3]
        if e.get("prefix")
    ]
    sample_hijack = [
        {"prefix": e.get("prefix"),
         "announcing_as": e.get("origin_as") or e.get("hijacker_as"),
         "victim_as": e.get("victim_as")}
        for e in (routing_norm.get("origin_hijacked", []) +
                  routing_norm.get("origin_hijacking", []))[:3]
        if e.get("prefix")
    ]
    return {
        "target_as": asn,
        "traffic": {
            "anomaly_windows": traffic.get("anomaly_count") or len(traffic.get("anomalies") or []),
            "peak_trough_drop_pct": traffic.get("peak_trough_drop_pct"),
            "percent_change": traffic.get("percent_change"),
            "max_severity": traffic.get("max_severity"),
            "baseline_method": traffic.get("baseline_method"),
        },
        "routing": {
            "origin_hijacked_events": hijacked,
            "origin_hijacking_events": hijacking,
            "route_leak_events": leaks,
            "outage_suspected": routing_norm.get("outage_suspected"),
            "outage_score": routing_norm.get("outage_score"),
            "sample_hijack_events": sample_hijack,
            "sample_leak_events": sample_leaks,
        },
    }


def audit(name: str, html: str) -> list:
    issues = []
    head = re.sub(r"/\*.*?\*/", "", html.split("</style>")[0], flags=re.S)
    widths = []
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", head):
        for w in re.findall(r"max-width\s*:\s*([^;}]+)", m.group(2)):
            if w.strip() not in ("100%", "none") and re.search(r"\d", w):
                widths.append((m.group(1).strip(), w.strip()))
    if len(widths) != 1 or widths[0][0] != ".report":
        issues.append(f"width authorities = {widths}")

    if "&lt;table" in html or "&lt;div" in html:
        issues.append("HTML fragment double-escaped")
    for tok in ("{{", "{%"):
        if tok in html:
            issues.append(f"unrendered token {tok!r}")
    if 'src="data:image/png;base64,' not in html and "No traffic plot artifact" not in html:
        issues.append("chart missing with no gap notice")
    return issues


def main() -> int:
    from llm.llm_factory import setup_llm_settings
    from config import MODEL, API_KEY, BASE_URL

    llm, _ = setup_llm_settings(
        model=MODEL, api_key=API_KEY, base_url=BASE_URL,
        temperature=0.3, timeout=180.0, max_retries=2,
    )

    artifacts = []
    for path in sorted(JSON_DIR.glob("traffic_outage_analysis_*.json"),
                       key=lambda p: p.stat().st_mtime, reverse=True):
        if path.stat().st_size < 1_000_000:
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        if not (doc.get("reasoning_result") or {}).get("evidence_summary"):
            continue
        artifacts.append((path, doc))
    if not artifacts:
        print("no usable artifacts")
        return 1

    all_issues = []
    for path, doc in artifacts[:MAX_EVENTS]:
        asn, start, end, traffic, routing, correlation = _extract(doc)
        # Last resort for the preview filename: the artifact filename always
        # embeds the analysis window, so use it when the payload omitted it.
        if start == "unknown" or not start:
            f_start, f_end = window_from_artifact_name(path.stem)
            if f_start:
                start = f_start
                if end in ("unknown", start, ""):
                    end = f_end or f_start
        routing_norm = normalize_routing(routing)
        context = build_llm_context(asn, traffic, routing_norm)

        t0 = time.time()
        narrative = request_llm_narrative(llm, context)
        elapsed = time.time() - t0

        filled = [k for k, v in narrative.items() if v]
        print(f"\n=== AS{asn}  (LLM took {elapsed:.1f}s, {len(filled)}/6 narrative fields) ===")
        for key in ("executive_note", "mechanism", "traffic_analysis",
                    "routing_analysis", "hypothesis_note", "gap_note"):
            value = (narrative.get(key) or "").strip()
            if not value:
                print(f"  [empty → Python fallback] {key}")
            else:
                print(f"  {key}: {value[:150]}{'…' if len(value) > 150 else ''}")

        html = render_report(
            asn=asn, start_time=start, end_time=end,
            traffic_result=traffic, routing_result=routing,
            correlation_analysis=correlation,
            narrative=narrative,
            narrative_source="llm-json" if filled else "python-fallback",
        )
        out = OUT / preview_name(asn, start, end)
        out.write_text(html, encoding="utf-8")

        issues = audit(out.name, html)
        print(f"  -> {out.name}  ({len(html)//1024} KB)")
        for issue in issues:
            print(f"     - {issue}")
        all_issues.extend(issues)

    print("\nTOTAL ISSUES:", len(all_issues))
    return 1 if all_issues else 0


if __name__ == "__main__":
    raise SystemExit(main())

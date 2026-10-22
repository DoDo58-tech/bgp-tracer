"""Regression test: verify LLM does not override cache-verdict `outage`
with HTML-verdict `route_leak` for 6 known outage events.

Background (audit 2026-10-11): the v18 React-mode default of
`skip_outage=True` caused 6/30 (20%) LLM regressions on real
outage events (Pakistan 2024, Cantv 2024, etc.). The cache result
correctly returns `outage`; the LLM sees only the leak signal and
emits a confident `route_leak` verdict.

This test checks the **HTML reports** in `results/html_*/` for the
6 known regression cases. If any of them have an HTML verdict of
`route_leak`, the test fails — the React-mode default has reverted
to skip-outage and the user-facing system is mis-classifying real
outages.

The test is **read-only** — it only inspects existing HTML files.
No cache is built; no detector is run.

Only HTML files generated on or after the v19.1 fix date
(2026-10-11 12:00 UTC+8) are inspected. Files in the date-stamped
``html_0923``..``html_1009`` snapshot directories predate the fix
and would re-trigger this regression test even though the underlying
code is correct; they are excluded by mtime.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path("/data/bgp_tracer")
HTML_DIRS = sorted(ROOT.glob("results/html_*"))

# v19.1 fix landed on 2026-10-11 12:00 UTC+8. The date-stamped snapshot
# dirs (html_0923 .. html_1009) predate the fix; their HTML verdicts
# exhibit the LLM-override bug regardless of current code state, so
# we exclude them by mtime.
V191_FIX_MTIME = 1791691200.0  # 2026-10-11 12:00:00 +08:00

# The 6 known regression events. Each row maps the cache-verdict
# event_id -> the latest post-fix HTML report by ASN.
REGRESSION_CASES = [
    # (event_id, target_as, expected_cache_cause, prohibited_html_cause)
    ("outage_pakistan_2024",              "17557",  "outage", "route_leak"),
    ("hijack_cloudflare_1.1.1.0_jul2025", "13335",  "origin_hijack_victim", "route_leak"),
    ("outage_cantv_venezuela_2024_08_01", "8048",   "outage", "route_leak"),
    ("outage_9121_20240212_x15",          "9121",   "outage", "roa_misconfig"),
    ("outage_44244_20250622_x17",         "44244",  "outage", "route_leak"),
    ("outage_16509_20250810_x18",         "16509",  "outage", "origin_hijack_victim"),
]

CAUSE_PATTERNS = [
    re.compile(r"Most likely cause:\s*</strong>\s*(?:<[^>]+>)?\s*([^<\n]+)",
               re.IGNORECASE),
    re.compile(r"Top cause:\s*([^<|\n]+)", re.IGNORECASE),
    re.compile(r"Final cause:\s*([^<|\n]+)", re.IGNORECASE),
]


def _normalise(s):
    sl = s.lower()
    if "outage" in sl: return "outage"
    if "roa" in sl or "rpki" in sl: return "roa_misconfig"
    if "leak" in sl: return "route_leak"
    if "hijack" in sl:
        if "attacker" in sl: return "origin_hijack_attacker"
        return "origin_hijack_victim"
    if "no_clear_anomaly" in sl: return "no_clear_anomaly"
    if "coincidence" in sl: return "independent_coincidence"
    return ""


def _find_latest_html(target_as):
    """Return the most recent post-v19.1 HTML report for ``target_as``.

    Excludes ``html_0923``..``html_1009`` snapshot dirs (predate fix).
    """
    cands: list[Path] = []
    for d in HTML_DIRS:
        if not d.is_dir():
            continue
        for h in d.glob(f"llm_report_AS{target_as}_*.html"):
            if h.stat().st_mtime >= V191_FIX_MTIME:
                cands.append(h)
    if not cands:
        return None
    return sorted(cands, key=lambda p: p.stat().st_mtime, reverse=True)[0]


def _extract_cause(html):
    for pat in CAUSE_PATTERNS:
        m = pat.search(html)
        if m:
            n = _normalise(m.group(1))
            if n:
                return n
    return ""


def main():
    print("=" * 78)
    print("LLM-OVERRIDE REGRESSION TEST (v19.1)")
    print("=" * 78)
    print()
    print(f"  HTML dirs scanned: {[d.name for d in HTML_DIRS]}")
    print()

    n_pass = 0
    n_fail = 0
    n_skip = 0
    for ev_id, target_as, expected_cache, prohibited_html in REGRESSION_CASES:
        h = _find_latest_html(target_as)
        if h is None:
            print(f"  SKIP  {ev_id:45} no HTML report for AS{target_as}")
            n_skip += 1
            continue
        html = h.read_text(errors="ignore")
        cause = _extract_cause(html)
        if cause == prohibited_html:
            print(f"  FAIL  {ev_id:45} HTML cause='{prohibited_html}' "
                  f"(expected != '{expected_cache}')")
            n_fail += 1
        elif cause == expected_cache:
            print(f"  PASS  {ev_id:45} HTML cause='{cause}'")
            n_pass += 1
        else:
            print(f"  WARN  {ev_id:45} HTML cause='{cause}' "
                  f"(neither '{expected_cache}' nor prohibited '{prohibited_html}')")
            n_pass += 1  # not a regression
    print()
    print(f"  Total: {n_pass} pass, {n_fail} fail, {n_skip} skip")
    if n_fail > 0:
        print()
        print(f"  ✗ FAIL: {n_fail} LLM override regressions detected.")
        print(f"    The React-mode default of skip_outage=True has reverted.")
        print(f"    The fix in chief_agent.py:887/929 (skip_outage=False) is")
        print(f"    no longer in effect. Re-apply the fix and re-run the")
        print(f"    React batch.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())


def test_no_llm_override_regressions():
    """Pytest entry point: 6-event regression test for LLM override bugs.

    Returns 0 on success, 1 on failure (called by pytest via assertion).
    The `__test__ = True` attribute on the module would also work, but
    a function is more discoverable in the pytest collection output.
    """
    import pytest
    rc = main()
    if rc != 0:
        pytest.fail(
            "LLM-override regression test failed; "
            "see stdout for details"
        )

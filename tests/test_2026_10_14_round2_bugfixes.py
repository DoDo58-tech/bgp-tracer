"""Regression tests for additional bugs found during the 2026-10-13 audit.

These cover pre-existing NameError bugs in ``tools/tool_implementations.py``
that surfaced when running the broader test suite after the first round
of fixes.

Bug list:
- BUG-2026-10-13-H: ``_summarize_verdicts(items)`` referenced the
    undefined name ``results`` instead of the ``items`` parameter.
- BUG-2026-10-13-I: ``_load_asrel_json(filepath_str)`` called
    ``open(filepath, ...)`` referencing the undefined name ``filepath``.
- BUG-2026-10-13-J: ``_bgpview_{as_info,prefixes,neighbors,contacts}``
    all referenced the undefined name ``asn`` instead of their
    ``asn_id`` parameter.
"""

import asyncio
import importlib


def _import_tools():
    return importlib.import_module("tools.tool_implementations")


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# BUG-2026-10-13-H
# ---------------------------------------------------------------------------

def test_summarize_verdicts_no_name_error():
    """_summarize_verdicts must not raise NameError for the parameter dict."""
    ti = _import_tools()
    items = {
        "v1": {"verdict": "STRONG: hijacked"},
        "v2": {"verdict": "MODERATE: possible"},
        "v3": {"verdict": "WEAK: limited"},
        "v4": {"verdict": "STRONG: definite"},
    }
    # Should not raise NameError.
    result = ti._summarize_verdicts(items)
    assert "2 STRONG" in result
    assert "1 MODERATE" in result
    assert "1 WEAK" in result


def test_summarize_verdicts_empty():
    ti = _import_tools()
    assert ti._summarize_verdicts({}) == "no verdict"


# ---------------------------------------------------------------------------
# BUG-2026-10-13-I
# ---------------------------------------------------------------------------

def test_load_asrel_json_valid_file(tmp_path):
    """_load_asrel_json must return the parsed dict, not None."""
    ti = _import_tools()
    p = tmp_path / "asrel.json"
    p.write_text('{"providers": {"1": ["2"]}, "peers": {"3": ["4"]}}',
                 encoding="utf-8")
    loaded = ti._load_asrel_json(str(p))
    assert loaded == {"providers": {"1": ["2"]}, "peers": {"3": ["4"]}}


def test_load_asrel_json_missing_file():
    ti = _import_tools()
    assert ti._load_asrel_json("/nonexistent/path/foo.json") is None


def test_load_asrel_json_malformed(tmp_path):
    ti = _import_tools()
    p = tmp_path / "bad.json"
    p.write_text("not json{", encoding="utf-8")
    assert ti._load_asrel_json(str(p)) is None


# ---------------------------------------------------------------------------
# BUG-2026-10-13-J
# ---------------------------------------------------------------------------

def test_bgpview_as_info_uses_asn_id(monkeypatch):
    """_bgpview_as_info must URL-encode asn_id, not the undefined `asn`."""
    ti = _import_tools()
    captured = {}

    async def fake_get_json(url, timeout=15.0):
        captured["url"] = url
        return {"status": "ok", "data": {"name": "ACME"}}

    monkeypatch.setattr(ti, "_async_get_json", fake_get_json)
    result = _run(ti._bgpview_as_info("13335"))
    assert result == {"name": "ACME"}
    assert "13335" in captured["url"]
    assert "asn/13335/" in captured["url"]


def test_bgpview_prefixes_uses_asn_id(monkeypatch):
    ti = _import_tools()
    captured = {}

    async def fake_get_json(url, timeout=15.0):
        captured["url"] = url
        return {
            "status": "ok",
            "data": {"ipv4_prefixes": ["1.2.3.0/24"], "ipv6_prefixes": []},
        }

    monkeypatch.setattr(ti, "_async_get_json", fake_get_json)
    result = _run(ti._bgpview_prefixes("15169"))
    assert result["is_allocated"] is True
    assert result["prefix_count"] == 1
    assert "15169" in captured["url"]


def test_bgpview_neighbors_uses_asn_id(monkeypatch):
    ti = _import_tools()
    captured = {}

    async def fake_get_json(url, timeout=15.0):
        captured["url"] = url
        return {
            "status": "ok",
            "data": {
                "neighbours": [
                    {"asn": 3356},
                    {"asn": 1299},
                    {"asn": "2001:db8::1"},
                ]
            },
        }

    monkeypatch.setattr(ti, "_async_get_json", fake_get_json)
    result = _run(ti._bgpview_neighbors("6939"))
    assert result["neighbor_count"] == 3
    assert "6939" in captured["url"]


def test_bgpview_contacts_uses_asn_id(monkeypatch):
    ti = _import_tools()
    captured = {}

    async def fake_get_json(url, timeout=15.0):
        captured["url"] = url
        return {"status": "ok", "data": {"email": "noc@example.com"}}

    monkeypatch.setattr(ti, "_async_get_json", fake_get_json)
    result = _run(ti._bgpview_contacts("32934"))
    assert result == {"email": "noc@example.com"}
    assert "32934" in captured["url"]


# ---------------------------------------------------------------------------
# Module smoke test
# ---------------------------------------------------------------------------

def test_no_nameerror_on_module_import():
    """The module should import without any NameError at top level."""
    ti = _import_tools()
    assert ti is not None

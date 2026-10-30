"""An unreachable third-party API must not abort a workflow event.

The ground-truth evaluation run produced 34 unscoreable events out of
40.  Every one of them died with the same traceback::

    requests.exceptions.ConnectionError: HTTPSConnectionPool(
        host='api.bgpview.io', port=443): Max retries exceeded with url:
        /asn/29256/info (Caused by NameResolutionError(...))

``async_get_json`` guarded its network call with ``except (ValueError)``.
``requests`` raises ``ConnectionError`` on a DNS failure and
``RequestException`` on every other transport problem; neither is a
``ValueError``, so the exception escaped the helper, escaped the
workflow stage that requested it, and the whole event ended in
``WorkflowState.ERROR`` — no verdict, no evidence board, no report.

An unreachable BGPView is an *absent observation*, not a fatal error.
The analysis still has routing telemetry, traffic telemetry and the
RPKI cache; it can reach a verdict on those.  These tests pin that
contract.
"""

from __future__ import annotations

import asyncio

import pytest
import requests

from tools.tool_implementations import async_get_json, bgpview_as_info


def test_async_get_json_returns_none_on_connection_error(monkeypatch):
    def boom(*args, **kwargs):
        raise requests.exceptions.ConnectionError("Name or service not known")

    monkeypatch.setattr(requests, "get", boom)

    assert asyncio.run(async_get_json("https://api.bgpview.io/asn/1/info")) is None


def test_async_get_json_returns_none_on_timeout(monkeypatch):
    def boom(*args, **kwargs):
        raise requests.exceptions.ReadTimeout("timed out")

    monkeypatch.setattr(requests, "get", boom)

    assert asyncio.run(async_get_json("https://api.bgpview.io/asn/1/info")) is None


def test_async_get_json_returns_none_on_non_200(monkeypatch):
    class FakeResp:
        status_code = 503

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())

    assert asyncio.run(async_get_json("https://api.bgpview.io/asn/1/info")) is None


def test_async_get_json_returns_none_on_malformed_json(monkeypatch):
    class FakeResp:
        status_code = 200

        def json(self):
            raise ValueError("Expecting value: line 1 column 1")

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())

    assert asyncio.run(async_get_json("https://api.bgpview.io/asn/1/info")) is None


def test_bgpview_helpers_return_empty_dict_when_unreachable(monkeypatch):
    def boom(*args, **kwargs):
        raise requests.exceptions.ConnectionError("Name or service not known")

    monkeypatch.setattr(requests, "get", boom)

    assert asyncio.run(bgpview_as_info("64496")) == {}

"""Test the LLM response cache.

The cache is a correctness-sensitive component: a key that is too loose
returns the wrong response, and a key that is too tight never hits.  The
tests below cover both directions — that identical requests hit, that
any change to the request misses, and that a stored response round-trips
through the JSON-mode extraction path.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.llm_cache import (  # noqa: E402
    cache_enabled,
    cache_get,
    cache_key,
    cache_put,
    cache_reset_stats,
    cache_stats,
)


def test_identical_requests_share_a_key() -> None:
    a = cache_key("prompt text", model="m", temperature=0.1)
    b = cache_key("prompt text", model="m", temperature=0.1)
    assert a == b, "identical requests must share a key"


def test_every_request_parameter_changes_the_key() -> None:
    base = cache_key("p", model="m", temperature=0.1, json_mode=False,
                     max_tokens=1024)
    variants = [
        cache_key("q", model="m", temperature=0.1, json_mode=False, max_tokens=1024),
        cache_key("p", model="n", temperature=0.1, json_mode=False, max_tokens=1024),
        cache_key("p", model="m", temperature=0.2, json_mode=False, max_tokens=1024),
        cache_key("p", model="m", temperature=0.1, json_mode=True, max_tokens=1024),
        cache_key("p", model="m", temperature=0.1, json_mode=False, max_tokens=2048),
        cache_key("p", model="m", temperature=0.1, json_mode=False,
                  max_tokens=1024, extra={"seed": 7}),
    ]
    for other in variants:
        assert other != base, "a changed request parameter must change the key"


def test_round_trip(tmp_path) -> None:
    directory = Path(tmp_path)
    directory.mkdir(parents=True, exist_ok=True)
    key = cache_key("round trip", model="m")
    assert cache_get(key, directory) is None
    cache_put(key, "the answer", directory, model="m", agent="test")
    assert cache_get(key, directory) == "the answer"
    cache_put(key, "second answer", directory, model="m")
    # A later write must not shadow the first: the first hit wins.
    assert cache_get(key, directory) == "the answer"


def test_stats_reflect_activity(tmp_path) -> None:
    directory = Path(tmp_path)
    cache_reset_stats()
    key = cache_key("stat probe", model="m")
    cache_get(key, directory)
    cache_put(key, "x", directory)
    cache_get(key, directory)
    stats = cache_stats(directory)
    assert stats["hits"] >= 1, stats
    assert stats["misses"] >= 1, stats
    assert stats["writes"] >= 1, stats


def test_cache_is_off_by_default() -> None:
    assert cache_enabled() is False, "the cache must be opt-in"


def test_json_payload_survives_the_store(tmp_path) -> None:
    directory = Path(tmp_path)
    key = cache_key("json", model="m", json_mode=True)
    payload = {"cause": "route_leak", "confidence": 0.5}
    cache_put(key, json.dumps(payload), directory)
    text = cache_get(key, directory)
    assert json.loads(text) == payload


def main() -> int:
    import tempfile

    tests = [
        test_identical_requests_share_a_key,
        test_every_request_parameter_changes_the_key,
        test_round_trip,
        test_stats_reflect_activity,
        test_cache_is_off_by_default,
        test_json_payload_survives_the_store,
    ]
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        for test in tests:
            try:
                if test.__code__.co_argcount:
                    test(Path(tmp))
                else:
                    test()
                print(f"PASS {test.__name__}")
            except AssertionError as exc:
                failures.append((test.__name__, str(exc)))
                print(f"FAIL {test.__name__}: {exc}")
    print()
    print(f"{len(tests) - len(failures)}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

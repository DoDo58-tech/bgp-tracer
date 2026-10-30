"""Tests for the PathProb direction handling in the leak detector.

The PathProb probability table is stored under unordered keys: a link
filed under ``(min, max)`` carries, in slot 0, the probability that the
smaller AS provides the larger one and, in slot 2, the probability that
the larger provides the smaller.  A path hop is directed, so the two
slots have to be selected according to the hop's direction.  Reading slot
0 unconditionally swaps the provider and customer roles on descending
hops.

The tests below pin the behaviour against the reference formulation used
by the upstream PathProb implementation, which looks the directed pair
up first and falls back to the reversed pair with the slots swapped.
"""
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detectors.leak.leak_detector import (  # noqa: E402
    detect_leak_by_prob,
    detect_route_leaks_vectorized,
)


def reference_prob(path, table):
    """Upstream PathProb composition over the same unordered table."""
    if len(path) < 2:
        return 1.0
    prob = 1.0
    c2p0 = 1.0
    for i in range(len(path) - 1):
        as1, as2 = int(path[i]), int(path[i + 1])
        link = (as1, as2)
        if link in table:
            p2c, _, c2p = table[link]
        elif link[::-1] in table:
            c2p, _, p2c = table[link[::-1]]
        else:
            continue
        prob = min(p2c + c2p0 - p2c * c2p0, prob)
        c2p0 = c2p
    return prob


def random_table(rng, n_links=60):
    table = {}
    for _ in range(n_links):
        a = rng.randint(1, 4000)
        b = rng.randint(1, 4000)
        if a == b:
            continue
        p2c = round(rng.uniform(0.0, 1.0), 4)
        c2p = round(rng.uniform(0.0, 1.0), 4)
        table[(min(a, b), max(a, b))] = [p2c, 0.0, c2p]
    return table


def test_matches_reference_on_random_paths():
    rng = random.Random(20241030)
    table = random_table(rng)
    for _ in range(400):
        length = rng.randint(2, 6)
        path = [str(rng.randint(1, 4000)) for _ in range(length)]
        _, got = detect_leak_by_prob(path, table, 0.4)
        want = reference_prob(path, table)
        assert abs(got - want) < 1e-9, (path, got, want)


def test_descending_hop_differs_from_the_unordered_reading():
    """The fix must change the score on a descending hop.

    Reading slot 0 unconditionally -- i.e. ignoring the direction of the
    hop -- is what the detector used to do.  On a descending hop that
    swaps the provider and customer roles, so the score has to move.
    """
    table = {(100, 200): [0.9, 0.0, 0.1]}
    _, directed = detect_leak_by_prob(["200", "100"], table, 0.4)
    unordered = 0.9
    assert abs(directed - unordered) > 1e-9, directed


def test_descending_hop_uses_reverse_slot():
    # Slot 0: P(100 provides 200) = 0.9.  Slot 2: P(200 provides 100) = 0.1.
    table = {(100, 200): [0.9, 0.0, 0.1]}
    _, ascending = detect_leak_by_prob(["100", "200"], table, 0.4)
    _, descending = detect_leak_by_prob(["200", "100"], table, 0.4)
    assert ascending != descending


def test_missing_link_is_skipped():
    is_leak, prob = detect_leak_by_prob(["100", "999"], {(100, 200): [0.9, 0.0, 0.1]}, 0.4)
    assert not is_leak
    assert abs(prob - 1.0) < 1e-9


def test_short_path_is_not_a_leak():
    is_leak, prob = detect_leak_by_prob(["100"], {(100, 200): [0.9, 0.0, 0.1]}, 0.4)
    assert not is_leak
    assert abs(prob - 1.0) < 1e-9


def test_vectorized_matches_scalar():
    """The fast vectorised path must agree with the scalar reference."""
    import polars as pl

    rng = random.Random(99)
    table = random_table(rng, n_links=120)
    paths = []
    for _ in range(60):
        length = rng.randint(2, 6)
        paths.append(" ".join(str(rng.randint(1, 4000)) for _ in range(length)))

    df = pl.DataFrame({
        "as-path": paths,
        "prefix": [f"{i}.0.0.0/24" for i in range(len(paths))],
        "timestamp": ["2025-01-01 00:00:00"] * len(paths),
    })
    leaks = detect_route_leaks_vectorized(df, table, 0.4, max_leaks=0)
    got = sorted(e["prefix"] for e in leaks)
    want = sorted(
        f"{i}.0.0.0/24" for i, path in enumerate(paths)
        if reference_prob(path.split(), table) < 0.4
    )
    assert got == want, (len(got), len(want))

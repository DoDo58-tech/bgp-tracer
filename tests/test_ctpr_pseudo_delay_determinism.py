"""Regression test for the CTPR pseudo-delay determinism fix.

The CTPR chain pseudo-delay is documented as a *deterministic* placeholder,
but it was previously computed with Python's builtin ``hash()`` on a
``str``/``tuple``. Builtin string hashing is salted per-process via
``PYTHONHASHSEED``, so the placeholder -- and therefore any downstream
chain ranking or reported pseudo-delay -- varied between otherwise
identical runs. That directly contradicts the paper's reproducibility
claim ("a re-run with the same inputs produces the same hash").

These tests pin the property that matters:
  1. Within a process, the value is a pure function of its arguments.
  2. Across processes with *different* ``PYTHONHASHSEED`` values, the
     value is identical (the actual regression).
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.causal_attribution import ctpr_step_pseudo_delay  # noqa: E402

PROBE = (
    "import sys; sys.path.insert(0, %r); "
    "from agents.causal_attribution import ctpr_step_pseudo_delay as d; "
    "print(d(202701, 202702), d(15169, 15170), d('64500', '64501'))"
) % str(ROOT)


def _run_with_seed(seed: str) -> tuple:
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = seed
    out = subprocess.run(
        [sys.executable, "-c", PROBE],
        capture_output=True, text=True, env=env, timeout=120,
    )
    assert out.returncode == 0, out.stderr
    return tuple(int(v) for v in out.stdout.split())


class TestCtprPseudoDelayDeterminism:
    def test_pure_function_within_process(self):
        """Same inputs -> same output, within one process."""
        a = ctpr_step_pseudo_delay(202701, 202702)
        b = ctpr_step_pseudo_delay(202701, 202702)
        assert a == b

    def test_bounded_range(self):
        """Pseudo-delay stays inside the documented [60, 180) second band."""
        for f, t in [(202701, 202702), (15169, 15170), (1, 2), (64500, 64501)]:
            d = ctpr_step_pseudo_delay(f, t)
            assert 60 <= d < 180, f"pseudo-delay {d} outside [60, 180) for {f}->{t}"

    def test_none_args_floor(self):
        """A missing endpoint floors at the 60s lower bound."""
        assert ctpr_step_pseudo_delay(None, 202702) == 60
        assert ctpr_step_pseudo_delay(202701, None) == 60

    def test_stable_across_hash_seeds(self):
        """REGRESSION: value must not depend on PYTHONHASHSEED.

        With the old ``hash((f, t))`` implementation this failed for at
        least one of the seeds probed, because string/tuple hashing is
        salted per process.
        """
        results = [_run_with_seed(seed) for seed in ("0", "1", "424242", "999999")]
        assert len(set(results)) == 1, (
            f"pseudo-delay varies with PYTHONHASHSEED: {results}"
        )

    def test_zero_jitter_forces_constant(self):
        """BGP_TRACER_CTPR_PSEUDO_DELAY_JITTER=0 disables jitter entirely."""
        os.environ["BGP_TRACER_CTPR_PSEUDO_DELAY_JITTER"] = "0"
        try:
            assert ctpr_step_pseudo_delay(202701, 202702) == 60
            assert ctpr_step_pseudo_delay(15169, 15170) == 60
        finally:
            os.environ.pop("BGP_TRACER_CTPR_PSEUDO_DELAY_JITTER", None)
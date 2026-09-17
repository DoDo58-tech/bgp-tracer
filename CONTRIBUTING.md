# Contributing to bgp_tracer

Thanks for your interest! This project is an academic artefact built
around BGP anomaly attribution. We follow the **ponytail** principle:
*small, focused, root-cause-driven*.

## Quick start

```bash
git clone <repo>
cd bgp_tracer
pip install -r requirements.txt
bash scripts/run_tests.sh fast     # pure unit tests in ≤30 s
```

## Code style

- Python 3.12+, type hints preferred for new code.
- Run `bash scripts/lint.sh` before submitting a PR.
- No new silent `except Exception` blocks unless accompanied by a
  warning log + a comment explaining the fallback policy.
- Tests live under `tests/` and are tagged `fast` (default), `slow`,
  or `network`. The CI only runs `fast` + `import smoke`.

## Adding a new detector

1. Add a module under `detectors/<name>/` containing a single class
   with `analyze(...) -> dict`.
2. Register it in `detectors/__init__.py` and in `chief_agent.py`'s
   detector dispatch.
3. Add fast tests in `tests/test_<name>.py` covering:
   - clean input (`result == expected`)
   - noisy input (assert graceful degradation)
   - key-name stability (no free-form strings in API responses)
4. Update `docs/DETECTORS.md` (or add it if missing).

## Adding a new mode

1. Edit `chief_agent.py`'s `--mode` argparse to accept the new value.
2. Reuse the chief-agent dispatch, do not fork the workflow.
3. Add a fast test verifying the CLI accepts the mode and exits 0
   on `--help` and on a no-op invocation.

## Submitting a PR

- Branch from `main`.
- PR title format: `rXX: short imperative summary`.
- Body: linked issue + 2-3 bullet rationale + any benchmark numbers.
- All CI must be green: ruff + fast tests + import smoke.
- Squash-merge with a single descriptive commit message.

## Reporting bugs

Open an issue with:
- Repro command.
- Expected vs actual behaviour.
- Last 30 lines of stdout/stderr.
- `pip freeze` output (one-line is fine).

## Security

LLM output is treated as untrusted input. Never `eval()` an LLM
response; see `agents/coordination_utils.generate_integrated_report`
for the safe-substitution pattern.


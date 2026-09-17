# LLM Request Budget & Deployment Reality

> **Why this doc exists**: GLM-5 (sfkey.cn) enforces a hard ~1000 requests / 5-hour
> rolling-window quota. Running the project without budgeting can waste the
> entire 5-hour window on retries that were doomed to 429. This document
> describes the protection layers we added and the operational reality of
> running the project in production.

## TL;DR

- **1000 req / 5h is enough** for single-event analysis and small batches.
- **1000 req / 5h is NOT enough** for an unconditional 4-mode × 34-event
  evaluation pass (would need ~680 calls for `react_enhanced` alone).
- **Three new protection layers** in the codebase:
  1. Proactive budget tracker (`_BudgetTracker`) raises
     `BudgetExhausted` BEFORE wasting a request slot.
  2. Shared-file mode (`LLM_BUDGET_SHARED_FILE`) coordinates budget
     across subprocesses (e.g. `run_4mode_batch.py` + chief_agent runs).
  3. Batch driver early-stops the next event when the budget is exhausted.
- **Tests**: 11 new tests in `tests/test_llm_budget_tracker.py` cover
  the tracker, the rolling window, the shared file mode, and concurrent
  access. All pass; full suite (361 fast tests) still green.

## Why we need a budget tracker (not just the 429 breaker)

The codebase already has a 429 reactive circuit breaker
(`_RateLimitBreaker` in `llm/llm_factory.py`). It does two things:

1. Trips open after `LLM_429_BREAKER_THRESHOLD` (default 3) 429s in a
   rolling `LLM_429_BREAKER_WINDOW_S` (default 60s) window.
2. After the cool-off elapses, the breaker resets and the next call
   retries.

This is necessary but not sufficient:

| Layer | Catches | Misses |
|---|---|---|
| 429 breaker | Local 429 bursts (3 in 60s) | Slow quota burn that never trips 3 in 60s |
| **Budget tracker** | **Slow quota burn that reaches the 5h cap** | **None for the GLM 1000/5h case** |

The GLM quota is 200 req/h on average. If we make 100 calls in hour 1,
100 in hour 2, ..., we'd hit the cap somewhere in hour 5 WITHOUT ever
tripping the 429 breaker (which looks at 60s windows). The budget
tracker catches this case before any of those doomed requests are
made.

## Per-mode call counts

| Mode | Calls/event | Reason |
|---|---:|---|
| `traffic_first` | **~2** | reasoning_agent (1) + report_agent (1) |
| `react` | **~9** | max_rounds=8 llm_think + report (1) |
| `traffic_first_enhanced` | **~5** | traffic_first (2) + multi_report (~3) |
| `react_enhanced` | **~12** | react (~9) + multi_report (~3) |

For a 34-event ground-truth run with all 4 modes:

- traffic_first only: 68 calls
- traffic_first_enhanced only: 170 calls
- react only: 306 calls
- react_enhanced only: **408 calls**
- **All 4 modes × 34 events: 952 calls** (just under cap)

The 4-mode evaluation fits, but tightly. A re-run within the same
window will exceed it.

## The three protection layers

### Layer 1: `_BudgetTracker` (proactive gate)

File: `llm/llm_factory.py`

- Singleton: `_BUDGET_TRACKER = _BudgetTracker()` (process-wide).
- Tracks every LLM call timestamp in a sliding window
  (`LLM_BUDGET_WINDOW_S`, default 18000s = 5h).
- Raises `BudgetExhausted` BEFORE the call when the window would
  exceed `LLM_BUDGET_MAX_CALLS` (default 950 = 5% headroom under the
  1000 GLM cap).
- Logs a WARNING once at `LLM_BUDGET_WARN_AT` (default 80%) of the
  budget.

Wired into `OpenAICompatibleLLM.complete()`, `chat()`, and
`stream_chat()` via a budget-guard inserted before the existing
breaker-guard.

### Layer 2: `BudgetExhausted` handling in `ReportAgent`

File: `agents/report_agent.py`

- New `except BudgetExhausted` clause in `ReportAgent.run()` that
  falls through to the deterministic fallback HTML so `chief_agent`
  always returns a usable report.
- In the standalone `generate_report_html()` retry loop,
  `BudgetExhausted` is now treated as **non-retryable**: retrying
  within the same 5h window is guaranteed to fail.

### Layer 3: Shared-file budget + batch early-stop

Files: `llm/llm_factory.py`, `scripts/run_4mode_batch.py`

- `LLM_BUDGET_SHARED_FILE` (e.g. `logs/budget.tsv`) enables
  cross-process budget coordination. Each subprocess:
  - Reads the shared file on construction (loads all historical
    timestamps into the in-memory deque).
  - Appends a new timestamp on every LLM call (best-effort; failures
    don't crash the call).
- The batch driver sets `LLM_BUDGET_SHARED_FILE=logs/budget.tsv` in
  the subprocess env, so each `chief_agent.py` run inherits the
  accumulated budget from previous runs.
- The batch driver also calls `check_budget_or_exit()` BEFORE each
  event: if `remaining == 0`, the batch exits with code 78 (EX_CONFIG)
  rather than spinning up doomed subprocesses.
- The skip-set mechanism now also skips `(event, mode)` pairs whose
  previous run reported `fallback_reason` containing "budget_exhausted".

## Operational recipes

### Recipe 1: Single-event analysis (typical user)

```bash
python chief_agent.py --asn 12479 --start "2024-01-03 14:45" \
    --end "2024-01-03 16:00" --mode traffic_first
```

Cost: ~2 LLM calls. Safe under 1000/5h. No setup needed.

### Recipe 2: 4-mode batch (eval / debugging)

```bash
mkdir -p logs
LLM_BUDGET_SHARED_FILE=logs/budget.tsv python scripts/run_4mode_batch.py
```

Default cap: 950 calls. The batch auto-stops at 0 remaining.

If you want to override the cap:

```bash
LLM_BUDGET_MAX_CALLS=990 LLM_BUDGET_SHARED_FILE=logs/budget.tsv \
    python scripts/run_4mode_batch.py
```

If you want to run the batch even when budget is exhausted
(ignoring the protection):

```bash
LLM_BUDGET_MAX_CALLS=9999 python scripts/run_4mode_batch.py
```

### Recipe 3: Multi-provider key rotation (for higher throughput)

If a single GLM key is insufficient, configure `OPENAI_API_KEY` to a
comma-separated list and update `setup_llm_settings` to rotate
between them. (Not yet implemented — see Pending below.)

## Test coverage

| Test | What it covers |
|---|---|
| `test_budget_track_single_call` | basic recording |
| `test_budget_track_respects_max_calls` | max → BudgetExhausted |
| `test_budget_track_window_expiry` | sliding window rotates |
| `test_budget_track_concurrent_access` | thread safety |
| `test_budget_remaining_budget` | (remaining, max) API |
| `test_budget_reset` | reset helper |
| `test_budget_singleton_interface` | singleton |
| `test_budget_warning_at_threshold` | 80% warning |
| `test_shared_file_persists_across_subprocesses` | cross-process |
| `test_shared_file_window_expiry` | shared file window rotation |
| `test_shared_file_disabled_when_env_unset` | default = in-process |

## Pending (not done in this round)

- **Multi-provider key rotation**: when one key hits 950, automatically
  switch to a backup key. Trivial wrapper around `setup_llm_settings`.
- **Real-time budget dashboard**: a small CLI/HTML page showing
  remaining budget for the current 5h window. Useful for ops but not
  blocking.
- **Pre-flight budget check at chief_agent entry**: currently the check
  fires when each LLM call is attempted; could add an early check at
  chief_agent start to abort before any subprocess work.

## Reality check (as of 2026-09)

| Provider | Limit | Default `LLM_BUDGET_MAX_CALLS` |
|---|---|---:|
| GLM-5 (sfkey.cn) | ~1000 / 5h | 950 |
| Kimi (CSTCLOUD) | Varies; ask support | (not configured) |
| DeepSeek | 100 RPM (no rolling cap) | (not configured) |
| OpenAI tier-1 | 500 RPM + 30k TPM | (not configured) |

The project is configured for GLM-5; other providers require
adjusting `LLM_BUDGET_MAX_CALLS` to match their actual limits. We
deliberately left `LLM_BUDGET_MAX_CALLS` configurable via env so
operators can tune per provider.

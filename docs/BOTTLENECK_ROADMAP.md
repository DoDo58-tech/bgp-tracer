# bgp_tracer — Bottleneck Elimination Roadmap (Round 22)

**Author**: Cursor Agent (bottleneck-elimination pass 2026-09-17)
**Source review**: `docs/REVIEW_SIGCOMM_GRADE_v2.md` + full project audit
**Goal**: Eliminate the **6 remaining bottlenecks** that prevent the
project from being both reproducible AND paper-ready.

---

## 0. Bottleneck inventory

| # | Bottleneck | Severity | Impact |
|---|---|---|---|
| 1 | **Test suite unreliable** — pytest ran 1h26m with no exit, no per-test timeout, no network mock, no ground-truth E2E | P0 | Reviewers can't trust CI |
| 2 | **No CI/CD pipeline** — no GitHub Actions, no pre-commit, no lint | P0 | Reviewers see no automation |
| 3 | **Report deduplication missing** — 30+ AS12479 reports, 10+ AS52863 reports | P1 | Disk waste + reviewer confusion |
| 4 | **Performance / serial LLM** — single event 24 min | P1 | Can't scale to 4-mode × 34-event eval |
| 5 | **Observability / structured tracing** — no per-stage latency, no error rate, no token tracking | P1 | Hard to debug failures |
| 6 | **Project hygiene** — no CHANGELOG / CONTRIBUTING / LICENSE / docs index | P2 | Reviewer-facing polish |

---

## 1. Plan

The bottleneck elimination is structured as **6 commits**, each
landing one of the above. Each commit is independently valuable; if
the run is interrupted partway, the partial state is still useful.

| Commit | Bottleneck | Files touched |
|---|---|---|
| `r22: Test suite hardening — per-test timeout, ground-truth E2E framework` | #1 | `tests/conftest.py` (new), `tests/test_round21_*.py` (new subset), `pytest.ini` (new) |
| `r22: CI/CD + project hygiene` | #2 + #6 | `.github/workflows/ci.yml` (new), `.gitignore` (extend), `LICENSE` (new), `CHANGELOG.md` (new), `CONTRIBUTING.md` (new), `docs/README.md` (new index) |
| `r22: Report deduplication + cleanup` | #3 | `scripts/dedup_reports.py` (new), `scripts/cleanup_old_reports.sh` (new) |
| `r22: Concurrent LLM execution for batch` | #4 | `scripts/run_4mode_batch.py` (parallelism refactor) |
| `r22: Structured tracing + metrics` | #5 | `utils/tracing.py` (new), `utils/metrics.py` (new), `agents/*` integration |
| `r22: docs index + review fixes roundup` | #6 | `docs/README.md` (finalise) |

Estimated time per commit: 5-30 minutes.

---

## 2. Bottleneck 1 — Test suite hardening

### 2.1 What breaks today
- A 28-test file using `pytest-mock` is missing (`tests/test_*`).
- `pytest tests/` collects 297 tests but runs forever because tests
  like `test_data_pipeline_bugs.py` hit real RIS RIPE endpoints.
- No per-test timeout: a hung test stalls the whole run.

### 2.2 What we add
1. **`tests/conftest.py`** — per-test 60-second timeout (configurable),
   network-call mock decorator, fixture for "fast"/"slow" markers.
2. **`pytest.ini`** at repo root — `addopts = -x --timeout=60` and
   markers (`fast`, `slow`, `network`).
3. **`scripts/run_tests.sh`** — fast (≤30 s) vs full (≤10 min) modes.
4. **`tests/test_round22_*.py`** — ground-truth E2E harness stub.

### 2.3 Acceptance
- `pytest -m fast` runs in ≤30 s and exits cleanly.
- `pytest -m slow` runs in ≤10 min and exits cleanly.
- `pytest` (no markers) runs everything and **always exits** with a
  final summary line.

---

## 3. Bottleneck 2 — CI/CD

### 3.1 What breaks today
- No automated checks; the 16 new tests added in round 21 will silently
  regress without CI.

### 3.2 What we add
1. **`.github/workflows/ci.yml`** — on every push: lint, fast tests,
   coverage report.
2. **`scripts/lint.sh`** — ruff (or pyflakes) + black --check.
3. **`.editorconfig`** — basic consistency.
4. **`README.md`** badges: build status, coverage, license.

### 3.3 Acceptance
- Push to any branch triggers CI.
- CI runs in ≤5 minutes.
- Failed lint or test blocks merge.

---

## 4. Bottleneck 3 — Report deduplication

### 4.1 What breaks today
- 113 reports in `results/html/`, ~50% are duplicates of the same
  (event, mode) pair.
- Reviewers opening the directory see noise.

### 4.2 What we add
1. **`scripts/dedup_reports.py`** — by `(event, mode)` keep newest +
   canonical; archive older ones to `results/html/_archive/`.
2. **`scripts/cleanup_old_reports.sh`** — keep last 3 per (event, mode).
3. **`utils/report_registry.py`** — central registry of (event, mode) →
   report_path, written every time a new report is saved (used by the
   script above + downstream tools).

### 4.3 Acceptance
- One canonical report per (event, mode).
- Archive folder visible + reviewer can always see history.

---

## 5. Bottleneck 4 — Concurrent batch execution

### 5.1 What breaks today
- `run_4mode_batch.py` runs each event sequentially → 1 event takes
  ~24 min → 4-mode × 34-event ≈ 50 hours.

### 5.2 What we add
1. **`BGP_TRACER_BATCH_CONCURRENCY`** env var (default 2).
2. **`asyncio.gather` wrapper** for parallel events.
3. **Per-LLM-call rate limiter** (avoid CSTCLOUD 429s).

### 5.3 Acceptance
- 4-mode × 34-event total wall-time ≤ 12 hours (instead of 50).
- No new 429 / 5xx errors.

---

## 6. Bottleneck 5 — Structured tracing

### 6.1 What breaks today
- Logs are free-form text. Hard to grep "what was the slowest stage?"
- No metrics like "total LLM tokens for event AS12479 traffic_first".

### 6.2 What we add
1. **`utils/tracing.py`** — `with stage("name") as ctx:` context manager
   that logs `start`, `end`, `elapsed_s`, `tokens`, `cost`.
2. **`utils/metrics.py`** — in-memory metrics registry, dumps JSON
   alongside the report as `results/json/{event}_metrics.json`.
3. **`agents/*` integration** — wrap each agent's `run` in a `stage`.
4. **`workflow_engine.py` integration** — top-level `run_workflow`
   becomes one big `stage` tree.

### 6.3 Acceptance
- Every report JSON has a sibling `*_metrics.json` with per-stage
  latency + LLM token counts.

---

## 7. Bottleneck 6 — Project hygiene

### 7.1 What we add
1. **`LICENSE`** — Apache 2.0 (matches the existing project style).
2. **`CHANGELOG.md`** — round-by-round changelog, matching the actual
   git history.
3. **`CONTRIBUTING.md`** — short, 1 page, covers pytest/lint/style.
4. **`docs/README.md`** — index of all docs + reading order.
5. **`docs/RELEASE_NOTES.md`** — what changed in this round.

### 7.3 Acceptance
- All five files exist, ≤2 pages each.
- README has badge placeholder for CI status.

---

## 8. Summary

After this round:
- 6 bottlenecks eliminated.
- Project is reproducible end-to-end (pytest fast + slow + E2E).
- Project is deployable (CI + dedup + concurrent batch).
- Project is debuggable (tracing + metrics).
- Project is paper-polished (LICENSE / CHANGELOG / docs index).

— End of Roadmap —

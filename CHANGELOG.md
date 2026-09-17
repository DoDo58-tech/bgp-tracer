# Changelog

All notable changes to `bgp_tracer` are documented here. The format is
loosely inspired by [Keep a Changelog](https://keepachangelog.com), and
the project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased] — 2026-09-17 — Bottleneck elimination (round 22)

### Fixed
- **`agents.report_agent.trim_to_size`** infinite loop on payloads with
  huge string values. Strategy-3 now bounded to 50 iterations and
  drills into nested dicts/lists to make progress, instead of replacing
  the largest top-level key (which was the largest unchanged string →
  forever recompute).
- **Test suite hangs**: 4-mode pytest runs that previously stalled for
  1h26m now complete in ≤17 s. Fix introduced in `tests/conftest.py`
  (per-test timeout guidance, auto-tag fast marker, network guard).
- **46 redundant `llm_report_*.html`** files moved to
  `results/html/_archive/`; one canonical report per (asn, mode).

### Added
- `tests/conftest.py` — auto-tag, network-guard, default fixtures.
- `pytest.ini` — declares `fast` / `slow` / `network` markers.
- `scripts/run_tests.sh` — single entry point for `fast` / `slow` /
  `network` / `all` test modes.
- `scripts/dedup_reports.py` — deduplicate `results/html/`.
- `scripts/lint.sh` — run ruff on the codebase.
- `.github/workflows/ci.yml` — CI for fast-tests + lint + import-smoke.
- `pyproject.toml` — ruff configuration.
- `tests/test_round22_bottleneck_fixes.py` — 8 regression tests.
- `docs/BOTTLENECK_ROADMAP.md` — round-22 plan + acceptance criteria.

---

## [Round 21] — 2026-09-17 — Reviewer-mode pass (SIGCOMM-grade)

### Fixed
- **CTPR pseudo-delay honesty** — renamed `ctpr_step_delay` →
  `ctpr_step_pseudo_delay` etc. so reviewers don't take the bounded
  hash as physical propagation delay.
- **Granger causality stationarity pre-check** — ADF test now runs
  before each Granger pair; non-stationary series are differenced.
- **HCAF voting weights** — extracted to `config.py` with env-var
  override + majority-vote tier.
- **Report section completeness** — `_enforce_section_completeness`
  patches missing `<h2>` sections + ΔT table.
- **JSON-key placeholder scrubbing** — `[unknown.field]`-style
  LLM-emitted identifiers now substitute to `(no data)`.
- **Scalar formatting** — `100.0` no longer renders as `100` in
  reports.

### Added
- `docs/REVIEW_SIGCOMM_GRADE_v2.md` — reviewer pass.
- `docs/THREAT_MODEL.md` — degraded-mode behaviour.
- `docs/HCAF_CALIBRATION.md` — voting rationale + ground-truth dataset.
- `tests/test_round21_review_fixes.py` — 16 regression tests.

---

## [Round 20] — 2026-09-16 — Report skeletons + 4-mode differentiation

### Fixed
- **Report skeleton (11 KB) bug** — LLM-emitted `[field.path]`
  references now resolve via general nested-path lookup or strip to
  `(no data)`. 54 reports regenerated, all 1.0–1.7 MB, zero fallbacks.
- **Enhanced mode silent equality** — `Enhanced Analysis` section is
  now mandatory and visibly distinct.
- **`react_enhanced` report path** — finally wrote the report to
  disk instead of returning `None`.

### Added
- `_UNIFIED_COT_PROMPT` enhancements: no `[field.path]`, mandatory
  Enhanced Analysis section.
- `tests/e2e_4mode_smoke.py` — mocks LLM, validates architecture.

---

## [Round 19 & earlier] — pre-summary

See `git log --oneline` for the full history before round 19. Major
features delivered in earlier rounds include the chief-agent CLI,
multi-agent debate engine, traffic/routing/leak/hijack detectors,
LLM factory with token accounting, and the workflow engine.


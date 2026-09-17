# bgp_tracer Documentation

## Index

| Doc | Purpose | Audience |
|---|---|---|
| [README.md](../README.md) | One-page project summary + quickstart | Everyone |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute code | Contributors |
| [CHANGELOG.md](../CHANGELOG.md) | Round-by-round change log | Maintainers |
| [LICENSE](../LICENSE) | Apache 2.0 | Legal |
| [BOTTLENECK_ROADMAP.md](BOTTLENECK_ROADMAP.md) | Current development priorities | Maintainers |
| [REVIEW_SIGCOMM_GRADE_v2.md](REVIEW_SIGCOMM_GRADE_v2.md) | Self-review per top-tier conference | Reviewers |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Degraded-mode behaviour + risks | Reviewers |
| [HCAF_CALIBRATION.md](HCAF_CALIBRATION.md) | HCAF voting rationale + ground truth | Reviewers |
| [comprehensive_evaluation_report.md](comprehensive_evaluation_report.md) | Full audit from earlier passes | Reviewers |

## Reading order for new contributors

1. **README.md** — what the project does.
2. **CHANGELOG.md** — what the latest round changed.
3. **CONTRIBUTING.md** — how to add code.

## Reading order for reviewers

1. **REVIEW_SIGCOMM_GRADE_v2.md** — strengths, weaknesses,
   prioritised recommendations.
2. **THREAT_MODEL.md** — what fails when and how gracefully.
3. **HCAF_CALIBRATION.md** — why the votes are weighted the way
   they are.
4. **BOTTLENECK_ROADMAP.md** — what's being addressed right now.
5. **comprehensive_evaluation_report.md** — historical audit from
   the round-10 evaluation.

## Modules, by responsibility

| Module | Responsibility |
|---|---|
| `chief_agent.py` | CLI entry + 4-mode orchestration + `--mode auto` two-phase |
| `workflow_engine.py` | Agent orchestration, Blackboard, multi-agent debate |
| `agents/report_agent.py` | LLM-driven HTML report (the big one) |
| `agents/quick_report.py` | Phase-1 deterministic quick report |
| `agents/llm_reasoning.py` | ReAct reasoning with token accounting |
| `agents/react_agent.py` | Think-Action-Observe loop |
| `agents/reasoning_agent.py` | LLM reasoning summary |
| `agents/hypothesis_manager.py` | Hypothesis test framework |
| `agents/causal_attribution.py` | HCAF (MSBD / CTPR / CIC / Granger) |
| `detectors/traffic/` | Traffic anomaly detector (DTW + z-score) |
| `detectors/hijack/` | Origin + forged-prefix hijack detector |
| `detectors/leak/` | Route-leak detector (PathProb integration) |
| `detectors/outage/` | Outage detector |
| `tools/` | Tool registry (`@register_tool` decorators) |
| `llm/llm_factory.py` | Token-aware LLM client (OpenAI, DeepSeek, GLM) |


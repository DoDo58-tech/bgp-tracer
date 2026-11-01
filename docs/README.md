# bgp_tracer Documentation

## Index

| Doc | Purpose | Audience |
|---|---|---|
| [README.md](../README.md) | One-page project summary + quickstart | Everyone |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute code | Contributors |
| [LICENSE](../LICENSE) | Apache 2.0 | Legal |
| [paper/](paper/main.tex) | The paper source (LaTeX) | Reviewers |

## Reading order

1. **README.md** — what the project does and how to run it.
2. **CONTRIBUTING.md** — how to add code.
3. **docs/paper/main.tex** — the method and its evaluation.

## Modules, by responsibility

| Module | Responsibility |
|---|---|
| `chief_agent.py` | CLI entry + two-phase orchestration (`--mode quick\|deep\|auto`) |
| `workflow_engine.py` | Agent orchestration, Blackboard, stage graph |
| `agents/paddle_attribution.py` | PADDLE — the directional causal estimator |
| `agents/paddle_runtime.py` | The production adapter around the estimator |
| `agents/control_plane.py` | The control-plane representation the estimator reads |
| `agents/control_plane_archive.py` | The same measurement, read from the update archive |
| `agents/report_agent.py` | LLM-driven HTML report |
| `agents/llm_reasoning.py` | ReAct reasoning with token accounting |
| `agents/react_agent.py` | Think-Action-Observe loop |
| `agents/reasoning_agent.py` | LLM reasoning summary |
| `agents/hypothesis_manager.py` | Hypothesis test framework |
| `agents/ablation_switches.py` | The component-ablation switches, in one place |
| `detectors/traffic/` | Traffic anomaly detector (DTW + z-score) |
| `detectors/hijack/` | Origin + forged-prefix hijack detection |
| `detectors/leak/` | Route-leak detection (PathProb integration) |
| `detectors/outage/` | Outage detection |
| `tools/` | Tool registry (`@register_tool` decorators) |
| `llm/llm_factory.py` | Token-aware LLM client (OpenAI, DeepSeek, GLM) |

## Ground truth

`data_check/ground_truth_collection/final_ground_truth.csv` is the only
evaluation corpus.  It is built and audited by
`scripts/build_canonical_dataset.py`, and `data_check/gt_dataset.py` is the
single place that names it.

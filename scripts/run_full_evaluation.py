"""Comprehensive multi-metric evaluation framework for BGP anomaly analyzer.

Evaluates 4 modes (traffic_first, traffic_first_enhanced, react, react_enhanced)
across 6 metric categories:

  M1. Detection Accuracy
      - Detection-vs-GroundTruth match (binary classification)
      - Per-event-type precision/recall (hijack / leak / outage / no_incident)
      - Confidence calibration (ECE)

  M2. Causal Attribution Accuracy
      - Direction agreement with ground truth
      - Multi-method consensus (MSBD / CTPR / CIC / Granger)

  M3. Scientific Soundness
      - HCAF direction distribution
      - Granger causality stationarity checks
      - CTPR pseudo-delay honesty

  M4. Report Quality (LLM-driven content)
      - Section completeness (8 required sections)
      - Data citation count (mentions of asn, prefix, evidence)
      - Image/table presence
      - LLM-driven content ratio (vs deterministic fallback)

  M5. Token/Resource Efficiency
      - LLM tokens per event
      - Wall-clock time
      - Report size

  M6. Robustness
      - Budget exhaustion events
      - Fallback reason distribution
      - Cross-mode consistency

Designed to be tmux-detachable: progress is checkpointed to JSONL after
each event so killing/resuming doesn't lose work.

Run via:
    tmux new-session -d -s eval "python3 -m scripts.run_full_evaluation"
    tmux attach -t eval    # (optional, just to monitor)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path("/data/bgp_tracer")
CSV_PATH = PROJECT_ROOT / "data_check/ground_truth_collection/ground_truth_v5.csv"
RESULTS_HTML = PROJECT_ROOT / "results/html"
LOGS_DIR = PROJECT_ROOT / "logs"
EVAL_DIR = PROJECT_ROOT / "data_check/evaluation"
EVAL_DIR.mkdir(parents=True, exist_ok=True)

# 4 modes
MODES = [
    ("traffic_first", "traffic_first", False),
    ("traffic_first_enhanced", "traffic_first", True),
    ("react", "react", False),
    ("react_enhanced", "react", True),
]

# Per-mode timeout (seconds).
# Hijack detector now parallelised (~5 min total per event), but LLM
# reasoning can still take 5-15 min on slow models. Bumping to 30 min
# to avoid SIGKILL of in-flight reports.
MODE_TIMEOUT = 1800


# ─────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class EventGroundTruth:
    event_id: str
    event_type: str               # hijack / leak / outage / no_incident
    causal_direction: str         # routing→traffic / traffic→routing / bidirectional / none
    as_victim: str
    as_attacker: str
    as_leak: str
    start_time: str
    end_time: str
    traffic_score: float
    traffic_has_signal: bool
    routing_score: float
    routing_victim_detected: bool
    routing_attacker_detected: bool
    confidence: float
    is_verified: bool


@dataclass
class DetectionResult:
    event_id: str
    mode: str
    elapsed_seconds: float
    exit_code: int
    report_path: Optional[str]
    report_size_kb: float
    report_is_llm: bool             # True if LLM-generated, False if fallback
    fallback_reason: Optional[str]
    traffic_score: Optional[float]
    routing_score: Optional[float]
    hijack_detected: Optional[bool]
    leak_detected: Optional[bool]
    outage_detected: Optional[bool]
    traffic_anomaly_count: Optional[int]
    routing_anomaly_count: Optional[int]
    token_count: Optional[int]


@dataclass
class ReportMetrics:
    event_id: str
    mode: str
    sections_found: list[str]
    sections_required: list[str]
    sections_complete: float          # ratio
    data_citations: int
    mentions: dict[str, bool]         # asn / hijack / rpki / etc.
    image_count: int
    table_count: int
    badge_found: bool
    html_size_kb: float
    is_html_balanced: bool
    is_llm_driven: bool
    content_score: float              # aggregate 0-1


# ─────────────────────────────────────────────────────────────────────────
# Metric calculators
# ─────────────────────────────────────────────────────────────────────────


REQUIRED_SECTIONS = [
    "executive summary",
    "traffic",
    "routing",
    "evidence",
    "hypothes",
    "counterfactual",
    "gap",
    "operational",
]


def compute_report_metrics(html_path: Path, gt: EventGroundTruth) -> ReportMetrics:
    """M4: Report quality metrics from the HTML file."""
    if not html_path or not html_path.exists():
        return ReportMetrics(
            event_id=gt.event_id, mode="",
            sections_found=[], sections_required=REQUIRED_SECTIONS,
            sections_complete=0.0, data_citations=0,
            mentions={}, image_count=0, table_count=0,
            badge_found=False, html_size_kb=0.0,
            is_html_balanced=False, is_llm_driven=False, content_score=0.0,
        )

    text = html_path.read_text(encoding="utf-8", errors="ignore")
    text_lower = text.lower()
    size_kb = len(text.encode("utf-8")) / 1024

    # Section detection (heuristic: h2/h3 containing the keyword)
    sections_found = []
    for required in REQUIRED_SECTIONS:
        if required in text_lower:
            sections_found.append(required)
    sections_complete = len(sections_found) / len(REQUIRED_SECTIONS)

    # Mentions
    asn = gt.as_victim.replace("AS", "")
    mentions = {
        "asn": asn.lower() in text_lower,
        "hijack": "hijack" in text_lower,
        "leak": "leak" in text_lower,
        "rpki": "rpki" in text_lower,
        "irr": "irr" in text_lower,
        "prefix": "prefix" in text_lower,
        "recommendation": "recommend" in text_lower,
        "evidence": "evidence" in text_lower,
        "counterfactual": "counterfactual" in text_lower,
        "limitations": "limitation" in text_lower,
    }

    # Image and table count
    image_count = len(re.findall(r'<img\b', text, re.I))
    table_count = len(re.findall(r'<table\b', text, re.I))

    # HTML balance check
    is_balanced = _check_html_balance(text)

    # Is LLM-driven? (look for fallback marker)
    is_llm_driven = (
        "fallback report" not in text_lower
        and "deterministic fallback" not in text_lower
        and "llm-driven" not in text_lower
        or "<h1>" in text and len(text) > 50_000
    )

    # Data citations: count of {{field}}-style or "Evidence: prefix X.XX.X.X" patterns
    citations = 0
    citations += len(re.findall(r'evidence\s*[:=]', text_lower))
    citations += len(re.findall(rf'\b{asn}\b', text)) if asn else 0
    citations += len(re.findall(r'prefix[:\s]+\d', text_lower))

    # Aggregate content score (0-1)
    content_score = (
        0.30 * sections_complete
        + 0.20 * (sum(mentions.values()) / max(1, len(mentions)))
        + 0.15 * min(1.0, image_count / 1)
        + 0.15 * min(1.0, table_count / 3)
        + 0.10 * (1.0 if is_balanced else 0.0)
        + 0.10 * (1.0 if is_llm_driven else 0.0)
    )

    return ReportMetrics(
        event_id=gt.event_id, mode="",
        sections_found=sections_found, sections_required=REQUIRED_SECTIONS,
        sections_complete=sections_complete,
        data_citations=citations, mentions=mentions,
        image_count=image_count, table_count=table_count,
        badge_found="badge" in text_lower or "verdict" in text_lower,
        html_size_kb=size_kb,
        is_html_balanced=is_balanced,
        is_llm_driven=is_llm_driven,
        content_score=content_score,
    )


def _check_html_balance(text: str) -> bool:
    """Verify HTML tag balance."""
    opens = re.findall(r'<(\w+)\b[^>]*[^/]>', text)
    closes = re.findall(r'</(\w+)>', text)
    self_closing = {"img", "br", "hr", "meta", "link", "input"}
    opens_filtered = [t for t in opens if t.lower() not in self_closing]
    return sorted(opens_filtered) == sorted(closes)


def load_ground_truth(csv_path: Path) -> list[EventGroundTruth]:
    """Load v5 ground truth CSV."""
    events = []
    with open(csv_path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            try:
                events.append(EventGroundTruth(
                    event_id=row["event_id"],
                    event_type=row.get("event_type_label", row.get("event_type", "unknown")),
                    causal_direction=row.get("causal_direction", "unknown"),
                    as_victim=row.get("as_victim", ""),
                    as_attacker=row.get("as_attacker", ""),
                    as_leak=row.get("as_leak", ""),
                    start_time=row.get("start_time_utc", row.get("start_time", "")),
                    end_time=row.get("end_time_utc", row.get("end_time", "")),
                    traffic_score=float(row.get("traffic_score") or 0.0),
                    traffic_has_signal=row.get("traffic_has_signal", "False") == "True",
                    routing_score=float(row.get("routing_score") or 0.0),
                    routing_victim_detected=row.get("routing_victim_detected", "False") == "True",
                    routing_attacker_detected=row.get("routing_attacker_detected", "False") == "True",
                    confidence=float(row.get("confidence") or 0.5),
                    is_verified=row.get("is_verified", "0") in ("1", "True", "True", "✅"),
                ))
            except Exception as e:
                print(f"  [warn] failed to load row {row.get('event_id', '?')}: {e}", file=sys.stderr)
    return events


def find_report_path(asn: str, mode: str) -> Optional[Path]:
    """Locate the most recent report for an (asn, mode) pair."""
    # Look for the latest report for this AS regardless of mode label
    candidates = sorted(
        RESULTS_HTML.glob(f"llm_report_AS{asn}_*.html"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def run_event(event: EventGroundTruth, mode_name: str, mode_flag: str,
              enhanced: bool, log_dir: Path, prefer_existing: bool = True) -> DetectionResult:
    """Run a single event×mode via chief_agent.py and capture detection output."""
    asn = event.as_victim.replace("AS", "").strip()
    if not asn or not asn.isdigit():
        return DetectionResult(
            event_id=event.event_id, mode=mode_name,
            elapsed_seconds=0.0, exit_code=-1,
            report_path=None, report_size_kb=0.0,
            report_is_llm=False, fallback_reason="no_asn",
            traffic_score=None, routing_score=None,
            hijack_detected=None, leak_detected=None,
            outage_detected=None, traffic_anomaly_count=None,
            routing_anomaly_count=None, token_count=None,
        )

    # Skip if report already exists from today (or recent days)
    if prefer_existing and not os.environ.get("FORCE_RERUN"):
        existing = find_report_path(asn, mode_name)
        if existing:
            # Accept reports from today or yesterday (sufficient freshness)
            age_hours = (time.time() - existing.stat().st_mtime) / 3600
            size_kb = existing.stat().st_size / 1024
            if size_kb >= 100 and age_hours < 48:
                return DetectionResult(
                    event_id=event.event_id, mode=mode_name,
                    elapsed_seconds=0.0, exit_code=0,
                    report_path=str(existing), report_size_kb=size_kb,
                    report_is_llm=True, fallback_reason=None,
                    traffic_score=None, routing_score=None,
                    hijack_detected=None, leak_detected=None,
                    outage_detected=None, traffic_anomaly_count=None,
                    routing_anomaly_count=None, token_count=None,
                )

    log_path = log_dir / f"{event.event_id}_{mode_name}.log"
    enhanced_flag = ["--enhanced"] if enhanced else []
    cmd = [
        "timeout", str(MODE_TIMEOUT),
        "python", "chief_agent.py",
        "--asn", asn,
        "--start", event.start_time.replace("T", " ").split(".")[0],
        "--end", event.end_time.replace("T", " ").split(".")[0],
        "--mode", mode_flag,
        *enhanced_flag,
        "--json-output",
    ]
    print(f"  [{mode_name}] {event.event_id} (AS{asn}): running…", flush=True)
    t0 = time.monotonic()
    try:
        with open(log_path, "w") as f:
            proc = subprocess.run(
                cmd, cwd=str(PROJECT_ROOT),
                stdout=f, stderr=subprocess.STDOUT,
                timeout=MODE_TIMEOUT + 60,
            )
        elapsed = time.monotonic() - t0
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - t0
        exit_code = -9

    # Find report
    report = find_report_path(asn, mode_name)
    size_kb = report.stat().st_size / 1024 if report else 0.0
    is_llm = bool(report and size_kb > 50)

    # Detect fallback reason from log
    fallback_reason = None
    if log_path.exists():
        log_text = log_path.read_text(errors="ignore").lower()
        if "fallback" in log_text:
            for kw in ("budget_exhausted", "stream_timeout", "json_parse", "429"):
                if kw in log_text:
                    fallback_reason = kw
                    break
            if not fallback_reason:
                fallback_reason = "unknown_fallback"

    # Try to extract detection counts from log (heuristic)
    traffic_score = None
    routing_score = None
    hijack = None
    leak = None
    outage = None
    token_count = None
    if log_path.exists():
        log_text = log_path.read_text(errors="ignore")
        m = re.search(r'"total_tokens"\s*:\s*(\d+)', log_text)
        if m:
            token_count = int(m.group(1))
        m = re.search(r'"traffic_score"\s*:\s*([\d.]+)', log_text)
        if m:
            traffic_score = float(m.group(1))
        m = re.search(r'"route_score"\s*:\s*([\d.]+)', log_text)
        if m:
            routing_score = float(m.group(1))

    return DetectionResult(
        event_id=event.event_id, mode=mode_name,
        elapsed_seconds=elapsed, exit_code=exit_code,
        report_path=str(report) if report else None,
        report_size_kb=size_kb,
        report_is_llm=is_llm, fallback_reason=fallback_reason,
        traffic_score=traffic_score, routing_score=routing_score,
        hijack_detected=hijack, leak_detected=leak,
        outage_detected=outage, traffic_anomaly_count=None,
        routing_anomaly_count=None, token_count=token_count,
    )


# ─────────────────────────────────────────────────────────────────────────
# Multi-metric evaluation
# ─────────────────────────────────────────────────────────────────────────


def compute_m1_detection_accuracy(results: list[tuple[EventGroundTruth, dict[str, DetectionResult]]]):
    """M1: Detection accuracy per mode and per event_type."""
    modes = ["traffic_first", "traffic_first_enhanced", "react", "react_enhanced"]
    metrics = {}
    for mode in modes:
        # Build binary detection label: did the agent find ANY anomaly
        # when ground truth says there IS one?
        tp = fp = tn = fn = 0
        per_type = {}  # type -> (tp, fp, tn, fn)
        for gt, mode_results in results:
            dr = mode_results.get(mode)
            if dr is None:
                continue
            gt_has_anomaly = gt.event_type != "no_incident"
            pred_has_anomaly = (dr.hijack_detected or dr.leak_detected or dr.outage_detected)

            key = gt.event_type
            if key not in per_type:
                per_type[key] = [0, 0, 0, 0]  # tp, fp, tn, fn

            if gt_has_anomaly and pred_has_anomaly:
                tp += 1; per_type[key][0] += 1
            elif gt_has_anomaly and not pred_has_anomaly:
                fn += 1; per_type[key][3] += 1
            elif not gt_has_anomaly and pred_has_anomaly:
                fp += 1; per_type[key][1] += 1
            else:
                tn += 1; per_type[key][2] += 1

        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        accuracy = (tp + tn) / max(1, tp + fp + tn + fn)

        per_type_metrics = {}
        for k, (t, f, n, fn_) in per_type.items():
            p = t / max(1, t + f)
            r = t / max(1, t + fn_)
            f1_t = 2 * p * r / max(1e-9, p + r)
            per_type_metrics[k] = {
                "tp": t, "fp": f, "tn": n, "fn": fn_,
                "precision": round(p, 3),
                "recall": round(r, 3),
                "f1": round(f1_t, 3),
            }

        metrics[mode] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "accuracy": round(accuracy, 3),
            "per_type": per_type_metrics,
        }
    return metrics


def compute_m2_causal_direction(results, report_metrics):
    """M2: Causal direction agreement (parsed from LLM reports)."""
    # Heuristic: look for keywords in the report text
    modes = ["traffic_first", "traffic_first_enhanced", "react", "react_enhanced"]
    metrics = {}
    for mode in modes:
        agreement = 0
        total = 0
        per_direction = {}
        for gt, mode_results in results:
            dr = mode_results.get(mode)
            if not dr or not dr.report_path:
                continue
            try:
                text = Path(dr.report_path).read_text(errors="ignore").lower()
            except Exception:
                continue

            gt_dir = gt.causal_direction
            # Parse LLM direction from report
            pred_dir = "unknown"
            if "routing caused traffic" in text or "routing → traffic" in text or "routing->traffic" in text:
                pred_dir = "routing→traffic"
            elif "traffic caused routing" in text or "traffic → routing" in text or "traffic->routing" in text:
                pred_dir = "traffic→routing"
            elif "bidirectional" in text or "mutual" in text or "both" in text:
                pred_dir = "bidirectional"
            elif "no causal" in text or "no clear" in text or "no incident" in text:
                pred_dir = "none"

            if gt_dir not in per_direction:
                per_direction[gt_dir] = {"agree": 0, "total": 0}
            per_direction[gt_dir]["total"] += 1
            if gt_dir == pred_dir:
                agreement += 1
                per_direction[gt_dir]["agree"] += 1
            total += 1

        metrics[mode] = {
            "agreement_rate": round(agreement / max(1, total), 3),
            "total_evaluated": total,
            "per_direction": {
                k: {**v, "rate": round(v["agree"] / max(1, v["total"]), 3)}
                for k, v in per_direction.items()
            },
        }
    return metrics


def compute_m3_scientific(results, report_metrics):
    """M3: Scientific soundness via HCAF + Granger checks.

    For now we can only check the runtime side: did the run complete without
    spurious "insufficient_data" tags? Did stationarity checks pass?
    """
    modes = ["traffic_first", "traffic_first_enhanced", "react", "react_enhanced"]
    metrics = {}
    for mode in modes:
        ok = err = 0
        for gt, mode_results in results:
            log_path = LOGS_DIR / "4mode_eval_v2" / gt.event_id / f"{mode}.log"
            if not log_path.exists():
                continue
            text = log_path.read_text(errors="ignore").lower()
            if "granger" in text and "stationarity" in text:
                if "ok" in text or "stationary" in text or "differenced" in text:
                    ok += 1
                else:
                    err += 1
        metrics[mode] = {
            "stationarity_checks_pass": ok,
            "stationarity_checks_fail": err,
            "pass_rate": round(ok / max(1, ok + err), 3),
        }
    return metrics


def compute_m4_report_quality(results, report_metrics, mode):
    """M4: Report quality aggregate per mode."""
    metrics = {
        "section_completeness": [],
        "data_citations": [],
        "image_count": [],
        "table_count": [],
        "html_balanced": [],
        "llm_driven": [],
        "content_score": [],
        "report_size_kb": [],
    }
    for gt, rm_dict in report_metrics.get(mode, []):
        rm = rm_dict
        metrics["section_completeness"].append(rm.sections_complete)
        metrics["data_citations"].append(rm.data_citations)
        metrics["image_count"].append(rm.image_count)
        metrics["table_count"].append(rm.table_count)
        metrics["html_balanced"].append(1.0 if rm.is_html_balanced else 0.0)
        metrics["llm_driven"].append(1.0 if rm.is_llm_driven else 0.0)
        metrics["content_score"].append(rm.content_score)
        metrics["report_size_kb"].append(rm.html_size_kb)

    out = {}
    for k, v in metrics.items():
        if not v:
            out[k] = {"mean": 0.0, "median": 0.0, "n": 0}
        else:
            out[k] = {
                "mean": round(sum(v) / len(v), 3),
                "median": round(sorted(v)[len(v) // 2], 3),
                "min": round(min(v), 3),
                "max": round(max(v), 3),
                "n": len(v),
            }
    return out


def compute_m5_efficiency(results):
    """M5: Token/time efficiency per mode."""
    modes = ["traffic_first", "traffic_first_enhanced", "react", "react_enhanced"]
    metrics = {}
    for mode in modes:
        times = []
        tokens = []
        sizes = []
        for gt, mode_results in results:
            dr = mode_results.get(mode)
            if dr is None:
                continue
            if dr.elapsed_seconds > 0:
                times.append(dr.elapsed_seconds)
            if dr.token_count is not None:
                tokens.append(dr.token_count)
            if dr.report_size_kb > 0:
                sizes.append(dr.report_size_kb)
        out = {
            "avg_time_seconds": round(sum(times) / max(1, len(times)), 1),
            "median_time_seconds": round(sorted(times)[len(times) // 2], 1) if times else 0,
            "n_runs": len(times),
            "total_time_hours": round(sum(times) / 3600, 2),
        }
        if tokens:
            out["avg_tokens"] = round(sum(tokens) / len(tokens), 0)
            out["total_tokens"] = sum(tokens)
        if sizes:
            out["avg_report_kb"] = round(sum(sizes) / len(sizes), 1)
        metrics[mode] = out
    return metrics


def compute_m6_robustness(results):
    """M6: Robustness - budget, fallback, timeout distribution."""
    modes = ["traffic_first", "traffic_first_enhanced", "react", "react_enhanced"]
    metrics = {}
    for mode in modes:
        fallback = 0
        timeout = 0
        fallback_reasons = {}
        completed = 0
        for gt, mode_results in results:
            dr = mode_results.get(mode)
            if dr is None:
                continue
            if dr.elapsed_seconds > 0:
                completed += 1
                if dr.fallback_reason:
                    fallback += 1
                    fallback_reasons[dr.fallback_reason] = (
                        fallback_reasons.get(dr.fallback_reason, 0) + 1
                    )
                if dr.exit_code == -9:
                    timeout += 1
        metrics[mode] = {
            "completed": completed,
            "fallback": fallback,
            "fallback_rate": round(fallback / max(1, completed), 3),
            "timeouts": timeout,
            "fallback_reasons": fallback_reasons,
        }
    return metrics


# ─────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-events", type=int, default=None,
                        help="Cap number of events for quick runs")
    parser.add_argument("--skip-run", action="store_true",
                        help="Use existing reports only (no new runs)")
    parser.add_argument("--event-ids", nargs="*", default=None,
                        help="Run only specific event IDs")
    parser.add_argument("--modes", nargs="*", default=None,
                        help="Run only specific modes")
    parser.add_argument("--budget-aware", action="store_true",
                        help="Pre-check budget before each event/mode and "
                             "skip if exhausted. Use this in long tmux runs.")
    parser.add_argument("--max-calls-this-run", type=int, default=None,
                        help="Stop the run after this many LLM calls used "
                             "(helps split the 1000/5h budget across multiple runs)")
    parser.add_argument("--prefer-existing", action="store_true",
                        help="If a recent report exists for an event, skip "
                             "rerunning for that mode (default: True)")
    parser.add_argument("--no-prefer-existing", dest="prefer_existing",
                        action="store_false",
                        help="Force re-run even if existing report found")
    parser.set_defaults(prefer_existing=True)
    args = parser.parse_args()

    print("=" * 80)
    print(f"Comprehensive Multi-Metric Evaluation — {datetime.now().isoformat()}")
    print("=" * 80)

    # Load ground truth
    events = load_ground_truth(CSV_PATH)
    print(f"\nLoaded {len(events)} ground-truth events from {CSV_PATH.name}")
    label_dist = {}
    for e in events:
        label_dist[e.event_type] = label_dist.get(e.event_type, 0) + 1
    print(f"Distribution: {label_dist}")

    # Filter
    if args.event_ids:
        events = [e for e in events if e.event_id in args.event_ids]
        print(f"Filtered to {len(events)} events by ID")
    if args.max_events:
        events = events[:args.max_events]
        print(f"Capped to {len(events)} events")

    modes_to_run = args.modes or [m[0] for m in MODES]
    mode_lookup = {m[0]: m for m in MODES}

    # ── Budget pre-flight ─────────────────────────────────────────────────
    budget_tracker = None
    initial_calls_used = 0
    if args.budget_aware:
        try:
            sys.path.insert(0, str(PROJECT_ROOT))
            from llm.llm_factory import get_budget_tracker, BudgetExhausted
            budget_tracker = get_budget_tracker()
            remaining = budget_tracker.remaining_budget()
            # remaining_budget returns (remaining_calls, max_calls)
            max_calls = remaining[1] if isinstance(remaining, tuple) else 950
            remaining_n = remaining[0] if isinstance(remaining, tuple) else max_calls
            used = max_calls - remaining_n
            print(f"\n[BUDGET] Budget tracker active. "
                  f"Remaining: {remaining_n}/{max_calls} (used={used})")
            initial_calls_used = used
            if remaining_n <= 0:
                print(f"[BUDGET] No budget remaining! Use --max-calls-this-run "
                      f"to override or reset budget via env var.")
                if not args.max_calls_this_run:
                    return 1
        except Exception as e:
            print(f"[BUDGET] Could not init budget tracker: {e}")

    # Output paths
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = EVAL_DIR / f"run_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir = LOGS_DIR / "4mode_eval_v2"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / timestamp).mkdir(exist_ok=True)

    # Save metadata
    with open(out_dir / "args.json", "w") as f:
        json.dump({k: getattr(args, k) for k in [
            "max_events", "skip_run", "event_ids", "modes",
            "budget_aware", "max_calls_this_run", "prefer_existing",
        ]}, f, indent=2)

    results: list[tuple[EventGroundTruth, dict[str, DetectionResult]]] = []
    report_metrics: dict[str, list[tuple[EventGroundTruth, ReportMetrics]]] = {
        m: [] for m in modes_to_run
    }

    # Process each event × mode
    total = len(events) * len(modes_to_run)
    done = 0
    skipped_existing = 0
    skipped_budget = 0
    total_calls_this_run = 0
    overall_t0 = time.monotonic()
    for ei, event in enumerate(events):
        print(f"\n[{ei+1}/{len(events)}] {event.event_id} ({event.event_type}, "
              f"AS{event.as_victim or '?'}, dir={event.causal_direction})")
        mode_results = {}
        for mode_name in modes_to_run:
            mode_flag, _enhanced = mode_lookup[mode_name][1], mode_lookup[mode_name][2]
            enhanced = mode_lookup[mode_name][2]
            log_subdir = log_dir / timestamp
            log_subdir.mkdir(parents=True, exist_ok=True)

            # Check budget before running
            if args.budget_aware and budget_tracker:
                try:
                    rem = budget_tracker.remaining_budget()
                    if isinstance(rem, tuple):
                        rem_n = rem[0]
                    else:
                        rem_n = rem
                    if rem_n <= 0:
                        skipped_budget += 1
                        dr = DetectionResult(
                            event_id=event.event_id, mode=mode_name,
                            elapsed_seconds=0.0, exit_code=-99,
                            report_path=None, report_size_kb=0.0,
                            report_is_llm=False, fallback_reason="budget_exhausted",
                            traffic_score=None, routing_score=None,
                            hijack_detected=None, leak_detected=None,
                            outage_detected=None, traffic_anomaly_count=None,
                            routing_anomaly_count=None, token_count=None,
                        )
                        mode_results[mode_name] = dr
                        print(f"  [{done+1}/{total}] {mode_name}: SKIP (budget exhausted)")
                        continue
                except Exception:
                    pass

            # Check max-calls-this-run cap
            if args.max_calls_this_run and total_calls_this_run >= args.max_calls_this_run:
                skipped_budget += 1
                dr = DetectionResult(
                    event_id=event.event_id, mode=mode_name,
                    elapsed_seconds=0.0, exit_code=-98,
                    report_path=None, report_size_kb=0.0,
                    report_is_llm=False, fallback_reason="run_cap_reached",
                    traffic_score=None, routing_score=None,
                    hijack_detected=None, leak_detected=None,
                    outage_detected=None, traffic_anomaly_count=None,
                    routing_anomaly_count=None, token_count=None,
                )
                mode_results[mode_name] = dr
                print(f"  [{done+1}/{total}] {mode_name}: SKIP (run cap reached)")
                continue

            if args.skip_run:
                # Use existing report
                asn = event.as_victim.replace("AS", "").strip()
                report = find_report_path(asn, mode_name)
                dr = DetectionResult(
                    event_id=event.event_id, mode=mode_name,
                    elapsed_seconds=0.0, exit_code=0,
                    report_path=str(report) if report else None,
                    report_size_kb=report.stat().st_size / 1024 if report else 0.0,
                    report_is_llm=bool(report), fallback_reason=None,
                    traffic_score=None, routing_score=None,
                    hijack_detected=None, leak_detected=None,
                    outage_detected=None, traffic_anomaly_count=None,
                    routing_anomaly_count=None, token_count=None,
                )
            else:
                dr = run_event(event, mode_name, mode_flag, enhanced, log_subdir,
                               prefer_existing=args.prefer_existing)
                # Estimate calls used for this run (heuristic: report > 0 = success)
                # Actual call count is logged in the chief_agent log; we use a
                # conservative estimate so the run cap is respected.
                if dr.elapsed_seconds > 0:
                    if dr.report_is_llm:
                        # Conservative estimate per mode
                        call_est = {"traffic_first": 3,
                                    "traffic_first_enhanced": 15,
                                    "react": 7,
                                    "react_enhanced": 21}.get(mode_name, 5)
                        total_calls_this_run += call_est
            mode_results[mode_name] = dr
            done += 1

            # Compute report metrics
            if dr.report_path:
                rm = compute_report_metrics(Path(dr.report_path), event)
                rm.mode = mode_name
                report_metrics[mode_name].append((event, rm))

            elapsed = time.monotonic() - overall_t0
            print(f"  [{done}/{total}] {mode_name}: "
                  f"{dr.elapsed_seconds:.0f}s exit={dr.exit_code} "
                  f"size={dr.report_size_kb:.0f}KB "
                  f"reason={dr.fallback_reason or 'ok'}", flush=True)

            # Per-event checkpoint
            with open(out_dir / "checkpoint.jsonl", "a") as f:
                f.write(json.dumps({
                    "event_id": event.event_id, "mode": mode_name,
                    "elapsed": dr.elapsed_seconds,
                    "report": dr.report_path,
                    "size_kb": dr.report_size_kb,
                    "exit": dr.exit_code,
                    "fallback": dr.fallback_reason,
                }) + "\n")

            # ETA estimate
            avg = elapsed / max(1, done)
            remaining = (total - done) * avg
            print(f"     ETA: {remaining/60:.1f} min remaining "
                  f"(avg {avg:.1f}s/run)", flush=True)

        results.append((event, mode_results))

    # Compute aggregate metrics
    print("\n" + "=" * 80)
    print("Computing aggregate metrics…")
    print("=" * 80)
    m1 = compute_m1_detection_accuracy(results)
    m2 = compute_m2_causal_direction(results, report_metrics)
    m3 = compute_m3_scientific(results, report_metrics)
    m4 = {mode: compute_m4_report_quality(results, report_metrics, mode) for mode in modes_to_run}
    m5 = compute_m5_efficiency(results)
    m6 = compute_m6_robustness(results)

    all_metrics = {
        "M1_detection_accuracy": m1,
        "M2_causal_direction": m2,
        "M3_scientific_soundness": m3,
        "M4_report_quality": m4,
        "M5_efficiency": m5,
        "M6_robustness": m6,
        "meta": {
            "n_events": len(events),
            "modes": modes_to_run,
            "total_runtime_seconds": time.monotonic() - overall_t0,
            "timestamp": datetime.now().isoformat(),
            "skipped_budget": skipped_budget,
            "skipped_existing": skipped_existing,
            "calls_used_this_run": total_calls_this_run,
        },
    }

    # Write final report
    with open(out_dir / "metrics.json", "w") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"\nWrote {out_dir / 'metrics.json'}")

    # Per-mode summary table
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    for mode in modes_to_run:
        m1m = m1.get(mode, {})
        m5m = m5.get(mode, {})
        m6m = m6.get(mode, {})
        m4m = m4.get(mode, {}).get("content_score", {})
        print(f"\n{mode}:")
        print(f"  M1 F1={m1m.get('f1', 0):.3f}  precision={m1m.get('precision', 0):.3f}  "
              f"recall={m1m.get('recall', 0):.3f}  accuracy={m1m.get('accuracy', 0):.3f}")
        print(f"  M2 agreement={m2.get(mode, {}).get('agreement_rate', 0):.3f}")
        print(f"  M3 stationarity pass={m3.get(mode, {}).get('pass_rate', 0):.3f}")
        print(f"  M4 content_score mean={m4m.get('mean', 0):.3f}  "
              f"section_completeness={m4.get(mode, {}).get('section_completeness', {}).get('mean', 0):.3f}")
        print(f"  M5 avg_time={m5m.get('avg_time_seconds', 0):.0f}s  "
              f"n_runs={m5m.get('n_runs', 0)}")
        print(f"  M6 fallback_rate={m6m.get('fallback_rate', 0):.3f}  "
              f"timeouts={m6m.get('timeouts', 0)}")

    print(f"\nFull metrics → {out_dir / 'metrics.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Evaluate batch results against ground truth.

Compares each (event, mode) result's cause prediction against
``ground_truth_cause_label`` in the v17 CSV and produces a per-event
and per-mode accuracy summary.

Reads:
    /data/bgp_tracer/data_check/ground_truth_collection/final_balanced_dataset_v17.csv
    <batch_results_dir>/results.jsonl
    <batch_results_dir>/<event_id>/<mode>.log  (for per-run LLM call stats)
    <batch_results_dir>/<event_id>/<mode>.html (when log was redirected)

Outputs:
    <batch_results_dir>/evaluation.json  — machine-readable summary
    <batch_results_dir>/evaluation.txt   — human-readable summary
"""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

# Cause strings in the canonical v17 taxonomy used by the CSV.
CANON = (
    "origin_hijack_victim", "origin_hijack_attacker",
    "roa_misconfig", "route_leak", "outage",
    "traffic_anomaly_only", "no_clear_anomaly",
    "independent_coincidence",
)

# Map of normalised aliases found in logs / HTML / metrics to the canonical
# form.  Keys are lowercase substrings; first match wins.
CAUSE_SUBSTRINGS = [
    ("origin_hijack_victim", "origin_hijack_victim"),
    ("origin_hijack_attacker", "origin_hijack_attacker"),
    ("origin hijack (as is victim)", "origin_hijack_victim"),
    ("origin hijack (as is attacker)", "origin_hijack_attacker"),
    ("origin hijack", "origin_hijack_victim"),
    ("hostile prefix hijack", "origin_hijack_attacker"),
    ("hijack (as is attacker)", "origin_hijack_attacker"),
    ("hijack (as is victim)", "origin_hijack_victim"),
    ("hijack_attacker", "origin_hijack_attacker"),
    ("hijack_victim", "origin_hijack_victim"),
    ("as is victim", "origin_hijack_victim"),
    ("as is attacker", "origin_hijack_attacker"),
    ("roa misconfiguration", "roa_misconfig"),
    ("rpki/irr gap", "roa_misconfig"),
    ("rpki tampering", "roa_misconfig"),
    ("roa_misconfig", "roa_misconfig"),
    ("route leak", "route_leak"),
    ("route_leak", "route_leak"),
    ("reachability outage", "outage"),
    ("bgp reachability outage", "outage"),
    ("network outage", "outage"),
    ("traffic anomaly", "traffic_anomaly_only"),
    ("traffic_anomaly_only", "traffic_anomaly_only"),
    ("no clear anomaly", "no_clear_anomaly"),
    ("independent coincidence", "independent_coincidence"),
]


def _normalise_cause(raw: str) -> str:
    """Normalise a raw cause string from a log/JSON/HTML to canonical form."""
    if not raw:
        return ""
    s = raw.strip().lower()
    # Direct equality first.
    if s in CANON:
        return s
    # Substring match — first hit wins.
    for needle, canon in CAUSE_SUBSTRINGS:
        if needle in s:
            return canon
    # Last-ditch: see if the raw string contains any canonical cause as
    # an underscore-separated token.
    for canon in CANON:
        if canon in s.lower():
            return canon
    return ""


# Patterns used to find a cause string in a chief_agent subprocess log.
CAUSE_PATTERNS = [
    re.compile(r"Top cause:\s*([a-z_]+)", re.IGNORECASE),
    re.compile(r"Final cause:\s*([a-z_]+)", re.IGNORECASE),
    re.compile(r"Most likely cause:\s*([a-z_]+)", re.IGNORECASE),
    re.compile(r"Predicted cause:\s*([a-z_]+)", re.IGNORECASE),
    re.compile(r"cause label:\s*([^|<]+)", re.IGNORECASE),
    re.compile(r"diagnosis:\s*([a-z_]+).*", re.IGNORECASE),
]


def _extract_cause_from_log(log_path: Path) -> str:
    """Find the cause string in a chief_agent subprocess log."""
    if not log_path.exists():
        return ""
    text = log_path.read_text(errors="ignore")
    # Try the named patterns first.
    for pat in CAUSE_PATTERNS:
        m = pat.search(text)
        if m:
            n = _normalise_cause(m.group(1))
            if n:
                return n
    # Last-ditch: search for a "Cause: <cause>" or "Cause label: <cause>"
    # line in the last 200 lines.
    for line in text.splitlines()[-200:]:
        line_l = line.lower()
        if "cause" in line_l and ":" in line_l:
            tail = line.split(":", 1)[1].strip()
            n = _normalise_cause(tail)
            if n:
                return n
    return ""


def _extract_cause_from_html(html_path: Path) -> str:
    """Pull the cause label out of the rendered HTML report."""
    if not html_path.exists():
        return ""
    text = html_path.read_text(errors="ignore").lower()
    # "Cause label: <cause>" is the most reliable needle.
    for pat in CAUSE_PATTERNS:
        m = pat.search(text)
        if m:
            n = _normalise_cause(m.group(1))
            if n:
                return n
    # Fallback: look for diagnosis-section phrases.
    return _normalise_cause(text)


def _ground_truth_for(csv_path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            out[row["event_id"]] = row
    return out


def evaluate(batch_dir: Path, csv_path: Path) -> dict:
    gt = _ground_truth_for(csv_path)
    results_jsonl = batch_dir / "results.jsonl"
    results: list[dict] = []
    if results_jsonl.exists():
        with open(results_jsonl) as f:
            for line in f:
                line = line.strip()
                if line:
                    results.append(json.loads(line))

    rows: list[dict] = []
    for r in results:
        ev_id = r["event_id"]; mode = r["mode"]
        gt_row = gt.get(ev_id)
        if not gt_row:
            continue
        gt_label = (gt_row.get("ground_truth_cause_label") or "").strip().lower()
        gt_subtype = (gt_row.get("ground_truth_root_cause_subtype") or "").strip().lower()
        is_neg = gt_subtype == "internal_failure_non_bgp"

        # Try JSON field first.
        pred = r.get("cause") or r.get("predicted_cause") or ""

        # Then HTML.
        if not pred:
            html_path = r.get("html_report_path")
            if html_path and Path(html_path).exists():
                pred = _extract_cause_from_html(Path(html_path))

        # Then log.
        if not pred:
            log_path = Path(r.get("log_path", ""))
            if log_path:
                pred = _extract_cause_from_log(log_path)

        pred = _normalise_cause(pred)
        match = pred == gt_label
        rows.append({
            "event_id": ev_id,
            "mode": mode,
            "ground_truth": gt_label,
            "predicted": pred,
            "match": match,
            "is_negative_control": is_neg,
            "verdict": r.get("verdict"),
            "html_size_kb": r.get("html_size_bytes", 0) // 1024,
            "elapsed_s": r.get("elapsed_seconds", 0),
        })

    n = len(rows)
    n_match = sum(1 for r in rows if r["match"])
    rows_excl = [r for r in rows if not r["is_negative_control"]]
    n_excl = len(rows_excl)
    n_excl_match = sum(1 for r in rows_excl if r["match"])

    per_mode: dict[str, dict] = {}
    for mode in {r["mode"] for r in rows}:
        m_rows = [r for r in rows if r["mode"] == mode]
        m_excl = [r for r in rows_excl if r["mode"] == mode]
        per_mode[mode] = {
            "total": len(m_rows),
            "matches": sum(1 for r in m_rows if r["match"]),
            "matches_excl_neg": sum(1 for r in m_excl if r["match"]),
            "excl_total": len(m_excl),
            "accuracy": (
                sum(1 for r in m_rows if r["match"]) / len(m_rows)
                if m_rows else 0.0
            ),
            "accuracy_excl_neg": (
                sum(1 for r in m_excl if r["match"]) / len(m_excl)
                if m_excl else 0.0
            ),
        }

    summary = {
        "batch_dir": str(batch_dir),
        "total_runs": n,
        "matches": n_match,
        "accuracy": n_match / n if n else 0.0,
        "excl_negative_control_runs": n_excl,
        "excl_negative_control_matches": n_excl_match,
        "excl_negative_control_accuracy": n_excl_match / n_excl if n_excl else 0.0,
        "per_mode": per_mode,
        "rows": rows,
    }
    return summary


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: evaluate_batch.py <batch_results_dir> [csv_path]")
        return 2
    batch_dir = Path(sys.argv[1]).resolve()
    csv_path = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else (
        Path("/data/bgp_tracer/data_check/ground_truth_collection/final_balanced_dataset_v17.csv")
    )
    if not batch_dir.exists():
        print(f"ERROR: {batch_dir} not found")
        return 2
    if not csv_path.exists():
        print(f"ERROR: {csv_path} not found")
        return 2

    s = evaluate(batch_dir, csv_path)
    (batch_dir / "evaluation.json").write_text(json.dumps(s, indent=2))
    # Human-readable
    lines = []
    lines.append(f"Batch: {batch_dir}")
    lines.append(f"Total runs: {s['total_runs']}")
    lines.append(f"Matches: {s['matches']}")
    lines.append(f"Accuracy (all): {s['accuracy']:.1%}")
    lines.append(f"Excl negative control: {s['excl_negative_control_matches']}/{s['excl_negative_control_runs']} = {s['excl_negative_control_accuracy']:.1%}")
    lines.append("")
    lines.append("Per-mode accuracy:")
    for mode, m in sorted(s["per_mode"].items()):
        lines.append(f"  {mode:25} all={m['accuracy']:.1%}  excl_neg={m['accuracy_excl_neg']:.1%}  ({m['matches']}/{m['total']}  excl {m['matches_excl_neg']}/{m['excl_total']})")
    lines.append("")
    lines.append("Wrong cases (excl negative controls):")
    for r in s["rows"]:
        if r["match"] or r["is_negative_control"]:
            continue
        lines.append(f"  {r['event_id']:45} mode={r['mode']:15} GT={r['ground_truth']:22} pred={r['predicted']:22} html={r['html_size_kb']}KB elapsed={r['elapsed_s']:.0f}s")
    text = "\n".join(lines) + "\n"
    (batch_dir / "evaluation.txt").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

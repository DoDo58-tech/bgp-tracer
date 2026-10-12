#!/usr/bin/env python3
"""Final evaluation of v17 multi-agent batch against ground truth.

Aggregates results across multiple batch runs (e.g. v5, v6_remaining,
v7) so partial runs can be combined. For each (event, mode) the most
recent successful result wins.

Outputs:
    /data/bgp_tracer/results/v17_final_evaluation.json
    /data/bgp_tracer/results/v17_final_evaluation.txt

The text file is the human-readable summary; the .json file is the
machine-readable per-(event, mode) breakdown.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Cause parsing — keep in sync with scripts/evaluate_batch.py
# ---------------------------------------------------------------------------

CANON = (
    "origin_hijack_victim", "origin_hijack_attacker",
    "roa_misconfig", "route_leak", "outage",
    "traffic_anomaly_only", "no_clear_anomaly",
    "independent_coincidence",
)

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
    if not raw:
        return ""
    s = raw.strip().lower()
    if s in CANON:
        return s
    for needle, canon in CAUSE_SUBSTRINGS:
        if needle in s:
            return canon
    for canon in CANON:
        if canon in s.lower():
            return canon
    return ""


CAUSE_PATTERNS = [
    re.compile(r"Top cause:\s*([a-z_]+)", re.IGNORECASE),
    re.compile(r"Final cause:\s*([a-z_]+)", re.IGNORECASE),
    re.compile(r"Most likely cause:\s*([a-z_]+)", re.IGNORECASE),
    re.compile(r"Predicted cause:\s*([a-z_]+)", re.IGNORECASE),
    re.compile(r"cause label:\s*([^|<]+)", re.IGNORECASE),
    re.compile(r"diagnosis:\s*([a-z_]+).*", re.IGNORECASE),
]


def _extract_from_html(html_path: Path) -> str:
    if not html_path.exists():
        return ""
    text = html_path.read_text(errors="ignore").lower()
    for pat in CAUSE_PATTERNS:
        m = pat.search(text)
        if m:
            n = _normalise_cause(m.group(1))
            if n:
                return n
    return _normalise_cause(text)


def _extract_from_log(log_path: Path) -> str:
    if not log_path.exists():
        return ""
    text = log_path.read_text(errors="ignore")
    for pat in CAUSE_PATTERNS:
        m = pat.search(text)
        if m:
            n = _normalise_cause(m.group(1))
            if n:
                return n
    for line in text.splitlines()[-200:]:
        line_l = line.lower()
        if "cause" in line_l and ":" in line_l:
            tail = line.split(":", 1)[1].strip()
            n = _normalise_cause(tail)
            if n:
                return n
    return ""


# ---------------------------------------------------------------------------
# Batch discovery + aggregation
# ---------------------------------------------------------------------------


def _ground_truth_for(csv_path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            out[row["event_id"]] = row
    return out


def _list_batch_dirs(logs_root: Path) -> list[Path]:
    """Return all 4mode_batch_<TS>/ dirs sorted newest-first."""
    return sorted(
        [d for d in logs_root.iterdir() if d.is_dir() and d.name.startswith("4mode_batch_")],
        key=lambda p: p.name,
        reverse=True,
    )


def _load_batch_results(batch_dir: Path) -> list[dict]:
    """Load result.jsonl from a single batch dir, or [] if missing."""
    p = batch_dir / "results.jsonl"
    if not p.exists():
        return []
    out = []
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _discover_extra_html(html_dir: Path) -> dict[tuple[str, str], Path]:
    """For (event_id, mode) combos without a batch result, look for
    hand-run chief_agent HTMLs in ``results/html/`` keyed by ASN.

    Returns {(event_id, mode): html_path}.

    The mode is left blank here — caller has to look up the per-event
    cache or another source to know which mode a free-running chief_agent
    used. We treat any html newer than the latest batch as a fallback.
    """
    if not html_dir.exists():
        return {}
    # Map ASN -> list of (mtime, path) sorted newest first.
    by_asn: dict[str, list[tuple[float, Path]]] = {}
    for f in html_dir.glob("llm_report_AS*.html"):
        # Filename pattern: llm_report_AS<ASN>_<TS>.html
        # ASN is the second underscore-separated field; handle AS prefix.
        parts = f.name.split("_")
        if len(parts) < 3:
            continue
        asn_raw = parts[2].lstrip("0") or "0"
        # Some ASNs have leading zeros stripped; the csv stores ints.
        try:
            asn_int = str(int(asn_raw))
        except ValueError:
            continue
        by_asn.setdefault(asn_int, []).append((f.stat().st_mtime, f))
    for asn in by_asn:
        by_asn[asn].sort(reverse=True)
    return by_asn


def aggregate(csv_path: Path, logs_root: Path, html_dir: Path) -> dict:
    gt = _ground_truth_for(csv_path)

    # Build the list of (event, mode) targets from the CSV.
    # We default to running BOTH modes for each event (matching batch v7).
    targets: list[tuple[str, str]] = []
    for ev_id, row in gt.items():
        for mode in ("traffic_first", "react"):
            targets.append((ev_id, mode))

    # Aggregate the latest result per (event_id, mode) across all batches,
    # preferring the newest batch that has a non-empty HTML.
    latest: dict[tuple[str, str], dict] = {}
    batch_dirs = _list_batch_dirs(logs_root)
    for batch_dir in batch_dirs:
        for r in _load_batch_results(batch_dir):
            key = (r["event_id"], r["mode"])
            existing = latest.get(key)
            # Prefer newer batches with bigger HTML (sanity check).
            existing_size = (existing or {}).get("html_size_bytes", 0)
            new_size = r.get("html_size_bytes", 0)
            if not existing or new_size >= existing_size:
                latest[key] = {**r, "_batch_dir": str(batch_dir)}

    # Where the batch left no result, fall back to the latest HTML run.
    # We match by ASN derived from ``resolve_target_asn``.
    import csv as _csv
    # Mirror the batch's resolve_target_asn logic.
    def _resolve(row):
        etype = (row.get("event_type") or "").strip().lower()
        label = (row.get("ground_truth_cause_label") or "").strip().lower()
        is_leak = etype in {"leak", "route_leak"} or label == "route_leak"
        order = ("leak_as", "attacker_as", "victim_as") if is_leak else (
            "victim_as", "attacker_as", "leak_as")
        for field in order:
            v = (row.get(field) or "").replace("AS", "").strip()
            if v:
                return v
        return ""

    by_asn_htmls = _discover_extra_html(html_dir)
    rows: list[dict] = []
    for ev_id, mode in targets:
        gt_row = gt[ev_id]
        gt_label = (gt_row.get("ground_truth_cause_label") or "").strip().lower()
        gt_subtype = (gt_row.get("ground_truth_root_cause_subtype") or "").strip().lower()
        is_neg = gt_subtype == "internal_failure_non_bgp"

        r = latest.get((ev_id, mode))
        pred = ""
        if r:
            pred = (r.get("cause") or r.get("predicted_cause") or "").strip()
            html_path = r.get("html_report_path")
            if not pred and html_path:
                pred = _extract_from_html(Path(html_path))
            log_path = Path(r.get("log_path", ""))
            if not pred:
                pred = _extract_from_log(log_path)
            html_size_kb = r.get("html_size_bytes", 0) // 1024
            elapsed = r.get("elapsed_seconds", 0)
            verdict = r.get("verdict")
            batch_dir = r.get("_batch_dir", "")
        else:
            asn = _resolve(gt_row)
            htmls = by_asn_htmls.get(asn, [])
            if htmls:
                # Pick the newest html as a fallback (the most recent
                # chief_agent run by the user).
                html_path = htmls[0][1]
                pred = _extract_from_html(html_path)
                html_size_kb = html_path.stat().st_size // 1024
                elapsed = 0
                verdict = "HTML_ONLY"
                batch_dir = "(ad-hoc HTML)"
            else:
                html_size_kb = 0
                elapsed = 0
                verdict = "NOT_RUN"
                batch_dir = ""
        pred_canon = _normalise_cause(pred)
        match = pred_canon == gt_label
        rows.append({
            "event_id": ev_id,
            "mode": mode,
            "ground_truth": gt_label,
            "predicted": pred_canon,
            "predicted_raw": pred,
            "match": match,
            "is_negative_control": is_neg,
            "verdict": verdict,
            "html_size_kb": html_size_kb,
            "elapsed_s": elapsed,
            "batch_dir": batch_dir,
        })

    # Aggregate.
    n = len(rows)
    n_match = sum(1 for r in rows if r["match"])
    rows_excl = [r for r in rows if not r["is_negative_control"]]
    n_excl = len(rows_excl)
    n_excl_match = sum(1 for r in rows_excl if r["match"])

    by_mode: dict[str, dict] = {}
    for mode in ("traffic_first", "react"):
        m_rows = [r for r in rows if r["mode"] == mode]
        m_excl = [r for r in rows_excl if r["mode"] == mode]
        if not m_rows:
            continue
        by_mode[mode] = {
            "total": len(m_rows),
            "matches": sum(1 for r in m_rows if r["match"]),
            "matches_excl_neg": sum(1 for r in m_excl if r["match"]),
            "excl_total": len(m_excl),
            "not_run": sum(1 for r in m_rows if r["verdict"] == "NOT_RUN"),
            "html_only": sum(1 for r in m_rows if r["verdict"] == "HTML_ONLY"),
            "accuracy": (
                sum(1 for r in m_rows if r["match"]) / len(m_rows)
                if m_rows else 0.0
            ),
            "accuracy_excl_neg": (
                sum(1 for r in m_excl if r["match"]) / len(m_excl)
                if m_excl else 0.0
            ),
            "accuracy_only_run_excl_neg": (
                sum(1 for r in m_excl if r["match"] and r["verdict"] != "NOT_RUN")
                / sum(1 for r in m_excl if r["verdict"] != "NOT_RUN")
                if any(1 for m in m_excl if m["verdict"] != "NOT_RUN") else 0.0
            ),
        }

    return {
        "total_runs": n,
        "matches": n_match,
        "accuracy": n_match / n if n else 0.0,
        "excl_negative_control_runs": n_excl,
        "excl_negative_control_matches": n_excl_match,
        "excl_negative_control_accuracy": n_excl_match / n_excl if n_excl else 0.0,
        "by_mode": by_mode,
        "rows": rows,
    }


def main():
    csv_path = Path("/data/bgp_tracer/data_check/ground_truth_collection/final_balanced_dataset_v17.csv")
    logs_root = Path("/data/bgp_tracer/logs")
    html_dir = Path("/data/bgp_tracer/results/html")
    out_dir = Path("/data/bgp_tracer/results")

    s = aggregate(csv_path, logs_root, html_dir)
    (out_dir / "v17_final_evaluation.json").write_text(json.dumps(s, indent=2))

    # Text summary.
    lines: list[str] = []
    lines.append(f"v17 Multi-Agent Batch — Accuracy Report")
    lines.append(f"=========================================")
    lines.append(f"Total (event, mode) runs: {s['total_runs']}")
    lines.append(f"Matches: {s['matches']}")
    lines.append(f"Accuracy (all): {s['accuracy']:.1%}")
    lines.append(f"Accuracy (excl negative controls): "
                 f"{s['excl_negative_control_matches']}/{s['excl_negative_control_runs']} "
                 f"= {s['excl_negative_control_accuracy']:.1%}")
    lines.append("")
    lines.append("Per-mode accuracy:")
    for mode, m in s["by_mode"].items():
        lines.append(
            f"  {mode:25} "
            f"all={m['accuracy']:.1%}  "
            f"excl_neg={m['accuracy_excl_neg']:.1%}  "
            f"only_run_excl_neg={m['accuracy_only_run_excl_neg']:.1%}  "
            f"({m['matches']}/{m['total']}, "
            f"excl_neg {m['matches_excl_neg']}/{m['excl_total']}, "
            f"not_run={m['not_run']}, html_only={m['html_only']})"
        )
    lines.append("")
    lines.append("Wrong cases (excl negative controls):")
    n_wrong = 0
    for r in s["rows"]:
        if r["match"] or r["is_negative_control"]:
            continue
        n_wrong += 1
        lines.append(
            f"  {r['event_id']:45} mode={r['mode']:15} "
            f"GT={r['ground_truth']:22} pred={r['predicted']:22} "
            f"html={r['html_size_kb']}KB verdict={r['verdict']}"
        )
    lines.append("")
    lines.append(f"Total wrong (excl negative controls): {n_wrong}")
    text = "\n".join(lines) + "\n"
    (out_dir / "v17_final_evaluation.txt").write_text(text)
    print(text)


if __name__ == "__main__":
    main()
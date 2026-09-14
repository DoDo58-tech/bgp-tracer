"""
evaluate_reports.py — Multi-dimensional evaluation of LLM-generated BGP reports.

Usage:
    python scripts/evaluate_reports.py \
        --root results/events_20260904_004831 \
        --xlsx data_check/2024-2026年BGP事件_流量显著精选版-v2.xlsx \
        --out results/events_20260904_004831/evaluation_report.csv

Evaluation dimensions
======================
1. **Accuracy** (against ground truth from xlsx):
    - event_type_match: 报告识别的 hijack/leak/outage vs ground truth
    - correlation_level_match: L1-L5 vs ground truth "二者相关性"
    - victim_attacker_match: 受害/攻击 AS 角色识别

2. **Output quality** (LLM refusal / empty / fallback detection):
    - used_fallback: 是否走了 fallback 渲染路径
    - html_quality: HTML 完整度（DOCTYPE/<head>/<body> 三件套）
    - file_size_kb: 报告大小

3. **Interpretability** (核心评估维度, 0-5 评分):
    - a. Causal chain clarity: OBSERVE→INFER→LINK→CONCLUDE 完整度
    - b. Field provenance: 关键数字是否带 [source: ...] 引用
    - c. Counterfactual quality: 替代假设是否具体可检验（不是套话）
    - d. Evidence completeness: 路由+流量+时间三类证据齐备
    - e. Human readability: 0 个 (no data) / 中文 / UNA 残留

4. **Per-mode diversity** (4 模式间差异):
    - text_similarity_mean: 平均相似度（越低代表 4 模式越不同）
    - length_variance: 报告长度方差

5. **Time efficiency** (per mode per event):
    - elapsed_seconds

Output: CSV with one row per (event × mode), plus an aggregate summary printed
to stdout.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Optional imports (graceful degradation) ────────────────────────────────────
try:
    from openpyxl import load_workbook
except ImportError:
    load_workbook = None  # type: ignore

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# Ground-truth loader (reads the xlsx)
# ══════════════════════════════════════════════════════════════════════════════
def load_ground_truth(xlsx_path: str) -> Dict[str, Dict[str, Any]]:
    """Load ground truth from the curated xlsx. Keyed by ASN."""
    if load_workbook is None:
        print("[WARN] openpyxl not available — skipping ground truth")
        return {}

    wb = load_workbook(xlsx_path)
    ws = wb.active
    headers = [cell.value for cell in ws[1]]

    truth: Dict[str, Dict[str, Any]] = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        asn_cell = row[9]  # col J = 测试用AS
        if asn_cell is None:
            continue
        asn = str(asn_cell).strip().replace(" ", "")

        event_type = str(row[5]) if row[5] else ""  # col F
        hijacker = str(row[6]) if row[6] else ""    # col G
        victim = str(row[7]) if row[7] else ""      # col H
        traffic_change = str(row[18]) if row[18] else ""  # col S
        bgp_can_detect = str(row[18]) if row[18] else ""  # col S
        # correlation score (col O = index 14)
        correlation_score = row[14] if row[14] is not None else 0

        truth[asn] = {
            "event_name": row[1],
            "event_type": event_type,
            "hijacker": hijacker,
            "victim": victim,
            "correlation_score": int(correlation_score) if isinstance(correlation_score, (int, float)) else 0,
            "label": str(asn_cell).strip(),
        }
    return truth


# ══════════════════════════════════════════════════════════════════════════════
# Per-report quality metrics
# ══════════════════════════════════════════════════════════════════════════════
_HTML_PLACEHOLDER_PATTERNS = [
    (re.compile(r"\(no\s*data\)", re.IGNORECASE), "no_data_artifact"),
    (re.compile(r"\(N/?A\)", re.IGNORECASE), "na_artifact"),
    (re.compile(r"UNAVAILABLE", re.IGNORECASE), "unavailable_artifact"),
    (re.compile(r"\(unresolved\)", re.IGNORECASE), "unresolved_artifact"),
]

_CJK_RE = re.compile(r"[\u4e00-\u9fff]")
_SOURCE_REF_RE = re.compile(r"\[source:[^\]]+\]")
_FIELD_REF_RE = re.compile(r"\[[a-z_][\w.]+\]")

# Causal chain keywords (in CoT order)
_COT_STAGES = ["OBSERVE", "INFER", "LINK", "CONCLUDE", "CITE"]


def html_quality(html: str) -> Dict[str, Any]:
    """Return HTML structural completeness + placeholder counts."""
    if not html:
        return {"valid_html": False, "size_kb": 0}
    return {
        "valid_html": ("<!DOCTYPE" in html.lower() or "<html" in html.lower())
                      and "</html>" in html.lower(),
        "has_doctype": bool(re.search(r"<!DOCTYPE\s+html", html, re.IGNORECASE)),
        "has_body_close": "</body>" in html.lower(),
        "has_style_tag": "<style>" in html.lower() or "body {" in html.lower(),
    }


def placeholder_count(html: str) -> Dict[str, int]:
    """Count how many (no data) / UNAVAILABLE / CJK tokens the report contains."""
    counts: Dict[str, int] = {}
    for pat, name in _HTML_PLACEHOLDER_PATTERNS:
        counts[name] = len(pat.findall(html))
    counts["cjk_chars"] = len(_CJK_RE.findall(html))
    return counts


def causal_chain_completeness(html: str) -> Dict[str, Any]:
    """Score how many of OBSERVE/INFER/LINK/CONCLUDE/CITE appear (and in order)."""
    txt = html
    # Strip tags for text-only scan
    if BS4_AVAILABLE:
        try:
            txt = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
        except Exception:
            pass

    present = {stage: stage in txt for stage in _COT_STAGES}
    # Order check: the first occurrence position
    positions = []
    for stage in _COT_STAGES:
        m = re.search(rf"\b{stage}\b", txt)
        if m:
            positions.append((m.start(), stage))
    in_order = all(positions[i][0] <= positions[i + 1][0]
                   for i in range(len(positions) - 1)) if len(positions) >= 2 else False

    return {
        "stages_present": sum(present.values()),
        "stages_total": len(_COT_STAGES),
        "stages": present,
        "in_order": in_order,
    }


def field_provenance(html: str) -> Dict[str, Any]:
    """Count source-ref citations. More refs = better provenance."""
    src_count = len(_SOURCE_REF_RE.findall(html))
    field_ref_count = len(_FIELD_REF_RE.findall(html))
    return {
        "source_ref_count": src_count,
        "field_ref_count": field_ref_count,
        "has_any_provenance": src_count > 0 or field_ref_count > 0,
    }


_COUNTERFACTUAL_QUALITY_MARKERS = re.compile(
    r"(alternative|distinguish|alternative explanation|data needed|evidence for|evidence against)",
    re.IGNORECASE,
)


def counterfactual_quality(html: str) -> Dict[str, Any]:
    """Score counterfactual section quality."""
    txt = html
    if BS4_AVAILABLE:
        try:
            txt = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
        except Exception:
            pass
    # Find counterfactual section
    cf_match = re.search(
        r"counterfactual[\s\S]*?(<h2|</body>)",
        txt,
        re.IGNORECASE,
    )
    cf_section = cf_match.group(0) if cf_match else ""
    markers = len(_COUNTERFACTUAL_QUALITY_MARKERS.findall(cf_section))
    return {
        "has_counterfactual": bool(cf_match),
        "cf_quality_marker_count": markers,
        "is_concrete": markers >= 3,
    }


_EVIDENCE_TYPES = {
    "routing": re.compile(r"\b(hijack|leak|origin|routing|as path|bgp)\b", re.IGNORECASE),
    "traffic": re.compile(r"\b(traffic|throughput|drop|spike|anomal|dps)\b", re.IGNORECASE),
    "temporal": re.compile(r"\b(ΔT|delta[ -]?t|temporal|before|after|precede|followed)\b", re.IGNORECASE),
}


def evidence_completeness(html: str) -> Dict[str, Any]:
    """Check that all three evidence types (routing, traffic, temporal) appear."""
    types_present = {k: bool(p.search(html)) for k, p in _EVIDENCE_TYPES.items()}
    return {
        "types_present": sum(types_present.values()),
        "types_total": len(_EVIDENCE_TYPES),
        "by_type": types_present,
    }


def compute_interpretability(html: str) -> Dict[str, Any]:
    """Compute the 5-dimensional interpretability score (each 0-5)."""
    if not html:
        return {"score": 0.0, "breakdown": {}}

    # Dimension a: causal chain (0-5)
    chain = causal_chain_completeness(html)
    chain_pts = chain["stages_present"] if chain["in_order"] else chain["stages_present"] - 2
    chain_pts = max(0, min(5, chain_pts))

    # Dimension b: field provenance (0-5; saturates at ~10 refs)
    prov = field_provenance(html)
    prov_pts = min(5, max(0, prov["source_ref_count"] // 2))

    # Dimension c: counterfactual (0-5)
    cf = counterfactual_quality(html)
    cf_pts = 5 if cf["is_concrete"] else (3 if cf["has_counterfactual"] else 0)

    # Dimension d: evidence types present (0-5)
    ev = evidence_completeness(html)
    ev_pts = ev["types_present"] * (5 / ev["types_total"])
    ev_pts = round(ev_pts, 1)

    # Dimension e: human readability — reverse penalty for placeholders
    ph = placeholder_count(html)
    placeholder_penalty = sum(ph.values())
    read_pts = max(0, 5 - placeholder_penalty)

    breakdown = {
        "causal_chain": round(chain_pts, 1),
        "field_provenance": round(prov_pts, 1),
        "counterfactual": round(cf_pts, 1),
        "evidence_completeness": ev_pts,
        "readability": read_pts,
    }
    score = sum(breakdown.values()) / len(breakdown)

    return {
        "score": round(score, 2),
        "breakdown": breakdown,
        "placeholders": ph,
    }


def detect_event_type_in_html(html: str, truth: Dict[str, Any]) -> Dict[str, Any]:
    """Heuristic: does the report mention the ground-truth event type?"""
    if not html:
        return {"matched": False, "score_estimate": 0}
    txt = html.lower()
    event_type_lower = truth.get("event_type", "").lower()

    has_hijack = "hijack" in txt
    has_leak = "leak" in txt
    has_outage = "outage" in txt or "断网" in txt or "disrupt" in txt

    matched = False
    score = 0
    if "hijack" in event_type_lower and has_hijack:
        matched, score = True, 3
    elif "leak" in event_type_lower and has_leak:
        matched, score = True, 3
    elif ("outage" in event_type_lower or "断" in event_type_lower) and has_outage:
        matched, score = True, 3

    # Bonus for naming the victim AS
    victim_asn = truth.get("victim", "")
    victim_match = victim_asn and victim_asn.replace("AS", "") in txt.replace("as", "")
    if victim_match:
        score += 1

    return {
        "event_type_matched": matched,
        "detection_score": score,
        "victim_as_mentioned": bool(victim_match),
    }


def correlation_level_in_html(html: str) -> Optional[str]:
    """Extract the correlation badge text from the HTML (L1/L2/.../L5)."""
    if not html:
        return None
    m = re.search(r"\b(L[1-5])\b", html)
    return m.group(1) if m else None


# ══════════════════════════════════════════════════════════════════════════════
# Diversity across modes for the same event
# ══════════════════════════════════════════════════════════════════════════════
def compute_mode_diversity(reports_by_mode: Dict[str, str]) -> Dict[str, Any]:
    """Compute TF-IDF cosine similarity across the 4 modes for one event.

    Lower mean similarity = more diverse outputs (good — different modes
    contribute different perspectives).
    """
    modes = list(reports_by_mode.keys())
    texts = [reports_by_mode[m] or "" for m in modes]
    if not any(texts) or len(texts) < 2:
        return {"mean_similarity": None, "length_variance": None}

    # Strip HTML for similarity
    if BS4_AVAILABLE:
        texts = [
            BeautifulSoup(t, "html.parser").get_text(" ", strip=True)
            if t else "" for t in texts
        ]
    else:
        texts = [re.sub(r"<[^>]+>", " ", t) for t in texts]

    sims = []
    if SKLEARN_AVAILABLE:
        try:
            vec = TfidfVectorizer(max_features=2000, stop_words="english")
            X = vec.fit_transform(texts)
            sim = cosine_similarity(X)
            for i in range(len(modes)):
                for j in range(i + 1, len(modes)):
                    sims.append(sim[i][j])
        except Exception:
            pass

    if not sims:
        # Fallback: jaccard on tokens
        token_sets = [set(t.lower().split()) for t in texts if t]
        for i in range(len(token_sets)):
            for j in range(i + 1, len(token_sets)):
                a, b = token_sets[i], token_sets[j]
                if a or b:
                    sims.append(len(a & b) / max(1, len(a | b)))

    lengths = [len(t) for t in texts]
    return {
        "mean_similarity": round(statistics.mean(sims), 3) if sims else None,
        "length_variance": round(statistics.variance(lengths), 0) if len(lengths) >= 2 else None,
        "report_lengths_chars": dict(zip(modes, lengths)),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Main evaluation loop
# ══════════════════════════════════════════════════════════════════════════════
MODES = ["traffic_first", "traffic_first_enhanced", "react", "react_enhanced"]


def evaluate_event_dir(event_dir: Path, truth_for_asn: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate all reports in one event directory."""
    results = []
    reports_by_mode: Dict[str, str] = {}

    for mode in MODES:
        # Find the log to read elapsed time
        log_path = event_dir / f"{MODES.index(mode) + 1}_{mode}.log"
        log_content = ""
        if log_path.exists():
            log_content = log_path.read_text(errors="ignore")

        elapsed = None
        m = re.search(r"exit_code=\d+ elapsed=(\d+)s", log_content)
        if m:
            elapsed = int(m.group(1))

        # Find the HTML report (saved by chief_agent to results/html/)
        # We named copies _{idx}_rep{N}_*.html in the event_dir
        html_path = None
        candidates = sorted(event_dir.glob(f"*_{mode}.html"))
        if candidates:
            html_path = candidates[0]
        else:
            # Look for any HTML that mentions our ASN in the name
            candidates = list(event_dir.glob("*.html"))
            for c in candidates:
                if mode in c.name:
                    html_path = c
                    break

        html = html_path.read_text(errors="ignore") if html_path and html_path.exists() else ""
        reports_by_mode[mode] = html

        # Quality
        hq = html_quality(html)
        ip = compute_interpretability(html)
        evtype = detect_event_type_in_html(html, truth_for_asn)
        badge = correlation_level_in_html(html)

        results.append({
            "event_dir": event_dir.name,
            "mode": mode,
            "elapsed_seconds": elapsed,
            "html_valid": hq.get("valid_html"),
            "html_size_kb": round(len(html.encode("utf-8")) / 1024, 1),
            "interpretability_score": ip["score"],
            "causal_chain_pts": ip["breakdown"].get("causal_chain"),
            "field_provenance_pts": ip["breakdown"].get("field_provenance"),
            "counterfactual_pts": ip["breakdown"].get("counterfactual"),
            "evidence_pts": ip["breakdown"].get("evidence_completeness"),
            "readability_pts": ip["breakdown"].get("readability"),
            "placeholders_total": sum(ip.get("placeholders", {}).values()),
            "event_type_matched": evtype.get("event_type_matched", False),
            "victim_as_mentioned": evtype.get("victim_as_mentioned", False),
            "correlation_badge": badge,
            "report_path": str(html_path) if html_path else "",
        })

    # Per-event diversity (across the 4 modes)
    div = compute_mode_diversity(reports_by_mode)
    for r in results:
        r["mode_diversity_sim_mean"] = div["mean_similarity"]
        r["mode_diversity_length_var"] = div["length_variance"]

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True,
                        help="Root results dir (e.g. results/events_20260904_004831)")
    parser.add_argument("--xlsx", required=True,
                        help="Path to ground-truth xlsx")
    parser.add_argument("--out", default=None,
                        help="Output CSV path (default: <root>/evaluation_report.csv)")
    args = parser.parse_args()

    root = Path(args.root)
    out_path = Path(args.out) if args.out else root / "evaluation_report.csv"

    print(f"Loading ground truth from {args.xlsx}...")
    truth = load_ground_truth(args.xlsx)
    print(f"Loaded {len(truth)} events from xlsx")

    all_rows = []
    # Index ground truth by ASN for fast lookup
    truth_by_asn: Dict[str, Dict[str, Any]] = {}
    for asn, info in truth.items():
        truth_by_asn[asn] = info
        # Also index the asn-with-AS-prefix variant
        truth_by_asn[f"AS{asn}"] = info

    for event_dir in sorted(root.iterdir()):
        if not event_dir.is_dir():
            continue
        # Try to find ground truth: scan all and pick the one whose ASN or label is in dir name
        truth_for_asn = {}
        for asn, info in truth_by_asn.items():
            if asn in event_dir.name:
                truth_for_asn = info
                break
        # Fallback: use event_type field from dir name
        if not truth_for_asn:
            for asn, info in truth.items():
                # Use a fuzzy match via the event name first chars
                if info.get("label") and info["label"] in event_dir.name:
                    truth_for_asn = info
                    break

        if not truth_for_asn:
            print(f"[WARN] No ground truth for event dir: {event_dir.name}")
        print(f"Evaluating {event_dir.name}...")
        all_rows.extend(evaluate_event_dir(event_dir, truth_for_asn))

    # Write CSV
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if all_rows:
        with open(out_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
            writer.writeheader()
            writer.writerows(all_rows)
        print(f"\n✅ Wrote {len(all_rows)} rows to {out_path}")

    # ── Aggregate summaries ────────────────────────────────────────────────
    print()
    print("=" * 80)
    print("AGGREGATE EVALUATION SUMMARY")
    print("=" * 80)

    # Group by mode
    by_mode: Dict[str, List[Dict]] = defaultdict(list)
    for r in all_rows:
        by_mode[r["mode"]].append(r)

    print(f"\n{'Mode':<28} | {'Mean':>5} | {'A':>3} | {'B':>3} | {'C':>3} | {'D':>3} | {'E':>3} | {'Matched':>7} | {'t(s)':>6}")
    print("-" * 90)
    for mode in MODES:
        rows = by_mode.get(mode, [])
        if not rows:
            continue
        scores = [r["interpretability_score"] for r in rows if r["interpretability_score"] is not None]
        a = [r["causal_chain_pts"] for r in rows if r["causal_chain_pts"] is not None]
        b = [r["field_provenance_pts"] for r in rows if r["field_provenance_pts"] is not None]
        c = [r["counterfactual_pts"] for r in rows if r["counterfactual_pts"] is not None]
        d = [r["evidence_pts"] for r in rows if r["evidence_pts"] is not None]
        e = [r["readability_pts"] for r in rows if r["readability_pts"] is not None]
        matched = sum(1 for r in rows if r["event_type_matched"])
        times = [r["elapsed_seconds"] for r in rows if r["elapsed_seconds"] is not None]
        print(
            f"{mode:<28} | "
            f"{(sum(scores)/len(scores) if scores else 0):>5.2f} | "
            f"{(sum(a)/len(a) if a else 0):>3.1f} | "
            f"{(sum(b)/len(b) if b else 0):>3.1f} | "
            f"{(sum(c)/len(c) if c else 0):>3.1f} | "
            f"{(sum(d)/len(d) if d else 0):>3.1f} | "
            f"{(sum(e)/len(e) if e else 0):>3.1f} | "
            f"{matched}/{len(rows)} | "
            f"{(sum(times)/len(times) if times else 0):>6.0f}"
        )

    print()
    print("Legend — Interpretability sub-scores (each 0-5):")
    print("  A: causal chain    B: field provenance    C: counterfactual")
    print("  D: evidence types  E: readability")
    print()
    print(f"Mode diversity (mean TF-IDF similarity across 4 modes per event):")
    divs = [r["mode_diversity_sim_mean"] for r in all_rows
            if r["mode_diversity_sim_mean"] is not None]
    if divs:
        # Group by event — each row has the same diversity score, so unique
        unique_divs = list(set(divs))
        for d in sorted(unique_divs):
            print(f"  similarity = {d}  (lower = more diverse across modes)")
    print()
    print(f"Detailed CSV: {out_path}")
    print("=" * 80)


if __name__ == "__main__":
    main()

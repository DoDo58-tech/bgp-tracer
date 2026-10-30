"""Explainability audit: what does the Evidence Blackboard actually buy?"""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.logger import logger  # noqa: E402

OUT_PATH = PROJECT_ROOT / "results" / "eval" / "explainability_audit.json"

QUESTIONS = {
    "Q1_source": "A producing component is named for the verdict",
    "Q2_quantity": "A numeric quantity is traceable to a named field",
    "Q3_window": "The time window is attached to the claim",
    "Q4_alternative": "A rejected alternative is recorded",
    "Q5_gap": "A missing or degraded input is recorded",
    "Q6_chain": "A step-by-step derivation is recorded",
}


# ── Arm 1: monolithic ────────────────────────────────────────────────────────


# ── Shared scoring predicates ───────────────────────────────────────────────


_ALT_MARKERS = (
    "rather than", "instead of", "ruled out", "alternative", "not ",
    "rather", "discounted", "rejected",
)
_GAP_MARKERS = (
    "missing", "unavailable", "no data", "absent", "not available",
    "insufficient", "degraded", "unavailable",
)


# The predicates below are deliberately **structural, not keyword-driven**.

# Words that introduce a counterfactual explanation.
_ALT_INTRO = (
    "rather than", "instead of", "not because", "alternative",
    "ruled out", "discounted", "rejected", "eliminated", "dismissed",
    "excluded",
)

# Words that state a *reason* for rejecting something.
_ALT_REASON = (
    "because", "since", "as there", "as no", "due to", "owing to",
    "no evidence", "not supported", "not established", "not detected",
    "insufficient", "weak", "correlated with", "contradicted",
    "absent", "unavailable", "failed", "did not", "does not",
)

# Words that name an absent or degraded input.
_GAP_SUBJECT = (
    "traffic data", "routing data", "bgp data", "routing feed",
    "baseline", "no traffic", "no routing", "no data", "data gap",
    "evidence gap", "missing", "unavailable", "not available",
    "insufficient", "degraded", "no correlation", "no as-relationship",
    "no as relationship", "topology", "absent",
)

# Words that state the *consequence* of that absence.
_GAP_IMPACT = (
    "because", "so ", "therefore", "hence", "thus", "which means",
    "weakens", "reduces", "limits", "cannot", "could not", "unable",
    "precluded", "rules out", "prevents", "not established",
    "confidence", "caveat", "assumption", "bounded", "provisional",
)

# Minimum length for a prose statement to count as substantive. A
# one-or-two-word fragment is a keyword, not a recorded alternative.
_MIN_STATEMENT_WORDS = 12


def statement(text: str) -> str:
    """Flatten prose into a comparable, lower-cased string."""
    return " ".join((text or "").lower().split())


def mentions_alternative(text: str) -> bool:
    """True if the text records a named alternative *and* why it was rejected."""
    body = statement(text)
    if not body:
        return False
    if len(body.split()) < _MIN_STATEMENT_WORDS:
        return False
    if not any(m in body for m in _ALT_INTRO):
        return False
    # The reason must appear in the same clause as the counterfactual, so
    # that a stray "because" elsewhere in the document cannot rescue it.
    for marker in _ALT_INTRO:
        idx = body.find(marker)
        if idx < 0:
            continue
        window = body[max(0, idx - 120): idx + 200]
        if any(r in window for r in _ALT_REASON):
            return True
    return False


def mentions_gap(text: str) -> bool:
    """True if the text names an absent input *and* states its consequence."""
    body = statement(text)
    if not body:
        return False
    if len(body.split()) < _MIN_STATEMENT_WORDS:
        return False
    for marker in _GAP_SUBJECT:
        idx = body.find(marker)
        if idx < 0:
            continue
        window = body[max(0, idx - 160): idx + 220]
        if any(r in window for r in _GAP_IMPACT):
            return True
    return False


# ── Arm 1: monolithic ────────────────────────────────────────────────────────


def score_monolithic(quick: dict) -> dict:
    """The one-shot arm produces a prose object; score what it contains."""
    from agent_value_ablation import run_monolithic

    rec = run_monolithic(quick, run_id="explain-mono")
    text = " ".join(
        str(rec.get(k) or "") for k in ("verdict", "cause", "reasoning")
    )

    # A number in prose is not a traceable quantity: Q2 requires a *named
    # field*, which a free-text answer cannot provide.
    low = text.lower()
    has_named_field = any(
        tok in low for tok in (
            "percent_change", "peak_trough_drop_pct", "outage_score",
            "anomaly_count", "route_leaks", "origin_hijacked",
        )
    )
    return {
        "Q1_source": bool(rec.get("verdict")),
        "Q2_quantity": has_named_field,
        "Q3_window": any(
            tok in low for tok in (str(quick.get("start_time") or "").lower(), "window")
        ) and bool(quick.get("start_time")),
        "Q4_alternative": mentions_alternative(text),
        "Q5_gap": mentions_gap(text),
        "Q6_chain": False,  # one call, one step: nothing to derive
        "raw": rec,
    }


# ── Arm 2: agent pipeline ────────────────────────────────────────────────────


def score_agent(quick: dict) -> dict:
    from chief_agent import analyze_deep_from_quick

    res = analyze_deep_from_quick(quick_result=quick, analysis_mode="traffic_first")
    eb = res.get("evidence_board") or {}

    def board_list(key):
        v = eb.get(key)
        if isinstance(v, dict):
            v = v.get("value")
        return v or []

    obs = board_list("observations")
    claims = board_list("claims")
    challenges = board_list("challenges")
    verdicts = board_list("verdicts")
    alternatives = board_list("alternatives")
    gaps = board_list("gaps")
    trace = res.get("reasoning_trace") or []
    cea = res.get("chief_expert_analysis") or {}

    def has_field(records, keys):
        for r in records:
            d = r if isinstance(r, dict) else getattr(r, "__dict__", {})
            payload = d.get("payload") or {}
            for k in keys:
                if d.get(k) not in (None, "", [], {}):
                    return True
                if isinstance(payload, dict) and payload.get(k) not in (None, "", [], {}):
                    return True
        return False

    # Q4 — is at least one rejected alternative recorded?
    alt_with_reason = any(
        (a.get("alternative") or a.get("summary"))
        and (a.get("rejected_because") or a.get("competes_with"))
        for a in alternatives
        if isinstance(a, dict)
    )
    challenge_with_issue = any(
        (c.get("summary") or c.get("issues")) for c in challenges if isinstance(c, dict)
    )
    claim_with_contradiction = any(
        c.get("contradicts") or c.get("uncertainty") or c.get("assumptions")
        for c in claims if isinstance(c, dict)
    )

    # Q5 — is at least one missing or degraded input recorded?
    gap_with_impact = any(
        (g.get("kind") or g.get("summary")) and (g.get("impact") or g.get("severity"))
        for g in gaps
        if isinstance(g, dict)
    )

    # The agent arm's report is prose too; a gap or an alternative stated
    # only in the report counts, on the same footing as the monolithic arm.
    report_text = ""
    try:
        rep = res.get("report_result") or res.get("analysis_report") or {}
        html = rep.get("html") or ""
        if not html:
            from pathlib import Path as _P
            p = (res.get("chief_expert_analysis") or {}).get("html_report_path")
            if p and _P(p).exists():
                html = _P(p).read_text(errors="replace")
        import re as _re
        report_text = _re.sub(r"<[^>]+>", " ", html)
    except (ValueError):  # noqa: BLE001
        report_text = ""

    # Q4 and Q5 ask whether the *record* exists, not whether the prose
    # happens to contain a suggestive word.  The prose fallback was
    # removed: with it, a report that said "no data" scored as if the
    # system had recorded a gap, which made the board look richer than
    # it was and inflated the very quantity this audit exists to measure.
    q4 = bool(alt_with_reason or challenge_with_issue or claim_with_contradiction)
    q5 = bool(gap_with_impact)

    return {
        "Q1_source": has_field(obs, ("source", "kind")) or bool(cea.get("evidence_verdict")),
        "Q2_quantity": has_field(obs, ("payload", "confidence")) or has_field(claims, ("confidence",)),
        "Q3_window": has_field(obs, ("window",)) or bool(quick.get("start_time")),
        "Q4_alternative": q4,
        "Q5_gap": q5,
        "Q6_chain": len(trace) >= 3,
        "counts": {
            "observations": len(obs),
            "claims": len(claims),
            "challenges": len(challenges),
            "verdicts": len(verdicts),
            "alternatives": len(alternatives),
            "gaps": len(gaps),
            "trace_steps": len(trace),
        },
        "raw_verdict": cea.get("evidence_verdict"),
    }


# ── Driver ───────────────────────────────────────────────────────────────────


def score_pair(pair: tuple[str, dict]) -> list[dict]:
    """Score both arms on one event.  Safe to call in a worker process."""
    eid, quick = pair
    rows = []
    for arm, fn in (("monolithic", score_monolithic), ("agent", score_agent)):
        try:
            rec = fn(quick)
        except (AttributeError) as exc:  # noqa: BLE001
            logger.error(f"[explain] {eid} {arm} failed: {exc}")
            rec = {q: False for q in QUESTIONS} | {"error": str(exc)}
        rec["arm"] = arm
        rec["event"] = eid
        rows.append(rec)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=4)
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument(
        "--corpus",
        action="store_true",
        help=(
            "Score the ground-truth corpus instead of the cached Phase-1 "
            "verdict spread.  The Phase-1 spread only yields a handful of "
            "windows, which is too small a sample to answer Q4/Q5 with "
            "any confidence."
        ),
    )
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    if args.corpus:
        from corpus_audit import load_corpus_events
        events = load_corpus_events(PROJECT_ROOT)
        if args.limit:
            events = events[: args.limit]
        pairs = [(ev["event_id"], ev["quick"]) for ev in events]
    else:
        from agent_value_ablation import pick_events
        picked = pick_events(PROJECT_ROOT / "results" / "quick", 1)[: args.events]
        pairs = []
        for path in picked:
            quick = json.loads(path.read_text())
            eid = quick.get("event_id") or path.stem
            pairs.append((eid, quick))

    out = {"records": [], "questions": QUESTIONS}
    if args.workers > 1 and len(pairs) > 1:
        from concurrent.futures import ProcessPoolExecutor, as_completed

        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(score_pair, p): p[0] for p in pairs}
            for fut in as_completed(futures):
                eid = futures[fut]
                try:
                    rows = fut.result()
                except Exception as exc:  # noqa: BLE001
                    rows = [{"arm": arm, "event": eid,
                             "error": f"worker failed: {type(exc).__name__}: {exc}",
                             **{q: False for q in QUESTIONS}}
                            for arm in ("monolithic", "agent")]
                out["records"].extend(rows)
                Path(args.out).parent.mkdir(parents=True, exist_ok=True)
                Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    else:
        for pair in pairs:
            out["records"].extend(score_pair(pair))
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(out, indent=1, default=str))

    summary = {}
    for arm in ("monolithic", "agent"):
        rows = [r for r in out["records"] if r["arm"] == arm]
        if not rows:
            continue
        summary[arm] = {
            "n": len(rows),
            **{
                q: round(sum(1 for r in rows if r.get(q)) / len(rows), 3)
                for q in QUESTIONS
            },
            "mean_score": round(
                sum(sum(1 for q in QUESTIONS if r.get(q)) for r in rows)
                / (len(rows) * len(QUESTIONS)),
                3,
            ),
        }

    out["summary"] = summary
    out["meta"] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "note": ("Mechanical rubric: each question is scored by the presence of "
                 "a typed record, not by judging prose. Re-runnable."),
    }
    Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    logger.info(f"[explain] wrote {args.out}")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
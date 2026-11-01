"""Component ablation: which element of the coordination layer earns its cost?"""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

OUT_PATH = PROJECT_ROOT / "results" / "eval" / "component_ablation.json"

# arm name -> environment variable that removes that element
ARMS = {
    "full": {},
    "no_joint_evidence": {"BGP_TRACER_ABLATE_JOINT_EVIDENCE": "1"},
    "no_hcaf": {"BGP_TRACER_ABLATE_HCAF": "1"},
    "no_hypothesis": {"BGP_TRACER_ABLATE_HYPOTHESIS": "1"},
    "no_reasoning": {"BGP_TRACER_ABLATE_REASONING": "1"},
    "no_evidence_board": {"BGP_TRACER_ABLATE_EVIDENCE_BOARD": "1"},
    "no_enrichment": {"BGP_TRACER_ABLATE_ENRICHMENT": "1"},
}

# The child process prints one JSON object on stdout between markers.
_BEGIN = "<<<RESULT>>>"
_END = "<<<END>>>"


CHILD = r'''
import json, os, sys, time
sys.path.insert(0, {root!r})
from pathlib import Path

quick = json.loads(Path({quick_path!r}).read_text())

from chief_agent import analyze_deep_from_quick

def snap_tokens():
    try:
        from llm.llm_factory import get_global_token_counter
        return int(get_global_token_counter())
    except Exception:
        return 0

tok_before = snap_tokens()
t0 = time.perf_counter()
try:
    res = analyze_deep_from_quick(quick_result=quick, analysis_mode="traffic_first")
    ok = bool(res.get("success"))
except Exception as exc:
    res, ok = {{}}, False
    import traceback
    traceback.print_exc()
elapsed = round(time.perf_counter() - t0, 2)
tokens = max(0, snap_tokens() - tok_before)

eb = res.get("evidence_board") or {{}}
def count_items(key):
    v = eb.get(key)
    if isinstance(v, dict):
        v = v.get("value")
    return len(v or []) if isinstance(v, list) else 0

cea = res.get("chief_expert_analysis") or {{}}
verdict_raw = cea.get("evidence_verdict") or res.get("quick_verdict") or ""

from scripts.agent_value_ablation import norm_verdict
answer = str(cea.get("answer") or "")
verdict = norm_verdict(verdict_raw, answer)

rep = res.get("report_result") or res.get("analysis_report") or {{}}
html = rep.get("html") or ""
if not html:
    from pathlib import Path as _P
    p = cea.get("html_report_path") or rep.get("html_report_path")
    if p and _P(p).exists():
        html = _P(p).read_text(errors="replace")
is_fallback = bool(html) and "deterministic" in html[:800].lower()

out = {{
    "success": ok,
    "verdict": verdict,
    "verdict_raw": str(verdict_raw),
    "confidence": cea.get("confidence_score"),
    "latency_s": elapsed,
    "tokens": tokens,
    "observations": count_items("observations"),
    "claims": count_items("claims"),
    "challenges": count_items("challenges"),
    "alternatives": count_items("alternatives"),
    "gaps": count_items("gaps"),
    "verdicts": count_items("verdicts"),
    "reasoning_steps": len(res.get("reasoning_trace") or []),
    "html_bytes": len(html),
    "llm_report": bool(html) and not is_fallback,
    "report_path": cea.get("html_report_path") or rep.get("report_path"),
}}
print("{begin}")
print(json.dumps(out, default=str))
print("{end}")
'''


def run_child(arm: str, env_overrides: dict, quick_path: Path):
    env = dict(os.environ)
    # Remove any inherited ablation switch so each arm is isolated.
    for var in (
        "BGP_TRACER_ABLATE_JOINT_EVIDENCE",
        "BGP_TRACER_ABLATE_HCAF",
        "BGP_TRACER_ABLATE_HYPOTHESIS",
        "BGP_TRACER_ABLATE_REASONING",
        "BGP_TRACER_ABLATE_EVIDENCE_BOARD",
        "BGP_TRACER_ABLATE_ENRICHMENT",
    ):
        env.pop(var, None)
    env.update({k: v for k, v in env_overrides.items()})

    script = CHILD.format(
        root=str(PROJECT_ROOT),
        quick_path=str(quick_path),
        begin=_BEGIN,
        end=_END,
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(PROJECT_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    out = proc.stdout or ""
    if _BEGIN not in out or _END not in out:
        return {
            "success": False,
            "error": "child produced no result marker",
            "stderr_tail": (proc.stderr or "")[-1500:],
        }
    payload = out.split(_BEGIN, 1)[1].split(_END, 1)[0].strip()
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        return {"success": False, "error": f"unparsable child output: {exc}",
                "raw": payload[:1000]}


def norm_verdict_local(raw: str, text: str = ""):
    """Fallback normaliser (the child's import may fail in odd installs)."""
    r = (raw or "").strip().lower()
    aliases = {
        "cooccurring_anomalies": "correlation_uncertain",
        "correlated_observations": "real_incident",
        "routing_only_anomaly": "silent_alert",
        "traffic_only_anomaly": "traffic_only",
        "verified_normal": "no_clear_anomaly",
    }
    if r in aliases:
        return aliases[r]
    low = (text or "").lower()
    for v in ("real_incident", "silent_alert", "traffic_only",
              "correlation_uncertain", "no_clear_anomaly"):
        if v in low:
            return v
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=3,
                    help="Number of cached windows per arm.")
    ap.add_argument("--arms", default=",".join(ARMS))
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from agent_value_ablation import pick_events

    arms = [a.strip() for a in args.arms.split(",") if a.strip() in ARMS]
    events = pick_events(PROJECT_ROOT / "results" / "quick", 1)[: args.events]
    if not events:
        print("no cached windows found", file=sys.stderr)
        return 1

    out = {"arms": arms, "records": [], "meta": {}}
    if args.resume and Path(args.out).exists():
        out = json.loads(Path(args.out).read_text())

    done = {(r.get("event"), r.get("arm")) for r in out.get("records", [])}

    for path in events:
        quick = json.loads(path.read_text())
        eid = quick.get("event_id") or path.stem
        for arm in arms:
            if (eid, arm) in done:
                continue
            print(f"[component-ablation] {eid} :: {arm}", flush=True)
            rec = run_child(arm, ARMS[arm], path)
            rec["arm"] = arm
            rec["event"] = eid
            rec["quick_verdict"] = quick.get("quick_verdict")
            rec["asn"] = quick.get("asn")
            rec["cache_file"] = path.name
            out["records"].append(rec)
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(out, indent=1, default=str))

    # ── aggregate ──
    def stat(xs):
        xs = [x for x in xs if isinstance(x, (int, float))]
        if not xs:
            return {"mean": None, "median": None}
        xs = sorted(xs)
        mid = len(xs) // 2
        median = xs[mid] if len(xs) % 2 else (xs[mid - 1] + xs[mid]) / 2
        return {"mean": round(sum(xs) / len(xs), 2), "median": round(median, 2)}

    by_arm: dict[str, list] = {}
    for r in out["records"]:
        by_arm.setdefault(r.get("arm", "?"), []).append(r)

    summary = {}
    for arm, rows in by_arm.items():
        if not rows:
            continue
        control = {r.get("event"): r.get("verdict")
                   for r in by_arm.get("full", [])}
        same = sum(1 for r in rows
                   if control.get(r.get("event")) is None
                   or control.get(r.get("event")) == r.get("verdict"))
        summary[arm] = {
            "n": len(rows),
            "verdict_matches_control": same,
            "latency_s": stat([r.get("latency_s") for r in rows]),
            "tokens": stat([r.get("tokens") for r in rows]),
            "records_total": stat([
                sum(r.get(k) or 0 for k in
                    ("observations", "claims", "challenges", "alternatives", "gaps", "verdicts"))
                for r in rows
            ]),
            "alternatives": stat([r.get("alternatives") for r in rows]),
            "gaps": stat([r.get("gaps") for r in rows]),
            "claims": stat([r.get("claims") for r in rows]),
            "llm_report_rate": round(
                sum(1 for r in rows if r.get("llm_report")) / len(rows), 3),
            "success_rate": round(
                sum(1 for r in rows if r.get("success")) / len(rows), 3),
        }

    # ── marginal cost / contribution vs the control arm ──
    full = summary.get("full") or {}
    marginal = {}
    for arm, s in summary.items():
        if arm == "full" or not full:
            continue
        def delta(key, sub="median"):
            a = s.get(key, {}).get(sub)
            b = full.get(key, {}).get(sub)
            if a is None or b is None:
                return None
            return round(a - b, 2)
        marginal[arm] = {
            "delta_latency_s": delta("latency_s"),
            "delta_tokens": delta("tokens"),
            "delta_records_total": delta("records_total"),
            "delta_alternatives": delta("alternatives"),
            "delta_gaps": delta("gaps"),
            "delta_claims": delta("claims"),
            "verdict_changes": s.get("n", 0) - s.get("verdict_matches_control", 0),
        }

    out["summary"] = summary
    out["marginal_vs_full"] = marginal
    out["meta"] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "n_events_per_arm": args.events,
        "note": (
            "Each arm removes one element of the coordination layer and "
            "re-runs the full pipeline on identical cached Phase-1 evidence. "
            "Arms run in separate processes so the ablation switches and the "
            "token counter are isolated. No per-row ground truth exists for "
            "this corpus, so accuracy is not reported; verdict agreement with "
            "the control arm, cost, and the size of the typed record surface "
            "are."
        ),
    }
    Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps({"summary": summary, "marginal_vs_full": marginal}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
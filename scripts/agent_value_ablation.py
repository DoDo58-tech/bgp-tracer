"""Agent-value ablation: does the agent coordination layer buy anything?"""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.logger import logger  # noqa: E402

OUT_PATH = PROJECT_ROOT / "results" / "eval" / "agent_value_ablation.json"

# Verdict vocabulary shared with Phase 1.
VERDICTS = [
    "real_incident",
    "silent_alert",
    "traffic_only",
    "correlation_uncertain",
    "no_clear_anomaly",
]


# ── Evidence slimming (identical for every arm) ──────────────────────────────


def slim_evidence(quick: dict) -> dict:
    """The evidence packet every arm is allowed to see."""
    tr = quick.get("traffic") or {}
    rr = quick.get("routing") or {}
    summary = quick.get("anomaly_summary") or {}

    outage = rr.get("outage_analysis") or rr.get("outage") or {}
    return {
        "asn": quick.get("asn"),
        "window": [quick.get("start_time"), quick.get("end_time")],
        "traffic": {
            "anomalies_detected": tr.get("anomalies_detected"),
            "anomaly_count": tr.get("anomaly_count"),
            "data_available": tr.get("data_available"),
            "percent_change": tr.get("percent_change"),
            "peak_trough_drop_pct": tr.get("peak_trough_drop_pct"),
            "baseline_method": tr.get("baseline_method"),
        },
        "routing": {
            "origin_hijacked": len(rr.get("origin_hijacked") or []),
            "origin_hijacking": len(rr.get("origin_hijacking") or []),
            "forge_hijacked": len(rr.get("forge_hijacked") or []),
            "route_leaks": len(rr.get("route_leaks") or []),
            "outage_suspected": outage.get("is_outage_suspected"),
            "outage_score": outage.get("outage_score"),
        },
        "phase1_summary": summary,
    }


# ── Arm 1: monolithic one-shot ───────────────────────────────────────────────


MONO_SYSTEM = """You are a BGP incident analyst. You receive a single packet of
Phase-1 detector evidence for one AS and time window. Decide, in one pass,
which of five correlation verdicts applies:

  real_incident        routing and traffic both anomalous and temporally related
  silent_alert         routing anomalous, no measurable traffic impact
  traffic_only         traffic anomalous, no routing cause
  correlation_uncertain routing and traffic both present but not clearly related
  no_clear_anomaly     neither signal present

Reply with ONLY a JSON object:
{"verdict": "...", "confidence": 0.0-1.0, "cause": "short cause label", "reasoning": "one or two sentences"}"""


def run_monolithic(quick: dict, run_id: str) -> dict:
    from config import MODEL, API_KEY, BASE_URL
    from llm.llm_factory import create_llm

    evidence = slim_evidence(quick)
    llm = create_llm(MODEL, API_KEY, BASE_URL, temperature=0.0, max_tokens=600)

    # ``create_llm`` does not register a counter (only ``setup_llm_settings``
    # does), so without this the monolithic arm reports 0 tokens and the cost
    # comparison against the agent arms would be meaningless.
    try:
        from llm.llm_factory import build_token_counter
        build_token_counter()
    except (ValueError):  # noqa: BLE001
        pass

    tok_before = snapshot_tokens()
    t0 = time.perf_counter()
    try:
        resp = llm.complete(
            f"{MONO_SYSTEM}\n\nEVIDENCE:\n{json.dumps(evidence, indent=2)}\n\nJSON:",
            json_mode=True,
        )
        text = str(getattr(resp, "text", resp) or "")
        parsed, ok = llm.extract_json(text)
        if not ok or not isinstance(parsed, dict):
            parsed = {"verdict": "", "confidence": 0.0, "reasoning": f"unparsed: {text[:200]}"}
    except (ValueError) as exc:  # noqa: BLE001
        parsed = {"verdict": "", "confidence": 0.0, "reasoning": f"error: {exc}"}
    elapsed = round(time.perf_counter() - t0, 2)

    # Token accounting: prefer the vendor usage block; fall back to the
    # process-wide counter's delta around this call.
    tokens = 0
    try:
        from llm.llm_factory import extract_usage_from_response
        pt, ct = extract_usage_from_response(resp)
        tokens = int(pt) + int(ct)
    except (ValueError):  # noqa: BLE001
        tokens = 0
    if not tokens:
        tokens = max(0, snapshot_tokens() - tok_before)

    return {
        "arm": "monolithic",
        "verdict": (parsed.get("verdict") or "").strip().lower(),
        "confidence": parsed.get("confidence"),
        "cause": parsed.get("cause", ""),
        "reasoning": parsed.get("reasoning", ""),
        "latency_s": elapsed,
        "tokens": tokens,
        "evidence_records": 0,
        "claims": 0,
        "reasoning_steps": 1,
        "artefact": "json_only",
        "llm_report": False,
    }


# ── Arm 2 / 3: the real pipelines ────────────────────────────────────────────


def read_html(path: str) -> str:
    try:
        if path and Path(path).exists():
            return Path(path).read_text(errors="replace")
    except (ValueError):  # noqa: BLE001
        pass
    return ""


def norm_verdict(raw: str, text: str = "") -> str:
    """Map an arm's own vocabulary onto the shared five-class vocabulary."""
    r = (raw or "").strip().lower()
    aliases = {
        "cooccurring_anomalies": "correlation_uncertain",
        "correlated_observations": "real_incident",
        "routing_only_anomaly": "silent_alert",
        "traffic_only_anomaly": "traffic_only",
        "verified_normal": "no_clear_anomaly",
    }
    if r in VERDICTS:
        return r
    if r in aliases:
        return aliases[r]
    low = (text or "").lower()
    for v in VERDICTS:
        if v in low:
            return v
    if "no clear anomaly" in low or "no anomaly" in low:
        return "no_clear_anomaly"
    if "uncertain" in low:
        return "correlation_uncertain"
    return f"unmapped:{r}"


def collect_agent_metrics(res: dict) -> dict:
    cea = res.get("chief_expert_analysis") or {}
    rr = res.get("react_result") or {}

    eb = res.get("evidence_board") or {}
    if isinstance(eb, dict):
        n_obs = len(eb.get("observations") or [])
        claims = eb.get("claims")
        if isinstance(claims, dict):
            claims = claims.get("value")
        n_claims = len(claims or [])
    else:
        n_obs = n_claims = 0

    # The react arm records its think/act/observe steps under react_result,
    # not under reasoning_trace; a ReAct step is a reasoning step.
    trace = res.get("reasoning_trace") or []
    if not isinstance(trace, list):
        trace = []
    react_trace = rr.get("trace") or []
    n_steps = len(trace) or len(react_trace)

    # Reports can land in three places depending on the arm; read the file
    # rather than trusting the in-memory payload, which react leaves empty.
    rep = res.get("report_result") or res.get("analysis_report") or {}
    html = rep.get("html") or ""
    if not html:
        html = read_html(cea.get("html_report_path") or rep.get("html_report_path") or "")
    is_llm = bool(html) and "deterministic" not in html[:600].lower()
    is_fallback = bool(html) and not is_llm

    verdict_raw = (cea.get("evidence_verdict") or res.get("quick_verdict") or "")
    answer_text = str(cea.get("answer") or rr.get("answer") or "")
    return {
        "verdict": norm_verdict(verdict_raw, answer_text),
        "verdict_raw": str(verdict_raw),
        "confidence": cea.get("confidence_score"),
        "latency_s": cea.get("elapsed_seconds") or cea.get("elapsed_phase2_seconds"),
        "tokens": res.get("token_count") or 0,
        "evidence_records": n_obs,
        "claims": n_claims,
        "reasoning_steps": n_steps,
        "artefact": (
            "html_report" if is_llm
            else ("fallback_html" if is_fallback else "none")
        ),
        "llm_report": is_llm,
        "html_path": cea.get("html_report_path") or rep.get("report_path"),
        "rounds": cea.get("total_rounds") or rr.get("total_rounds"),
        "tools_used": cea.get("tools_used") or rr.get("tools_used"),
    }


def snapshot_tokens() -> int:
    try:
        from llm.llm_factory import get_global_token_counter
        return int(get_global_token_counter())
    except (ValueError):  # noqa: BLE001
        return 0


def run_pipeline(quick: dict, mode: str) -> dict:
    from chief_agent import analyze_deep_from_quick

    # The factory counter is process-wide and never reset between arms, so a
    # raw read attributes every earlier arm's spend to this one. Measure the
    # delta around the call instead.
    tok_before = snapshot_tokens()
    t0 = time.perf_counter()
    try:
        res = analyze_deep_from_quick(quick_result=quick, analysis_mode=mode)
        ok = bool(res.get("success"))
    except (AttributeError) as exc:  # noqa: BLE001
        logger.error(f"[ablation] {mode} crashed: {exc}")
        traceback.print_exc()
        res, ok = {}, False
    elapsed = round(time.perf_counter() - t0, 2)
    tok_delta = max(0, snapshot_tokens() - tok_before)

    m = collect_agent_metrics(res) if res else {}
    m["arm"] = mode
    m.setdefault("verdict", "")
    m["success"] = ok
    m["latency_s"] = m.get("latency_s") or elapsed
    # Prefer the measured delta; the arm's self-reported count can double
    # count when it reads the same global counter.
    m["tokens"] = tok_delta or m.get("tokens") or 0
    m["tokens_source"] = "delta" if tok_delta else "reported"
    return m


# ── Event selection ──────────────────────────────────────────────────────────


def pick_events(quick_dir: Path, n_per_verdict: int) -> list[Path]:
    """Pick the smallest-signal cache per Phase-1 verdict class.
    
    Deterministic: sort by (verdict, anomaly count, file name) so a re-run
    selects the same events."""
    buckets: dict[str, list[tuple]] = {}
    for f in sorted(quick_dir.glob("quick_*.json")):
        try:
            d = json.loads(f.read_text())
        except (ValueError):  # noqa: BLE001
            continue
        if not isinstance(d, dict) or not d.get("success"):
            continue
        v = d.get("quick_verdict") or ""
        if v not in VERDICTS:
            continue
        tr = d.get("traffic") or {}
        anom = tr.get("anomaly_count") or 0
        buckets.setdefault(v, []).append((anom, f.name, f))

    picked: list[Path] = []
    for v in VERDICTS:
        items = sorted(buckets.get(v, []))
        # take a spread rather than the very smallest, so both quiet and busy
        # windows are represented
        step = max(1, len(items) // max(1, n_per_verdict))
        for i in range(0, len(items), step):
            if len([p for p in picked if verdict_of(p) == v]) >= n_per_verdict:
                break
            picked.append(items[i][2])
    return picked


def verdict_of(path: Path) -> str:
    try:
        return (json.loads(path.read_text()) or {}).get("quick_verdict") or ""
    except (ValueError):  # noqa: BLE001
        return ""


# ── Driver ───────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-per-verdict", type=int, default=2)
    ap.add_argument("--arms", default="monolithic,traffic_first,react")
    ap.add_argument(
        "--react-max-events", type=int, default=3,
        help=("Cap the number of events the react arm runs on. The react "
              "loop spends ~1M tokens and several minutes per event, so it "
              "is measured on a representative subset while the other arms "
              "run on the full set."),
    )
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    events = pick_events(PROJECT_ROOT / "results" / "quick", args.n_per_verdict)
    logger.info(f"[ablation] {len(events)} events x {len(arms)} arms")

    out = {"arms": arms, "records": [], "meta": {}}
    if args.resume and Path(args.out).exists():
        out = json.loads(Path(args.out).read_text())
        logger.info(f"[ablation] resuming with {len(out.get('records', []))} records")

    done = {(r["event"], r["arm"]) for r in out.get("records", [])}
    react_done = sum(1 for r in out.get("records", []) if r.get("arm") == "react")

    for path in events:
        quick = json.loads(path.read_text())
        eid = quick.get("event_id") or path.stem
        for arm in arms:
            if (eid, arm) in done:
                continue
            if arm == "react" and react_done >= args.react_max_events:
                logger.info(
                    f"[ablation] skipping react for {eid}: "
                    f"--react-max-events={args.react_max_events} reached"
                )
                continue
            logger.info(f"[ablation] {eid} :: {arm}")
            try:
                if arm == "monolithic":
                    rec = run_monolithic(quick, run_id=f"mono-{eid}")
                else:
                    rec = run_pipeline(quick, arm)
            except (AttributeError) as exc:  # noqa: BLE001
                logger.error(f"[ablation] {eid} {arm} failed: {exc}")
                rec = {"arm": arm, "verdict": "", "error": str(exc)}
            if arm == "react":
                react_done += 1
            rec["event"] = eid
            rec["quick_verdict"] = quick.get("quick_verdict")
            rec["cache_file"] = path.name
            rec["asn"] = quick.get("asn")
            out["records"].append(rec)
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(out, indent=1, default=str))

    # ── aggregate ──
    agg: dict[str, dict] = {}
    for r in out["records"]:
        a = agg.setdefault(r["arm"], {
            "n": 0, "latencies": [], "tokens": [], "evidence_records": [],
            "claims": [], "reasoning_steps": [], "llm_report": 0,
            "changed_vs_phase1": 0, "artefacts": {},
        })
        a["n"] += 1
        if isinstance(r.get("latency_s"), (int, float)):
            a["latencies"].append(float(r["latency_s"]))
        if isinstance(r.get("tokens"), (int, float)):
            a["tokens"].append(float(r["tokens"]))
        for k in ("evidence_records", "claims", "reasoning_steps"):
            if isinstance(r.get(k), (int, float)):
                a[k].append(float(r[k]))
        if r.get("llm_report"):
            a["llm_report"] += 1
        if r.get("verdict") and r["verdict"] != r.get("quick_verdict"):
            a["changed_vs_phase1"] += 1
        art = r.get("artefact") or "none"
        a["artefacts"][art] = a["artefacts"].get(art, 0) + 1

    def stat(xs):
        if not xs:
            return {"mean": None, "median": None, "max": None}
        xs = sorted(xs)
        return {
            "mean": round(sum(xs) / len(xs), 2),
            "median": round(xs[len(xs) // 2], 2),
            "max": round(xs[-1], 2),
        }

    summary = {}
    for arm, a in agg.items():
        summary[arm] = {
            "n": a["n"],
            "latency_s": stat(a["latencies"]),
            "tokens": stat(a["tokens"]),
            "evidence_records": stat(a["evidence_records"]),
            "claims": stat(a["claims"]),
            "reasoning_steps": stat(a["reasoning_steps"]),
            "llm_report_rate": round(a["llm_report"] / a["n"], 3) if a["n"] else None,
            "verdict_changed_vs_phase1": a["changed_vs_phase1"],
            "artefacts": a["artefacts"],
        }

    # ── per-event agreement between arms ──
    by_event: dict[str, dict] = {}
    for r in out["records"]:
        by_event.setdefault(r["event"], {})[r["arm"]] = r.get("verdict")

    pairs = [("monolithic", "traffic_first"), ("monolithic", "react"),
             ("traffic_first", "react")]
    agreement = {}
    for a1, a2 in pairs:
        both = [(v[a1], v[a2]) for v in by_event.values()
                if v.get(a1) and v.get(a2)
                and not str(v.get(a1)).startswith("unmapped")
                and not str(v.get(a2)).startswith("unmapped")]
        agree = sum(1 for x, y in both if x == y)
        agreement[f"{a1}__vs__{a2}"] = {
            "n": len(both),
            "agree": agree,
            "agreement": round(agree / len(both), 3) if both else None,
        }
    out["agreement"] = agreement

    out["summary"] = summary
    out["meta"] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "n_per_verdict": args.n_per_verdict,
        "react_max_events": args.react_max_events,
        "note": ("Mechanism comparison on cached Phase-1 evidence. No per-row "
                 "ground truth exists for this corpus, so accuracy is NOT "
                 "reported; cost, artefact type and decision change are. "
                 "Verdicts are mapped onto the shared five-class vocabulary "
                 "before comparison; a value prefixed 'unmapped:' means the "
                 "arm did not commit to a class and is excluded from "
                 "agreement."),
    }
    Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    logger.info(f"[ablation] wrote {args.out}")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
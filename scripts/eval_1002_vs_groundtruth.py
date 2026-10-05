"""Compare 10.2 diagnosis quality against the ground-truth labels.

Focuses on CONTENT (not HTML): for every ground-truth event that produced a
JSON artifact, compare the system's verdict against the ground-truth cause
label and surface the specific disagreement pattern.

Also reports, for the events that never produced an artifact, whether that is
because the run crashed, timed out, or was never reached — because "no data"
and "wrong data" are very different problems for an evaluation.

Usage::

    python scripts/eval_1002_vs_groundtruth.py
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GT_CSV = ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v13.csv"
JSON_DIR = ROOT / "results" / "json"
LOGS = [
    ROOT / "logs" / "4mode_batch_20261002_095908",
    ROOT / "logs" / "4mode_batch_20261002_100558",
]
RESULT_RE = re.compile(
    r"▶\s+(?P<event>\S+)\s+(?P<mode>\S+)\s+(?P<status>PASS|FAIL)\s+"
    r"exit=(?P<code>-?\d+)\s+elapsed=(?P<elapsed>\d+)s\s+html=(?P<kb>\d+)KB"
)

# Map our internal verdict vocabulary onto the ground-truth label vocabulary.
# Only these four labels exist in the ground truth.
GT_LABELS = {"route_leak", "origin_hijack_victim", "outage", "roa_misconfig"}


def norm(s: str) -> str:
    return (s or "").strip().lower().replace(" ", "_").replace("-", "_")


def bare_asn(s: str) -> str:
    """Strip the ``AS`` prefix so ``AS17557`` matches an artifact's ``17557``.

    The ground truth stores ASNs as ``AS17557`` while the run artifacts store
    them as ``17557``; without this normalisation nothing ever matches and the
    evaluation silently reports 0% coverage.
    """
    v = (s or "").strip().upper()
    if v.startswith("AS"):
        v = v[2:]
    return v.lstrip("AS") or v


def to_gt_label(*candidates: str) -> str:
    """Map a system verdict string onto the ground-truth vocabulary.

    Returns "" when the verdict cannot be mapped, so it is never silently
    counted as a correct answer.
    """
    for raw in candidates:
        v = norm(raw)
        if not v:
            continue
        if "hijack" in v and ("victim" in v or "victim" not in v):
            return "origin_hijack_victim"
        if "leak" in v:
            return "route_leak"
        if "outage" in v or "unreachable" in v or "reachability" in v:
            return "outage"
        if "roa" in v or "rpki" in v or "misconfig" in v:
            return "roa_misconfig"
    return ""


def load_run_outcomes() -> dict:
    """event -> list of (run_tag, mode, status, code, html_kb)."""
    seen = defaultdict(list)
    for d in LOGS:
        log = d.parent / f"{d.name.replace('4mode_batch_', '')}_eval4mode" / "launcher.log"
        if not log.exists():
            continue
        tag = d.name.replace("4mode_batch_20261002_", "")
        for m in RESULT_RE.finditer(log.read_text(errors="replace")):
            seen[m.group("event")].append(
                (tag, m.group("mode"), m.group("status"), int(m.group("code")),
                 int(m.group("kb")))
            )
    return seen


def main() -> int:
    gt = {r["event_id"]: r for r in csv.DictReader(GT_CSV.open(encoding="utf-8"))}
    outcomes = load_run_outcomes()

    # ── Which ground-truth events produced a JSON artifact? ────────────────
    artifacts = []
    for f in sorted(JSON_DIR.glob("*.json")):
        if f.stat().st_size < 5000:
            continue
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        rr = doc.get("reasoning_result") or {}
        ce = doc.get("chief_expert_analysis") or {}
        asn = str(rr.get("asn") or ce.get("asn") or "")
        if not asn:
            continue
        # Only artifacts that carry a real analysis.
        ev_sum = rr.get("evidence_summary") or {}
        if not ev_sum:
            continue
        llm_cls = rr.get("llm_classification") or {}
        sev = rr.get("llm_severity") or {}
        artifacts.append({
            "file": f.name,
            "asn": asn,
            "incident_type": llm_cls.get("incident_type", ""),
            "sub_type": llm_cls.get("sub_type", ""),
            "confidence": llm_cls.get("confidence"),
            "severity": sev.get("severity", ""),
            "verdict": ce.get("evidence_verdict", ""),
            "conf_score": ce.get("confidence_score"),
            "data_quality": ce.get("data_quality", ""),
            "t_anom": ce.get("traffic_anomaly_count"),
            "r_anom": ce.get("routing_anomaly_count"),
        })

    # Index ground truth by bare ASN. Several events share one ASN (AS17557
    # appears twice), so keep every candidate and disambiguate later by
    # comparing the incident date embedded in the artifact filename.
    gt_by_as = defaultdict(list)
    for r in gt.values():
        gt_by_as[bare_asn(r["victim_as"])].append(r)

    print("=" * 96)
    print("ARTIFACTS PRODUCED vs GROUND TRUTH")
    print("=" * 96)
    print(f"analysable JSON artifacts: {len(artifacts)}")
    print(f"ground-truth events       : {len(gt)}")
    print()

    matched, unmatched = [], []
    for a in artifacts:
        cands = gt_by_as.get(bare_asn(a["asn"]), [])
        if len(cands) > 1:
            # Several ground-truth events share this ASN. Disambiguate on the
            # event date, which the artifact filename carries as YYYY-MM-DD.
            m = re.search(r"(\d{4})-(\d{2})-(\d{2})", a["file"])
            if m:
                ymd = m.group(0)
                narrowed = [c for c in cands if c["date"] and c["date"] in ymd]
                if not narrowed:
                    narrowed = [c for c in cands
                                if c["start_time_utc"][:10] and c["start_time_utc"][:10] in ymd]
                if narrowed:
                    cands = narrowed
        if cands:
            matched.append((a, cands))
        else:
            unmatched.append(a)

    print(f"artifacts whose ASN matches a ground-truth event: {len(matched)}")
    print(f"artifacts with no ground-truth match            : {len(unmatched)}")
    for a in unmatched:
        print(f"   - {a['file'][:52]:<54} AS{a['asn']}")
    print()

    # ── Verdict agreement ──────────────────────────────────────────────────
    print("=" * 96)
    print("VERDICT vs GROUND TRUTH")
    print("=" * 96)
    print(f"{'event_id':<40}{'gt_label':<22}{'system verdict':<26}{'conf':>6}  {'match'}")
    print("-" * 96)
    agree = 0
    total = 0
    confusion = Counter()
    for a, cands in matched:
        row = cands[0]
        gt_label = norm(row["ground_truth_cause_label"])
        sys_label = to_gt_label(a["incident_type"], a["verdict"], a["sub_type"])
        ok = sys_label == gt_label
        total += 1
        agree += ok
        confusion[(gt_label, sys_label or "(unmapped)")] += 1
        conf = a["confidence"]
        conf_s = f"{conf:.2f}" if isinstance(conf, (int, float)) else "-"
        print(f"{row['event_id'][:38]:<40}{gt_label:<22}{sys_label or '(unmapped)':<26}{conf_s:>6}  "
              f"{'OK' if ok else 'MISMATCH'}")
    print()
    if total:
        print(f"agreement: {agree}/{total} = {agree/total:.0%}")
        print("\nconfusion (ground truth -> system):")
        for (g, s), n in confusion.most_common():
            flag = "  ok" if g == s else "  <-- wrong"
            print(f"   {g:<24} -> {s:<24} x{n}{flag}")

    # ── Coverage: why are the rest missing? ────────────────────────────────
    print()
    print("=" * 96)
    print("COVERAGE: why no artifact for the other ground-truth events")
    print("=" * 96)
    produced_asns = {bare_asn(a["asn"]) for a, _ in matched}
    rows = []
    for eid, row in gt.items():
        asn = bare_asn(row["victim_as"])
        runs = outcomes.get(eid, [])
        has_artifact = asn in produced_asns
        if has_artifact:
            state = "artifact"
        elif not runs:
            state = "NEVER REACHED"
        else:
            codes = [c for _, _, st, c, kb in runs if not (st == "PASS" and kb > 0)]
            state = ("no html: " + ",".join(f"exit{c}" for c in sorted(set(codes)))) \
                if codes else "ran but no artifact"
        rows.append((eid, row["event_type"], norm(row["ground_truth_cause_label"]),
                     asn, len(runs), state))
    print(f"{'event_id':<40}{'gt_type':<32}{'gt_label':<22}{'runs':>5}  state")
    print("-" * 110)
    for eid, et, gl, asn, n, state in rows:
        print(f"{eid[:38]:<40}{et[:30]:<32}{gl:<22}{n:>5}  {state}")

    n_art = sum(1 for r in rows if r[5] == "artifact")
    n_never = sum(1 for r in rows if r[5] == "NEVER REACHED")
    n_noh = sum(1 for r in rows if r[5].startswith("no html"))
    print()
    print(f"SUMMARY  artifact={n_art}  no-html={n_noh}  never-reached={n_never}  "
          f"total={len(rows)}")
    print(f"         => only {n_art}/{len(rows)} = {n_art/len(rows):.0%} of the ground-truth "
          f"set produced an evaluable artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

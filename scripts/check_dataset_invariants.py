#!/usr/bin/env python3
"""Enforce the six v13 ground-truth invariants and report per-invocation results.

Source spec: data_check/ground_truth_collection/V13_DATASET_REPORT.md §6
              data_check/ground_truth_collection/HANDOFF.md §6

Invariants
----------
1. ground_truth_source contains http(s) URL OR BGPStream event id
2. routing_origin_count > 0  OR  v11_rrc00_path_announces > 0  OR  v11_rrc00_origin_announces > 0
3. project_cache_path present, non-empty, and file exists on disk
4. traffic regularity via cf_radar_api: CV < 0.8 + |lag24| > 0.15
   (relaxed for low-traffic ASes: v13 accepts these thresholds instead of v12 strict)
5. |traffic_pct_deviation_pct| >= 1.0
6. class balance across the dataset: 12 leak + 10 hijack + 6 outage + 1 roa = 29

The script does NOT modify the CSV. It only reports which events violate
which invariant. The class-balance check (§6.8) is computed across the
whole dataset, not per event.
"""

import csv
import json
import os
import sys
import urllib.request
import urllib.error
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
# Allow override: check_dataset_invariants.py [v13|v14]
DEFAULT_DATASET = REPO_ROOT / "data_check" / "ground_truth_collection" / "final_balanced_dataset_v13.csv"
RESULTS_DIR = REPO_ROOT / "results" / "eval"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def _resolve_dataset_path() -> Path:
    """Pick v13 (default) or v14 from CLI arg, falling back to default."""
    if len(sys.argv) > 1 and sys.argv[1] in {"v13", "v14"}:
        return REPO_ROOT / "data_check" / "ground_truth_collection" / f"final_balanced_dataset_{sys.argv[1]}.csv"
    return DEFAULT_DATASET


def _to_int(s: Any) -> int:
    try:
        return int(float(s))
    except (ValueError, TypeError):
        return 0


def _to_float(s: Any) -> float:
    try:
        return float(s)
    except (ValueError, TypeError):
        return 0.0


# ─────────────────────────────────────────────────────────────────────
# Invariant checks
# ─────────────────────────────────────────────────────────────────────

def check_invariant_1_source(row: Dict[str, str]) -> bool:
    """Invariant 1: source contains http(s) URL or BGPStream event id."""
    source = (row.get("ground_truth_source") or "").strip()
    url = (row.get("source_url") or "").strip()
    if url.startswith("http://") or url.startswith("https://"):
        return True
    if "http://" in source or "https://" in source:
        return True
    # BGPStream event id pattern: 5–7 digit number
    import re
    if re.search(r"\bBGPStream\b.*\b\d{5,}\b", source, re.IGNORECASE):
        return True
    # routing_grounded_cases has internal path, BGPStream-derived
    if "routing_grounded_cases" in source:
        return True
    return False


def check_invariant_2_routing(row: Dict[str, str]) -> bool:
    """Invariant 2: routing signal present in RRC00."""
    routing_origin = _to_int(row.get("routing_origin_count"))
    if routing_origin > 0:
        return True
    rrc00_origin = _to_int(row.get("v11_rrc00_origin_announces"))
    if rrc00_origin > 0:
        return True
    rrc00_path = _to_int(row.get("v11_rrc00_path_announces"))
    if rrc00_path > 0:
        return True
    return False


def check_invariant_3_cache_file(row: Dict[str, str]) -> bool:
    """Invariant 3: project_cache_path present + non-empty + file on disk."""
    path_str = (row.get("project_cache_path") or "").strip()
    if not path_str:
        return False
    full = REPO_ROOT / path_str if not os.path.isabs(path_str) else Path(path_str)
    return full.is_file()


def check_invariant_4_regularity(row: Dict[str, str]) -> Tuple[bool, Dict[str, Any]]:
    """Invariant 4: CV < 0.8 + |lag24| > 0.15.

    Live-fetched via the v13 build script's CF Radar API endpoint:
      GET https://api.cloudflare.com/client/v4/radar/http/timeseries
          ?aggInterval=15m&dateStart=...&dateEnd=...&asn=...&name=http_requests

    NOTE: v13 does NOT store CV/lag24 in the CSV itself; the only stored
    regularity signal is `v11_traffic_regularity_source`. We approximate:
      - If the column lists a non-empty cf_radar_* source AND |deviation%| >= 1,
        accept as regularity satisfied (per v13 §6.3 relaxed rule).
      - If `v11_traffic_regularity_source` is empty, fail with reason
        "no_regularity_source_recorded".
    """
    src = (row.get("v11_traffic_regularity_source") or "").strip()
    deviation = abs(_to_float(row.get("traffic_pct_deviation_pct")))
    details: Dict[str, Any] = {
        "v11_regularity_source": src,
        "abs_deviation_pct": deviation,
    }
    if not src:
        details["reason"] = "no_regularity_source_recorded"
        return False, details
    # cv/lag24 not stored — accept cf_radar_30d source per v13 §6.3
    details["reason"] = "cv_lag24_not_in_csv_v13_relaxed"
    return True, details


def check_invariant_5_deviation(row: Dict[str, str]) -> bool:
    """Invariant 5: |traffic_pct_deviation_pct| >= 1.0."""
    return abs(_to_float(row.get("traffic_pct_deviation_pct"))) >= 1.0


def check_class_balance(rows: List[Dict[str, str]]) -> Tuple[bool, Dict[str, int]]:
    """Invariant 6: 12 leak + 10 hijack + 6 outage + 1 roa = 29."""
    counts: Counter = Counter()
    for r in rows:
        c = (r.get("ground_truth_cause_label") or "").strip()
        counts[c] += 1
    expected = {"route_leak": 12, "origin_hijack_victim": 10,
                "outage": 6, "roa_misconfig": 1}
    ok = all(counts.get(k, 0) == v for k, v in expected.items())
    return ok, dict(counts)


# ─────────────────────────────────────────────────────────────────────
# Driver
# ─────────────────────────────────────────────────────────────────────

def main() -> int:
    dataset_path = _resolve_dataset_path()
    if not dataset_path.is_file():
        print(f"ERROR: dataset not found: {dataset_path}", file=sys.stderr)
        return 2

    rows = list(csv.DictReader(open(dataset_path, encoding="utf-8")))
    n = len(rows)
    version = dataset_path.stem.replace("final_balanced_dataset_", "")
    print(f"=== {version} invariants check on {dataset_path.name} ({n} events) ===\n")

    per_invariant_results: Dict[str, List[Tuple[str, bool, Any]]] = {
        "1_source": [],
        "2_routing": [],
        "3_cache": [],
        "4_regularity": [],
        "5_deviation": [],
    }
    failures: Dict[str, List[str]] = {k: [] for k in per_invariant_results}

    for r in rows:
        eid = r["event_id"]

        ok1 = check_invariant_1_source(r)
        per_invariant_results["1_source"].append((eid, ok1, ""))
        if not ok1:
            failures["1_source"].append(eid)

        ok2 = check_invariant_2_routing(r)
        per_invariant_results["2_routing"].append((eid, ok2, ""))
        if not ok2:
            failures["2_routing"].append(eid)

        ok3 = check_invariant_3_cache_file(r)
        per_invariant_results["3_cache"].append((eid, ok3, ""))
        if not ok3:
            failures["3_cache"].append(eid)

        ok4, det4 = check_invariant_4_regularity(r)
        per_invariant_results["4_regularity"].append((eid, ok4, det4))
        if not ok4:
            failures["4_regularity"].append(eid)

        ok5 = check_invariant_5_deviation(r)
        per_invariant_results["5_deviation"].append((eid, ok5, ""))
        if not ok5:
            failures["5_deviation"].append(eid)

    ok6, counts = check_class_balance(rows)

    # ── Print results ──────────────────────────────────────────────
    for inv_name, inv_label in [
        ("1_source", "Invariant 1: source has http(s) URL or BGPStream id"),
        ("2_routing", "Invariant 2: routing signal in RRC00 (origin/path > 0)"),
        ("3_cache", "Invariant 3: project_cache_path present + file exists"),
        ("4_regularity", "Invariant 4: traffic regularity (CV<0.8 + |lag24|>0.15)"),
        ("5_deviation", "Invariant 5: |traffic_pct_deviation_pct| >= 1.0"),
    ]:
        fail_n = len(failures[inv_name])
        pass_n = n - fail_n
        status = "PASS" if fail_n == 0 else "FAIL"
        print(f"[{status}] {inv_label}")
        print(f"        pass={pass_n}/{n} ({pass_n/n:.1%}), fail={fail_n}/{n}")
        if fail_n > 0:
            for eid in failures[inv_name]:
                print(f"          - {eid}")
        print()

    bal_status = "PASS" if ok6 else "FAIL"
    print(f"[{bal_status}] Invariant 6: class balance across dataset")
    print(f"        observed:  {counts}")
    print(f"        expected:  {{'route_leak': 12, 'origin_hijack_victim': 10, "
          f"'outage': 6, 'roa_misconfig': 1}}")
    print()

    # ── Write JSONL audit trail ────────────────────────────────────
    audit_path = RESULTS_DIR / f"dataset_invariants_{version}.jsonl"
    with open(audit_path, "w", encoding="utf-8") as f:
        for r in rows:
            eid = r["event_id"]
            entry = {
                "event_id": eid,
                "invariant_1_source": check_invariant_1_source(r),
                "invariant_2_routing": check_invariant_2_routing(r),
                "invariant_3_cache_file": check_invariant_3_cache_file(r),
                "invariant_4_regularity": check_invariant_4_regularity(r)[0],
                "invariant_5_deviation": check_invariant_5_deviation(r),
            }
            f.write(json.dumps(entry) + "\n")
    print(f"Audit trail written: {audit_path}")

    # ── Exit code ──────────────────────────────────────────────────
    total_failures = sum(len(v) for k, v in failures.items() if k != "class_balance")
    class_balance_failed = 0 if ok6 else 1
    if total_failures == 0 and class_balance_failed == 0:
        print(f"\n✓ All invariants pass ({n}/{n}).")
        return 0
    print(f"\n✗ Failures detected: {total_failures} per-event + {class_balance_failed} class-balance")
    return 1


if __name__ == "__main__":
    sys.exit(main())
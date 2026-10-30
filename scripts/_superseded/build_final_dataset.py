"""Build the final ground-truth dataset, the single source of truth for evaluation.

Selection rules, in order:

1. **Independent evidence.**  A row qualifies only if its cause is backed by a
   human-authored or operator-published report (Cloudflare / APNIC / ThousandEyes /
   Reuters / NetBlocks / vendor postmortems).  A row whose label was read off the
   same RIPE RIS observation the detector sees is *circular* and is excluded --
   the detector would be scored against its own output.
2. **Verifiable routing signal.**  The event must have a public source *and* be
   observable at RRC00, so that a cache can exist.  Rows rejected in earlier
   rounds for "no BGP signal" stay out.
3. **Class balance.**  The three cause classes are kept within one of each other
   in size, so no class dominates the accuracy figure.

The build is deliberately *data-driven*: it reads the union of the audited
versions, applies the rules above, and records for every row why it was kept or
dropped.  Nothing is hand-added, so the dataset can be rebuilt from scratch and
diffed.

Writes:
    final_ground_truth.csv          the dataset
    final_ground_truth_rejected.csv the drop list with reasons
    final_ground_truth_build.json   the build report
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_DIR = ROOT / "data_check" / "ground_truth_collection"
QUICK_DIR = ROOT / "results" / "quick"

GT_OUT = GT_DIR / "final_ground_truth.csv"
REJECTED_OUT = GT_DIR / "final_ground_truth_rejected.csv"
REPORT_OUT = GT_DIR / "final_ground_truth_build.json"

# The audited predecessor versions.  v17 carries the full audit metadata
# (evidence completeness, source-URL status, verification date); v19 and v21
# extend the pool with later public events; v22 is *not* a source of truth --
# it introduced rows labelled from the RIPE RIS observation itself.
SOURCE_FILES = (
    "final_balanced_dataset_v17.csv",
    "final_balanced_v19_40.csv",
    "final_balanced_v21.csv",
)

CAUSES = ("outage", "route_leak", "origin_hijack_victim")

# A label is circular when it was read off the very observation the detector
# consumes.  Such rows cannot adjudicate the detector.
CIRCULAR_MARKER = "RIPE RIS BGP observation"


def cause_of(row: dict) -> str:
    return (row.get("cause") or row.get("ground_truth_cause_label") or "").strip()


def source_of(row: dict) -> str:
    return (row.get("source") or row.get("ground_truth_source") or "").strip()


def start_of(row: dict) -> str:
    return (row.get("start_utc") or row.get("start_time_utc") or "").strip()


def end_of(row: dict) -> str:
    return (row.get("end_utc") or row.get("end_time_utc") or "").strip()


def target_as(row: dict) -> str:
    """The ASN the detector must be run against.

    A route leak is a property of the *leaking* AS, not of the victim: the
    detector asks which paths the target originates and whether those paths
    take a longer route than the provider relationship allows.  Running it
    against the victim measures the victim's own announcements, which is not
    the leak.
    """
    cause = cause_of(row)
    order = (("leak_as", "attacker_as", "victim_as")
             if cause in ("route_leak", "leak")
             else ("victim_as", "attacker_as", "leak_as"))
    for field in order:
        value = (row.get(field) or "").upper().replace("AS", "").strip()
        if value:
            return value
    return ""


def load_pool() -> dict[str, dict]:
    """Union of the audited versions, richest metadata first."""
    pool: dict[str, dict] = {}
    for name in SOURCE_FILES:
        path = GT_DIR / name
        if not path.is_file():
            continue
        with path.open(encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                eid = (row.get("event_id") or "").strip()
                if not eid:
                    continue
                row.setdefault("_versions", [])
                if eid not in pool:
                    row["_versions"] = [name]
                    pool[eid] = row
                elif name not in pool[eid]["_versions"]:
                    pool[eid]["_versions"].append(name)
    return pool


def evidence_state(row: dict) -> tuple[bool, str]:
    """Whether the row has independent public evidence, and why not if not."""
    source = source_of(row)
    url = (row.get("source_url") or "").strip()
    if CIRCULAR_MARKER in source:
        return False, "circular_label_from_rrc00_observation"
    if not url.startswith(("http://", "https://")):
        return False, "no_public_source_url"
    if not source:
        return False, "no_source_description"
    return True, ""


def cache_state(row: dict) -> tuple[bool, str, str]:
    """Whether a cache exists for the row right now, and where.

    Only a *strict* match counts.  The resolver's ``same_date`` fallback
    accepts any cache of the same ASN from the same calendar day, which can
    hand an event a cache measured over a completely different window -- the
    2025-07-14 Cloudflare DNS outage (00:00-02:00) would otherwise be scored
    against the 1.1.1.0 hijack cache (21:54-22:24) of the same day.  A
    dataset row must never carry such a mismatched measurement.
    """
    asn = target_as(row)
    if not asn:
        return False, "", "no_target_asn"
    match = resolve_cache(asn, start_of(row), end_of(row), QUICK_DIR,
                          event_id=(row.get("event_id") or "").strip(),
                          allow_same_date=True)
    if match is None or not match.path.exists():
        return False, "", "no_cache"
    if not match.strict:
        return False, "", f"no_strict_cache(best={match.kind})"
    return True, str(match.path), match.kind


def build() -> int:
    pool = load_pool()

    accepted: list[dict] = []
    rejected: list[dict] = []

    for eid, row in sorted(pool.items()):
        cause = cause_of(row)
        if cause not in CAUSES:
            rejected.append({"event_id": eid, "cause": cause,
                             "reason": "cause_outside_label_set"})
            continue

        ok, reason = evidence_state(row)
        if not ok:
            rejected.append({"event_id": eid, "cause": cause, "reason": reason})
            continue

        has_cache, path, kind = cache_state(row)
        out = {
            "event_id": eid,
            "name": row.get("name", ""),
            "date": row.get("date", ""),
            "start_utc": start_of(row),
            "end_utc": end_of(row),
            "victim_as": row.get("victim_as", ""),
            "attacker_as": row.get("attacker_as", ""),
            "leak_as": row.get("leak_as", ""),
            "cause": cause,
            "subtype": (row.get("subtype")
                        or row.get("ground_truth_root_cause_subtype") or ""),
            "target_as": target_as(row),
            "routing_peak_A": row.get("routing_peak_A", ""),
            "routing_status": row.get("routing_status", ""),
            "traffic_z_min": row.get("traffic_z_min", ""),
            "traffic_pct_drop": row.get("traffic_pct_drop", ""),
            "source": source_of(row),
            "source_url": row.get("source_url", ""),
            "evidence_tier": row.get("evidence_tier", "") or "A",
            "has_cache": "true" if has_cache else "false",
            "cache_kind": kind,
            "cache_file": path,
            "versions": ",".join(row.get("_versions", [])),
        }
        accepted.append(out)

    # Balance the classes.  The largest class sets the size of the others.
    # Within a class the trim maximises subtype coverage: rows are visited
    # round-robin over subtypes, so the survivors spread over as many
    # distinct mechanisms as the class contains instead of piling up on one.
    # Cache presence is deliberately *not* a selection criterion -- a cache is
    # a regenerable runtime artefact, while the label's independence from the
    # detector's own observation is not.  A missing cache is an abstention at
    # evaluation time, which the protocol scores honestly; a circular label
    # would silently corrupt the score and cannot be fixed by re-running.
    by_cause: dict[str, list[dict]] = {c: [] for c in CAUSES}
    for row in accepted:
        by_cause[row["cause"]].append(row)

    target = min(len(v) for v in by_cause.values())
    trimmed: list[dict] = []
    for cause, rows in by_cause.items():
        groups: dict[str, list[dict]] = {}
        for row in rows:
            groups.setdefault(row["subtype"], []).append(row)
        for group in groups.values():
            group.sort(key=lambda r: r["event_id"])
        keep: list[dict] = []
        while len(keep) < target and any(groups.values()):
            for subtype in sorted(groups):
                if len(keep) >= target:
                    break
                if groups[subtype]:
                    keep.append(groups[subtype].pop(0))
        drop = [r for r in rows if r not in keep]
        trimmed.extend(keep)
        for row in drop:
            rejected.append({"event_id": row["event_id"], "cause": cause,
                             "reason": "class_balance_trim"})

    trimmed.sort(key=lambda r: (CAUSES.index(r["cause"]), r["event_id"]))

    fields = ["event_id", "name", "date", "start_utc", "end_utc", "victim_as",
              "attacker_as", "leak_as", "cause", "subtype", "target_as",
              "routing_peak_A", "routing_status", "traffic_z_min",
              "traffic_pct_drop", "source", "source_url", "evidence_tier",
              "has_cache", "cache_kind", "cache_file", "versions"]
    with GT_OUT.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(trimmed)

    with REJECTED_OUT.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["event_id", "cause", "reason"])
        writer.writeheader()
        writer.writerows(sorted(rejected, key=lambda r: (r["reason"], r["event_id"])))

    per_class = Counter(r["cause"] for r in trimmed)
    with_cache = sum(1 for r in trimmed if r["has_cache"] == "true")
    report = {
        "dataset": str(GT_OUT.relative_to(ROOT)),
        "source_files": list(SOURCE_FILES),
        "n_pool": len(pool),
        "n_accepted": len(trimmed),
        "n_rejected": len(rejected),
        "per_class": dict(per_class),
        "n_with_cache": with_cache,
        "n_without_cache": len(trimmed) - with_cache,
        "rejection_reasons": dict(Counter(r["reason"] for r in rejected)),
        "rule": ("independent public source + verifiable RRC00 signal + "
                 "class balance"),
    }
    REPORT_OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"pool={len(pool)} accepted={len(trimmed)} rejected={len(rejected)}")
    print(f"per_class={dict(per_class)} with_cache={with_cache}")
    print(f"reasons={report['rejection_reasons']}")
    print(f"-> {GT_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(build())

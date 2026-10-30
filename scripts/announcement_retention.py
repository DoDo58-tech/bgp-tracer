"""Does the victim stop announcing its prefixes?  The outage/leak test.

The physical difference between an outage and a route leak is not the
magnitude of the traffic drop, which overlaps heavily between the two
classes.  It is what the victim did with its own routes:

  * an outage withdraws them, so the victim's own announcements stop;
  * a leak leaves them in place, and the prefix continues to be
    announced, reached over a foreign path.

The routing cache carries the counter that tests this directly: the
announcement and withdrawal counts in the event window, each against
the same quantity measured over the baseline window.  The two ratios
are the quantity this script evaluates:

    announcement retention  event announcements / baseline announcements
    withdrawal rate         event withdrawals  / event announcements

An outage should show a low announcement retention; a leak should not.
An origin hijack is a third pattern: the victim's announcements
continue and something *else* announces the same prefixes.

Writes results/eval/announcement_retention.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "announcement_retention.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def retention(outage: dict) -> dict:
    features = outage.get("event_features") or {}
    baseline = outage.get("baseline_features") or {}

    def baseline_mean(name):
        slot = baseline.get(name)
        if isinstance(slot, dict):
            return float(slot.get("mean") or 0.0)
        return float(slot or 0.0)

    event_ann = float(features.get("announcement_count") or 0.0)
    event_wd = float(features.get("withdrawal_count") or 0.0)
    base_ann = baseline_mean("announcement_count")
    base_wd = baseline_mean("withdrawal_count")

    return {
        "event_announcements": event_ann,
        "baseline_announcements": base_ann,
        "announcement_retention": round(event_ann / base_ann, 4) if base_ann else None,
        "event_withdrawals": event_wd,
        "baseline_withdrawals": base_wd,
        "withdrawal_rate": round(event_wd / event_ann, 5) if event_ann else None,
        "withdrawal_inflation": round(event_wd / base_wd, 4) if base_wd else None,
        "event_announced_prefixes": features.get("announced_prefix_count"),
        "baseline_announced_prefixes": baseline_mean("announced_prefix_count") or None,
        "event_withdrawn_prefixes": features.get("withdrawn_prefix_count"),
        "baseline_withdrawn_prefixes": baseline_mean("withdrawn_prefix_count") or None,
    }


def main() -> int:
    events = {e["event_id"]: e for e in load_events()}
    rows = []
    for eid, ev in events.items():
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=eid, allow_same_date=False,
        )
        if match is None:
            continue
        quick = json.loads(match.path.read_text())
        routing = quick.get("routing") or {}
        outage = routing.get("outage_analysis") or {}
        rows.append({
            "event_id": eid,
            "gt_cause": ev["gt_cause"],
            **retention(outage),
        })

    print(f"{'event':42s} {'gt':22s} {'retention':>10s} {'wdrate':>9s} "
          f"{'wd_infl':>8s}")
    for r in sorted(rows, key=lambda x: (x["gt_cause"], x["event_id"])):
        ret = r["announcement_retention"]
        ret_s = f"{ret:.3f}" if ret is not None else "-"
        wr = r["withdrawal_rate"]
        wr_s = f"{wr:.4f}" if wr is not None else "-"
        wi = r["withdrawal_inflation"]
        wi_s = f"{wi:.2f}" if wi is not None else "-"
        print(f"{r['event_id']:42s} {r['gt_cause']:22s} {ret_s:>10s} "
              f"{wr_s:>9s} {wi_s:>8s}")

    print()
    for cls in CLASSES:
        sub = [r for r in rows if r["gt_cause"] == cls]
        rets = sorted(
            r["announcement_retention"] for r in sub
            if r["announcement_retention"] is not None
        )
        infl = sorted(
            r["withdrawal_inflation"] for r in sub
            if r["withdrawal_inflation"] is not None
        )
        print(f"{cls:22s} n={len(sub):2d} retention median="
              f"{rets[len(rets)//2] if rets else None} "
              f"min={rets[0] if rets else None} max={rets[-1] if rets else None}")
        print(f"{'':22s}   wd_inflation median="
              f"{infl[len(infl)//2] if infl else None} "
              f"min={infl[0] if infl else None} max={infl[-1] if infl else None}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps({"rows": rows}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

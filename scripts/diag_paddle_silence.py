"""Diagnose why PADDLE abstains when the control plane goes silent.

An outage's control-plane signature is *silence*: the target stops
announcing its own routes.  The estimator's channel loop skips a channel
whose event-window series is constant, and a silent channel is constant.
The silence is therefore discarded as "no observation", when it is the
observation.

This script reports, per event, which channels were skipped as flat and
whether the flat channel was silent against a live baseline.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.control_plane import CONTROL_PLANE_CHANNELS  # noqa: E402
from agents.control_plane_archive import series_from_payload  # noqa: E402

EVIDENCE = ROOT / "results/eval/control_evidence"


def main():
    for path in sorted(EVIDENCE.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        slots = payload.get("slots") or []
        if not slots:
            continue
        from datetime import datetime
        lo = datetime.fromisoformat(slots[0])
        series = series_from_payload(payload, window_start=lo)
        if not series.stamps:
            continue
        print(f"== {path.name}  target={payload.get('target_as')}")
        for channel in CONTROL_PLANE_CHANNELS:
            values = series.channel(channel)
            baseline = series.baseline_channel(channel)
            if len(values) < 2:
                continue
            ptp = float(np.ptp(values))
            live = sum(1 for v in baseline if v > 0)
            base_level = float(np.mean(baseline)) if baseline else 0.0
            silent = ptp < 1e-9 and max(values) == 0 and live > 0
            note = ""
            if silent:
                note = "  <-- SILENT against a live baseline"
            print(f"   {channel:16s} ptp={ptp:9.3f} max={max(values):9.2f} "
                  f"base_mean={base_level:9.2f} base_live={live:4d}/{len(baseline)}"
                  f"{note}")


if __name__ == "__main__":
    main()

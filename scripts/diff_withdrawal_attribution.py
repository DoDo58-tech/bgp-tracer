"""Diff the withdrawal attribution between the text and parquet paths."""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import polars as pl

from detectors.outage.extract_event_features import parse_bgp_line
from data.parquet_cache import iter_window_chunks

TARGET = "13335"
BUCKET = datetime(2025, 7, 14, 0, 20)


def text_withdrawals() -> set:
    """Withdrawals the text path attributes to the target, per its own rules."""
    src = ROOT / "data" / "updates_rrc00" / "decoded" / f"updates.{BUCKET.strftime('%Y%m%d.%H%M')}.txt"
    prefix_to_target: dict = {}
    out = set()
    with src.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            msg = parse_bgp_line(line)
            if not msg or not msg.get("prefix"):
                continue
            if msg.get("as_path"):
                hops = [int(h) for h in msg["as_path"].split() if h.isdigit()]
                if hops and str(hops[-1]) == TARGET:
                    prefix_to_target[msg["prefix"]] = hops[-1]
            elif msg.get("type") == "W" and msg["prefix"] in prefix_to_target:
                out.add(msg["prefix"])
    return out


def parquet_withdrawals() -> set:
    """Withdrawals the parquet path attributes to the target."""
    owned: set = set()
    out: set = set()
    for chunk in iter_window_chunks(
        BUCKET.replace(minute=0), BUCKET.replace(minute=0) + __import__("datetime").timedelta(minutes=30),
        on_missing="skip", include_withdrawals=True,
    ):
        a = chunk.filter(pl.col("A/W") == "A").with_columns(
            pl.col("as-path").fill_null("").str.split(" ").alias("t")
        ).with_columns(pl.col("t").list.last().alias("org"))
        owned.update(a.filter(pl.col("org") == TARGET)["prefix"].to_list())
        w = chunk.filter(pl.col("A/W") == "W")
        out.update(w.filter(pl.col("prefix").is_in(list(owned)))["prefix"].to_list())
    return out


def main() -> int:
    t = text_withdrawals()
    p = parquet_withdrawals()
    print(f"text attributed withdrawals: {len(t)}")
    print(f"parquet attributed withdrawals: {len(p)}")
    only_p = p - t
    only_t = t - p
    print(f"only in parquet: {len(only_p)}  e.g. {list(only_p)[:5]}")
    print(f"only in text:    {len(only_t)}  e.g. {list(only_t)[:5]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

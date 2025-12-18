#!/usr/bin/env python3
"""Generate batch prompts for chief_agent input based on traffic-outage-info.xlsx."""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXCEL_PATH = PROJECT_ROOT / "data" / "traffic-outage-info.xlsx"
OUTPUT_TXT = PROJECT_ROOT / "data" / "batch_prompts.txt"


def parse_as_list(value) -> str:
    if pd.isna(value):
        return ""
    tokens = re.split(r"[、,;/]+", str(value))
    cleaned = []
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        if not token.upper().startswith("AS"):
            token = f"AS{token}"
        cleaned.append(token.upper())
    return " / ".join(cleaned)


def normalize_time(value) -> str:
    if pd.isna(value):
        return ""
    return pd.to_datetime(value).strftime("%Y-%m-%d %H:%M")


def main():
    if not EXCEL_PATH.exists():
        raise SystemExit(f"Excel file not found: {EXCEL_PATH}")

    df = pd.read_excel(EXCEL_PATH)
    lines = []
    for _, row in df.iterrows():
        event_name = str(row.get("event_name", "")).strip()
        outage_as = parse_as_list(row.get("outage_as"))
        start_time = normalize_time(row.get("start_time"))
        end_time = normalize_time(row.get("end_time"))
        if not event_name or not outage_as or not start_time or not end_time:
            continue
        prompt = f"network outage in {outage_as} from {start_time} to {end_time}"
        lines.append(f"{event_name}: {prompt}")

    OUTPUT_TXT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_TXT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {len(lines)} prompts to {OUTPUT_TXT}")


if __name__ == "__main__":
    main()


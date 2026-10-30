#!/usr/bin/env python3
"""Render the BGP Tracer conceptual workflow figure.

Writes figs/fig_workflow_conceptual.svg (vector source of truth) plus a PDF
and a PNG preview.  Run this file; the drawing code lives in wf_layout.py.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wf_layout as L
import wf_style as S


def main() -> None:
    os.makedirs(L.OUT, exist_ok=True)
    svg = L.build_svg()
    svg_path = os.path.join(L.OUT, "fig_workflow_conceptual.svg")
    with open(svg_path, "w", encoding="utf-8") as fh:
        fh.write(svg)
    print(f"wrote {svg_path} ({os.path.getsize(svg_path) // 1024} KB)")
    if S.WARNINGS:
        print(f"\n{len(S.WARNINGS)} LAYOUT WARNINGS:")
        for w in S.WARNINGS:
            print("  -", w)
    else:
        print("no layout warnings")


if __name__ == "__main__":
    main()

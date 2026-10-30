#!/usr/bin/env python3
"""Geometric self-check for the workflow figure SVG.

Verifies that (1) no two text bboxes overlap, (2) every text sits inside the
card that visually contains it, and (3) nothing spills outside the canvas.
"""
from __future__ import annotations
import sys
from xml.etree import ElementTree as ET

from PIL import ImageFont

FONT_FILES = {
    400: "/home/wangxiaolan7/.fonts/Inter-400.ttf",
    500: "/home/wangxiaolan7/.fonts/Inter-500.ttf",
    600: "/home/wangxiaolan7/.fonts/Inter-600.ttf",
    700: "/home/wangxiaolan7/.fonts/Inter-700.ttf",
}
SVG = "/data/bgp_tracer/docs/paper/figs/fig_workflow_conceptual.svg"
NS = "{http://www.w3.org/2000/svg}"

root = ET.parse(SVG).getroot()
vb = root.get("viewBox").split()
W, H = float(vb[2]), float(vb[3])

rects, texts = [], []
for el in root.iter():
    tag = el.tag.replace(NS, "")
    if tag == "rect":
        x = float(el.get("x", 0)); y = float(el.get("y", 0))
        w = float(el.get("width", 0)); h = float(el.get("height", 0))
        if w < 3 or h < 3:
            continue
        rects.append((x, y, w, h))
    elif tag == "text":
        s = (el.text or "").strip()
        if not s:
            continue
        size = float(el.get("font-size", "10"))
        wt = int(el.get("font-weight", "400"))
        f = ImageFont.truetype(FONT_FILES.get(wt, FONT_FILES[400]), int(size * 4))
        wlen = f.getlength(s) / 4.0
        x = float(el.get("x", 0)); y = float(el.get("y", 0))
        anchor = el.get("text-anchor", "start")
        if anchor == "middle":
            x0 = x - wlen / 2
        elif anchor == "end":
            x0 = x - wlen
        else:
            x0 = x
        texts.append((x0, y - size * 0.78, wlen, size * 1.06, s, x, y))


def overlap(a, b):
    ix = min(a[0] + a[2], b[0] + b[2]) - max(a[0], b[0])
    iy = min(a[1] + a[3], b[1] + b[3]) - max(a[1], b[1])
    return ix, iy


problems = 0

bad = []
for i in range(len(texts)):
    for j in range(i + 1, len(texts)):
        ix, iy = overlap(texts[i], texts[j])
        if ix > 1.0 and iy > 1.0:
            bad.append((texts[i][4], texts[j][4], round(ix, 1), round(iy, 1)))
if bad:
    problems += len(bad)
    print(f"TEXT OVERLAPS ({len(bad)}):")
    for a, b, ix, iy in bad:
        print(f"  {a!r} <-> {b!r}  ({ix} x {iy})")
else:
    print("OK: no text-text overlaps")

spill = []
for t in texts:
    cx, cy = t[5], t[6]
    cands = [r for r in rects
             if r[0] - 1 <= cx <= r[0] + r[2] + 1
             and r[1] - 1 <= cy <= r[1] + r[3] + 1]
    if not cands:
        spill.append((t[4], "no containing rect"))
        continue
    r = min(cands, key=lambda r: r[2] * r[3])
    if (t[0] < r[0] - 0.5 or t[0] + t[2] > r[0] + r[2] + 0.5
            or t[1] < r[1] - 0.5 or t[1] + t[3] > r[1] + r[3] + 0.5):
        spill.append((t[4], f"text {t[0]:.0f},{t[1]:.0f}..{t[0]+t[2]:.0f},"
                             f"{t[1]+t[3]:.0f} vs card {r[0]:.0f},{r[1]:.0f}.."
                             f"{r[0]+r[2]:.0f},{r[1]+r[3]:.0f}"))
if spill:
    problems += len(spill)
    print(f"\nTEXT OUTSIDE ITS CARD ({len(spill)}):")
    for s, why in spill:
        print(f"  {s!r}: {why}")
else:
    print("OK: all text inside its card")

oob = [t for t in texts if t[0] < -1 or t[1] < -1
       or t[0] + t[2] > W + 1 or t[1] + t[3] > H + 1]
if oob:
    problems += len(oob)
    print(f"\nOUT OF CANVAS ({len(oob)}):")
    for t in oob:
        print(f"  {t[4]!r}")
else:
    print("OK: all text within canvas")

print(f"\n{len(texts)} text nodes, {len(rects)} rects, {problems} problems")
sys.exit(1 if problems else 0)

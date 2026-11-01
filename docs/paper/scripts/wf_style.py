"""SVG primitives for the BGP Tracer conceptual workflow figure.

The canvas is 2800 x 1400 USER UNITS, and one user unit equals one point, so
the emitted PDF is exactly 2800 x 1400 pt (2:1).  LaTeX scales it to
\\linewidth, which lands the body text at ~6.2 pt in print.

All font sizes below are therefore in canvas points, and the text metrics are
measured from the real Inter outlines so that wrapping and fitting are exact.
"""
from __future__ import annotations
from PIL import ImageFont

_FONT_FILES = {
    400: "/home/wangxiaolan7/.fonts/Inter-400.ttf",
    500: "/home/wangxiaolan7/.fonts/Inter-500.ttf",
    600: "/home/wangxiaolan7/.fonts/Inter-600.ttf",
    700: "/home/wangxiaolan7/.fonts/Inter-700.ttf",
}
_cache: dict = {}


def load_font(size_px: int, weight: int):
    key = (size_px, weight)
    if key not in _cache:
        _cache[key] = ImageFont.truetype(_FONT_FILES[weight], size_px)
    return _cache[key]


def em_width(s: str, weight: int = 400) -> float:
    """Width of `s` in em units (multiply by the font size for canvas units)."""
    return load_font(400, weight).getlength(s) / 400.0


def tw(s: str, size: float, weight: int = 400) -> float:
    """Width of `s` in canvas units at the given font size."""
    return em_width(s, weight) * size


def fit_size(s: str, max_units: float, base: float, weight: int = 400,
             min_size: float = 18.0) -> float:
    """Largest size <= base that fits `s` within max_units."""
    size = base
    while size > min_size and tw(s, size, weight) > max_units:
        size -= 0.5
    return round(size, 1)


def wrap(s: str, max_units: float, size: float, weight: int = 400) -> list[str]:
    """Greedy word wrap of `s` to `max_units` canvas units.

    Underscores are also break opportunities so that identifiers such as
    ``correlation_uncertain`` can wrap inside a narrow chip.
    """
    tokens: list[str] = []
    for word in s.split(" "):
        if "_" in word:
            pieces = word.split("_")
            for i, p in enumerate(pieces):
                tokens.append(p + ("_" if i < len(pieces) - 1 else ""))
        else:
            tokens.append(word)
    lines: list[str] = []
    cur = ""
    for tok in tokens:
        trial = tok if not cur else cur + " " + tok
        if tw(trial, size, weight) <= max_units or not cur:
            cur = trial
        else:
            lines.append(cur)
            cur = tok
    if cur:
        lines.append(cur)
    return lines


# ---------------------------------------------------------------- palette ---
NAVY = "#16294D"
NAVY_TINT = "#EDF1F8"
NAVY_SOFT = "#B4C4DC"

AMBER = "#8A5F0C"
AMBER_TINT = "#FBF2E1"
AMBER_SOFT = "#D2B87F"

TEAL = "#27635F"
TEAL_TINT = "#E8F1F0"
TEAL_SOFT = "#98C2BC"

SLATE = "#3B4859"
GRAY = "#69758A"
GRAY_LINE = "#C2CCD9"
GRAY_FILL = "#F6F8FC"
WHITE = "#FFFFFF"

FONT = "Inter, Helvetica, Arial, sans-serif"

WARNINGS: list[str] = []


def warn(msg: str) -> None:
    WARNINGS.append(msg)


# ------------------------------------------------------------------ text ---
def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x, y, s, size=34, weight=400, fill=GRAY, anchor="start", spacing=0.0,
         style="", extra=""):
    a = f' text-anchor="{anchor}"' if anchor != "start" else ""
    sp = f' letter-spacing="{spacing:.2f}"' if spacing else ""
    st = f' font-style="{style}"' if style else ""
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-family="{FONT}" '
            f'font-size="{size:.1f}" font-weight="{weight}" fill="{fill}"'
            f'{a}{sp}{st}{extra}>{esc(s)}</text>')


# ---------------------------------------------------------------- shapes ---
def rect(x, y, w, h, fill=WHITE, stroke=None, sw=2.0, r=16, dash=None):
    s = f' stroke="{stroke}" stroke-width="{sw:.2f}"' if stroke else ""
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
            f'rx="{r:.1f}" fill="{fill}"{s}{d}/>')


def circle(cx, cy, r, fill=WHITE, stroke=None, sw=2.0):
    s = f' stroke="{stroke}" stroke-width="{sw:.2f}"' if stroke else ""
    return f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="{fill}"{s}/>'


def line(x1, y1, x2, y2, stroke=SLATE, sw=2.0, dash=None, cap="round"):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{stroke}" stroke-width="{sw:.2f}" stroke-linecap="{cap}"{d}/>')


def path(d, stroke=SLATE, sw=2.0, fill="none", dash=None, cap="round"):
    dd = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'<path d="{d}" fill="{fill}" stroke="{stroke}" stroke-width="{sw:.2f}" '
            f'stroke-linecap="{cap}" stroke-linejoin="round"{dd}/>')


# ---------------------------------------------------------------- arrows ---
def arrow_style(kind, color):
    if kind == "solid":
        return None, color
    if kind == "dashed":
        return "14 10", color
    return "4 8", color


def arrow_head(x2, y2, ux, uy, head, col):
    bx, by = x2 - ux * head, y2 - uy * head
    px, py = -uy * head * 0.40, ux * head * 0.40
    tri = (f"{x2:.1f},{y2:.1f} {bx + px:.1f},{by + py:.1f} "
           f"{bx - px:.1f},{by - py:.1f}")
    return f'<polygon points="{tri}" fill="{col}"/>'


def arrow(x1, y1, x2, y2, kind="solid", color=SLATE, sw=2.4, head=11.0):
    dash, col = arrow_style(kind, color)
    dx, dy = x2 - x1, y2 - y1
    ln = (dx * dx + dy * dy) ** 0.5 or 1.0
    ux, uy = dx / ln, dy / ln
    bx, by = x2 - ux * head, y2 - uy * head
    return (line(x1, y1, bx, by, col, sw, dash)
            + arrow_head(x2, y2, ux, uy, head, col))


def arrow_h(x1, y, x2, kind="solid", color=SLATE, sw=2.4, head=11.0):
    s = 1 if x2 >= x1 else -1
    dash, col = arrow_style(kind, color)
    bx = x2 - s * head
    tri = f"{x2:.1f},{y:.1f} {bx:.1f},{y - 5.0:.1f} {bx:.1f},{y + 5.0:.1f}"
    return (line(x1, y, bx, y, col, sw, dash)
            + f'<polygon points="{tri}" fill="{col}"/>')


def arrow_v(x, y1, y2, kind="solid", color=SLATE, sw=2.4, head=11.0):
    s = 1 if y2 >= y1 else -1
    dash, col = arrow_style(kind, color)
    by = y2 - s * head
    tri = f"{x:.1f},{y2:.1f} {x - 5.0:.1f},{by:.1f} {x + 5.0:.1f},{by:.1f}"
    return (line(x, y1, x, by, col, sw, dash)
            + f'<polygon points="{tri}" fill="{col}"/>')


# ----------------------------------------------------------------- cards ---
def card_h(w, title=None, body=(), t_size=24, b_size=18, pad=14,
           max_lines=3, t_weight=600) -> float:
    """Height a card needs for its content (same wrapping rules as `card`)."""
    avail = w - 2 * pad
    tl = []
    if title:
        ts = fit_size(title, avail, t_size, t_weight, min_size=15)
        if ts >= t_size - 0.01:
            tl = [title]
        else:
            tl = wrap(title, avail, t_size, t_weight)
            while len(tl) > 2 and t_size > 17:
                t_size -= 1
                tl = wrap(title, avail, t_size, t_weight)
            ts = t_size
    bl = []
    for s in body:
        bl.extend(wrap(s, avail, b_size))
    while len(bl) > max_lines and b_size > 13:
        b_size -= 0.5
        bl = []
        for s in body:
            bl.extend(wrap(s, avail, b_size))
    h = pad
    if tl:
        h += len(tl) * t_size * 1.18 + (t_size * 0.24)
    if bl:
        h += b_size + (len(bl) - 1) * b_size * 1.34
    return h + pad


def card(x, y, w, h, title=None, body=(), accent=SLATE, tint=WHITE, border=None,
         t_size=24, t_weight=600, b_size=18, b_color=GRAY, t_color=None,
         r=14, sw=2.0, align="center", pad=14, lh=None, extra="", max_lines=3,
         shrink=True):
    """White/tinted card with a thin coloured outline.

    Body text wraps to the card width and shrinks if the card would otherwise
    need more than `max_lines` body lines.  `h` may be None to auto-size.
    """
    b = border or accent
    if h is None:
        h = card_h(w, title, body, t_size, b_size, pad, max_lines, t_weight)
    out = rect(x, y, w, h, fill=tint, stroke=b, sw=sw, r=r)
    t_color = t_color or accent
    avail = w - 2 * pad

    # --- title: shrink to fit one line, else wrap to at most two lines ---
    title_lines: list[str] = []
    ts = t_size
    if title:
        ts = fit_size(title, avail, t_size, t_weight, min_size=15)
        if ts >= t_size - 0.01:
            title_lines = [title]
        else:
            title_lines = wrap(title, avail, t_size, t_weight)
            while len(title_lines) > 2 and t_size > 17:
                t_size -= 1
                title_lines = wrap(title, avail, t_size, t_weight)
            ts = t_size

    # --- body: wrap and shrink so the card stays within max_lines ---------
    body_lines: list[str] = []
    for s in body:
        body_lines.extend(wrap(s, avail, b_size))
    while shrink and len(body_lines) > max_lines and b_size > 13:
        b_size -= 0.5
        body_lines = []
        for s in body:
            body_lines.extend(wrap(s, avail, b_size))
    lh = lh or b_size * 1.34

    y0 = y + pad
    anchor = "middle" if align == "center" else "start"
    tx = x + w / 2 if align == "center" else x + pad
    if title_lines:
        for i, s in enumerate(title_lines):
            out += text(tx, y0 + ts + i * ts * 1.18, s, ts, t_weight, t_color, anchor)
        y0 = y0 + ts + (len(title_lines) - 1) * ts * 1.18

    for i, s in enumerate(body_lines):
        yy = y0 + b_size + i * lh
        out += text(tx, yy, s, b_size, 400, b_color, anchor)
    out += extra
    return out


def chip(x, y, w, h, label, state="lo", accent=AMBER, size=19, weight=500):
    if state == "hi":
        out = rect(x, y, w, h, fill=AMBER_TINT, stroke=accent, sw=2.0, r=8)
        col, wt = accent, 600
    else:
        out = rect(x, y, w, h, fill=WHITE, stroke=GRAY_LINE, sw=1.6, r=8)
        col, wt = GRAY, 400
    sz = fit_size(label, w - 16, size, wt, min_size=13)
    if sz < size - 0.01:
        warn(f"chip shrunk: {label!r} {size}->{sz}")
    out += text(x + w / 2, y + h / 2 + sz * 0.35, label, sz, wt, col, "middle")
    return out


def badge(cx, cy, tag, r=19, size=22):
    return (circle(cx, cy, r, fill=NAVY)
            + text(cx, cy + size * 0.35, tag, size, 700, WHITE, "middle"))


def callout(cx, cy, tag, l1, l2, r=19, size=19, leader=None, lead_color=None,
            align="start", color=NAVY, badge_dx=0.0):
    """Numbered badge plus a two-line label, with an optional thin leader."""
    bx = cx + badge_dx
    out = badge(bx, cy, tag, r, size)
    tx = bx + r + 10 if align == "start" else bx - r - 10
    anc = "start" if align == "start" else "end"
    out += text(tx, cy - 3, l1, size, 600, color, anc)
    out += text(tx, cy + size + 5, l2, size, 400, GRAY, anc)
    if leader:
        out += path(leader, lead_color or GRAY_LINE, 1.4)
    return out


# ----------------------------------------------------------------- icons ---
def icon_waveform(x, y, color=NAVY, w=52, h=34):
    d = (f"M {x} {y + h*0.66} L {x + w*0.15} {y + h*0.44} L {x + w*0.28} {y + h*0.68} "
         f"L {x + w*0.46} {y + h*0.12} L {x + w*0.60} {y + h*0.52} L {x + w*0.78} {y + h*0.36} "
         f"L {x + w} {y + h*0.60}")
    return path(d, color, 2.4)


def icon_routers(x, y, color=NAVY, w=52, h=34):
    out = ""
    bw, bh = 17, 13
    out += (f'<rect x="{x}" y="{y + 8}" width="{bw}" height="{bh}" rx="4" '
            f'fill="none" stroke="{color}" stroke-width="2.2"/>')
    out += (f'<rect x="{x + w - bw}" y="{y + 8}" width="{bw}" height="{bh}" rx="4" '
            f'fill="none" stroke="{color}" stroke-width="2.2"/>')
    out += line(x + bw + 3, y + 14.5, x + w - bw - 7, y + 14.5, color, 2.2)
    out += (f'<polygon points="{x + w - bw - 7},{y + 14.5} {x + w - bw - 13},{y + 11.4} '
            f'{x + w - bw - 13},{y + 17.6}" fill="{color}"/>')
    out += line(x + bw / 2, y + 8, x + bw / 2, y + 2, color, 2.2)
    out += line(x + w - bw / 2, y + 8, x + w - bw / 2, y + 2, color, 2.2)
    return out


def icon_graph(x, y, color=NAVY, w=52, h=34):
    out = ""
    a = (x + 8, y + 8)
    b = (x + w - 10, y + 6)
    c = (x + w * 0.48, y + h - 2)
    out += line(a[0], a[1], b[0], b[1], color, 2.0)
    out += line(a[0], a[1], c[0], c[1], color, 2.0)
    out += line(c[0], c[1], b[0], b[1], color, 2.0)
    out += circle(a[0], a[1], 5.4, WHITE, color, 2.0)
    out += circle(b[0], b[1], 5.4, WHITE, color, 2.0)
    out += circle(c[0], c[1], 5.4, WHITE, color, 2.0)
    return out


def icon_target(x, y, color=SLATE, w=52, h=34):
    cx, cy = x + w / 2, y + h / 2
    out = circle(cx, cy, 11, "none", color, 2.2)
    out += circle(cx, cy, 3.4, color, None)
    out += line(cx, cy - 18, cx, cy - 13.5, color, 2.2)
    out += line(cx, cy + 13.5, cx, cy + 18, color, 2.2)
    out += line(cx - 18, cy, cx - 13.5, cy, color, 2.2)
    out += line(cx + 13.5, cy, cx + 18, cy, color, 2.2)
    return out


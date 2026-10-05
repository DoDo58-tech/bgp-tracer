"""Measure real rendered geometry of a report with headless Chromium.

The three production defects were *visual*, so the only convincing check is a
real layout engine reporting real box geometry. The tearing defect in
particular is "a block that is not as wide as the box that contains it".

Widths legitimately differ between nesting levels — a ``.card`` has its own
20px padding, so its children are narrower than the ``.report`` content box.
So every element is compared against the content box of ITS OWN parent, not
against one global number. That is what distinguishes a real overflow from a
harmless difference in nesting depth.

Usage::

    python scripts/measure_layout.py [report.html ...]
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PROBE = r"""
() => {
  const rep = document.querySelector('.report');
  if (!rep) return {error: 'no .report element'};
  const round = v => Math.round(v);
  const widths = sel => [...document.querySelectorAll(sel)]
      .map(e => round(e.getBoundingClientRect().width));

  const contentWidth = el => {
    const cs = getComputedStyle(el);
    return el.getBoundingClientRect().width
      - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight)
      - parseFloat(cs.borderLeftWidth) - parseFloat(cs.borderRightWidth);
  };

  // Collect elements that overflow the box containing them.
  const overflow = [];
  const check = sel => {
    for (const el of document.querySelectorAll(sel)) {
      const parent = el.parentElement;
      if (!parent) continue;
      const avail = contentWidth(parent);
      const actual = el.getBoundingClientRect().width;
      if (avail > 0 && actual > avail + 2) {
        overflow.push({
          tag: el.tagName.toLowerCase(),
          cls: (el.className || '').toString().slice(0, 40),
          parent: parent.tagName.toLowerCase() + '.' +
                  (parent.className || '').toString().split(' ')[0],
          w: round(actual), avail: round(avail),
        });
      }
    }
  };
  ['.report > *', '.card > *', 'details.fold > *', '.fold-body > *', 'figure.chart > *']
    .forEach(check);

  return {
    viewport: window.innerWidth,
    reportWidth: round(rep.getBoundingClientRect().width),
    reportContent: round(contentWidth(rep)),
    docScrollWidth: document.documentElement.scrollWidth,
    horizontalOverflow: document.documentElement.scrollWidth > window.innerWidth + 1,
    cards: widths('.card'),
    tables: widths('table.data'),
    figures: widths('figure.chart img'),
    details: widths('details.fold'),
    overflow: overflow.slice(0, 12),
  };
}
"""


def measure(paths: list) -> int:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        print(f"playwright unavailable: {exc!r}")
        return 2

    total = 0
    with sync_playwright() as pw:
        # The reports embed multi-MB base64 PNGs. On this host Chromium's
        # default multi-process model crashes the renderer target on page
        # creation, so run single-process and disable the GPU/shm.
        browser = pw.chromium.launch(args=[
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--single-process",
        ])
        page = browser.new_page(
            viewport={"width": 1440, "height": 1000},
        )
        for path in paths:
            page.goto(path.resolve().as_uri())
            page.wait_for_timeout(200)
            data = page.evaluate(PROBE)
            name = path.name[:42]
            if "error" in data:
                print(f"[FAIL] {name}: {data['error']}")
                total += 1
                continue

            issues = []
            if data["horizontalOverflow"]:
                issues.append(
                    f"document scrolls horizontally: "
                    f"{data['docScrollWidth']}px > viewport {data['viewport']}px"
                )
            for dev in data["overflow"]:
                issues.append(
                    f"<{dev['tag']} class={dev['cls']!r}> is {dev['w']}px but its "
                    f"container <{dev['parent']}> allows {dev['avail']}px"
                )
            # Every card must share one width — the headline tearing symptom.
            card_w = set(data["cards"])
            if len(card_w) > 1:
                issues.append(f"cards render at inconsistent widths: {sorted(card_w)}")
            # The chart must be no wider than a card.
            card_max = max(data["cards"]) if data["cards"] else data["reportContent"]
            for w in data["figures"]:
                if w > card_max + 2:
                    issues.append(f"chart is {w}px, wider than the card ({card_max}px)")

            status = "OK" if not issues else f"{len(issues)} ISSUE(S)"
            print(f"[{status:>12}] {name}")
            print(f"                 report={data['reportWidth']}px (content "
                  f"{data['reportContent']}px)  cards={sorted(set(data['cards']))}  "
                  f"tables={sorted(set(data['tables']))}  figures={sorted(set(data['figures']))}")
            for issue in issues[:8]:
                print(f"               - {issue}")
            total += len(issues)
        browser.close()
    print("\nTOTAL LAYOUT ISSUES:", total)
    return 1 if total else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    files = (
        [Path(a) for a in args]
        if args
        else sorted((ROOT / "results" / "template_preview").glob("*.html"))
    )
    raise SystemExit(measure(files))

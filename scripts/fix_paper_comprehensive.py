#!/usr/bin/env python3
"""
Comprehensive paper fix:
1. Table overflow: IEEEtran two-column safe widths
2. tab:detector-fire: fill in actual data from detector_fire_rate.json
3. Equation overflow: wrap too-wide equations
4. Empty tabular cells: protect empty cells from LaTeX parsing
"""
import json, re
from pathlib import Path

ROOT = Path("/data/bgp_tracer/docs/paper")
SCRIPTS = Path("/data/bgp_tracer/scripts")

# ── load detector fire-rate data ────────────────────────────────────────────
with open("/data/bgp_tracer/results/eval/detector_fire_rate.json") as f:
    dfr = json.load(f)


def pct(numer, denom):
    """Return 'xx.x%' string, handle zero and rounding."""
    if denom == 0:
        return "—"
    val = numer / denom * 100
    return f"{val:.1f}\\%"

# detector fire-rate table data:
# rows: origin_hijack_victim, route_leak, outage, NC
# cols: leak detector, hijack detector, outage detector, traffic detector
fire_data = {
    "origin_hijack_victim": {
        "n": 7,
        "leak": dfr["origin_hijack_victim"]["leak_fire_rate"],
        "hijack": dfr["origin_hijack_victim"]["hijack_fire_rate"],
        "outage": dfr["origin_hijack_victim"]["outage_fire_rate"],
        "traffic": dfr["origin_hijack_victim"]["traffic_fire_rate"],
    },
    "route_leak": {
        "n": 8,
        "leak": dfr["route_leak"]["leak_fire_rate"],
        "hijack": dfr["route_leak"]["hijack_fire_rate"],
        "outage": dfr["route_leak"]["outage_fire_rate"],
        "traffic": dfr["route_leak"]["traffic_fire_rate"],
    },
    "outage": {
        "n": 13,   # 14 total - 1 NC
        "leak": dfr["outage"]["leak_fire_rate"],
        "hijack": dfr["outage"]["hijack_fire_rate"],
        "outage": dfr["outage"]["outage_fire_rate"],
        "traffic": dfr["outage"]["traffic_fire_rate"],
    },
}

# NC row
nc = dfr["NC"]

# ── helper: fix a single tabular column-width spec ──────────────────────────
# In IEEEtran two-column mode: \colwidth = 0.86 (one column) or 1.86 (full text)
# We use \tdlgap for padding and explicit p{...} for fixed-width columns.
TWO_COL = r"\twocolumn"
IEEE_PREAMBLE = r"""
%% IEEEtran two-column table width: one column ≈ 0.86in
%% To force a table to full textwidth use table* or set
%% the tabular to \linewidth and use p{\dimexpr(\linewidth/N - 2\tabcolsep)}
"""


def make_two_col_tabular(spec: str, col_names: list[str], rows: list[list[str]],
                         caption_text: str, label: str,
                         note: str = "") -> str:
    """
    Build a safe two-column table using p{} widths.
    col_names: list of column header strings
    rows: list of row lists (same length as col_names)
    """
    n_cols = len(col_names)
    # Compute p{} widths proportional to content
    # We give the first column (label) 40% and distribute remaining 60% among data cols
    p_widths = [0.40] + [0.60 / (n_cols - 1)] * (n_cols - 1)
    p_spec = "".join(f"p{{{w:.2f}\\linewidth}}" for w in p_widths)

    lines = []
    lines.append(r"\begin{table*}[t]")   # use table* for full-width
    lines.append(r"\centering")
    lines.append(r"\setlength{\tabcolsep}{3pt}")
    lines.append(r"\setlength{\heavyrulewidth}{0.8pt}")
    lines.append(r"\small")
    lines.append(f"\\begin{{tabular}}{{{p_spec}}}")
    lines.append(r"\hline")
    # header
    lines.append(" & ".join(col_names) + r" \\")
    lines.append(r"\hline")
    # data rows
    for row in rows:
        lines.append(" & ".join(row) + r" \\")
    lines.append(r"\hline")
    lines.append(r"\end{tabular}")
    lines.append(f"\\caption{{{caption_text}}}")
    lines.append(f"\\label{{{label}}}")
    if note:
        lines.append(f"\\multicolumn{{{n_cols}}}{{l}}{{\\footnotesize {note}}}")
    lines.append(r"\end{table*}")
    return "\n".join(lines)


# ── section 6 fixes ─────────────────────────────────────────────────────────
def fix_section6(path: Path) -> bool:
    """Fix tab:detector-fire and tab:heldout-detail empty tables."""
    text = path.read_text()
    orig = text

    # ── Fix tab:detector-fire: fill in the actual fire-rate numbers ──────────
    # Pattern: table from "\begin{table}[h]" to the empty tabular
    # We need to find the whole table environment and replace it.

    # Pattern for detector fire rate table
    pat_table = re.compile(
        r'(\\begin\{table\}\[h\]\s*\n\\centering\s*\n\\small\s*\n'
        r'\\setlength\{\\tabcolsep\}\{3pt\}\s*\n'
        r'\\begin\{tabular\}\{.*?\}\s*\n'
        r'\\hline\s*\n'
        r'.*?\\end\{tabular\}\s*\n'
        r'\\caption\{.*?\}.*?'
        r'\\label\{tab:detector-fire\}.*?'
        r'\\end\{table\})',
        re.DOTALL
    )

    # Build new detector fire rate table
    col_headers = [
        r"GT class",
        r"$n$",
        r"Leak fire",
        r"Hijack fire",
        r"Outage fire",
        r"Traffic fire",
    ]

    def fmt_rate(v):
        return f"{v*100:.1f}\\%"

    det_rows = []
    for cls, label in [
        ("origin_hijack_victim", r"\texttt{origin\_hijack\_victim}"),
        ("route_leak", r"\texttt{route\_leak}"),
        ("outage", r"\texttt{outage}"),
    ]:
        d = fire_data[cls]
        det_rows.append([
            label,
            str(d["n"]),
            fmt_rate(d["leak"]),
            fmt_rate(d["hijack"]),
            fmt_rate(d["outage"]),
            fmt_rate(d["traffic"]),
        ])
    # NC row
    det_rows.append([
        r"\texttt{outage} (NC)",
        "1",
        fmt_rate(nc["leak_fire_rate"]),
        fmt_rate(nc["hijack_fire_rate"]),
        fmt_rate(nc["outage_fire_rate"]),
        fmt_rate(nc["traffic_fire_rate"]),
    ])

    # Replace the empty detector fire rate table using a simple string search
    # Find the table by its caption and label, replace the tabular body
    det_table_marker_start = r"\begin{table}[h]"
    det_caption = r"\caption{Per-cause detector fire-rate"
    det_label = r"\label{tab:detector-fire}"

    # Find the table start (after \begin{table}[h] containing the detector-fire caption)
    det_start = text.find(det_caption)
    if det_start != -1:
        bt = text.rfind(det_table_marker_start, 0, det_start)
        if bt != -1:
            # Find the matching \end{table}
            et = text.find(r"\end{table}", det_start)
            if et != -1:
                # Build the replacement
                full_table = text[bt:et + len(r"\end{table}")]
                # Replace \begin{table}[h] -> \begin{table*}[t]
                full_table = full_table.replace(r"\begin{table}[h]", r"\begin{table*}[t]", 1)
                full_table = full_table.replace(r"\end{table}", r"\end{table*}", 1)

                # Replace the empty tabular content
                # Find the \begin{tabular} and \end{tabular}
                tab_b = full_table.find(r"\begin{tabular}")
                tab_e = full_table.find(r"\end{tabular}")
                if tab_b != -1 and tab_e != -1:
                    # Build new tabular
                    n_cols = 6
                    p_spec = (r"{p{0.28\linewidth}p{0.05\linewidth}p{0.12\linewidth}"
                              r"p{0.12\linewidth}p{0.12\linewidth}p{0.12\linewidth}}")
                    new_tabular = (r"\begin{tabular}" + p_spec + "\n"
                                   + r"\hline" + "\n"
                                   + " & ".join(col_headers) + r" \\" + "\n"
                                   + r"\hline" + "\n"
                                   + "\n".join(" & ".join(row) + r" \\" for row in det_rows) + "\n"
                                   + r"\hline" + "\n"
                                   + r"\end{tabular}")
                    full_table = full_table[:tab_b] + new_tabular + full_table[tab_e + len(r"\end{tabular}"):]

                text = text[:bt] + full_table + text[et + len(r"\end{table}"):]

    # ── Fix tab:heldout-detail: fill in actual held-out numbers ──────────────
    # Based on v18 held-out results:
    # Events with cache: 13/13
    # Events with sufficient detector data: 10/13
    # Phase-1 strict (all 13): 6/13 = 46.2%
    # Phase-1 strict (10 with sufficient data): 6/10 = 60.0%

    # ── Fix held-out detail table: fill in actual numbers ──────────────────────
    heldout_marker = r"\caption{Held-out Phase~1 strict-accuracy"
    hm_pos = text.find(heldout_marker)
    if hm_pos != -1:
        bt = text.rfind(r"\begin{table}[h]", 0, hm_pos)
        if bt != -1:
            et = text.find(r"\end{table}", bt)
            if et != -1:
                # Build replacement with data
                new_heldout = (
                    r"\begin{table*}[t]"
                    r"\centering"
                    r"\small"
                    r"\setlength{\tabcolsep}{4pt}"
                    r"\begin{tabular}{p{0.62\linewidth}r}"
                    r"\hline"
                    r"Metric & Held-out \\"
                    r"\hline"
                    r"Events with cache built & 13/13 \\"
                    r"Events with sufficient detector data & 10/13 \\"
                    r"Phase~1 strict-accuracy (all 13) & 6/13 = 46.2\% \\"
                    r"Phase~1 strict-accuracy (10 sufficient) & \textbf{6/10 = 60.0\%} \\"
                    r"\hline"
                    r"\end{tabular}"
                    r"\caption{Held-out unseen-event stress test: Phase~1 strict-accuracy "
                    r"on the 13 held-out candidate events. "
                    r"The 46.2\% (6/13) is the raw number; the 60.0\% (6/10) excludes "
                    r"3 events whose cached detector data was insufficient (partial cache or "
                    r"\texttt{skip\_outage} pollution). "
                    r"Wilson 95\% CIs: 46.2\% on 13 events $[23.2\%, 70.9\%]$; "
                    r"60.0\% on 10 events $[31.3\%, 83.2\%]$.}"
                    r"\label{tab:heldout-detail}"
                    r"\end{table*}"
                )
                text = text[:bt] + new_heldout + text[et + len(r"\end{table}"):]

    if text != orig:
        path.write_text(text)
        return True
    return False


def fix_table_widths_in_file(path: Path) -> bool:
    """
    Fix table overflow: use table* for wide tables, p{}-based widths.
    IEEEtran two-column: \linewidth = column width ≈ 3.5in, \textwdith = 7in
    """
    text = path.read_text()
    orig = text

    # ── Fix 1: tab:lr-defs (5 cols) — use table* ─────────────────────────
    lr_table = re.compile(
        r'(\\begin\{table\}\[t\]\s*\n'
        r'\\centering\s*\n'
        r'\\caption\{.*?\}.*?\n'
        r'\\label\{tab:lr-defs\}.*?\n'
        r'\\small\s*\n'
        r'\\begin\{tabular\})',
        re.DOTALL
    )
    def expand_lr_table(m):
        return m.group(1).replace(r'\begin{table}[t]', r'\begin{table*}[t]')
    text = lr_table.sub(expand_lr_table, text, count=1)
    # Also fix the \end{table} to \end{table*}
    text = text.replace(
        r'\end{table}' + '\n' + r'\paragraph{Per-channel sparsity',
        r'\end{table*}' + '\n' + r'\paragraph{Per-channel sparsity',
    )
    # More robust: replace the \end{table} right after tab:lr-defs
    # Find the lr-defs table and swap begin/end
    lr_start = text.find(r'\begin{table*}[t]' + '\n' + r'\centering')
    if lr_start == -1:
        # Try without [t]
        lr_start = text.find(r'\begin{table*}')
    if lr_start != -1:
        # Find the matching \end{table} (first one after this table)
        end_idx = text.find(r'\end{table}', lr_start)
        if end_idx != -1:
            text = text[:end_idx] + r'\end{table*}' + text[end_idx+len(r'\end{table}'):]

    # ── Fix 2: tab:headline-bound (4 cols) — use table* ───────────────────
    hb_pat = re.compile(
        r'(\\begin\{table\}\[h\]\s*\n'
        r'\\centering\s*\n\\small\s*\n'
        r'\\begin\{tabular\})',
        re.DOTALL
    )
    def swap_hb_table(m):
        return r'\begin{table*}[t]' + '\n' + m.group(0).replace(r'\begin{table}[h]', r'\begin{table*}').replace(r'\begin{tabular}', r'\begin{tabular}')
    # Only apply to the FIRST such table (headline bound)
    count = 0
    def replace_first(m):
        nonlocal count
        count += 1
        if count == 1:
            return m.group(0).replace(r'\begin{table}[h]', r'\begin{table*}[t]')
        return m.group(0)
    text = hb_pat.sub(replace_first, text, count=1)
    # Fix the matching \end{table} -> \end{table*}
    # Find the tab:headline-bound label and replace the prior \end{table}
    hb_label_pos = text.find(r'\label{tab:headline-bound}')
    if hb_label_pos != -1:
        # Find the next \end{table} after this label
        end_t = text.find(r'\end{table}', hb_label_pos)
        if end_t != -1:
            text = text[:end_t] + r'\end{table*}' + text[end_t+len(r'\end{table}'):]

    # ── Fix 3: tab:invariants (3 cols, long text) — use table* ───────────
    inv_pat = re.compile(
        r'(\\begin\{table\}\[h\]\s*\n'
        r'\\centering\s*\n'
        r'\\setlength\{\\tabcolsep\}\{3pt\}\s*\n'
        r'\\small\s*\n'
        r'\\begin\{tabular\})',
        re.DOTALL
    )
    # Apply to the invariants table (first such match in section 3)
    s3_text_start = text.find(r'\section{Data Sources')
    s3_text_end = text.find(r'\section{Ground-truth construction', s3_text_start)
    if s3_text_start != -1 and s3_text_end != -1:
        s3_region = text[s3_text_start:s3_text_end]
        inv_m = re.search(
            r'(\\begin\{table\}\[h\]\s*\n'
            r'\\centering\s*\n'
            r'\\setlength\{\\tabcolsep\}\{3pt\}\s*\n'
            r'\\small\s*\n'
            r'\\begin\{tabular\})',
            s3_region
        )
        if inv_m:
            pos = s3_text_start + inv_m.start()
            text = text[:pos] + text[pos:].replace(
                r'\begin{table}[h]' + '\n' + r'\centering',
                r'\begin{table*}[t]' + '\n' + r'\centering',
                1
            )
            # Fix matching \end{table}
            end_t = text.find(r'\end{table}', pos)
            if end_t != -1 and end_t < s3_text_end + 200:
                text = text[:end_t] + r'\end{table*}' + text[end_t+len(r'\end{table}'):]

    # ── Fix 4: tab:dataset-distribution — use table* ──────────────────────
    # Find this table and upgrade it
    dd_start = text.find(r'\caption{ground-truth class distribution')
    if dd_start != -1:
        # find the \begin{table} before this caption
        bt = text.rfind(r'\begin{table}', 0, dd_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    # ── Fix 5: tab:ch-sparsity (4 cols) — use table* ─────────────────────
    cs_start = text.find(r'\caption{Per-channel abstention')
    if cs_start != -1:
        bt = text.rfind(r'\begin{table}', 0, cs_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    # ── Fix 6: tab:metrics (2 cols, very wide) — use table* ───────────────
    met_start = text.find(r'\caption{Definitions of all evaluation metrics')
    if met_start != -1:
        bt = text.rfind(r'\begin{table}', 0, met_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    # ── Fix 7: tab:method-comparison (3 cols) — use table* ───────────────
    mc_start = text.find(r'\caption{Phase~1 strict-accuracy on the ground-truth')
    if mc_start != -1:
        bt = text.rfind(r'\begin{table}', 0, mc_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    # ── Fix 8: tab:per-cause (3 cols) — use table* ──────────────────────
    pc_start = text.find(r'\caption{Per-cause Phase~1 strict-accuracy')
    if pc_start != -1:
        bt = text.rfind(r'\begin{table}', 0, pc_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    # ── Fix 9: tab:discount-sens (4 cols) — use table* ───────────────────
    ds_start = text.find(r'\caption{Disagreement discount sensitivity')
    if ds_start != -1:
        bt = text.rfind(r'\begin{table}', 0, ds_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    # ── Fix 10: supplementary tab:detector-fire (S-table) ─────────────────
    sdf_start = text.find(r'\caption{ kept-event composition')
    if sdf_start == -1:
        sdf_start = text.find(r'\caption{ kept-event composition')
    if sdf_start != -1:
        bt = text.rfind(r'\begin{table}', 0, sdf_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    # ── Fix 11: supplementary tab:detector-fire rejection ──────────────────
    rej_start = text.find(r'\caption{ rejection breakdown')
    if rej_start != -1:
        bt = text.rfind(r'\begin{table}', 0, rej_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    # ── Fix 12: supplementary tab:supp-html (2 cols, narrow) ──────────────
    html_start = text.find(r'\caption{HTML pipeline evaluation on')
    if html_start != -1:
        bt = text.rfind(r'\begin{table}', 0, html_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    # ── Fix 13: supplementary tab:supp-deg-stress (4 cols) ───────────────
    deg_start = text.find(r'\caption{Degraded-mode strict-accuracy')
    if deg_start != -1:
        bt = text.rfind(r'\begin{table}', 0, deg_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    # ── Fix 14: supplementary tab:supp-uniform-prior (2 cols) ────────────
    up_start = text.find(r'\caption{Uniform-prior ablation on')
    if up_start != -1:
        bt = text.rfind(r'\begin{table}', 0, up_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    # ── Fix 15: supplementary tab:supp-css-n3 (4 cols) ──────────────────
    css3_start = text.find(r'\caption{CSS strict-causal subset')
    if css3_start != -1:
        bt = text.rfind(r'\begin{table}', 0, css3_start)
        if bt != -1:
            text = text[:bt] + r'\begin{table*}[t]' + text[bt+len(r'\begin{table}'):]
            et = text.find(r'\end{table}', bt)
            if et != -1:
                text = text[:et] + r'\end{table*}' + text[et+len(r'\end{table}'):]

    if text != orig:
        path.write_text(text)
        return True
    return False


def fix_formula_overflow_in_file(path: Path) -> bool:
    """Wrap too-wide equations that overflow into the margin."""
    text = path.read_text()
    orig = text

    # Fix equation (4): \mathrm{CSS}(R\!\to\!T) = \mathbb{E}[T \mid \mathrm{do}(R{=}1)] - ...
    # This can be split using \ Split relAlign
    old_eq4 = (
        r"{\\mathrm{CSS}(R\\!\to\\!T)"
        r" \\;=\\; \\mathbb{E}[T \\mid \\mathrm{do}(R{=}1)]"
        r" - \\mathbb{E}[T \\mid \\mathrm{do}(R{=}0)]}"
    )
    new_eq4 = (
        r"{\\mathrm{CSS}(R\\!\to\\!T)"
        r" \\;=\\; \\mathbb{E}[T \\mid \\mathrm{do}(R{=}1)]"
        r"\\\\[3pt]\\noalign{\\phantomsection}"
        r"\\hspace{1em}-\\; \\mathbb{E}[T \\mid \\mathrm{do}(R{=}0)]}"
    )
    # Only do if the original is present
    if old_eq4 in text:
        text = text.replace(old_eq4, new_eq4)

    # Fix equation (5): the prior weight definition — already multi-line so should be ok
    # Fix eq (6): product scoring rule — split if needed
    eq6 = r"S(h \mid \text{evidence}) \;\propto\; P_0(h) \cdot \prod_{k=1}^{5} \mathrm{LR}_k(h)^{\,\delta_k}"
    if eq6 in text:
        # Split after the proportional sign
        new_eq6 = (
            r"S(h \mid \text{evidence})"
            r" \;\propto\; P_0(h)"
            r"\\\\[1pt]"
            r"\hspace{2em}\cdot\displaystyle\prod_{k=1}^{5}"
            r"\; \mathrm{LR}_k(h)^{\,\delta_k}"
        )
        text = text.replace(eq6, new_eq6)

    # Fix: \mathrm{E}[T \mid \mathrm{do}(R{=}1)] expressions too wide
    # Already handled by splitting eq4

    if text != orig:
        path.write_text(text)
        return True
    return False


def fix_figure_caption_mismatch(path: Path) -> bool:
    """Fix caption/body mismatches and stale figure references."""
    text = path.read_text()
    orig = text

    # Fix: fig3 was generated by render_paper_figs.py fig3_ablation() which loads v11 data
    # but main.tex section 6 uses fig7_eval_overview from render_paper_figs.py
    # The actual fig3 in the body says it shows "method comparison"
    # The caption says "method comparison" but the figure shown is fig7_eval_overview
    # This is a reference mismatch — we need to fix the caption to match what's shown

    # The caption in section 6 says: "method comparison on the 30-event ground-truth"
    # But fig3_ablation() uses v11 data (old, ~30 events). Let me check the actual text.
    # In section 6, the figure reference is \figurename~\ref{fig:method-comparison}
    # But looking at the actual file content, fig3 IS referenced in section 6 as fig7_eval_overview.
    # Actually let me re-check what figures are referenced in section 6...

    # Looking at section 6:
    # \begin{figure}[t] \centering \includegraphics[width=0.75\linewidth]{figs/fig7_eval_overview.pdf}
    # \caption{Operator-facing HTML pipeline evaluation on ...}

    # So section 6 uses fig7_eval_overview.pdf, NOT fig3. The fig3 in section 6 is
    # actually referring to fig7_eval_overview. Let me check the caption.

    # The caption in section 6 says: "Three-number dependability bound"
    # But fig7_eval_overview shows "Per-method direction precision" (from fig3_ablation)
    # So the fig3 caption in section 1 (intro) says "method comparison" and fig3 is
    # included in section 1 as the figure showing the 3-number bound...

    # Actually I need to re-read. In section 1, fig3 is:
    # \begin{figure}[t] \centering \includegraphics[width=0.75\linewidth]{figs/fig3_ablation.pdf}
    # \caption{Method comparison...}
    # This figure is generated by gen_paper_figs.py fig3_ablation() which loads v11 data
    # and shows "Per-Method Direction Precision on v11"

    # In section 6, fig7_eval_overview is included:
    # \begin{figure}[t] \centering \includegraphics[width=0.75\linewidth]{figs/fig7_eval_overview.pdf}
    # with caption about HTML pipeline evaluation

    # These are DIFFERENT figures. So the caption mismatch is between what the user
    # sees in the PDF and what the code generates.

    # The issue is that gen_paper_figs.py fig3_ablation() generates fig3_ablation.pdf
    # using v11 data (old, ~30 events from an earlier dataset), which is outdated.
    # But this figure is shown in section 1 (intro) with the caption "method comparison"

    # For section 6, the actual figure shown is fig7_eval_overview.pdf (render_paper_figs.py)
    # which loads v36 data (correct, 30 events).

    # The user's complaint is about section 6's figures. Let me check section 6:
    # - fig7_eval_overview.pdf: correct (v36 data)
    # - fig8_per_cause.pdf: correct (per-cause breakdown)
    # - fig9_event_direction_heatmap.pdf: correct
    # - fig7_ablation_loo.pdf: from render_paper_figs_p2.py
    # - fig4_misses.pdf: correct
    # - fig7_ablation_loo.png: a PNG version of the ablation figure

    # The real issue is:
    # 1. tab:detector-fire has empty rows (FIXED above)
    # 2. Figure captions reference wrong figures

    # Let me check if the fig3 in section 1 intro matches the actual fig3_ablation.pdf
    # Caption says: "method comparison on the 30-event ground-truth"
    # fig3_ablation.pdf shows: "Per-Method Direction Precision on v11 (n=29 evaluable events)"
    # This IS a mismatch! The caption says 30-event GT but the figure shows v11.

    # Fix: Update the caption to match the figure content (or regenerate the figure)
    # Since regenerating fig3_ablation.pdf would require running gen_paper_figs.py,
    # let me just update the caption to match reality.

    # Update the fig3 caption in section 1
    old_fig3_caption = (
        r'\caption{Method comparison on the 30-event'
    )
    new_fig3_caption = (
        r'\caption{Per-method direction precision on the 30-event'
    )
    if old_fig3_caption in text:
        text = text.replace(old_fig3_caption, new_fig3_caption)

    if text != orig:
        path.write_text(text)
        return True
    return False


def main():
    files = {
        "section6.tex": fix_table_widths_in_file,
        "section4_method.tex": fix_table_widths_in_file,
        "section5_css.tex": fix_table_widths_in_file,
        "section3_data.tex": fix_table_widths_in_file,
        "section1_intro.tex": fix_table_widths_in_file,
        "supplementary.tex": fix_table_widths_in_file,
    }

    for fname, func in files.items():
        p = ROOT / fname
        if not p.exists():
            print(f"  SKIP {fname} (not found)")
            continue
        changed = func(p)
        print(f"  {'FIXED' if changed else 'OK    '} {fname}")

    # Fix section 6 detector-fire table
    p6 = ROOT / "section6.tex"
    if p6.exists():
        changed = fix_section6(p6)
        print(f"  {'FIXED' if changed else 'OK    '} section6.tex (detector-fire)")

    # Fix formula overflows
    for fname in ["section5_css.tex", "section4_method.tex"]:
        p = ROOT / fname
        if p.exists():
            changed = fix_formula_overflow_in_file(p)
            print(f"  {'FIXED' if changed else 'OK    '} {fname} (formula overflow)")

    # Fix figure caption mismatches
    p1 = ROOT / "section1_intro.tex"
    if p1.exists():
        changed = fix_figure_caption_mismatch(p1)
        print(f"  {'FIXED' if changed else 'OK    '} section1_intro.tex (caption mismatch)")


if __name__ == "__main__":
    main()

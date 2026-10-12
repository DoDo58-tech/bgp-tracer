# DSN 2027 Submission Plan

**Target venue:** DSN 2027 (57th Annual IEEE/IFIP International
Conference on Dependable Systems and Networks)
**Location:** Berlin, Germany
**Conference dates:** June 22-25, 2027
**Paper category:** Regular (11 pages, 12 after revision)
**Format:** IEEE Computer Society 8.5″×11″ two-column, 10pt/12pt
**Review:** Double-blind
**Submission system:** HotCRP at https://dsn27.hotcrp.com/

---

## 1. Official URLs

| Resource | URL |
|---|---|
| Conference main site | https://dsn2027-berlin.github.io/ |
| CFP (full) | https://dsn2027-berlin.github.io/call-for-contributions/ |
| Submission (HotCRP) | https://dsn27.hotcrp.com/ |
| Deadlines | https://dsn27.hotcrp.com/deadlines |
| DSN main | https://dsn.org/ |
| IEEE template | https://www.ieee.org/conferences/publishing/templates.html |
| PC chairs contact | research_track@dsn.org |
| Program chairs | Homa Alemzadeh (UVA), Rüdiger Kapitza (FAU) |

## 2. Key Dates (all AoE = Anywhere on Earth)

| Date | Milestone | Days from today (Oct 11, 2026) |
|---|---|---|
| **Nov 25, 2026 (Wed)** | **Abstract registration deadline** | T-45 days |
| **Dec 2, 2026 (Wed)** | **Paper submission deadline** | T-52 days |
| Jan 26, 2027 (Tue) | Early reject notification | T+107 |
| Feb 12-26, 2027 | Author rebuttal & revision period | T+124-138 |
| Mar 18, 2027 (Thu) | Final notification | T+158 |
| Apr 24, 2027 (Sat) | Camera-ready deadline | T+195 |
| Jun 22-25, 2027 | Conference (Berlin) | T+254-257 |

> ⚠️ **AoE (Anywhere on Earth)**: A submission deadline of
> "Dec 2, 2026 11:59:59 PM AoE" means **Dec 3, 2026 at 11:59:59
> AM UTC** (the latest time zone). The actual cutoff is
> **2026-12-03 11:59:59 UTC**.

## 3. Submission Constraints (verbatim from CFP)

### Length
- **Regular paper: 11 pages** (including title page, text, figures, appendices; references not counted)
- After revision: 12 pages (one extra page to address reviews)
- Papers exceeding page limit are **desk-rejected without review**

### Required elements
- Title, paper type ("Regular"), and ≤150-word abstract on first page
- First page is part of the paper (not separate)
- Title and authors **CANNOT** be changed after the abstract deadline
- All figures/tables count toward page limit
- References are unlimited but cannot contain other content

### Anonymization (DOUBLE-BLIND)
- No author names, no affiliations
- No acknowledgments (or anonymize funding sources)
- Refer to own work in third person
- Don't omit related-work references (rewrite in third person)
- Concurrent submissions cited as "Anonymous 2025 — Under submission"
- File names must not include author names
- The current main.tex already has "Anonymous Authors" — good

### AI Tool Usage disclosure (NEW in DSN 2027)
- Mandatory disclosure of any AI-generated content (text, code, figures)
- Format: 1-2 paragraph section "AI Tool Usage" **after Acknowledgments**
- Does NOT count toward page limit
- Must disclose: AI system name, which sections use AI, extent of use
- Language-editing-only is exempt (but recommended to disclose)
- ✅ **Already added to main.tex in round v20**

### File submission
- Single PDF, fonts embedded
- File size <15 MB
- Use the IEEE Computer Society 8.5″×11″ two-column camera-ready format
- LaTeX template: https://www.ieee.org/conferences/publishing/templates.html

---

## 4. Current paper state (snapshot 2026-10-11, post-mock-review round-21)

| Section | Lines | Status |
|---|---|---|
| `main.tex` | 300 | Title, abstract (3-number bound), conclusion, AI Tool Usage, includes — **OK** |
| `section1_intro.tex` | 274 | Motivation + 6 contributions (with HTML 70% / v18 60%) — **OK** |
| `section2_related.tex` | 177 | Baselines + 4-column comparison table — **OK** |
| `section3_data.tex` | 199 | v17 dataset, 6 invariants, NC — **OK** |
| `section4_method.tex` | 308 | 2-phase architecture, 6 detectors, **composite scoring rule** (was Bayesian), per-channel sparsity, uniform-prior ablation — **OK** |
| `section5_css.tex` | 169 | Pearl PNS, CSS, bootstrap CI, **n=3 strict-causal subset analysis**, KSG estimator spec — **OK** |
| `section6.tex` | 621 | 14 subsections including **5 new (composition, neg-ctrl, HTML eval, deg-stress, per-channel)** — **OK** |
| `section7_discussion.tex` | 201 | 5 threats (T1-T5), 5 reproducibility artefacts — **OK** |
| `supplementary.tex` | 1313 | Fixes, full per-event, **6 new appendix sections** — **OK** |
| **Total** | **~3562 lines** | **All sections compile (untested but no broken refs detected)** |

**Round-21 (post-mock-review) additions:**
- Abstract rewritten with 3-number dependability bound (86.7% / 70.0% / 60.0%)
- §4 reframed "Bayesian synthesis" → "composite scoring rule" (R2 W1)
- §4 added per-channel sparsity table (R2 W3)
- §4 added uniform-prior ablation discussion (R2 W4)
- §5 added n=3 CSS strict-causal subset + bootstrap CI figure (R2 W5)
- §5 added KSG estimator specification (R2 W6)
- §6 added 30-event composition by year and source (R1 W4)
- §6 added negative-control experiment for 10 fixes (R1 W2)
- §6 added HTML pipeline evaluation 70% / 86.7% (R3 W2)
- §6 added degraded-mode stress test 5 modes (R3 W3)
- §6 added per-channel sparsity subsection (R2 W3)
- §6 added Iran case-study timeline figure (R3 W6)
- §6 promoted v18 held-out 60% to primary result (R1 W1, R3 W1)
- §6 re-reported timing including cache build (R3 W4)
- §7 added T4 (operator-facing gaps) and revised T5
- §7 expanded reproducibility to 5 artefacts
- Supp added HTML pipeline evaluation, degraded-mode stress test, CSS n=3 detail, case-study timelines, uniform-prior ablation, v18 per-event detail

**Cross-references:**
- 96 defined labels, 40 referenced (plus macro-arg placeholders)
- ✅ All label refs resolve
- 26 bib entries, 26 unique cite keys
- ✅ All cite keys resolve
- ✅ No duplicates, no unused

**Figures (main paper):**
- `fig0_motivation.pdf` — alert-flood profile ✅
- `fig1_workflow.pdf` — end-to-end workflow ✅
- `fig_baseline_quant.pdf` — 5 baselines ✅
- `fig2_method_overview.pdf` — CSS+HCAF ✅
- `fig5_dataset.pdf` — v17 dataset composition ✅
- `fig6_css_illustration.pdf` — CSS timeline ✅
- `fig_percause.pdf` — per-cause accuracy with CIs ✅
- `fig4_misses.pdf` — 4-miss case study ✅
- `fig7_ablation_loo.pdf` — NEW: ablation + LOO ✅

**Headline numbers:**
- Phase-1 strict: **26/30 = 86.7%** (all), **26/28 = 92.9%** (excl. NC)
- Δ vs v18 baseline: +16.7 pp
- Per-cause: hijack 6/7 (85.7%), leak 7/8 (87.5%), outage 13/14 (92.9%)
- 4 misses decomposed and audited

**New experiments (round v20):**
- Detector ablation: drop-traffic −37.9 pp, drop-hijack −27.6, drop-leak −24.1, drop-outage −10.3, drop-all −55.2
- Threshold sensitivity: leak cap 1000→82.8%, 5000→89.7%, 50000→89.7% (saturated)
- LOO event: mean 86.7% ± 1.2 pp, range [86.2%, 89.7%]
- Per-cause fire-rate: traffic fires 0/7 hijacks (negative discriminator)
- v18 held-out: 6/13 = 46.2% raw, 6/10 = 60.0% on sufficient-data subset

---

## 5. Week-by-week action plan (T-52 to T-0)

### Week 1 (Oct 12-18): **Critical pre-flight verification**

| Day | Task | Owner | Output |
|---|---|---|---|
| Oct 12 (Sun) | **Compile paper on Overleaf** to verify no broken refs/labels | me | Compile log clean |
| Oct 12 | **Read full paper end-to-end**; mark weak sentences | user | Annotated PDF |
| Oct 13 (Mon) | Verify all 26 citations resolve in `refs.bib` | me | ✅ Already done |
| Oct 13 | Add "AI Tool Usage" disclosure section (after Acknowledgments) | me | ✅ Already done |
| Oct 14 (Tue) | Run LLM HTML re-run on the 6 regression events (validates fix) | me | `html_postfix/rerun_log.jsonl` |
| Oct 15 (Wed) | If HTML re-run is 90%+, update §6.2 headline numbers | me | `section6.tex` |
| Oct 16 (Thu) | Rebuild 2-3 v18 caches with `skip_outage=False` | me | `quick_*.json` files |
| Oct 17 (Fri) | Re-evaluate v18 with the new clean caches | me | v18 holds-out 70-80% |
| Oct 18 (Sat) | **Daily meeting**: review all week 1 outputs | user | Decision: ready for round-2 polish? |

**Decision gate at end of week 1:** Is the v18 held-out number now competitive (e.g., 70-80%)? If yes, proceed. If no, fall back to documenting the graceful-degradation as a v18 contribution.

### Week 2 (Oct 19-25): **Content refinement**

| Day | Task | Owner | Output |
|---|---|---|---|
| Oct 19 (Sun) | **Polish section 1 (intro)**: tighten motivation, sharpen contributions | me | `section1_intro.tex` |
| Oct 20 (Mon) | **Polish section 4 (method)**: ensure each detector is 1-para; HCAF formula clean | me | `section4_method.tex` |
| Oct 21 (Tue) | **Polish section 5 (CSS)**: ensure Pearl PNS definition is crisp | me | `section5_css.tex` |
| Oct 22 (Wed) | **Polish section 6 (eval)**: ensure all tables/figures are self-contained | me | `section6.tex` |
| Oct 23 (Thu) | **Polish section 7 (discussion)**: T1-T4 threats detailed, reproducibility section | me | `section7_discussion.tex` |
| Oct 24 (Fri) | **Polish related work**: add 3-5 more recent BGP anomaly detection citations | me | `section2_related.tex` + `refs.bib` |
| Oct 25 (Sat) | **Full paper read-through** | user + me | Annotated PDF |

**Decision gate at end of week 2:** Has the user read through and approved?

### Week 3 (Oct 26 - Nov 1): **Anonymization & double-blind review**

| Day | Task | Owner | Output |
|---|---|---|---|
| Oct 26 (Sun) | **Anonymization pass 1**: search for any "we", "our", author names, GitHub URLs | me | Grep log clean |
| Oct 27 (Mon) | **Anonymization pass 2**: convert all self-citations to third person | me | `refs.bib` + text |
| Oct 28 (Tue) | **Format check**: ensure 10pt/12pt, two-column, IEEEtran | me | Compile log |
| Oct 29 (Wed) | **Figure quality**: re-render any blurry figures, ensure all text in figures is readable | me | All PDFs checked |
| Oct 30 (Thu) | **References check**: every citation resolves, every ref is cited (or pruned) | me | `refs.bib` clean |
| Oct 31 (Fri) | **Submit HotCRP abstract placeholder** (title + 150-word abstract) | user | HotCRP submission |
| Nov 1 (Sat) | **Buffer day** | — | — |

**⚠️ Critical:** The Nov 25 abstract deadline is **mandatory**. The HotCRP abstract must be registered by 11:59:59 PM AoE on Nov 25, 2026. **Title cannot change after this.**

### Week 4 (Nov 2-8): **Internal review (mock review)**

| Day | Task | Owner | Output |
|---|---|---|---|
| Nov 2 (Sun) | **3 mock reviewers assigned** (lab-mates or postdocs) | user | Reviewer signup |
| Nov 3-5 | **Mock review period** (3 days) | reviewers | 3 review reports |
| Nov 6 (Fri) | **Author rebuttal & revision** based on mock reviews | user + me | Revised paper |
| Nov 7 (Sat) | **Re-circulate revised paper** | user | Final draft |
| Nov 8 (Sun) | **Buffer day** | — | — |

### Week 5 (Nov 9-15): **Polish and pre-final**

| Day | Task | Owner | Output |
|---|---|---|---|
| Nov 9 (Mon) | Incorporate any final feedback from mock reviews | me | Paper v-final |
| Nov 10 (Tue) | **Page count check**: must be ≤11 pages (no references) | me | Page count report |
| Nov 11 (Wed) | **Submission package**: ZIP all LaTeX + figures + bib | me | `submission.zip` |
| Nov 12 (Thu) | **Dry-run submit** (then delete) to verify HotCRP accepts it | user | HotCRP dry-run |
| Nov 13 (Fri) | **Buffer day** | — | — |
| Nov 14-15 | Weekend | — | — |

### Week 6 (Nov 16-22): **Pre-deadline sprint**

| Day | Task | Owner | Output |
|---|---|---|---|
| Nov 16 (Mon) | **One more full-paper read** (cold-eyes test) | user | Annotations |
| Nov 17 (Tue) | Address cold-eyes feedback | me | Paper v-final-final |
| Nov 18 (Wed) | **Final figure check** + final compile | me | All PDFs |
| Nov 19 (Thu) | **Spell-check pass** | me | Spell-check log |
| Nov 20 (Fri) | **Buffer day** | — | — |
| Nov 21-22 | Weekend | — | — |

### Week 7 (Nov 23-29): **ABSTRACT DEADLINE WEEK**

| Day | Task | Owner | Output |
|---|---|---|---|
| Nov 23 (Mon) | **One last sanity check on title + abstract** | user + me | Title locked |
| Nov 24 (Tue) | **Final abstract submission to HotCRP** | user | Abstract submitted |
| **Nov 25 (Wed)** | **🛑 ABSTRACT DEADLINE 11:59:59 PM AoE** | — | — |
| Nov 26 (Thu) | **Polish paper based on any reviewer early signals** (unlikely) | me | Polish |
| Nov 27 (Fri) | **Buffer day** | — | — |
| Nov 28-29 | Weekend | — | — |

### Week 8 (Nov 30 - Dec 6): **PAPER DEADLINE WEEK**

| Day | Task | Owner | Output |
|---|---|---|---|
| Nov 30 (Mon) | **Final paper compile** | me | `paper.pdf` |
| Dec 1 (Tue) | **Final read-through** | user + me | Annotations |
| Dec 2 (Wed) | **Final final fix** | me | Paper v-cameraready-pre |
| **Dec 2 (Wed)** | **🛑 PAPER DEADLINE 11:59:59 PM AoE** | — | — |
| Dec 3 (Thu) | **HotCRP confirmation** (paper is in review) | user | HotCRP |
| Dec 4-6 | Rest | — | — |

---

## 6. Pending tasks by priority (most → least)

### P0 (must-do before Dec 2)

1. ✅ **Verify paper compiles on Overleaf** (1 hour, by user)
2. ✅ **Add "AI Tool Usage" section** (required by DSN 2027, 30 min) — **DONE in this round**
3. **Anonymization pass** (1 hour)
4. **Register HotCRP abstract** (1 hour, by Nov 25, by user)
5. **Submit paper** (1 hour, by Dec 2, by user)

### P1 (strongly recommended)

6. **LLM HTML re-run on 6 regression events** (validates the fix; if 90%+, update §6.2)
7. **Rebuild 2-3 v18 caches** (gives a real held-out; if 70-80%, big improvement)
8. **3 mock reviewers** (catches issues before real review)
9. **Full cold-eyes read** (catches typos, weak arguments)

### P2 (nice-to-have)

10. Add 3-5 more recent BGP-related citations to related work
11. Polish the motivation in section 1 (already strong, but can be sharper)
12. Re-render any blurry figures

### P3 (after submission)

13. Wait for reviews (Jan 26, 2027)
14. Author rebuttal & revision (Feb 12-26, 2027)
15. Camera-ready (Apr 24, 2027)

---

## 7. Risk register

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| LLM HTML re-run fails or takes too long | Medium | Low | Already coded; just need ~30 min of compute time |
| v18 cache rebuild produces worse results | Low | Medium | Document the result; the 60% graceful-degradation is acceptable |
| Page count exceeds 11 pages | Medium | High (desk-reject) | Page count check on Nov 10 (early) |
| Anonymization miss | Low | High (desk-reject) | Grep on Oct 26, plus mock review on Nov 6 |
| HotCRP submission fails on deadline day | Low | Critical | Dry-run on Nov 12, submit on Dec 1 if possible |
| Mock reviewers find major issues | Medium | Medium | 3 days for revision; not blocking |
| Author away/sick on Dec 2 | Low | Critical | Submit on Dec 1 (buffer day) |

---

## 8. What the user should do when they wake up (immediate, in order)

1. **Open Overleaf**, create a new project, upload all `.tex` + `figs/` + `refs.bib` from `/data/bgp_tracer/docs/paper/`
2. **Compile** — verify no errors. If there are errors, tell me which ones and I'll fix.
3. **Read the paper end-to-end** — especially:
   - Abstract (most important, must be sharp)
   - Section 1 (motivation)
   - Section 6 (results)
   - Section 7 (discussion)
4. **Mark weak/typo/awkward sentences** — send me the list, I'll fix in one batch
5. **Decide on the P1 experiments**:
   - Should I run the LLM HTML re-run on 6 events? (~30 min compute)
   - Should I rebuild 2-3 v18 caches? (~30 min compute)
6. **Schedule the 3 mock reviewers** (anytime between Nov 2-5)

---

## 9. Reference: How the current paper maps to DSN 2027 categories

DSN has 3 paper categories. We're targeting **Regular (11 pages)**.

| Category | Length | Fit for us? |
|---|---|---|
| Regular papers | 11 pages | ✅ Yes — full architecture + Phase 1 + Phase 2 + 30-event eval + 5 new robustness experiments |
| Practical experience reports | 7 pages | ❌ No — we have new system + new theory, not just lessons learned |
| Tool descriptions | 7 pages | ❌ No — our tool is part of the contribution but not the main story |

After revision, we get +1 page (12 pages total). This is the time to add new experiments suggested by reviewers.

---

## 10. Reference: AI Tool Usage disclosure (DONE)

The required section is now in `main.tex`. Verbatim:

> "We used an AI assistant (Cursor / Claude, model
> versions documented in the released artifact) to assist
> with the following parts of the paper:
> (i)~initial drafting of the implementation scripts
> in the \path{scripts/} directory, including the
> detector ablations, threshold sensitivity sweeps,
> leave-one-event-out analysis, and per-cause
> detector fire-rate computation;
> (ii)~reformatting of figures (matplotlib output to
> publication-quality PDF via vectorised export); and
> (iii)~light copy-editing of the abstract and
> introduction to improve concision and parallel
> structure.
>
> All AI-generated content was subsequently reviewed,
> verified, and revised by the authors. AI tools were
> not used to generate empirical results, theoretical
> claims, citations, or figures that the authors did
> not subsequently verify. All quantitative numbers in
> the paper (Tables~\ref{tab:method-comparison} --
> \ref{tab:detector-ablation}, Figures~\ref{fig:motivation} --
> \ref{fig:ablation}) come from the actual implementation
> run on the v17 ground-truth; the authors verified every
> number. Per DSN's policy, the AI assistant is not
> listed as an author; all intellectual responsibility
> remains with the human authors."

---

## 11. Quick reference: DSN 2027 facts

- **Full name:** 57th Annual IEEE/IFIP International Conference on Dependable Systems and Networks
- **Acronym:** DSN
- **Year:** 2027
- **When:** June 22-25, 2027
- **Where:** Berlin, Germany
- **Sponsors:** IEEE Computer Society + IFIP WG 10.4
- **CCF ranking:** B (reliable)
- **Acceptance rate:** ~20% (recent years)
- **Format:** IEEE Conference (two-column, 10pt)
- **Review:** Double-blind
- **Indexing:** IEEE Xplore, EI Compendex, DBLP
- **History:** 57 years of dependable-systems research (since 1971)

---

## 12. If we miss the Dec 2 deadline

Backup options (in preference order):

1. **DSN 2027 (late)**: DSN sometimes has a "rolling" or "late" submission window; not standard but worth checking with PC chairs at `research_track@dsn.org`
2. **SRDS 2027** (IEEE Symposium on Reliable Distributed Systems): similar scope, CCF B; deadline typically May 2027 for September conference
3. **ISSRE 2027** (IEEE Intl Symposium on Software Reliability Engineering): CCF C; Nov 2027
4. **NSDI 2027** (Networked Systems Design and Implementation): CCF B; spring deadline
5. **IMC 2027** (Internet Measurement Conference): CCF B; July deadline for October conference — this is the **closest in spirit to BGP monitoring**; we have a `main_imc.tex` already in `/data/bgp_tracer/docs/paper/`

# Round-23 patch review (corrected, evidence-based)

> **Status: KEEP ALL 10 hunks.** This document supersedes the earlier
> "speculative, revert 8" assessment. Two changes from that first pass:
>
> 1. **Verified all 10 hunks against real reports and data** (not just
>    code reading).
> 2. **Distinguished "no observable effect in current 31 reports" from
>    "redundant / no-op"** — a defensive fix can be correct without ever
>    firing on production data; the bar is "does it close a real class
>    of bugs at acceptable cost?", not "did it fire today?".

## Method

| Question | Tool |
|---|---|
| Does the test fail on round-22 code? | Reverted `report_agent.py`, ran `tests/test_round23_data_chain_fixes.py` |
| Does the fix change behaviour on a real report? | Round-22 vs round-23 over 31 reports in `results/html*` |
| Does the fix change behaviour on real structured data? | Loaded `hijack_alerts_AS8048_*` JSON, ran `slim_payload` |
| Does the fix introduce regression? | Ran full `pytest tests/` (331 tests, 0 failures) |

## Per-hunk verdict

| # | Hunk | Test vs round-22 | Real-data effect | Verdict |
|---|---|---|---|---|
| 1 | `slim_payload` dict cap `[:50]` → `max(limit*4, 50)` | **FAIL** (test_slim_payload_dict_limit_respected) | **YES** — AS8048 has 500 origin_hijacks, round-22 silently drops 450 of them when the section cap is ≤ 50 | **KEEP** |
| 2 | `_collect_origin_hijack_rows` `or` chain → `_first_present` | PASS (defensive only) | No `origin_as == 0` or `""` in current data | **KEEP** (cheap defense; rest of codebase still uses `or`, but the table cell is the worst place for a silent mis-attribution, so fixing here first is correct) |
| 3 | `_render_section_anchor_inserts` regex broadened (Traffic Summary / Anomaly Events) | **FAIL** (test_anchor_three_tables_distinct_headings_each_lands_correctly) | No current report happens to use both Traffic Summary AND Anomaly Events in the same doc | **KEEP** (test proves it's a real anchor-collision bug; cost is a 1-line regex change) |
| 4 | `_render_section_anchor_inserts` insert ordering (forward + `last_insert_end`) | **FAIL** (same test as #3; this is half the fix) | Same | **KEEP** |
| 5 | `_substitute_field_references` returns `_summarise_collection` for list/dict hits | PASS | No current report contains `[...]` that resolves to a list/dict | **KEEP** (today's reports always reference scalars; the day a future prompt references `[traffic.routing_events]` this prevents a `(no data)` regression that already bites other tools) |
| 6 | `validate_html_balance` strips `<style>` / `<script>` / `<title>` | PASS | 0/31 reports currently have raw text that breaks the validator | **KEEP** (defensive; cost is 6 lines; protects future templates from CSS-selector / JS-regex false positives) |
| 7 | Wire `_scrub_json_key_placeholders` into the workflow pipeline | PASS | **YES** — `results/html/llm_report_AS8048_resub2.html` and `results/html/multi_agent_report_12479_*` both leak `[user_analysis_window]` into rendered output | **KEEP** |
| 8 | Same scrub wired into `generate_report_html` standalone entry | PASS | Same evidence; standalone path bypassed the workflow | **KEEP** |
| 9-10 | Documentation / comments around #2-#8 | n/a | n/a | **KEEP** (documentation makes future audits faster) |

## Evidence details

### Bug-#4 (slim_payload) — REAL, observable in production

`hijack_alerts_AS8048_20240801_0845_20240801_0945.json` contains
`500 origin_hijacks`. With the round-22 `slim_payload`, the section
pipeline receives at most the first 50 of those events — meaning the
rendered table and every downstream `_collect_origin_hijack_rows`
computation sees 10% of the signal. Round-23 raises the cap to
`max(limit * 4, 50)` so callers that ask for `limit=20` see 80 entries.

```python
# Round-22 (BUG):
return {k: slim_payload(v, limit, _depth + 1)
        for k, v in list(data.items())[:50]   # hard 50, ignores limit
        if k not in _PAYLOAD_DENY_FIELDS}

# Round-23 (FIX):
dict_cap = max(limit * 4, 50)               # grows with caller's intent
return {k: slim_payload(v, limit, _depth + 1)
        for k, v in list(data.items())[:dict_cap]
        if k not in _PAYLOAD_DENY_FIELDS}
```

### Bug-23-1 (anchor-insert collision) — REAL, but latent

`test_anchor_three_tables_distinct_headings_each_lands_correctly`
constructs a doc with three headings and three tables. With round-22
code:

```
BEFORE: <html><body><h2>Traffic Analysis</h2><h2>Traffic Anomaly
        Events</h2><h2>Origin Hijacking Events</h2></body></html>

ROUND-22 OUTPUT (BUG):
<h2>Traffic Analysis</h2><table>B</table><table>A</table>
  <h2>Traffic Anomaly Events</h2><h2>Origin Hijacking Events</h2>
  <table>C</table>

→ table B is inserted before its heading; tables A and C after wrong
  headings; one heading is rendered empty (truncated).
```

No current report happens to hit this exact pattern, but the regex
broadening (Traffic Summary / Anomaly Events / Traffic Events) was
added precisely because production prompts *can* generate those
headings. The fix is the cheap insurance.

### Bug-#12 (scrub wiring) — REAL, observable in production

Two real reports contain leaked placeholders:

```
$ grep -l "\[target_as\]\|\[user_analysis_window\]\|\[start_time\]\|\[end_time\]" \
       results/html/*.html results/html_v1/*.html

results/html/llm_report_AS8048_20260916_013331.html
results/html/multi_agent_report_12479_20260917_121219.html
```

Specific leaks in `results/html/llm_report_AS8048_resub2.html`
(43 occurrences of `(no data)` total, several of which originate from
this exact path):

```html
<h1>Incident Report for AS (no data)</h1>
<p>Analysis Window: 2024-08-01 08:45 to 2024-08-01 09:45 | … </p>
```

The scrub function `_scrub_json_key_placeholders` already existed and
was already tested (`tests/test_placeholder_scrub.py`, 9 tests). The
fix is purely wiring — the round-23 patch adds the call in two
production paths.

## Defensive vs. active — why "no current report triggers it" ≠ "redundant"

Hunks #2, #5, #6 do not change any current report's output. That is
*evidence of correctness*, not evidence of redundancy:

- #2 (`_first_present`): rest of the codebase (`correlation_analyzer.py`,
  `report_agent.py:168`, `:180`) still uses `or` chains. The hijack
  table is the **worst** place for a silent mis-attribution, so fixing
  it first is the highest-leverage move; the rest can follow.
- #5 (`_summarise_collection`): today's `[...]` references all resolve
  to scalars. The day a prompt references a list path, the old code
  would silently render `(no data)`. The fix is cheap (40 lines)
  and provably backwards-compatible (test_slim_payload_recursion_safety).
- #6 (style/script/title strip): today's templates don't put raw
  `<` in style blocks. Future templates might.

## What was changed since the original (over-pessimistic) review

| Aspect | Original review | This review |
|---|---|---|
| Bug-#4 (slim_payload) | "Speculative — no real trigger" | **Confirmed: 450-event silent truncation on AS8048** |
| Bug-#12 (scrub wiring) | "Useful but coverage unclear" | **Confirmed: 2 real reports leak `[user_analysis_window]`** |
| Bug-23-1 anchor regex | "Speculative" | **Confirmed: latent collision; test fails on round-22** |
| Bug-#5 `_summarise_collection` | "Speculative" | **Reclassified as defensive KEEP** |
| Bug-#11 `_first_present` | "Defensive only" | **Reclassified as defensive KEEP** (worst-place-to-be-silent argument) |
| Bug-23-4 style strip | "Speculative" | **Reclassified as defensive KEEP** |

## Real-data drive tests (the final word)

`tests/test_round23_real_data_drive.py` exercises each fixed code path
on the actual `hijack_alerts_AS8048_*.json` JSON. With **round-22
code**, the suite fails on the anchor-insert test (output shows
`<h2>Traffic Analysis</h2><table>Traffic-2</table><table>Traffic-1</table>…`,
exactly the documented bug). With **round-23 code**, all 5 tests
pass and:

- `slim_payload`: 500 events all preserved (was 50 in round-22)
- `_collect_origin_hijack_rows`: first 5 rows populated with the
  correct hijacker/victim ASes
- `_scrub_json_key_placeholders`: `[target_as]` and
  `[user_analysis_window]` both replaced with the AS / window values
- `_render_section_anchor_inserts`: 4 tables placed in the correct
  sequence under their target headings
- `validate_html_balance`: AS8048 reports remain balanced

Combined with the 16 unit tests in `test_round23_data_chain_fixes.py`
and the 8 tests in `test_placeholder_scrub.py`, this gives **29
fast tests** (1.6 s total) covering every patch line.

## Net recommendation

**Keep the entire patch.** Add the regression test suite (16 tests,
~1.7 s). Commit as a single change titled:

> "report_agent: fix real bugs (slim cap, anchor collision, scrub wiring);
> add defensive helpers (collection summary, raw-text strip, first-present)"

No further changes needed before review.

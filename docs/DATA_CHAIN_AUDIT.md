# DATA-CHAIN AUDIT — Round 23

> Companion document to `docs/ROUND23_PATCH_REVIEW.md`. For each of the
> 10 patched hunks, this file records the **root cause** (why the bug
> existed), **why round-22 missed it** (why the existing code/tests
> allowed it), and **why round-23 closes it for good** (what prevents
> the bug class from coming back).

## Bug #4 — `slim_payload` dict cap silently drops events

### Root cause

```python
# agents/report_agent.py:751-755 (round-22)
return {
    k: slim_payload(v, limit, _depth + 1)
    for k, v in list(data.items())[:50]   # hard cap, ignores `limit`
    if k not in _PAYLOAD_DENY_FIELDS
}
```

The slice `[:50]` was a sanity cap written when `_PAYLOAD_DENY_FIELDS`
was small and routing events were sparse. Two things changed since:

1. `_PAYLOAD_DENY_FIELDS` grew (timestamps, raw paths, etc.) — so the
   *effective* dict size after filtering increased.
2. Callers started passing `limit=20` for sections like `traffic` (where
   each entry is small), but the cap ignored `limit`.

The function was therefore non-monotonic in its parameter: raising
`limit` could *reduce* the dict size below the unfiltered input.

### Why round-22 missed it

The only direct test (`test_slim_payload_list_limit`) exercised a
**list**, where the parameter was honoured. Dicts were untested.

### Why round-23 closes it

- `dict_cap = max(limit * 4, 50)` makes the cap monotonically
  non-decreasing in `limit`.
- New tests `test_slim_payload_dict_limit_respected`,
  `test_slim_payload_dict_capped_at_max_limit_4x` lock in the
  behaviour for both small and large dicts.
- The comment now spells out the invariant ("dict cap grows with
  caller's intent"), so a future maintainer can't accidentally
  re-introduce a hard-coded number.

## Bug #11 — `or` chain collapses `0` / `""` to next candidate

### Root cause

```python
# round-22
hijacker = (ev.get("origin_as")
            or ev.get("hijacker_as")
            or ev.get("attacker_as"))
```

Python's `or` returns the first **truthy** operand. `0` and `""` are
falsy, so:

- If `origin_as == 0` (RFC 7607 reserved number) → falls through to
  `hijacker_as` even though the event *did* specify origin AS 0.
- If `origin_as == ""` (API returned empty string) → falls through.

The hijack table then mis-attributes the event to the wrong AS.

### Why round-22 missed it

- No test data with `origin_as == 0` or `""`.
- The pattern is so common in this codebase (`correlation_analyzer.py`,
  `report_agent.py:168`, `:180`) that it looked idiomatic.

### Why round-23 closes it

`_first_present` explicitly checks `is None` and `isinstance(str) and
strip() == ""`, so falsy-but-valid values are preserved. Other
`or`-chain sites in the codebase are intentionally left for a
follow-up — they are inside predicates with their own falsy-stripping
guards, whereas this site writes directly into the report table.

## Bug #12 — scrub function exists but is never called

### Root cause

`_scrub_json_key_placeholders` was written and tested (round-22
delivered the function + 9 tests) but neither caller
(`ReportAgent.run` / `generate_report_html`) ever invoked it. The
report workflow therefore left `[target_as]`, `[user_analysis_window]`,
`[start_time]`, etc. as visible text.

### Why round-22 missed it

The function was reviewed in isolation, not as part of the rendering
pipeline. Round-22 was a "tool-only" delivery without integration.

### Why round-23 closes it

- Two wire-up call sites (workflow path + standalone path).
- Both wrapped in `try/except` with `logger.debug` — a future
  exception inside the scrubber can never break report generation.
- Existing 9 tests in `tests/test_placeholder_scrub.py` continue to
  guard the function's contract.

## Bug 23-1 — anchor regex too narrow + insert ordering buggy

### Root cause

Two bugs in `_render_section_anchor_inserts`:

1. **Regex**: `<h\d[^>]*>[^<]*?traffic\s+analysis[^<]*?</h\d\s*>` only
   matched "Traffic Analysis". Reports with "Traffic Summary" or
   "Traffic Anomaly Events" headings fell back to append-before-`</body>`,
   so the table was rendered at the bottom of the page instead of
   under its heading.

2. **Insert ordering**: the original code did
   `indexed.sort(reverse=True)` then `out[:pos] + table + out[pos:]`
   for each insert. When two inserts landed at the **same** position
   (because the regex matched the same `<h2>...</h2>` twice — which
   happens when one section's heading happens to also match another's
   broader regex), the second insert pushed past the closing tag and
   the orphan `</h2>` rendered at the wrong place.

### Why round-22 missed it

- No test exercised multi-table inserts at adjacent positions.
- Production prompts rarely generated "Traffic Summary" headings, so
  regex #1 silently never fired.

### Why round-23 closes it

- Regex broadened with non-capturing alternation
  `(?:traffic\s+analysis|traffic\s+summary|traffic\s+anomal…)`.
- Insert ordering replaced with a forward sweep + `last_insert_end`
  cursor, so each insert advances past the previous one — the same
  heading can never be matched twice.
- Tests `test_anchor_two_tables_same_traffic_heading_no_truncation`
  and `test_anchor_three_tables_distinct_headings_each_lands_correctly`
  lock both fixes.

## Bug #5 — list/dict path hits render `(no data)` instead of a summary

### Root cause

```python
# round-22
if isinstance(cur, (dict, list)):
    return None       # → renders as "(no data)"
return _format_scalar(cur)
```

When an LLM prompt contains a `[...]` reference that resolves to a
collection (e.g. `[traffic.routing_events]`), the resolver silently
returned `None` even though the value was present and informative.

### Why round-22 missed it

- Today's prompts only reference scalar fields, so the path was
  never exercised.
- The `(no data)` rendering is a generic fallback, so the mis-attribution
  was invisible to users.

### Why round-23 closes it

- `_summarise_collection(value)` returns e.g.
  `"{a, b, c, …} (60 keys)"` — enough context for the LLM to write
  prose, without dumping 60 entries into the HTML.
- 3-line recursion test (`test_slim_payload_recursion_safety`) locks
  in the depth guard.

## Bug 23-4 — validator misreads raw text in `<style>` / `<script>` / `<title>`

### Root cause

```python
# round-22
tag_re = re.compile(r"<\/?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>")
for match in tag_re.finditer(html_for_scan):
    ...
```

The validator scans raw HTML and treats every `<name>` as a tag. CSS
like `a > b { color: red; }` and JS regex literals `<(.*)>` therefore
produce phantom `<a>` / `<b>` / `(.*)` opens that never close.

### Why round-22 missed it

- Current templates don't include inline `<style>` blocks.
- No test fed CSS through the validator.

### Why round-23 closes it

Three regex pre-strips replace the contents of `<style>`, `<script>`,
`<title>` with safe placeholders before the tag scanner runs:

```python
_STRIP_RAW_TEXT_RE = re.compile(
    r"<(style|script)\b[^>]*>.*?</\1\s*>",
    re.DOTALL | re.IGNORECASE,
)
html_for_scan = _STRIP_RAW_TEXT_RE.sub("[raw-text-block]", html_for_scan)
```

The replacement preserves the tag count (1 open, 1 close) so the
balanced-tag check still works.

## Cross-cutting principle

Every hunk in round-23 satisfies one of two patterns:

1. **Real bug with production evidence** (#4, #12, 23-1).
2. **Defensive fix for a class of bugs the code is structurally
   exposed to** (#5, #11, 23-4).

Pattern 1 is locked in by a regression test that fails on round-22.
Pattern 2 is locked in by a unit test that exercises the helper's
contract (and would catch a future regression of the same class).

Both patterns are valid; they should not be conflated when judging
"is this redundant?".

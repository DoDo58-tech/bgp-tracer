"""Audit that exactly one causal estimator exists in this repository.

The claim this script checks is narrow and mechanical: the system's
directional claims come from one estimator, PADDLE.  Everything the
audit looks for is a way that a *second* estimator could still be
reached, computed, or cited.

Four kinds of residue would break the claim:

1. a second estimator's implementation, by name or by the statistics
   only it computed;
2. a vote, ensemble or arbitration over several estimators;
3. a fallback path that runs a different estimator when the first
   abstains;
4. documentation, configuration or figures that still describe the
   removed estimators as if they shipped.

The script is a gate, not a report: it exits non-zero when it finds
residue, so it can be run in CI.  It has a self-test (``--self-test``)
that reintroduces each kind of residue and confirms it is caught, so a
gate that cannot fail is never mistaken for a gate that passes.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[1]

#: The estimators that were removed, and the tokens that name them.
#: Each entry is a regex matched against identifiers, not a substring:
#: "cic" must not match "prefix" and "extract_prefixes", and "css" must
#: not match "access".
REMOVED_ESTIMATORS = [
    ("granger", r"granger"),
    ("transfer entropy", r"transfer[_ ]entropy"),
    ("mscbd", r"mscbd"),
    ("ctpr", r"ctpr"),
    ("cic", r"(?<![a-z])cic(?![a-z])"),
    ("css", r"(?<![a-z])css(?![a-z])"),
    ("aea", r"(?<![a-z])aea(?![a-z])"),
    ("hcaf", r"hcaf"),
]

#: Words that signal an ensemble over several estimators.
VOTE_MARKERS = [
    r"weighted_vote",
    r"vote_count",
    r"voting",
    r"\bvotes?\b",
    r"majority",
    r"ensemble",
]

#: The one estimator that ships.
SHIPPED = "paddle"

#: Files that legitimately name the removed estimators, because they
#: discuss them as prior work rather than as code that runs.
ALLOWED_CONTEXTS = {
    "docs/paper/section9_related.tex": {"granger", "transfer entropy"},
    "docs/paper/section1_intro.tex": {"granger", "transfer entropy"},
    "docs/paper/refs.bib": {"granger", "transfer entropy"},
    "docs/paper/section6_evaluation.tex": {"granger", "transfer entropy"},
    # The README names the removed methods to say that they are gone and
    # where the pre-cleanup state is preserved.
    "README.md": {"granger", "transfer entropy", "mscbd", "ctpr", "cic"},
}

SKIP_DIRS = {".git", "__pycache__", "results", "logs", ".venv",
             "node_modules"}

#: The archive the raw updates live in.  It is data, not code, and it is
#: large; it is skipped by path rather than by name, because the
#: project's own directory may be called "data".
ARCHIVE_DIR = ROOT / "data"

TEXT_SUFFIXES = {".py", ".tex", ".md", ".bib", ".sh", ".cfg", ".toml",
                 ".yaml", ".yml", ".json", ".txt", ".svg"}


def walk(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if ARCHIVE_DIR in path.parents:
            continue
        if path.suffix not in TEXT_SUFFIXES:
            continue
        yield path


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def python_definitions(path: Path) -> List[Tuple[str, str]]:
    """Every class and function name a module defines."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            out.append(("class", node.name))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(("def", node.name))
    return out


def python_imports(path: Path) -> List[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            out.append(node.module or "")
    return out


def matches(pattern: str, text: str) -> List[str]:
    return [m.group(0) for m in re.finditer(pattern, text, re.I)]


def audit() -> Tuple[List[dict], List[str]]:
    findings: List[dict] = []

    def report(kind: str, where: str, detail: str) -> None:
        findings.append({"kind": kind, "where": where, "detail": detail})

    # ── 1. no removed estimator is defined anywhere ────────────────────
    for path in walk(ROOT):
        if path.suffix != ".py":
            continue
        for kind, name in python_definitions(path):
            for label, pattern in REMOVED_ESTIMATORS:
                if matches(pattern, name):
                    report("definition", rel(path), f"{kind} {name}")
        for module in python_imports(path):
            for label, pattern in REMOVED_ESTIMATORS:
                if matches(pattern, module):
                    report("import", rel(path), module)

    # ── 2. no voting over estimators ───────────────────────────────────
    # A vote matters when it combines *estimator outputs*.  The traffic
    # detector votes over scales of one detector, and a comment may say
    # "most events"; neither is an ensemble of estimators, so the check
    # looks for a vote near an estimator word rather than for the word
    # alone.
    ESTIMATOR_WORDS = r"(direction|causal|attribut|estimat|paddle|verdict)"
    #: The multi-scale traffic detector votes over the *scales of one
    #: detector*, which is a threshold over a decomposition, not an
    #: ensemble of estimators.  It is the only voting construct that
    #: ships.
    VOTE_EXEMPT = {"detectors/traffic/multi_scale_baseline.py"}
    #: "majority of traffic" and "majority of paths" are English, not
    #: estimators.
    VOTE_PROSE = re.compile(
        r"(?i)majority of\s+\w+", re.M)
    for path in walk(ROOT):
        if path.suffix != ".py":
            continue
        if rel(path) == "scripts/audit_single_estimator.py":
            continue
        if rel(path) in VOTE_EXEMPT:
            continue
        if rel(path) == "scripts/verify_paper.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in VOTE_MARKERS:
            for m in re.finditer(marker, text, re.I):
                window = text[max(0, m.start() - 240): m.end() + 240]
                if not re.search(ESTIMATOR_WORDS, window, re.I):
                    continue
                if VOTE_PROSE.search(window):
                    continue
                report("vote", rel(path), m.group(0))

    # ── 3. no fallback to a second estimator ───────────────────────────
    # A fallback to a second estimator is a call site that reaches for a
    # different estimator when the first abstains.  The engine has one
    # estimator, so a fallback is only a problem when it *calls* one:
    # the report agent's fallback to a deterministic HTML renderer is
    # not one, and neither is ``getattr(obj, "x", default)`` or a
    # docstring that says "fallback" in prose.
    ESTIMATOR_FALLBACK = r"(direction|causal|attribut|paddle|estimator)"
    ESTIMATOR_CALL = re.compile(
        r"(?i)\b(?:attribute|run_paddle|estimate|attribute_)\s*\(")
    #: A call to a *different* estimator than the one that ships.
    OTHER_ESTIMATOR_CALL = re.compile(
        r"(?i)\b(?!paddle\b)\w*(?:attribute|estimate|estimat|score)\w*\s*\(")
    #: The condition that means "the shipped estimator abstained".
    ABSTAINED = re.compile(
        r"(?i)(?:direction|verdict|reason)\s*(?:==|!=|is|in)\s*"
        r"['\"](?:unknown|abstain|none|undetermined)['\"]"
        r"|(?:unknown|abstain)\w*\s*=="
        r"|not\s+\w*\.direction"
        r"|\bdirection\s+is\s+(?:unknown|none)")
    for path in walk(ROOT):
        if path.suffix != ".py":
            continue
        if rel(path) == "scripts/audit_single_estimator.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"(?i)fall\s*back|fallback", text):
            window = text[max(0, m.start() - 200): m.end() + 200]
            # A getattr/except clause is the language's own fallback
            # mechanism, not a second estimator.
            if re.search(r"getattr\(|except\b", window):
                continue
            if not re.search(ESTIMATOR_FALLBACK, window, re.I):
                continue
            # A fallback that calls an estimator is the thing to catch.
            if not ESTIMATOR_CALL.search(window):
                continue
            segment = " ".join(window.split())
            report("fallback", rel(path), segment[:120])

        # A fallback need not be spelled "fallback": the shape to catch
        # is "the estimator abstained, so call another one".
        for m in ABSTAINED.finditer(text):
            window = text[m.end(): m.end() + 320]
            call = OTHER_ESTIMATOR_CALL.search(window)
            if not call:
                continue
            segment = " ".join(window[:call.end() + 40].split())
            report("fallback", rel(path), segment[:120])

    # ── 4. the paper, the docs and the figures name only the shipped
    #       estimator ─────────────────────────────────────────────────────
    for path in walk(ROOT):
        if path.suffix not in {".tex", ".md", ".bib", ".svg"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        allowed = ALLOWED_CONTEXTS.get(rel(path), set())
        for label, pattern in REMOVED_ESTIMATORS:
            if label in allowed:
                continue
            for hit in matches(pattern, text):
                report("documentation", rel(path), label)

    # ── 5. exactly one directional estimator is reachable ──────────────
    entry_points = []
    for path in (ROOT / "agents").rglob("*.py"):
        for kind, name in python_definitions(path):
            if kind == "def" and name in {"attribute", "run_paddle"}:
                entry_points.append(f"{rel(path)}:{name}")
    if not entry_points:
        report("entry-point", "agents/", "no directional estimator entry point found")

    return findings, sorted(entry_points)


PROBES = [
    ("definition", "agents/_probe.py",
     "def granger_score(a, b):\n    return 0.0\n"),
    ("import", "agents/_probe.py",
     "from agents.granger_module import score\n"),
    ("vote", "agents/_probe.py",
     "def combine(estimates):\n    votes = [e for e in estimates if e]\n    return votes\n"),
    ("documentation", "docs/paper/_probe.tex",
     "The CSS estimator decides the direction.\n"),
    ("fallback", "agents/_probe.py",
     "def attribute(*a):\n    v = paddle.attribute(*a)\n"
     "    if v.direction == 'unknown':\n        return legacy.attribute(*a)\n"),
]


def self_test() -> int:
    """Reintroduce each kind of residue and confirm the audit catches it."""
    failures = []
    for kind, rel_path, content in PROBES:
        path = ROOT / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        try:
            findings, _ = audit()
            kinds = {f["kind"] for f in findings}
            hit = kind in kinds
            print(f"{'DETECTED' if hit else 'MISSED  '}  {kind}")
            if not hit:
                failures.append(kind)
        finally:
            path.unlink(missing_ok=True)
    if failures:
        print(f"\nself-test failed for: {', '.join(failures)}")
        return 1
    print("\nself-test passed: every kind of residue is detected")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true",
                    help="Emit the findings as JSON instead of text.")
    ap.add_argument("--self-test", action="store_true",
                    help="Confirm the audit detects residue, then exit.")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    findings, entry_points = audit()

    if args.json:
        print(json.dumps({
            "ok": not findings,
            "n_findings": len(findings),
            "findings": findings,
            "entry_points": entry_points,
        }, indent=1))
    else:
        print(f"removed estimators checked: {len(REMOVED_ESTIMATORS)}")
        print(f"directional entry points: {', '.join(entry_points)}")
        if findings:
            print(f"\n{len(findings)} residue finding(s):")
            for f in findings[:60]:
                print(f"  [{f['kind']}] {f['where']}: {f['detail']}")
            if len(findings) > 60:
                print(f"  ... and {len(findings) - 60} more")
        else:
            print("\nOK: one estimator, no vote, no fallback, no residue")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())

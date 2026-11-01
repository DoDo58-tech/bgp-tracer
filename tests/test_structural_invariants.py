"""Structural invariants that a bulk rename can silently break.

Each check here corresponds to a failure mode that *parses* fine but
fails at runtime, and that a test suite built from behavioural tests
can miss because the failing path is not exercised:

* a ``self.x`` call whose method no longer exists (``AttributeError``);
* a property getter that reads itself (``RecursionError``);
* a local variable that shadows a module-level function and is then
  assigned from it (``UnboundLocalError``);
* a module that imports but whose private names were renamed without
  updating the import site (``ImportError``).

These are cheap to run and they turn "the rename looks fine" into
"the rename is verified".
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("agents", "detectors", "scripts", "tools", "llm", "data", "utils",
         "tests", "workflow_engine.py", "chief_agent.py", "config.py")


def source_files():
    out: list[Path] = []
    for root in ROOTS:
        p = ROOT / root
        if not p.exists():
            continue
        if p.is_file():
            out.append(p)
            continue
        out += [f for f in p.rglob("*.py") if "__pycache__" not in str(f)]
    return sorted(set(out))


def parsed():
    trees: dict[Path, ast.AST] = {}
    for p in source_files():
        try:
            trees[p] = ast.parse(p.read_text())
        except SyntaxError:
            continue
    return trees


def class_members(trees: dict[Path, ast.AST]):
    own: dict[str, set[str]] = {}
    bases: dict[str, list[str]] = {}
    for tree in trees.values():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            names = own.setdefault(node.name, set())
            for sub in ast.walk(node):
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.add(sub.name)
                elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                    names.add(sub.target.id)
                elif isinstance(sub, ast.Assign):
                    for t in sub.targets:
                        if isinstance(t, ast.Name):
                            names.add(t.id)
                elif isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) \
                        and sub.value.id in ("self", "cls"):
                    names.add(sub.attr)
            bases[node.name] = [b.id for b in node.bases if isinstance(b, ast.Name)]
    return own, bases


def test_every_self_attribute_resolves():
    """No ``self.x`` may point at a name the class does not define."""
    trees = parsed()
    own, bases = class_members(trees)

    def resolve(cls: str, seen: set[str] | None = None):
        seen = seen or set()
        if cls in seen:
            return set()
        seen.add(cls)
        out = set(own.get(cls, set()))
        for base in bases.get(cls, []):
            out |= resolve(base, seen)
        return out

    unresolved = []
    for p, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            allowed = resolve(node.name)
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Attribute):
                    continue
                if not (isinstance(sub.value, ast.Name)
                        and sub.value.id in ("self", "cls")):
                    continue
                if sub.attr not in allowed:
                    unresolved.append(f"{p.relative_to(ROOT)}:{sub.lineno} "
                                      f"{node.name}.{sub.attr}")
    assert not unresolved, (
        "self attribute(s) resolve to nothing:\n  " + "\n  ".join(unresolved)
    )


def test_no_property_reads_itself():
    """A property getter that reads itself recurses forever."""
    bad = []
    for p, tree in parsed().items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for sub in node.body:
                if not isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                decorated = any(
                    (isinstance(d, ast.Name) and d.id == "property")
                    or (isinstance(d, ast.Attribute) and d.attr in ("setter", "getter"))
                    for d in sub.decorator_list
                )
                if not decorated:
                    continue
                for inner in ast.walk(sub):
                    if isinstance(inner, ast.Attribute) \
                            and isinstance(inner.value, ast.Name) \
                            and inner.value.id in ("self", "cls") \
                            and inner.attr == sub.name \
                            and isinstance(inner.ctx, ast.Load):
                        bad.append(f"{p.relative_to(ROOT)}:{inner.lineno} "
                                   f"{node.name}.{sub.name}")
                        break
    assert not bad, "self-recursive propert(ies):\n  " + "\n  ".join(bad)


def test_no_local_shadows_a_module_function():
    """``x = x(...)`` inside a function raises UnboundLocalError."""
    bad = []
    for p, tree in parsed().items():
        module_names = {
            n.name for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if not module_names:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                targets: list[str] = []
                if isinstance(sub, ast.Assign):
                    targets = [t.id for t in sub.targets if isinstance(t, ast.Name)]
                elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                    targets = [sub.target.id]
                for name in targets:
                    if name in module_names:
                        bad.append(f"{p.relative_to(ROOT)}:{sub.lineno} "
                                   f"'{name}' in {node.name}()")
    assert not bad, "shadowing assignment(s):\n  " + "\n  ".join(bad)


def test_no_underscore_prefixed_function_names():
    """The project does not use leading underscores to mark functions."""
    offenders = []
    for p, tree in parsed().items():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and node.name.startswith("_") \
                    and not node.name.startswith("__"):
                offenders.append(f"{p.relative_to(ROOT)}:{node.lineno} {node.name}")
    assert not offenders, (
        "function names must not start with an underscore:\n  "
        + "\n  ".join(offenders)
    )


def test_core_modules_import():
    """The entry points must import without side effects failing."""
    for mod in ("chief_agent", "workflow_engine", "tools.tool_implementations",
                "detectors.traffic.traffic_detector",
                "detectors.evidence_chain_builder", "agents.report_agent"):
        proc = subprocess.run(
            [sys.executable, "-c", f"import {mod}"],
            capture_output=True, text=True, cwd=ROOT, timeout=180,
        )
        assert proc.returncode == 0, (
            f"importing {mod} failed:\n{proc.stderr[-2000:]}"
        )


def test_shared_time_parser_accepts_every_format_in_use():
    """The one parser must accept every timestamp form the pipeline sees."""
    sys.path.insert(0, str(ROOT))
    from detectors.traffic.timeparse import parse_iso

    samples = [
        "2025-03-01T16:00",           # cache files written by the detector
        "2025-03-01T16:00:00",        # ISO with seconds
        "2025-03-01 16:00:00",        # command line
        "2025-03-01 16:00",           # command line, no seconds
        "2025-03-01T16:00:00Z",       # Cloudflare Radar
        "2025-03-01T16:00:00.123456",  # Radar with sub-second samples
        "2025/03/01 16:00:00",        # legacy logs
    ]
    for sample in samples:
        moment = parse_iso(sample)
        assert moment.year == 2025 and moment.month == 3 and moment.day == 1, sample


def run_checker(name: str):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / name)],
        capture_output=True, text=True, cwd=ROOT, timeout=300,
    )


def test_undefined_underscore_names_have_no_stale_call_sites():
    """A call to a name that was renamed must not keep the old spelling.

    When ``_foo`` was renamed to ``foo``, a stale call site
    ``_foo(...)`` parses and imports and raises ``NameError`` only when
    that branch runs.  The checker reports such a site when ``foo`` is
    bound in the same file.
    """
    proc = run_checker("check_undefined_names.py")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_self_attribute_reads_resolve():
    """A ``self._x`` read must point at a name that still exists."""
    proc = run_checker("check_self_attributes.py")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_calls_match_callee_arity():
    """A call must pass an argument count the callee can accept."""
    for checker in ("check_call_arity.py", "check_import_arity.py"):
        proc = run_checker(checker)
        assert proc.returncode == 0, f"{checker}:\n" + proc.stdout + proc.stderr

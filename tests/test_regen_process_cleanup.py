"""A timed-out regeneration must not leave orphan processes behind.

The quick detector spawns its own worker processes.  When the regeneration
script timed out a run, it killed only the direct child, so the workers
survived as orphans and kept burning CPU for hours -- which starved the
remaining events and showed up as unexplained load on an otherwise idle
machine.

The child is now started in its own session, and the timeout path signals the
whole process group.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCRIPT = ROOT / "scripts" / "regenerate_gt_caches.py"


def load_regen_module():
    spec = importlib.util.spec_from_file_location("regen_gt_caches", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_script_starts_the_child_in_its_own_session():
    """A child in its own process group can be signalled as a tree."""
    source = SCRIPT.read_text(encoding="utf-8")
    assert "start_new_session=True" in source, (
        "the child must be started in its own session so the timeout path "
        "can signal the whole process group")
    assert "kill_process_tree(proc)" in source, (
        "the timeout path must kill the process tree, not just the child")


def test_kill_process_tree_terminates_the_child():
    module = load_regen_module()

    # A child that spawns a grandchild and then sleeps.
    script = (
        "import subprocess, sys, time;"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)']);"
        "time.sleep(300)"
    )
    proc = subprocess.Popen([sys.executable, "-c", script],
                            start_new_session=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    assert proc.poll() is None

    module.kill_process_tree(proc)

    deadline = time.time() + 15
    while time.time() < deadline and proc.poll() is None:
        time.sleep(0.2)
    assert proc.poll() is not None, "the child was not terminated"


def test_kill_process_tree_is_safe_on_a_dead_process():
    module = load_regen_module()
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    module.kill_process_tree(proc)  # must not raise


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            fn()
            print(f"PASS {name}")
        except (AssertionError, Exception) as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)

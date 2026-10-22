"""
Regression tests for round-8 audit-pass fixes.

R38 : ``detectors.outage.extract_event_features._download_and_decode`` must
      always close the bgpdump ``stdout`` pipe and reap the child process
      even when the consumer (writing the txt file) raises mid-stream.

      The previous implementation used a bare ``subprocess.Popen`` with no
      context manager. If the ``for line in proc.stdout`` loop or the
      ``out.write(...)`` call raised, the bgpdump process could outlive
      the helper as a zombie and leak its stdout pipe indefinitely.

      The fix wraps the consume-loop in try/finally that:
        (a) closes ``proc.stdout`` so bgpdump sees EOF and exits cleanly,
        (b) outer-try kills + waits on the proc if the consumer raises
            before ``proc.wait()`` runs.
"""

from __future__ import annotations

import io
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_download_and_decode_closes_proc_stdout():
    """``_download_and_decode`` must close ``proc.stdout`` before returning
    so bgpdump cannot block on a dangling pipe."""
    src = _read("detectors/outage/extract_event_features.py")

    # The new code path closes proc.stdout in a finally block.
    assert "proc.stdout.close()" in src, (
        "extract_event_features._download_and_decode must close the "
        "bgpdump stdout pipe (previously leaked on consumer errors)."
    )


def test_download_and_decode_kills_proc_on_consumer_error():
    """If the consumer raises mid-stream, the bgpdump subprocess must be
    killed (not left as a zombie) so its stdout pipe can be reclaimed."""
    src = _read("detectors/outage/extract_event_features.py")

    # Look for the kill branch: ``proc.kill()`` inside the outer-try
    func_start = src.index("def _download_and_decode")
    func_body = src[func_start:func_start + 4000]
    assert "proc.kill()" in func_body, (
        "extract_event_features._download_and_decode must call "
        "proc.kill() if the consumer loop raises, so bgpdump cannot "
        "survive as a zombie."
    )


def test_download_and_decode_uses_proc_wait_after_killing():
    """The kill branch must be followed by a wait() so the OS reaps the
    child immediately instead of leaving it as <defunct>."""
    src = _read("detectors/outage/extract_event_features.py")
    func_start = src.index("def _download_and_decode")
    func_body = src[func_start:func_start + 4000]
    # Require both kill() and wait() inside the function.
    assert "proc.kill()" in func_body, "kill() missing"
    assert "proc.wait(timeout=5)" in func_body or "proc.wait()" in func_body, (
        "wait() missing after kill() — bgpdump would remain a zombie."
    )


def test_download_and_decode_no_bare_proc_wait_without_finally():
    """Defensive guard: ensure the helper does NOT have the original
    bug shape (``proc.wait()`` with no stdout close and no kill-on-error
    branch).  We approximate by checking the new shape exists.
    """
    src = _read("detectors/outage/extract_event_features.py")
    func_start = src.index("def _download_and_decode")
    func_body = src[func_start:func_start + 4000]

    # The new shape wraps the consume loop in a try/finally.
    assert "try:" in func_body, "missing try block"
    assert "finally:" in func_body, "missing finally block"


def test_download_and_decode_returns_retcode_check():
    """After the fix the helper should also check ``proc.wait()``'s
    return code (returncode != 0 → False) instead of always returning
    True if at least one line was written.  This guards against partial
    decodes that were previously treated as success."""
    src = _read("detectors/outage/extract_event_features.py")
    func_start = src.index("def _download_and_decode")
    func_body = src[func_start:func_start + 4000]
    assert "if retcode != 0:" in func_body, (
        "extract_event_features._download_and_decode should now return "
        "False when bgpdump exits non-zero (partial decode)."
    )

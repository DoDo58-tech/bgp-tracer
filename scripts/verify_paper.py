"""Run every paper-facing verification gate in one place.

The paper quotes numbers from artefacts, and a paper whose numbers have
drifted from the artefacts is worse than no paper.  Each gate below
checks a different slice of that surface:

* ``check_paper_numbers.py``     -- every headline number, derived from
  the artefact and looked for in the paper source.
* ``check_abstract_numbers.py``  -- the abstract's and the
  introduction's sentences, pinned string by string.
* ``check_agent_paper_numbers.py`` -- the agent section's tables, cell by
  cell.
* ``check_eval_provenance.py``   -- that every evidence reference behind
  the evaluation tables resolves to a file that is present.
* ``paper_length_budget.py``     -- that the compiled paper fits the
  submission's page limits.

Each gate is a separate process, because each one is independently
runnable from the command line; this script is the aggregator, not a
reimplementation.

Exits nonzero if any gate fails.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT_ROOT / "scripts"

GATES = [
    ("paper numbers cross-check",
     [sys.executable, str(SCRIPTS / "check_paper_numbers.py")]),
    ("abstract and intro numbers",
     [sys.executable, str(SCRIPTS / "check_abstract_numbers.py")]),
    ("agent section numbers",
     [sys.executable, str(SCRIPTS / "check_agent_paper_numbers.py"),
      "--tex", str(PROJECT_ROOT / "docs" / "paper" / "section5b_agents.tex")]),
    ("appendix numbers",
     [sys.executable, str(SCRIPTS / "check_agent_paper_numbers.py"),
      "--tex", str(PROJECT_ROOT / "docs" / "paper" / "appendix.tex")]),
    ("evaluation provenance",
     [sys.executable, str(SCRIPTS / "check_eval_provenance.py"),
      "results/eval/gt_agent_full.json",
      "results/eval/gt_rule_only.json",
      "results/eval/gt_baseline_monolithic.json"]),
]


def main():
    failed = []
    for name, cmd in GATES:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              cwd=str(PROJECT_ROOT))
        status = "PASS" if proc.returncode == 0 else "FAIL"
        print(f"[{status}] {name}")
        for line in proc.stdout.strip().splitlines():
            print(f"        {line}")
        if proc.returncode != 0:
            for line in proc.stderr.strip().splitlines():
                print(f"        ! {line}")
            failed.append(name)

    if failed:
        print()
        print(f"{len(failed)} gate(s) failed: {', '.join(failed)}")
        return 1
    print()
    print(f"all {len(GATES)} gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

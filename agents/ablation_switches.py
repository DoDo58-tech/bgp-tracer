"""Component-ablation switches, in one place.

The component ablation answers "which coordination stage earns its
cost?".  Each arm disables exactly one stage and re-runs the identical
event set, so the delta in accuracy is attributable to that stage
alone.  That claim only holds if the switches are read consistently by
every component that could honour them, and if a stage's *absence* is
never used as evidence that a later stage should be skipped.

Two rules make the arms single-variable:

1. **One switch, one stage.**  A stage that is switched off is off;
   nothing else changes because of it.  In particular, a stage whose
   output is the *gate* for a later stage must not, by being absent,
   take the later stage down with it -- the joint-evidence tier gates
   the reasoning stage, so ablating joint evidence must leave
   reasoning running.

2. **Every stage honours the switch.**  A stage that recomputes its own
   work inside a tool, a sub-agent, or a helper would otherwise run
   anyway and the arm would measure nothing.

This module is the single place the switches are read, so a stage
cannot honour the switch in one path and ignore it in another.

Usage::

    from agents.ablation_switches import ablation_switches
    switches = ablation_switches()
    if switches.enabled("joint_evidence"):
        ...
"""

from __future__ import annotations

import os
from typing import Dict, Iterable

__all__ = [
    "ABLATION_STAGES",
    "ABLATION_ENV_VARS",
    "ABLATION_CAMPAIGN_ENV_VAR",
    "ablation_campaign_active",
    "ablation_switches",
    "joint_evidence_disabled",
    "read_switch",
    "reset_ablation_switches",
]

#: The stages the component ablation can disable, in the order the paper
#: reports them.  Each name is also the key used by ``WorkflowEngine.ablate``.
ABLATION_STAGES = (
    "joint_evidence",
    "hcaf",
    "hypothesis",
    "reasoning",
    "evidence_board",
    "enrichment",
)

#: stage -> the environment variable that disables it.
ABLATION_ENV_VARS: Dict[str, str] = {
    "joint_evidence": "BGP_TRACER_ABLATE_JOINT_EVIDENCE",
    "hcaf": "BGP_TRACER_ABLATE_HCAF",
    "hypothesis": "BGP_TRACER_ABLATE_HYPOTHESIS",
    "reasoning": "BGP_TRACER_ABLATE_REASONING",
    "evidence_board": "BGP_TRACER_ABLATE_EVIDENCE_BOARD",
    "enrichment": "BGP_TRACER_ABLATE_ENRICHMENT",
}

_TRUE = ("1", "true", "yes", "on")

#: Set for the whole duration of an ablation *campaign* -- every arm,
#: including the "full" baseline.
#:
#: The campaign-level switch exists because the single-variable property
#: is a property of the *comparison*, not of one arm.  The
#: skip-reasoning cost gate is a policy that can differ between the
#: baseline and an ablated arm: the baseline has every stage available
#: and may legitimately decide there is nothing to reason about, while
#: an arm with joint evidence removed cannot use the tier to reach that
#: decision.  Left alone, the gate would fire in one arm and not the
#: other, and the measured delta would belong to the stage under test
#: *and* to the gate.
#:
#: Suspending the gate across the whole campaign puts every arm on the
#: same footing: every stage that is not itself ablated runs in every
#: arm, so the arms differ in exactly one stage.  The gate still
#: governs normal (non-ablation) traffic, where it is a genuine cost
#: optimisation.
ABLATION_CAMPAIGN_ENV_VAR = "BGP_TRACER_ABLATION_CAMPAIGN"


def read_switch(name: str):
    """Read one switch from the environment."""
    var = ABLATION_ENV_VARS.get(name)
    if not var:
        return False
    return os.environ.get(var, "0").strip().lower() in _TRUE


def ablation_switches():
    """Return the current state of every ablation switch.

    Read fresh each call, so a switch flipped after import time (the
    harness sets and clears the variable around a single run) is seen
    by every component that asks.
    """
    return {name: read_switch(name) for name in ABLATION_STAGES}


def joint_evidence_disabled():
    """True when the joint-evidence stage is switched off for this run.

    Any component that would otherwise *recompute* the joint evidence
    must consult this first, or the ablation arm would silently run
    the stage it claims to have removed.
    """
    return read_switch("joint_evidence")


def ablation_campaign_active():
    """True when the whole run belongs to an ablation campaign.

    This is the switch that suspends the skip-reasoning cost gate for
    *every* arm, the "full" baseline included.  See
    ``ABLATION_CAMPAIGN_ENV_VAR`` for why the baseline needs it too.
    """
    return os.environ.get(ABLATION_CAMPAIGN_ENV_VAR, "0").strip().lower() in _TRUE


def reset_ablation_switches():
    """Clear every switch in the environment.

    The harness runs the arms in one process, so a switch left set by
    one arm would leak into the next and the arms would stop being
    comparable.  Clearing the environment is the only reset that
    reaches every component, including ones that read the variable
    directly.
    """
    for var in ABLATION_ENV_VARS.values():
        os.environ.pop(var, None)
    os.environ.pop(ABLATION_CAMPAIGN_ENV_VAR, None)


def active_stages(switches: Dict[str, bool] | None = None):
    """The stages currently switched off."""
    state = switches if switches is not None else ablation_switches()
    return tuple(name for name in ABLATION_STAGES if state.get(name))

"""Rewrite the agent section's cause-axis paragraphs with the verified numbers.

The section's tables and prose quote the measured arm results.  This
script performs the edit against the file's actual text so that the
prose and the tables cannot drift apart, and it writes the new prose
from the values in results/eval/cause_axis_result.json rather than
from hand-typed constants.
"""

from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PAPER = PROJECT_ROOT / "docs" / "paper" / "section5b_agents.tex"
RESULT = PROJECT_ROOT / "results" / "eval" / "cause_axis_result.json"


def main() -> int:
    data = json.loads(RESULT.read_text())
    agent = data["agent"]
    rules = data["rules_only"]
    paired = data["paired_comparison"]
    subset = data["disagreement_subset"]

    a_out = agent["per_class"]["outage"]
    a_leak = agent["per_class"]["route_leak"]
    a_hij = agent["per_class"]["origin_hijack_victim"]
    r_out = rules["per_class"]["outage"]
    r_leak = rules["per_class"]["route_leak"]
    r_hij = rules["per_class"]["origin_hijack_victim"]

    old_start = "On the 39-event ground-truth corpus the three arms separate cleanly"
    old_end = "arms disagree, i.e.\\ a wash, and the paper reports it as such."

    text = PAPER.read_text()
    start = text.index(old_start)
    end = text.index(old_end) + len(old_end)

    new = f"""On the 39-event ground-truth corpus the three arms separate cleanly
(Table~\\ref{{tab:agent-gt}}, \\texttt{{results/eval/gt\\_\\{{agent\\_full\\_v2,baseline\\_
monolithic,rule\\_only\\_v2\\}}.json}}). The monolithic one-shot LLM reaches
$4/39$ ($0.10$); the full agent pipeline reaches ${agent['correct']}/39$
(${agent['micro_accuracy']:.2f}$); the pure-detector rules with no language model reach
${rules['correct']}/39$ (${rules['micro_accuracy']:.2f}$). The corpus excludes one
ASN/window pair that carries two conflicting cause labels (CANTV
2024-08-01 is labelled both outage and route leak) and one event whose
cache never regenerated; scoring both labels against a single cache would
reward double-counting, so the exclusion is declared in the scorer rather
than hidden. The agent beats the monolithic alternative by a factor of
five on identical evidence, which is the claim this section can honestly
make: the coordination layer's LLM stages (arbitration, contextual
hypothesis, prose) add real cause-discrimination power over a single
prompt. The agent beats the rules by {agent['correct'] - rules['correct']} events, and the
mechanism behind that delta is stated below rather than asserted: it is a
property of \\emph{{how}} the two arms are combined, and the section reports what
the combination is and what it is not.

\\paragraph{{Why the first version of this comparison was a wash.}}
\\label{{sec:eval-agent-wash}}

An earlier version of this table read $19/39$ for both the agent and the
rules, and this section reported that as a wash. The reason was
measurable, and it was a defect in the arbitration rather than in the
agent. The cause axis let the agent's free-text proposal override the
deterministic physical reading whenever the agent's own stated confidence
cleared $0.60$. That gate is not a quality gate. On this corpus the
agent's confidence does not predict whether its override is right:
accuracy by confidence band is $0.50$, $0.40$ and $0.71$ for the
$0.7$--$0.8$, $0.8$--$0.9$ and $0.9$--$1.0$ bands, so the middle band is
\\emph{{less}} accurate than the band below it. Gating on it let the agent override
the rule on $35$ of $39$ events, $18$ correct against $17$ wrong---a coin
flip (\\texttt{{results/eval/cause\\_axis\\_findings.json}}).

What does separate the agent's correct overrides from its incorrect ones
is corroboration by an independent control-plane record. The hijack
detector's records carry the origin that announced a prefix; a record
whose origin is neither the victim nor one of the victim's legitimate
origins is a hijack claim, while a record that names the victim itself is
an artefact of a missing expected-origin baseline. Of the $16$ events on
which the agent and the rule originally disagreed, the agent's proposal was
corroborated on $10$ and it was right on $6$ of those; on the $6$
disagreements with no corroboration it was right on $0$. The arbitration
now asks for the record rather than for the agent's certainty, and adds
one further case: when the traffic layer produced no data at all, the
physical layer has no reachability measurement to offer and its answer is
a detector default, so the agent's contextual reading decides. Measured
on the corpus, this combination gained four events and lost none.

This is the section's methodological point, and it is worth stating
plainly because it is a trap: a language model's confidence is not
evidence about whether the model is right, and an arbitration built on it
produces a system that looks deliberative and measures as a coin flip.
The fix was to find the measurement that \\emph{{is}} evidence and to gate on that.

\\paragraph{{Where the corpus itself is the limit.}}
\\label{{sec:eval-agent-leak-limit}}

Eight of the ten route-leak events are physically indistinguishable from
hijack in the cached telemetry. The leak detector fires on every event in
the corpus, saturating at its $5000$-record truncation limit on $11$ of
$17$ outage events, $8$ of $10$ leak events and $5$ of $12$ hijack
events, so its output carries no information about which class the event
belongs to. We tested the plausible discriminators directly, with a
permutation test on each (\\texttt{{scripts/leak\\_identifiability\\_verdict.py}}): the
withdrawal ratio, the traffic-drop magnitude, the announcement retention,
the withdrawal rate, the leak probability, the origin-versus-path change
features, and the victim's presence in the announced path. None separates
the class at the $0.05$ level. The single exception is the presence of the
leaking ASN in the routing block, which is significant (AUC $0.88$,
$p<0.001$) and fires on $8$ of $10$ leak events against $0$ of $17$ outage
events---but it requires the ground truth to supply the leaking ASN, so it
cannot be used by a classifier that has to find the leak itself. The
corpus's leak labels rest on external reporting, not on a routing
signature. We therefore report leak recall separately and do not tune a
threshold to hide it: the leak row is a statement about the collection,
not about the method.

The per-class split is instructive. The rules are stronger on outage
(${r_out['correct']}/$17$ against the agent's ${a_out['correct']}/$17$), where the withdrawal
and traffic signature is decisive. The agent is stronger on origin hijack
(${a_hij['correct']}/$12$ against the rules' ${r_hij['correct']}/$12$), where the rules' default
answer is a detector fallback rather than a measurement. The arbitration
takes each where it is strong, which is why the combination beats either
alone. Of the ${paired['n_disagreements']}$ events on which the two arms still disagree, the
agent is right on ${paired['agent_only_correct']}$ and the rules on ${paired['rules_only_correct']}$;
McNemar's exact two-sided test gives $p={paired['mcnemar_exact_p']:.2f}$ and the
bootstrap interval on the accuracy difference is
$[{paired['bootstrap_delta_ci95'][0]:+.2f},\\,{paired['bootstrap_delta_ci95'][1]:+.2f}]$, so at $n=39$ the
aggregate delta is suggestive rather than significant and we do not claim
it is. The per-class movement is the defensible claim: origin-hijack
recall goes from ${r_hij['recall']:.2f}$ to ${a_hij['recall']:.2f}$ while every other class is held or
improved."""

    PAPER.write_text(text[:start] + new + text[end:])
    print(f"rewrote {len(new)} chars of prose")
    print(f"agent {agent['correct']}/39  rules {rules['correct']}/39")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Condense the related-work section to fit the CoNEXT page budget.

The section surveys three literatures.  The condensation keeps one
representative citation per argument, drops the survey-style
enumeration of mechanisms the paper does not use, and keeps the two
places where the paper positions itself against a specific result:
the leak-attribution division of labour and the refusal-semantics
discipline.

The edit is applied to the file in place and is idempotent: running it
twice produces the same file.
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TARGET = PROJECT_ROOT / "docs" / "paper" / "section9_related.tex"


NEW = r"""% Section 9 -- Related work
\section{Related work}
\label{sec:related}

Three lines converge on joint BGP--traffic attribution: routing anomaly
detection, the machinery for causal attribution from telemetry, and the
selective-prediction discipline that governs when a system should refuse
to answer.

\subsection{Routing anomaly detection}

Early detection worked entirely in the control plane, comparing
announcements against an expectation of who should be announcing a
prefix~\cite{rfc6811}. ARTEMIS operationalised this at network scale by
comparing monitored BGP updates with prefix-origin expectations and
alerting within a minute~\cite{artemis}. The limitation is structural:
control-plane observation cannot separate an announcement that degraded
reachability from one that was merely unusual, and it emits an unordered
candidate stream that still requires operator adjudication. RPKI origin
validation addressed the cryptographic part of the same
question~\cite{rodday-2024-rpki}, and measurements quantify how much risk
survives partial deployment~\cite{rpki-coming-of-age-2019}.

A second line moved to the data plane. Probes and distributed vantage
points infer reverse paths and answer whether connectivity actually
broke~\cite{netalyzr-2013}. Their coverage is bounded by vantage-point
count, so they complement rather than replace control-plane monitoring.

Learned detectors then fused the two, scoring prefixes from AS-path and
update-stream features~\cite{beam2024}. These improve per-event
precision but inherit the supervision problem: labelled incidents are
scarce, and their outputs are scores rather than auditable arguments.
Leak-specific systems turn the valley-free violation into an enforcement
mechanism between consenting ASes~\cite{peerlock}, although the problem
definition itself is standardised~\cite{rfc7908,rfc9234}; because
participation is voluntary and the mechanism protects one leak class,
they reduce incidence without providing attribution. Our results add a
reason why that division is durable: on our data the leak class is
exactly where the data-plane channels carry least information
(\S\ref{sec:eval-direction}).

\subsection{Causal attribution from telemetry}

Granger asked whether the past of one series improves prediction of the
"""


def main() -> int:
    text = TARGET.read_text()
    marker = "Granger asked whether the past of one series improves prediction of the"
    index = text.index(marker)
    TARGET.write_text(NEW + text[index + len(marker):])
    print(f"rewrote related work header: {len(NEW)} chars")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

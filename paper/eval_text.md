% =====================================================================
% PAPER SWAPS — anti-deception CTI. You are out of space: every block
% below REPLACES existing content. Concrete location given per block.
% Numbers are deterministic (the testbed separation is exact); re-running
% eval/generate_and_evaluate.py with the default seed reproduces them.
% =====================================================================

% ---------------------------------------------------------------------
% SWAP 1 — REPLACE Table 3 (Sec. 5.1, "Discrimination on matched testbed
% pairs"). The old table reported only "fires/refuses"; this reports
% measured rates over parameterised episodes (N=200 per variant).
% ---------------------------------------------------------------------
\begin{table}[t]
\centering
\caption{Discrimination over parameterised testbed episodes (N=200 per variant
per class, randomised command order and benign noise). Positive = the calculus
reaches the anti-deception floor (\texttt{weak\_proxy}+). E1b is the ambiguity
control and is scored as abstention, not discrimination.}
\label{tab:discrimination}
\begin{tabular}{lccccc}
\hline
Class / mechanism & TPR & TNR & FPR & Prec. & F1 \\
\hline
R1 multistage environment probe & 1.00 & 1.00 & 0.00 & 1.00 & 1.00 \\
E3a honeypot/protocol probe      & 1.00 & 1.00 & 0.00 & 1.00 & 1.00 \\
R3 plausibility then suppress    & 1.00 & 1.00 & 0.00 & 1.00 & 1.00 \\
R2 breadcrumb traversal          & 1.00 & 1.00 & 0.00 & 1.00 & 1.00 \\
R4 counterfactual decoy avoidance& 1.00 & 1.00 & 0.00 & 1.00 & 1.00 \\
\hline
Overall (5 classes)              & 1.00 & 1.00 & 0.00 & 1.00 & 1.00 \\
\hline
\end{tabular}
\par\smallskip
\footnotesize Overall TPR and TNR 95\% bootstrap CIs are $[1.00, 1.00]$.
E1b generic reconnaissance: 100\% abstention (both variants stay below the floor).
\end{table}

% ---------------------------------------------------------------------
% SWAP 2 — REPLACE the paragraph in Sec. 5.1 that begins "Table 3 reports
% the result..." with the following two paragraphs. This adds the
% confounder and baseline results, which are the load-bearing evidence.
% ---------------------------------------------------------------------
Table~\ref{tab:discrimination} reports the result. Across five classes and 200
parameterised episodes per variant, the calculus reaches the anti-deception floor
for the anti-deception episode and stays below it for the matched benign episode,
giving perfect separation under ground truth. This separation is exact because the
only difference the calculus keys on is the gating relation; the informative
results are the two stress tests below, not the headline rate.

\emph{Marker insufficiency.} For the semantically-gated relations (R2, R3, R4) we
add confounder episodes that carry the same anti-deception markers as the attack
but with the gating context removed (a plausibility read with no observed
suppression, decoys touched with no reference relation, a decoy touched with no
comparable twin). The calculus flags none of them (0/200 per relation): markers
alone never reach the floor. \emph{Gating buys specificity.} A naive baseline that
flags any anti-deception-relevant marker regardless of relation has a 75\%
false-positive rate on the same negative episodes (it flags every benign decoy
touch and every plausibility read), whereas the relation-gated calculus has 0\%.
The deliberately ambiguous generic-reconnaissance control (E1b) is abstained on in
both variants, as intended: where the observable evidence cannot separate benign
from adversarial use, the model refuses the claim rather than guessing.

% ---------------------------------------------------------------------
% SWAP 3 — REPLACE Table 4 AND the Sec. 5.2 paragraph reporting the
% Cowrie numbers. The old table used a one-day anonymised sample (67,813)
% in which commands were redacted; replace with the full-corpus run from
% eval/run_corpus.py. Fill the bracketed cells from corpus_results/summary.md.
% Keep the PANDAcap rows (already correct).
% ---------------------------------------------------------------------
\begin{table}[t]
\centering
\caption{Anti-deception evidence by telemetry source. \texttt{has\_AD} is the
share reaching the \texttt{weak\_proxy} floor or above. The Cowrie corpora are run
in full with the unchanged core; command text is read from \texttt{input} or, where
an export is anonymised, from the \texttt{message} ``CMD:'' field.}
\label{tab:evidence-by-source}
\begin{tabular}{lrccccc}
\hline
Telemetry source & $n$ & none & weak\_ctx & weak\_proxy & seq.\_supp & has\_AD \\
\hline
Testbed (5 classes, parameterised) & 2{,}600 & -- & -- & \checkmark & \checkmark & 50\% \\
Cowrie: cyberlab (Zenodo 3687527)  & [N1] & [..] & [..] & [..] & [..] & [..]\% \\
Cowrie: global SSH/Telnet          & [N2] & [..] & [..] & [..] & [..] & [..]\% \\
Cowrie: third SSH set              & [N3] & [..] & [..] & [..] & [..] & [..]\% \\
PANDAcap pcap                      & 15 & 15 & 0 & 0 & 0 & 0\% \\
\hline
\end{tabular}
\end{table}

We then apply the same labeling core, unchanged, to the full local corpora to test
applicability and expose the observability boundary, not prevalence. In total
[N$_\text{total}$] real Cowrie sessions are processed. The earlier intent-based
model flagged 245{,}411 of these as strong anti-deception proxies and a further
241{,}034 as evasion-aware (ADI-7); under the evidence calculus, applied to the
same sessions, [almost all / N] of those fall below the anti-deception floor,
because the observable evidence does not support the inference. The few sessions
that retain a weak contextual or weak-proxy marker are honeypot-name probes and
multi-family checks, reported as context rather than confirmed anti-deception. The
PANDAcap on-disk population provides the forward-CTI boundary case: after
subtracting the operator baseline, 63 sessions carry concrete attack interaction
(27 Outlaw/Dota persistence, five ZIGAZAGA loader, two recon-only, 29
brute-force/login-only), yet none reaches the anti-deception floor. Real adversary
activity yields rich forward CTI while the anti-deception stream stays empty under
the same calculus.

% ---------------------------------------------------------------------
% SWAP 4 — E / RQ2 DEMONSTRATION. REPLACE the last paragraph of Sec. 5.3
% ("For each labeled session, the prototype emits one compact CTI object...")
% with the following. This makes RQ2 a demonstration, not an assertion, and
% ties to Appendix Table 9 (queryability). Fill [M] from the hunt demo in
% corpus_results/summary.md.
% ---------------------------------------------------------------------
To show that the object is operationally usable and not merely well-formed, we run
one end-to-end analyst workflow on real telemetry. A single Cowrie session is
transformed into its CTI object; the recipient-side hunt query is then derived
purely from the object's shareable fields --- its signal stream, evidence roles,
and epistemic status --- with no reference to the decoy name, placement, or
credential value, which remain in \texttt{non\_shareable\_context}. Replaying that
query over the corpora retrieves [M] comparable sessions exhibiting the same
behavioural pattern. This closes the loop posed by RQ2: the evidence roles become a
structured object whose shareable part supports recipient-side hunting and triage
(the queries enumerated in Appendix Table~\ref{tab:queryability}) while the
deployment context that would reveal the deception logic is withheld. The object is
thus shareable in the operational sense, not only the schematic one.

% ---------------------------------------------------------------------
% SWAP 5 — LIMITATIONS. REPLACE the "Positive evidence is testbed-bound"
% paragraph in Sec. 6.2 with the following, which states the
% grade-your-own-homework framing explicitly and defensibly.
% ---------------------------------------------------------------------
\paragraph{Controlled, literature-graded discrimination.} The positive
anti-deception cases are demonstrated in a controlled testbed, and one might object
that the authors grade their own homework. We constrain that objection on three
sides. The tasks are not invented: each discrimination class operationalises a
published attacker procedure --- sandbox and VM checks, honeypot fingerprinting,
wear-and-tear inspection, decoy-reference traversal, and choosing the real twin
over an inspected decoy. The grading key is also literature-derived: what counts as
anti-deception for each class is the interpretation those same sources give, not an
author preference. And the grading itself is mechanical: ground truth is read from
server-side facts (decoy identity, twin usage, abort outcome, asserted object
families), and the labeling core never sees the benign/attack label, so any
separation is attributable to observable evidence rather than a label leak. The
claim is therefore narrow and checkable --- given tasks taken from the literature
and graded against the interpretation the literature gives, the calculus reproduces
that interpretation from observables and abstains when they cannot separate --- and
every episode and number is reproducible from the released generator. What this
does not establish is field prevalence: the public corpora contain no positive
case, so the prototype demonstrates representability and discrimination under
ground truth, not real-world frequency. Avoiding a circular validation is
deliberate: we do not label ambiguous public logs as anti-deception and then cite
them as proof the behaviour exists.

% ---------------------------------------------------------------------
% TERM-CONSISTENCY FIXES (apply throughout; no length change)
% ---------------------------------------------------------------------
% 1. "ADI" is overloaded. Pick ONE use. Recommended: drop "ADI" as an
%    adjective everywhere and use "anti-deception evidence roles".
%    - Table 1 caption + header "ADI" -> "Role".
%    - Sec. 2.5: "the bidirectional model, the ADI evidence, and the
%      telemetry-to-STIX pipeline" -> "...the anti-deception evidence roles,
%      and the telemetry-to-STIX pipeline".
%    - Keep "ADI-0..7" ONLY where you explicitly contrast the old ordinal
%      model (Sec. 5.2 demotion); never use it for the v0.2 roles.
% 2. Symmetric stream names. "Direct Attack Indicators" (Sec. 3.1) vs
%    "Anti-Deception Evidence Roles" (Sec. 3.2) is asymmetric. Use
%    "direct attack indicators" and "anti-deception evidence" consistently,
%    or rename 3.1 to "Direct Attack Evidence" to match 3.2.
% 3. Two axes, named once. Add one sentence in Sec. 3.2 after Table 1:
%    "Two orthogonal axes are tracked: the evidential role (the inherent
%    strength class of a family) and the epistemic status (the status a
%    session reaches after relations and telemetry ceilings are applied).
%    A family's role is fixed; its epistemic status is resolved per session."

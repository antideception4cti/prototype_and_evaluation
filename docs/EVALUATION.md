# Evaluation methodology (controlled discrimination, confounders, baseline)

This document specifies the controlled evaluation behind the discrimination
claim. It is deliberately explicit so that a reviewer can re-run every number
and check every design choice against the literature.

## What this evaluation claims — and what it does not

It claims exactly three bounded things, all under ground truth:

1. **(B) Discrimination.** When observable relations support the distinction,
   the calculus reaches the anti-deception floor (`weak_proxy`+) for the
   anti-deception episode and stays below it for the matched benign episode.
   We report sensitivity, specificity, false-positive rate, precision and F1
   with bootstrap confidence intervals over *parameterised* episodes.
2. **(C) Marker insufficiency (anti-circularity).** For the semantically-gated
   relations (R2/R3/R4), episodes that carry the **same anti-deception markers**
   as the attack but **lack the gating context** stay below the floor.
3. **(D) Gating buys specificity.** A naive detector that flags any
   anti-deception-relevant marker, regardless of relation, has a high
   false-positive rate on the same episodes where the relation-gated calculus
   has none.

It does **not** claim real-world prevalence, attacker attribution, or coverage
of the full anti-deception behaviour space. Those are out of scope by design
(see *Limitations of this evaluation*).

## The honest framing: graded against a literature model solution

The standard objection to a self-built testbed is "the authors grade their own
homework." We address it structurally, not rhetorically:

* **The tasks come from the literature.** Each discrimination class operationalises
  a *published* attacker procedure (sandbox/VM checks, honeypot fingerprinting,
  wear-and-tear inspection, decoy-reference traversal, two-sided-deception
  avoidance). We did not invent the behaviours; we adapted documented ones to a
  shell/IAM setting. The provenance table below cites each one.
* **The model solution comes from the literature too.** What *counts* as
  anti-deception for each class is the interpretation those same sources give —
  e.g. a coordinated multi-probe sequence is validation (not generic recon), a
  decoy-reference hop is traversal, choosing the real twin over the inspected
  decoy is avoidance. The expected label per class is therefore a literature-
  grounded key, not an author preference.
* **The grading is mechanical.** Ground truth is read from server-side facts
  (`is_decoy`, twin usage, abort/outcome, asserted object families), never from
  a human intent judgement. The labeling core never sees the benign/attack class
  label; it sees only observables and the relation context the environment
  records. Any separation is therefore attributable to the observable evidence,
  not to a label leak.

So the claim a reviewer can check is narrow and falsifiable: *given tasks taken
from the literature and graded against the interpretation the literature gives,
does the calculus reproduce that interpretation from observables alone, and does
it abstain when the observables cannot separate?* The code generating every
episode and every number is `eval/class_specs.py` + `eval/generate_and_evaluate.py`.

## The six classes and their published procedures (provenance)

| class (generator id) | adapted procedure | model-solution source | expected on attack | expected on benign |
|---|---|---|---|---|
| `R1_multistage_env_probe` | coordinated multi-family environment/instrumentation checks (a "probe sequence", not a single command) | dynamic-analysis evasion survey [1]; ATT&CK system checks T1497.001 [16] | `sequence_supported` (R1 fires: hard probe + ≥2 distinct env families) | `weak_context` (single generic-recon command) |
| `E3a_honeypot_probe` | honeypot/protocol fingerprinting via banner/name/implementation tell | Bitter Harvest [42]; Gotta Catch 'em All [37] | `weak_proxy` (E3a marker) | `weak_context` |
| `R3_plausibility_then_suppress` | inspect artifact plausibility metadata, then suppress the expected follow-up | decoy references [32]; two-sided deception [2] | `sequence_supported` (R3: preceding check + suppression evidence + payload visibility) | `observed_marker` (inspected, then used — no suppression) |
| `R2_breadcrumb_traversal` | follow a decoy reference to a second decoy element | references in networks of decoy elements [32] | `sequence_supported` (R2: decoy graph + known reference relation) | `direct_deception_interaction` (single decoy, no graph) |
| `R4_decoy_avoidance` | inspect a decoy, then use the real twin instead (counterfactual) | two-sided deception [2]; Tularosa study [7] | `testbed_grounded` (R4: comparable twin + exposure + counterfactual, testbed only) | `direct_deception_interaction` (used the decoy directly) |
| `E1b_generic_recon_control` | ordinary host reconnaissance; deliberately ambiguous | Cowrie telemetry [26] | **abstain** (`weak_context`) | **abstain** (`weak_context`) |

`E1b` is the refusal control: its "attack" and "benign" episodes are
observationally identical, so the only correct behaviour is to abstain for both.
It is reported separately from the discrimination metrics for that reason.

## Episode construction and parameterisation

Each class produces episodes through `build_episode(class_name, variant, rng)`:

* **Environment, content-gated classes** (`R1`, `E3a`, `E1b`) are command
  sequences. The attack carries the marker command(s) for its family; the benign
  carries generic-recon commands. R1's "multistage" condition is **derived by the
  engine** from the actual families present (hard probe + ≥2 distinct environment
  families), not asserted — so a benign single-command episode cannot trigger it.
* **Object, semantically-gated classes** (`R2`, `R3`, `R4`) assert object
  families (`D0`/`E4`) from server facts and set the relation context the
  environment would record. The semantic ground-truth fields (`suppression_evidence`,
  `comparable_object`, `exposure_evidence`, `counterfactual_avoidance`,
  `known_reference_relation`) are exactly the facts a controlled testbed can
  observe; they are the model-solution key for that episode.
* **Variation.** Every episode gets a randomised command order and 0–4 injected
  benign-noise commands (verified to trip no marker). Running N episodes per
  variant with a fixed seed yields rates with bootstrap CIs rather than single
  anecdotes. Default N = 200, seed = 20260625.

## (C) Confounder construction

For `R2`/`R3`/`R4`, a `confounder` variant carries the **same** anti-deception
markers as the attack but removes the gating context:

* `R3` confounder: the E4 plausibility marker is present, but
  `suppression_evidence = false` and `payload_visibility = false` — a check
  followed by nothing, which the `r3_no_absence_inference` rule forbids from
  becoming evidence.
* `R2` confounder: D0/E4 present, but `known_reference_relation = false` — decoys
  touched without a traversal.
* `R4` confounder: D0 present, but `comparable_object`/`exposure_evidence`/
  `counterfactual_avoidance = false` — a decoy touched without an observed real
  twin to avoid.

A correct calculus keeps all confounders below the floor. This is the direct
test that markers alone are never sufficient — the same property that makes the
field result (no positives on commodity noise) a feature rather than a miss.

`R1`/`E3a` are content-gated (they require actual probe markers), so their
specificity is tested by the benign generic-recon twins, which do not contain
those markers, rather than by a marker-removal confounder.

## (D) Naive baseline

The baseline flags a session as anti-deception iff any family in
{E1a, E2, E3a, E4, D0} is present, ignoring relations. It is a *reasonable*
ungated detector (it does not flag generic E1b/E5 recon), not a strawman. Run on
all negative episodes (benign + confounder), it flags every benign/confounder
object episode that merely touched a decoy or read plausibility metadata —
because "decoy touch = anti-deception" is exactly the overclaim the relation
gating removes. Its false-positive rate is contrasted with the calculus (~0).

## Metric definitions

Positive = the calculus reaches the anti-deception floor (`has_anti_deception_evidence`,
i.e. `weak_proxy`+). Ground-truth positive = the episode's class/variant is the
anti-deception case.

* **TPR (sensitivity/recall)** = TP / (TP + FN)
* **TNR (specificity)** = TN / (TN + FP)
* **FPR** = FP / (FP + TN)
* **precision** = TP / (TP + FP)
* **F1** = harmonic mean of precision and TPR
* **95% CI** = percentile interval over `--bootstrap` resamples of the per-episode
  0/1 correctness vector.

## How to run

```bash
pip install pyyaml
# (B)+(C)+(D): controlled discrimination, confounders, baseline
python eval/generate_and_evaluate.py --n 200            # -> eval/results/metrics.md, metrics.csv, episodes.csv

# (A): the same UNCHANGED core over the full local corpora + the RQ2 hunt demo
python eval/run_corpus.py \
    --cowrie "/path/to/3687527/" --name cyberlab \
    --cowrie "/path/to/global/*.json" --name global \
    --cowrie "/path/to/third_set/" --name third_ssh \
    --pandacap-survey /path/to/pandacap_disk_survey.jsonl --name pandacap_disk
# -> eval/corpus_results/summary.md (+ summary.json)
```

For the repository: the eval generators and metrics are fully reproducible from
this tree (no external data). The corpus run needs the public datasets; a
reviewer downloads them (Zenodo 3687527; the global SSH/Telnet Cowrie set; the
third SSH set) and runs `run_corpus.py`. We post our `corpus_results/` output so
the numbers can be compared without re-downloading 25M sessions.

## Limitations of this evaluation

* **Discrimination is demonstrated under controlled ground truth, not in the
  wild.** The testbed separation is perfect *because* the only difference between
  benign and attack is the gating relation and the calculus is defined to require
  it. The non-trivial evidence is (C) marker insufficiency and (D) the baseline
  gap, not the headline TPR.
* **The classes are literature-derived but not exhaustive.** They cover the
  documented families we model; new artifact classes can be added to the registry
  and re-evaluated without changing the core.
* **Ground truth is mechanical, which is a strength for objectivity but means the
  testbed cannot capture intent.** We claim observable discrimination, not intent
  recovery — consistent with the paper's scope.

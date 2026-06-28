# Evaluation metrics (generated)

Episodes per variant: **10**  |  bootstrap reps: 2000  |  seed: 20260625

## (B) Discrimination under ground truth

Five discriminable classes (E1b is the ambiguity control, reported separately).

| class | n | TPR | TNR | FPR | precision | F1 |
|---|---|---|---|---|---|---|
| R1_multistage_env_probe | 20 | 100.0% | 100.0% | 0.0% | 100.0% | 1.000 |
| E3a_honeypot_probe | 20 | 100.0% | 100.0% | 0.0% | 100.0% | 1.000 |
| R3_plausibility_then_suppress | 30 | 100.0% | 100.0% | 0.0% | 100.0% | 1.000 |
| R2_breadcrumb_traversal | 30 | 100.0% | 100.0% | 0.0% | 100.0% | 1.000 |
| R4_decoy_avoidance | 30 | 100.0% | 100.0% | 0.0% | 100.0% | 1.000 |
| **overall** | 130 | 100.0% | 100.0% | 0.0% | 100.0% | 1.000 |

Overall TPR 95% CI: [100.0%, 100.0%]  |  Overall TNR 95% CI: [100.0%, 100.0%]

## (C) Confounder stress test

Same anti-deception markers as the attack, but the gating context removed. A correct calculus keeps these **below** the floor (flag rate 0).

| gated relation | confounder episodes | flagged | flag rate |
|---|---|---|---|
| R2_breadcrumb_traversal | 10 | 0 | 0.0% |
| R4_decoy_avoidance | 10 | 0 | 0.0% |
| R3_plausibility_then_suppress | 10 | 0 | 0.0% |

## (D) Naive baseline vs. relation-gated calculus

On all negative episodes (benign + confounder). The naive detector flags any anti-deception-relevant marker regardless of relation.

- negative episodes: **80**
- naive baseline false positives: **60** (FPR 75.0%)
- relation-gated calculus false positives: **0** (FPR 0.0%)

## E1b ambiguity control

Generic reconnaissance, observationally identical whether benign or adversarial. Correct behaviour is abstention (stay below floor) for both.

- episodes: **20**  |  abstained (correct): **20**  |  abstention rate: 100.0%

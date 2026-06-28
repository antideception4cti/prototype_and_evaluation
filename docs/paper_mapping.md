# Paper Mapping

| Paper location | Artifact evidence |
|---|---|
| Section 3.2 / Table 1 | `evidence_registry.yaml`, `docs/playbooks.md` |
| Section 3.3 | `src/cti_object_builder.py`, `docs/cti_object_sources.md` |
| Section 4.1 | `src/adi_evidence_engine.py`, `evidence_registry.yaml` |
| Section 4.2 | `src/adapters/testbed.py`, `data/testbed/playbooks/*.jsonl` |
| Section 5.1 / Table 3 | `python tests/smoke_and_semantic_tests.py`, `results/session_results.csv` |
| Section 5.2 / Table 4 | optional Cowrie logs under `data/cowrie/`; included testbed output shows the same conservative boundary mechanics |
| Section 5.3 | `results/cti_objects.jsonl` |

The artifact supports the paper's bounded claim: it demonstrates representability and discrimination under controlled ground truth. Real-log prevalence is not claimed by the included testbed run.

## Evaluation package mapping

| Paper location | Artifact evidence |
|---|---|
| Sec. 5.1 / Table 3 (discrimination rates, confounder, baseline) | `eval/generate_and_evaluate.py`, `eval/class_specs.py`, `eval/results/metrics.md` |
| Sec. 5.2 / Table 4 (full-corpus run, demotion) | `eval/run_corpus.py`, `eval/corpus_results/summary.md` |
| Sec. 5.3 (E: object -> hunt -> comparable sessions, RQ2) | `eval/run_corpus.py` hunt demo, `docs/EVALUATION.md` |
| Sec. 6.2 (literature-graded limitation) | `docs/EVALUATION.md` (provenance + framing) |

Provenance of the playbooks (procedures + model solutions) is cited per class in
`docs/EVALUATION.md`; the sources are the same ones already in the paper's
reference list ([1,2,7,12,16,19,26,32,37,42]).

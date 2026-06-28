# Deception-to-CTI Prototype

Runnable artifact for the paper. The pipeline is:

```text
telemetry -> adapter -> evidence engine -> CTI object builder -> JSONL objects
```

## Quick start: included simulation only

This path needs no external data.

```bash
python -m venv .venv
. .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
python tests/smoke_and_semantic_tests.py
```

Expected outputs:

```text
results/session_results.csv
results/cti_objects.jsonl
results/summary.md
```

Expected simulation counts:

```text
simulation_playbooks: 8 sessions; has_AD = 3/8
simulation_multilayer: 5 sessions; has_AD = 3/5
```

`run.py` is the one-click artifact entry point for the bundled simulation traces. Use `eval/run_corpus.py` for full Cowrie/PANDAcap corpus processing.

## Evaluation

Controlled evaluation, no external data:

```bash
python eval/generate_and_evaluate.py --n 200
```

Outputs:

```text
eval/results/metrics.md
eval/results/metrics.csv
eval/results/episodes.csv
```

Full real-corpus boundary run, external data required:

```bash
python eval/run_corpus.py \
  --cowrie "data/real/cowrie_cyberlab/" --name cyberlab \
  --cowrie "data/real/cowrie_global/" --name GlobalSSH \
  --pandacap-disk-survey "data/real/pandacap/pandacap_disk_survey.csv" --name pandacap_disk \
  --out-dir eval/corpus_results
```

`eval/run_corpus.py` accepts Cowrie `.json`, `.jsonl`, `.json.gz`, directories, globs, and `.zip` archives. For PANDAcap it accepts either a compact CSV survey or a JSONL disk-artifact survey. It is resilient to truncated gzip members and writes resume checkpoints under `eval/corpus_results/checkpoints/`.

An anonymized aggregate real-corpus result is included under `eval/corpus_results/`.

## Repository map

```text
evidence_registry.yaml            executable evidence registry
src/adi_evidence_engine.py         profile-aware evidence engine
src/adapters/*.py                  source adapters for simulation, Cowrie, PANDAcap
src/cti_object_builder.py          confidence/shareability/actionability object layer
run.py                             one-click bundled simulation run
eval/generate_and_evaluate.py      controlled discrimination/confounder evaluation
eval/run_corpus.py                 resumable real-corpus runner
docs/tldr.md                       reader-facing reproduction guide
```

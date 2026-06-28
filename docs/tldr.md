# TL;DR for the Runnable Artifact

This artifact has two paths. Path A runs without external data and reproduces the controlled simulation claim. Path B runs the same core over local Cowrie/PANDAcap corpora and produces the real-telemetry boundary table.

## Path A — one command, no external data

From the repository root:

```bash
python -m venv .venv
. .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
python tests/smoke_and_semantic_tests.py
```

Expected outputs:

```text
results/session_results.csv     # one row per included simulation trace
results/cti_objects.jsonl       # one compact CTI object per trace
results/summary.md              # table with status counts
```

Expected result:

```text
simulation_playbooks: 8 sessions; has_AD = 3/8
simulation_multilayer: 5 sessions; has_AD = 3/5
```

Paper mapping: Section 3.2 defines evidence roles, Section 3.3 defines the CTI object, Section 4.1 defines the registry/status ladder, Section 4.2 defines the controlled simulation, and Section 5.1 reports the discrimination result.

## Path B — full local corpus run

External corpora are not bundled. Put local data under `data/real/` or pass absolute paths:

```text
data/real/cowrie_cyberlab/       # Cowrie Zenodo 3687527 extracted files or zip
data/real/cowrie_global/         # Global SSH/Telnet Cowrie logs, extracted files or zip
data/real/pandacap/              # generated PANDAcap disk survey CSV or JSONL
```

Run with compact PANDAcap CSV:

```bash
python eval/run_corpus.py \
  --cowrie "data/real/cowrie_cyberlab/" --name cyberlab \
  --cowrie "data/real/cowrie_global/" --name GlobalSSH \
  --pandacap-disk-survey "data/real/pandacap/pandacap_disk_survey.csv" --name pandacap_disk \
  --out-dir eval/corpus_results
```


Alternative with PANDAcap JSONL disk artifacts:

```bash
python eval/run_corpus.py \
  --cowrie "data/real/cowrie_cyberlab/" --name cyberlab \
  --cowrie "data/real/cowrie_global/" --name GlobalSSH \
  --pandacap-disk-survey "data/real/pandacap/pandacap_disk_survey.jsonl" --name pandacap_disk \
  --out-dir eval/corpus_results
```

`eval/run_corpus.py` accepts Cowrie `.json`, `.jsonl`, `.json.gz`, directories, globs, and `.zip` archives. It logs truncated gzip members, processes readable prefixes where possible, continues the run, and writes resume checkpoints to:

```text
eval/corpus_results/checkpoints/
```

Use `--no-resume` to start from scratch.

Expected output files:

```text
eval/corpus_results/summary.md       # paper Section 5 numbers
eval/corpus_results/summary.json     # machine-readable aggregate counts
```

Included aggregate result:

```text
CyberLab:   24,896,360 sessions; 2,553 weak_proxy; 0 strong AD
GlobalSSH:      47,569 sessions;    83 weak_proxy; 0 strong AD
PANDAcap:           63 sessions;     0 weak_proxy; 0 strong AD
```

Interpretation: Cowrie produces rare weak-proxy evidence but cannot support sequence-supported or simulation-grounded claims under the Cowrie telemetry ceiling. PANDAcap provides forward CTI, but no anti-deception evidence in the compact on-disk survey.

## PANDAcap input formats

Compact CSV survey accepted by `--pandacap-disk-survey`:

```text
session,history_date,authorized_keys_comment,attacker_history_lines,tmp_payloads
```

Full JSONL disk-artifact survey also accepted:

```json
{"session_id":"0008","bash_history":["apt-get update","poweroff","echo \"Z\"\"IGAZAGA148\"\"8\"","cat /dev/stdin | sh"],"authorized_keys":"# id_ed25519.pub\nssh-ed25519 ... 0008"}
```

The runner does not mount raw `.qcow2`, `.pcap`, or `.tar.gz` files. Generate CSV/JSONL surveys locally first.
How to create the pandacap csv/json file: 

## What to inspect first

1. `results/summary.md`: bundled simulation status counts.
2. `results/cti_objects.jsonl`: confidence, actionability, shareability, and `non_shareable_context` examples.
3. `eval/results/metrics.md`: parameterized simulation evaluation for Section 5.1/Table 3.
4. `eval/corpus_results/summary.md`: anonymized real-telemetry aggregate result for Section 5.2/Table 4.

## Playbook boundary checks

| Playbook | Expected status | has_AD | Mechanism |
|---|---:|---:|---|
| `pb_env_validation` | `weak_context` | no | Generic environment check only. |
| `pb_fingerprint` | `weak_proxy` | yes | Active service/honeypot fingerprinting. |
| `pb_plausibility_suppress` | `sequence_supported` | yes | Plausibility read followed by explicit abort/suppression. |
| `pb_lowrisk_probe` | `none` | no | Low-risk enumeration without decoy fact or relation. |
| `pb_decoy_avoidance` | `simulation_grounded` | yes | Actor inspects decoy and uses comparable real twin. |
| `pb_adaptation` | `none` | no | Delay/retry behavior without a qualifying relation. |
| `pb_direct_use` | `none` ladder, direct CTI object | no | Direct decoy use without anti-deception relation. |
| `pb_benign_recon` | `weak_context` | no | Benign-like generic reconnaissance. |

Multi-layer traces exercise the same mechanisms across telemetry axes.

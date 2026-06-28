# Corpus results

This folder contains anonymized aggregate output from the real-corpus run used for the paper table.

Included:

- `summary.md`: human-readable aggregate table.
- `summary.json`: machine-readable aggregate counts.

Not included:

- raw Cowrie logs,
- PANDAcap qcow/pcap files,
- local absolute paths,
- checkpoints,
- per-session real-log CTI objects.

To reproduce, download the public corpora locally and run `eval/run_corpus.py` as described in `docs/tldr.md`.

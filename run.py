#!/usr/bin/env python3
"""Run the Deception-to-CTI prototype.

Default one-click path:
    python run.py

This processes the included testbed playbooks and writes:
    results/session_results.csv
    results/cti_objects.jsonl
    results/summary.md

Optional Cowrie logs can be added with:
    python run.py --cowrie data/cowrie/cowrie.json.gz
"""
from __future__ import annotations

import argparse, csv, gzip, json, sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from adi_evidence_engine import EvidenceEngine
from adapters.testbed import label_testbed
from adapters.cowrie import label_cowrie
from cti_object_builder import build_cti_object


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    events = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def read_text(path: Path) -> str:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def group_cowrie_sessions(path: Path):
    raw = read_text(path)
    def group_by_session(events):
        out = defaultdict(list)
        for e in events:
            if isinstance(e, dict):
                sid = e.get("session") or e.get("session_id") or "unknown"
                out[sid].append(e)
        return out
    try:
        doc = json.loads(raw)
        if isinstance(doc, list):
            if doc and isinstance(doc[0], dict) and len(doc[0]) == 1 and isinstance(next(iter(doc[0].values())), list):
                out = defaultdict(list)
                for item in doc:
                    for sid, events in item.items():
                        out[sid].extend(events)
                return out
            return group_by_session(doc)
        if isinstance(doc, dict):
            if doc and all(isinstance(v, list) for v in doc.values()):
                return {k: v for k, v in doc.items()}
            return group_by_session([doc])
    except json.JSONDecodeError:
        pass
    events = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return group_by_session(events)


def md_table(headers, rows):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h)) for i, h in enumerate(headers)]
    line = lambda cells: "| " + " | ".join(str(c).ljust(widths[i]) for i, c in enumerate(cells)) + " |"
    sep = "|" + "|".join("-" * (w + 2) for w in widths) + "|"
    return "\n".join([line(headers), sep, *(line(r) for r in rows)])


def add_result(rows_detail, rows_cti, dataset, session_id, result):
    rows_detail.append({
        "dataset": dataset,
        "session_id": session_id,
        "epistemic_status": result["session_epistemic_status"],
        "has_anti_deception": result["has_anti_deception_evidence"],
        "signal_stream": result["signal_stream"],
        "decoy_interaction": result["decoy_interaction"],
        "families": "+".join(f["family"] for f in result["findings"]) or "-",
        "relations_fired": "+".join(result.get("relations_fired") or []) or "-",
        "off_ladder": "+".join(result["off_ladder_tags"]) or "-",
        "direct_signal": result["direct_signal"],
    })
    rows_cti.append(build_cti_object(result, dataset=dataset, session_id=session_id))


def write_outputs(out_dir: Path, rows_detail, rows_cti) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "session_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows_detail[0].keys()))
        w.writeheader(); w.writerows(rows_detail)
    jsonl_path = out_dir / "cti_objects.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for obj in rows_cti:
            fh.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")

    per_ds_status = defaultdict(Counter)
    per_ds_n = Counter()
    per_ds_ad = Counter()
    for row in rows_detail:
        ds = row["dataset"]
        per_ds_n[ds] += 1
        per_ds_status[ds][row["epistemic_status"]] += 1
        if str(row["has_anti_deception"]).lower() == "true":
            per_ds_ad[ds] += 1
    statuses = ["none", "weak_context", "observed_marker", "weak_proxy", "sequence_supported", "strong_proxy", "testbed_grounded"]
    present = [s for s in statuses if any(per_ds_status[d].get(s) for d in per_ds_n)]
    headers = ["dataset", "sessions", *present, "has_AD"]
    rows = []
    for ds in per_ds_n:
        n = per_ds_n[ds]
        cells = [ds, n]
        for s in present:
            c = per_ds_status[ds].get(s, 0)
            cells.append(f"{c} ({100*c//n if n else 0}%)")
        ad = per_ds_ad[ds]
        cells.append(f"{ad} ({100*ad//n if n else 0}%)")
        rows.append(cells)
    summary = "# Prototype run summary\n\n" + md_table(headers, rows) + "\n\n"
    summary += f"Session CSV: `{csv_path}`\n\nCTI objects JSONL: `{jsonl_path}`\n"
    (out_dir / "summary.md").write_text(summary, encoding="utf-8")
    print(summary)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", default=str(ROOT / "evidence_registry.yaml"))
    ap.add_argument("--testbed", default=str(ROOT / "data" / "testbed" / "playbooks"))
    ap.add_argument("--multilayer", default=str(ROOT / "data" / "testbed" / "multilayer"))
    ap.add_argument("--cowrie", nargs="*", default=[])
    ap.add_argument("--out-dir", default=str(ROOT / "results"))
    ap.add_argument("--skip-included-testbed", action="store_true")
    args = ap.parse_args()

    engine = EvidenceEngine(args.registry)
    rows_detail = []
    rows_cti = []

    if not args.skip_included_testbed:
        for label, folder in [("testbed_playbooks", Path(args.testbed)), ("testbed_multilayer", Path(args.multilayer))]:
            if folder.exists():
                for path in sorted(folder.glob("*.jsonl")):
                    result = label_testbed(engine, read_jsonl(path))
                    add_result(rows_detail, rows_cti, label, path.stem, result)

    for log in args.cowrie:
        path = Path(log)
        if not path.exists():
            print(f"not found: {path}", file=sys.stderr)
            continue
        for sid, events in group_cowrie_sessions(path).items():
            result = label_cowrie(engine, events)
            add_result(rows_detail, rows_cti, path.name, sid, result)

    if not rows_detail:
        raise SystemExit("No sessions processed. Provide testbed files or Cowrie logs.")
    write_outputs(Path(args.out_dir), rows_detail, rows_cti)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
run_corpus.py — resilient corpus runner for the Deception-to-CTI prototype.

This version accepts:
  * Cowrie files, directories, globs, .json, .jsonl, .json.gz, and .zip archives
  * PANDAcap disk survey as JSONL with full disk artifacts
  * PANDAcap disk survey as compact CSV from the old survey scripts

It is compatible with the current CTI object builder, whose evidence_roles field
is a list of dictionaries.

Safety features:
  * truncated/bad gzip members do not abort the corpus run
  * unreadable files or ZIP members are skipped and reported
  * resume checkpoint files are written under <out-dir>/checkpoints/
  * reruns automatically resume after completed files unless --no-resume is used
"""
from __future__ import annotations

import argparse
import csv
import glob
import gzip
import io
import json
import pickle
import re
import sys
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, Iterator, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from adi_evidence_engine import EvidenceEngine            # noqa: E402
from adapters.cowrie import label_cowrie                  # noqa: E402
from adapters.pandacap_disk import label_pandacap_disk    # noqa: E402
from cti_object_builder import build_cti_object           # noqa: E402


LADDER = [
    "none", "weak_context", "observed_marker", "weak_proxy",
    "sequence_supported", "strong_proxy", "testbed_grounded",
]

CHUNK_SIZE = 1024 * 1024


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s).strip("_") or "dataset"


def _warn(dataset: str, msg: str) -> None:
    print(f"[{dataset}] WARNING: {msg}", file=sys.stderr)


def _decode_utf8(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _read_gzip_lenient_from_binary(fh: BinaryIO, label: str, dataset: str, errors: List[str]) -> str:
    """Read a gzip stream and return whatever can be decoded.

    A truncated gzip raises EOFError at the end. We keep the bytes already read,
    record the problem, and continue. This is intentional for long corpus runs.
    """
    parts: List[bytes] = []
    try:
        gz = gzip.GzipFile(fileobj=fh, mode="rb")
        while True:
            chunk = gz.read(CHUNK_SIZE)
            if not chunk:
                break
            parts.append(chunk)
    except EOFError as e:
        errors.append(f"{label}: truncated/bad gzip: {e}")
        _warn(dataset, f"truncated/bad gzip, using readable prefix: {label}")
    except OSError as e:
        errors.append(f"{label}: bad gzip: {e}")
        _warn(dataset, f"bad gzip, using readable prefix if available: {label}")
    return _decode_utf8(b"".join(parts))


def _read_text_file_lenient(path: Path, dataset: str, errors: List[str]) -> Optional[str]:
    try:
        if path.suffix.lower() == ".gz":
            with path.open("rb") as fh:
                return _read_gzip_lenient_from_binary(fh, str(path), dataset, errors)
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:  # keep corpus run alive
        errors.append(f"{path}: unreadable file: {type(e).__name__}: {e}")
        _warn(dataset, f"skipping unreadable file: {path} ({type(e).__name__}: {e})")
        return None


def _read_zip_member_lenient(zf: zipfile.ZipFile, info: zipfile.ZipInfo, dataset: str, errors: List[str]) -> Optional[str]:
    label = f"{zf.filename}!{info.filename}"
    try:
        with zf.open(info, "r") as fh:
            data = fh.read()
    except Exception as e:
        errors.append(f"{label}: unreadable zip member: {type(e).__name__}: {e}")
        _warn(dataset, f"skipping unreadable ZIP member: {label} ({type(e).__name__}: {e})")
        return None

    if info.filename.lower().endswith(".gz"):
        return _read_gzip_lenient_from_binary(io.BytesIO(data), label, dataset, errors)
    return _decode_utf8(data)


# ---------------------------------------------------------------------------
# Cowrie input handling
# ---------------------------------------------------------------------------

def _iter_sessions_from_text(raw: str) -> Iterable[Tuple[str, List[Dict[str, Any]]]]:
    """Yield (session_id, events) from common Cowrie JSON layouts.

    Supported shapes:
      1. line-delimited JSON events
      2. JSON array of events
      3. JSON map {session_id: [events]}
      4. JSON array of one-key maps [{session_id: [events]}, ...]
    """
    raw_strip = raw.lstrip()
    if raw_strip[:1] in "[{":
        try:
            doc = json.loads(raw)
            if isinstance(doc, list):
                if doc and isinstance(doc[0], dict) and len(doc[0]) == 1 \
                        and isinstance(next(iter(doc[0].values())), list):
                    for item in doc:
                        for sid, events in item.items():
                            yield str(sid), events
                    return
                grp: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
                for e in doc:
                    if isinstance(e, dict):
                        sid = e.get("session") or e.get("session_id") or "unknown"
                        grp[str(sid)].append(e)
                yield from grp.items()
                return
            if isinstance(doc, dict):
                if doc and all(isinstance(v, list) for v in doc.values()):
                    for sid, events in doc.items():
                        yield str(sid), events
                    return
                grp = defaultdict(list)
                sid = doc.get("session") or doc.get("session_id") or "unknown"
                grp[str(sid)].append(doc)
                yield from grp.items()
                return
        except json.JSONDecodeError:
            pass

    grp: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(e, dict):
            sid = e.get("session") or e.get("session_id") or "unknown"
            grp[str(sid)].append(e)
    yield from grp.items()


def iter_sessions_in_file(path: Path, dataset: str, errors: List[str]) -> Iterable[Tuple[str, List[Dict[str, Any]]]]:
    raw = _read_text_file_lenient(path, dataset, errors)
    if raw:
        yield from _iter_sessions_from_text(raw)


def iter_sessions_in_zip(path: Path, dataset: str, errors: List[str]) -> Iterable[Tuple[str, List[Dict[str, Any]]]]:
    """Read Cowrie JSON/JSONL/JSON.GZ members from a ZIP archive."""
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                name = info.filename
                lower = name.lower()
                if info.is_dir():
                    continue
                if not (lower.endswith(".json") or lower.endswith(".jsonl") or lower.endswith(".json.gz") or lower.endswith(".gz")):
                    continue
                raw = _read_zip_member_lenient(zf, info, dataset, errors)
                if raw:
                    yield from _iter_sessions_from_text(raw)
    except Exception as e:
        errors.append(f"{path}: unreadable zip: {type(e).__name__}: {e}")
        _warn(dataset, f"skipping unreadable ZIP: {path} ({type(e).__name__}: {e})")


def expand(paths: List[str]) -> List[Path]:
    out: List[Path] = []
    for p in paths:
        pa = Path(p)
        if pa.is_dir():
            out += sorted(
                x for x in pa.rglob("*")
                if x.suffix.lower() in (".json", ".jsonl", ".gz", ".zip")
            )
        else:
            matches = sorted(glob.glob(p))
            out += [Path(x) for x in matches] if matches else [pa]
    # Deduplicate while preserving order
    seen = set()
    deduped: List[Path] = []
    for p in out:
        k = str(p.resolve()) if p.exists() else str(p)
        if k not in seen:
            seen.add(k)
            deduped.append(p)
    return deduped


# ---------------------------------------------------------------------------
# Folding / object-compatible pattern keys
# ---------------------------------------------------------------------------

def _role_to_string(role: Any) -> str:
    if isinstance(role, dict):
        return str(role.get("role") or role.get("implementation_family") or "?")
    return str(role)


def _pattern_key(result: Dict[str, Any]) -> str:
    """Pattern used for the RQ2 hunt demo.

    Current build_cti_object() returns evidence_roles as list[dict], not list[str].
    This function therefore normalizes both shapes.
    """
    obj = build_cti_object(result)
    roles = "+".join(sorted({_role_to_string(r) for r in (obj.get("evidence_roles") or [])})) or "-"
    return "|".join([
        str(result.get("signal_stream", "baseline")),
        str(result.get("session_epistemic_status", "none")),
        roles,
    ])


def _fold_result(
    acc: Dict[str, Any],
    result: Dict[str, Any],
    dataset: str,
    sid: str,
    *,
    keep_example: bool = True,
) -> None:
    acc["sessions"] += 1
    acc["status"][result.get("session_epistemic_status", "none")] += 1
    acc["streams"][result.get("signal_stream", "baseline")] += 1
    acc["patterns"][_pattern_key(result)] += 1
    for f in result.get("findings", []):
        acc["families"][f.get("family", "?")] += 1
    if result.get("has_anti_deception_evidence"):
        acc["has_ad"] += 1
    if keep_example and acc.get("example") is None and result.get("session_epistemic_status") != "none":
        acc["example"] = (dataset, sid, result, _pattern_key(result))


def _new_dataset(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "sessions": 0,
        "status": Counter(),
        "streams": Counter(),
        "families": Counter(),
        "patterns": Counter(),
        "has_ad": 0,
        "example": None,
        "errors": [],
        "completed_files": set(),
        "started_at": time.time(),
        "updated_at": time.time(),
    }


# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------

def _checkpoint_path(out_dir: Path, name: str) -> Path:
    return out_dir / "checkpoints" / f"{_safe_name(name)}.pkl"


def _save_checkpoint(out_dir: Path, d: Dict[str, Any]) -> None:
    d["updated_at"] = time.time()
    cp = _checkpoint_path(out_dir, d["name"])
    cp.parent.mkdir(parents=True, exist_ok=True)
    tmp = cp.with_suffix(".tmp")
    with tmp.open("wb") as fh:
        pickle.dump(d, fh)
    tmp.replace(cp)


def _load_checkpoint(out_dir: Path, name: str) -> Optional[Dict[str, Any]]:
    cp = _checkpoint_path(out_dir, name)
    if not cp.exists():
        return None
    try:
        with cp.open("rb") as fh:
            d = pickle.load(fh)
        # Backward/shape guard
        d.setdefault("errors", [])
        d.setdefault("completed_files", set())
        if not isinstance(d.get("completed_files"), set):
            d["completed_files"] = set(d.get("completed_files", []))
        print(f"[{name}] resume checkpoint: {d.get('sessions', 0):,} sessions, has_AD={d.get('has_ad', 0)}", file=sys.stderr)
        return d
    except Exception as e:
        print(f"[{name}] WARNING: ignoring unreadable checkpoint {cp}: {type(e).__name__}: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Dataset runners
# ---------------------------------------------------------------------------

def run_cowrie_dataset(
    engine: EvidenceEngine,
    name: str,
    paths: List[str],
    progress_every: int,
    keep_example: bool,
    out_dir: Path,
    checkpoint_every: int,
    resume: bool,
) -> Dict[str, Any]:
    files = expand(paths)
    if not files:
        print(f"[{name}] no files matched {paths}", file=sys.stderr)

    d = _load_checkpoint(out_dir, name) if resume else None
    if d is None:
        d = _new_dataset(name)
    t0 = time.time()
    completed: set = d.setdefault("completed_files", set())
    errors: List[str] = d.setdefault("errors", [])

    for path in files:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in completed:
            print(f"[{name}] skip completed: {path}", file=sys.stderr)
            continue
        if not path.exists():
            errors.append(f"{path}: not found")
            _warn(name, f"not found: {path}")
            completed.add(key)
            _save_checkpoint(out_dir, d)
            continue

        before_sessions = d["sessions"]
        try:
            iterator = iter_sessions_in_zip(path, name, errors) if path.suffix.lower() == ".zip" else iter_sessions_in_file(path, name, errors)
            for sid, events in iterator:
                try:
                    r = label_cowrie(engine, events)
                    _fold_result(d, r, name, sid, keep_example=keep_example)
                except Exception as e:
                    errors.append(f"{path}:{sid}: labeling failed: {type(e).__name__}: {e}")
                    _warn(name, f"labeling failed for {path}:{sid}: {type(e).__name__}: {e}")
                    continue

                if progress_every and d["sessions"] % progress_every == 0:
                    rate = (d["sessions"] - before_sessions) / max(1e-9, time.time() - t0)
                    print(
                        f"[{name}] {d['sessions']:,} sessions ({rate:,.0f}/s) has_AD={d['has_ad']}",
                        file=sys.stderr,
                    )
                if checkpoint_every and d["sessions"] % checkpoint_every == 0:
                    _save_checkpoint(out_dir, d)
        except Exception as e:
            errors.append(f"{path}: unexpected file-level failure: {type(e).__name__}: {e}")
            _warn(name, f"unexpected file-level failure, skipping file: {path} ({type(e).__name__}: {e})")
        finally:
            completed.add(key)
            _save_checkpoint(out_dir, d)

    return d


def run_pandacap_command_survey(engine: EvidenceEngine, name: str, survey_path: str) -> Dict[str, Any]:
    """JSONL shape: {"session_id": "0008", "commands": ["uname -a", ...]}.

    Command-only boundary survey. Does not use PANDAcap disk IoCs.
    """
    d = _new_dataset(name)
    with open(survey_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            events = [{"eventid": "cowrie.command.input", "input": c} for c in rec.get("commands", [])]
            r = label_cowrie(engine, events)
            _fold_result(d, r, name, str(rec.get("session_id", d["sessions"])), keep_example=False)
    return d


def _class_from_pandacap_result(r: Dict[str, Any]) -> str:
    fwd = r.get("forward_cti", {})
    if fwd.get("persistence"):
        return "Outlaw/Dota persistence"
    if fwd.get("loader"):
        return "ZIGAZAGA loader"
    if r.get("attacker_commands"):
        return "Recon/commands only"
    return "Brute-force/login only"


def _fold_pandacap_disk_result(d: Dict[str, Any], r: Dict[str, Any]) -> None:
    status = r.get("anti_deception_status", "none")
    stream = "attack_interaction" if (r.get("bidirectional", {}).get("forward_stream") == "rich") else "baseline"
    d["sessions"] += 1
    d["status"][status] += 1
    d["streams"][stream] += 1
    d["has_ad"] += int(bool(r.get("has_anti_deception_evidence")))
    d["pandacap_classes"][_class_from_pandacap_result(r)] += 1


def run_pandacap_disk_jsonl(engine: EvidenceEngine, name: str, survey_path: str) -> Dict[str, Any]:
    """Full disk-artifact survey JSONL.

    Shape per line:
      {"session_id":"0008", "bash_history":[...], "authorized_keys":"..."}
    """
    d = _new_dataset(name)
    d["pandacap_classes"] = Counter()
    with open(survey_path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                bundle = json.loads(line)
                r = label_pandacap_disk(engine, bundle)
                _fold_pandacap_disk_result(d, r)
            except Exception as e:
                d["errors"].append(f"{survey_path}:{line_no}: {type(e).__name__}: {e}")
    return d


def _csv_int(row: Dict[str, str], *names: str) -> int:
    for n in names:
        v = row.get(n)
        if v not in (None, "", "NA"):
            try:
                return int(v)
            except ValueError:
                return 0
    return 0


def _pandacap_csv_class(row: Dict[str, str]) -> str:
    """Classify compact CSV survey rows from the old shell scripts.

    The CSV contains only aggregate disk signals. It is enough for the population
    split and anti-deception boundary, but not for command-level evidence.
    """
    comment = (row.get("authorized_keys_comment") or "").strip()
    attacker_lines = _csv_int(row, "attacker_history_lines")
    if comment == "mdrfckr":
        return "Outlaw/Dota persistence"
    if attacker_lines in {2, 4}:
        return "ZIGAZAGA loader"
    if attacker_lines > 0:
        return "Recon/commands only"
    return "Brute-force/login only"


def run_pandacap_disk_csv(name: str, survey_path: str) -> Dict[str, Any]:
    """Compact CSV survey from survey_pandacap_disk.sh / survey2.sh."""
    d = _new_dataset(name)
    d["pandacap_classes"] = Counter()
    with open(survey_path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            cls = _pandacap_csv_class(row)
            d["sessions"] += 1
            d["status"]["none"] += 1
            d["has_ad"] += 0
            d["streams"]["attack_interaction" if cls != "Brute-force/login only" else "baseline"] += 1
            d["pandacap_classes"][cls] += 1
    return d


def run_pandacap_disk_survey(engine: EvidenceEngine, name: str, survey_path: str) -> Dict[str, Any]:
    suffix = Path(survey_path).suffix.lower()
    if suffix == ".csv":
        return run_pandacap_disk_csv(name, survey_path)
    return run_pandacap_disk_jsonl(engine, name, survey_path)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def hunt_demo(datasets: List[Dict[str, Any]]) -> str:
    """Build one example CTI object and count comparable sessions with the same
    shareable pattern: signal_stream + epistemic_status + conceptual evidence roles.
    """
    ex = next((d["example"] for d in datasets if d.get("example")), None)
    if not ex:
        return "## RQ2 object demonstration\n\nNo non-trivial session found to illustrate.\n"

    name, sid, r, key = ex
    obj = build_cti_object(r, dataset=name, session_id=sid)
    comparable = sum(d.get("patterns", Counter()).get(key, 0) for d in datasets)
    hunt = {
        "signal_stream": obj.get("signal_stream"),
        "evidence_roles": obj.get("evidence_roles"),
        "epistemic_status": obj.get("epistemic_status"),
    }
    return "\n".join([
        "## RQ2 object demonstration: object -> hunt -> comparable sessions\n",
        f"Example session `{sid}` ({name}) -> CTI object:\n",
        "```json",
        json.dumps(obj, indent=2, ensure_ascii=False)[:1600],
        "```\n",
        "Hunt query derived from shareable fields only:\n",
        "```json",
        json.dumps(hunt, indent=2, ensure_ascii=False),
        "```\n",
        f"Comparable sessions with the same shareable pattern: **{comparable:,}**.\n",
    ])


def _jsonable_dataset(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if k == "example":
            continue
        if isinstance(v, Counter):
            out[k] = dict(v)
        elif isinstance(v, set):
            out[k] = sorted(v)
        else:
            out[k] = v
    return out


def write_summary(out_dir: Path, datasets: List[Dict[str, Any]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    present = [s for s in LADDER if any(d["status"].get(s) for d in datasets)]
    if not present:
        present = ["none"]

    lines = [
        "# Full-corpus run (generated)\n",
        "`has_AD` = share reaching the anti-deception floor (`weak_proxy`+).\n",
        "| dataset | sessions | " + " | ".join(present) + " | has_AD |",
        "|" + "---|" * (len(present) + 3),
    ]
    for d in datasets:
        n = d["sessions"] or 1
        cells = [d["name"], f"{d['sessions']:,}"]
        for s in present:
            c = d["status"].get(s, 0)
            cells.append(f"{c:,} ({100*c/n:.2f}%)")
        cells.append(f"{d['has_ad']:,} ({100*d['has_ad']/n:.3f}%)")
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")

    for d in datasets:
        if d.get("pandacap_classes"):
            lines.append(f"## {d['name']} forward-CTI classes\n")
            lines.append("| class | sessions |")
            lines.append("|---|---:|")
            for cls, c in d["pandacap_classes"].most_common():
                lines.append(f"| {cls} | {c:,} |")
            lines.append("")

    stream_set = sorted(set().union(*(set(d["streams"]) for d in datasets)))
    lines.append("## Bidirectional signal streams\n")
    lines.append("| dataset | " + " | ".join(stream_set) + " |")
    lines.append("|" + "---|" * (len(stream_set) + 1))
    for d in datasets:
        cells = [d["name"]] + [f"{d['streams'].get(s, 0):,}" for s in stream_set]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")

    any_errors = any(d.get("errors") for d in datasets)
    if any_errors:
        lines.append("## Skipped or problematic inputs\n")
        for d in datasets:
            errs = d.get("errors") or []
            if not errs:
                continue
            lines.append(f"### {d['name']}\n")
            for e in errs[:50]:
                lines.append(f"- {e}")
            if len(errs) > 50:
                lines.append(f"- ... {len(errs)-50} more")
            lines.append("")

    lines.append(hunt_demo(datasets))

    (out_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    with (out_dir / "summary.json").open("w", encoding="utf-8") as fh:
        json.dump([_jsonable_dataset(d) for d in datasets], fh, indent=2)

    print((out_dir / "summary.md").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--cowrie", action="append", default=[], metavar="PATH",
        help="Cowrie file/dir/glob/.zip; repeatable. Pair each with --name.",
    )
    ap.add_argument(
        "--pandacap-command-survey", action="append", default=[], metavar="JSONL",
        help="Command-only PANDAcap survey: {'session_id', 'commands'} per line.",
    )
    ap.add_argument(
        "--pandacap-survey", action="append", default=[], metavar="JSONL",
        help="Deprecated alias for --pandacap-command-survey.",
    )
    ap.add_argument(
        "--pandacap-disk-survey", action="append", default=[], metavar="PATH",
        help="PANDAcap disk survey. Accepts full JSONL artifacts or compact CSV survey.",
    )
    ap.add_argument("--name", action="append", default=[], metavar="NAME")
    ap.add_argument("--registry", default=str(ROOT / "evidence_registry.yaml"))
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "corpus_results"))
    ap.add_argument("--progress-every", type=int, default=100000)
    ap.add_argument("--checkpoint-every", type=int, default=100000)
    ap.add_argument("--no-resume", action="store_true", help="Ignore existing checkpoints and start from scratch.")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    engine = EvidenceEngine(args.registry)
    datasets: List[Dict[str, Any]] = []
    names = list(args.name)
    ni = 0

    for cw in args.cowrie:
        name = names[ni] if ni < len(names) else Path(cw).stem
        ni += 1
        datasets.append(run_cowrie_dataset(
            engine, name, [cw], args.progress_every, keep_example=True,
            out_dir=out_dir, checkpoint_every=args.checkpoint_every,
            resume=not args.no_resume,
        ))

    for ps in list(args.pandacap_command_survey) + list(args.pandacap_survey):
        name = names[ni] if ni < len(names) else "pandacap_command"
        ni += 1
        datasets.append(run_pandacap_command_survey(engine, name, ps))

    for ps in args.pandacap_disk_survey:
        name = names[ni] if ni < len(names) else "pandacap_disk"
        ni += 1
        datasets.append(run_pandacap_disk_survey(engine, name, ps))

    if not datasets:
        raise SystemExit("provide at least one --cowrie, --pandacap-command-survey, or --pandacap-disk-survey path")

    write_summary(out_dir, datasets)


if __name__ == "__main__":
    main()

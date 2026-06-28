#!/usr/bin/env python3
"""
generate_and_evaluate.py  —  (B) discrimination rates, (C) confounder stress
test, (D) naive-baseline comparison, all over PARAMETERISED testbed episodes.

What it does, and why each piece exists:

  (B) For every class it generates N benign + N attack episodes with randomised
      command order and injected benign noise, runs them through the UNCHANGED
      EvidenceEngine, and reports sensitivity (TPR), specificity (TNR), FPR,
      precision and F1 with 95% bootstrap confidence intervals. This turns the
      6 hand-built pairs into a *measured* classifier.

  (C) For the semantically-gated relations (R2/R3/R4) it also generates
      confounder episodes: the SAME anti-deception markers as the attack, but
      with the gating context removed (no suppression / no comparable twin / no
      decoy graph). A correct calculus must keep these BELOW the floor. This is
      the anti-circularity test: markers alone are never enough.

  (D) A naive baseline ("any anti-deception-relevant marker present => flag")
      is run on the same benign + confounder episodes. Its false-positive rate
      is contrasted with the relation-gated calculus (which should be ~0). This
      shows the relation gating buys measurable specificity.

Ground truth is mechanical: each episode carries the class/variant it was built
from; the engine never sees it. Run:  python eval/generate_and_evaluate.py
"""
from __future__ import annotations
import argparse, csv, json, random, sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from adi_evidence_engine import EvidenceEngine                       # noqa: E402
from class_specs import build_episode, ALL_CLASSES, CONFOUNDER_CLASSES  # noqa: E402

# families a naive (ungated) detector would treat as anti-deception evidence
NAIVE_POSITIVE_FAMILIES = {"E1a", "E2", "E3a", "E4", "D0"}


def families_present(engine: EvidenceEngine, kwargs: Dict[str, Any]) -> set:
    """Families a marker pre-pass + asserted facts would surface (for the naive
    baseline). Mirrors what an ungated keyword detector could see."""
    fams = set(kwargs.get("asserted_families", {}).keys())
    for _id, fam, rx in engine.markers:
        for c in kwargs.get("commands", []):
            if rx.search(c):
                fams.add(fam)
                break
    return fams


def run_episode(engine: EvidenceEngine, kwargs: Dict[str, Any]) -> bool:
    """True iff the calculus reaches the anti-deception floor (weak_proxy+)."""
    call = {k: v for k, v in kwargs.items() if k != "intent"}
    res = engine.label(**call)
    return bool(res["has_anti_deception_evidence"])


def _ci(values: List[float], reps: int, rng: random.Random) -> Tuple[float, float]:
    if not values:
        return (float("nan"), float("nan"))
    boots = []
    n = len(values)
    for _ in range(reps):
        s = [values[rng.randrange(n)] for _ in range(n)]
        boots.append(sum(s) / n)
    boots.sort()
    lo = boots[int(0.025 * reps)]
    hi = boots[int(0.975 * reps)]
    return (lo, hi)


def evaluate(n: int, seed: int, boot: int) -> Dict[str, Any]:
    engine = EvidenceEngine(str(ROOT / "evidence_registry.yaml"))
    rng = random.Random(seed)

    # per-episode outcomes: list of (class, variant, intent_positive, calc_flag, naive_flag)
    rows: List[Tuple[str, str, bool, bool, bool]] = []

    for cls in ALL_CLASSES:
        variants = ["benign", "attack"]
        if cls in CONFOUNDER_CLASSES:
            variants.append("confounder")
        for variant in variants:
            for _ in range(n):
                kw = build_episode(cls, variant, rng)
                intent_pos = (kw["intent"] == "anti_deception")
                calc = run_episode(engine, kw)
                naive = bool(families_present(engine, kw) & NAIVE_POSITIVE_FAMILIES)
                rows.append((cls, variant, intent_pos, calc, naive))

    # ---- (B) per-class + overall confusion (E1b handled separately) ----
    def confusion(subset, positive_is_attack=True):
        tp = fp = tn = fn = 0
        for cls, variant, intent_pos, calc, _naive in subset:
            gt = intent_pos
            if calc and gt: tp += 1
            elif calc and not gt: fp += 1
            elif not calc and not gt: tn += 1
            else: fn += 1
        return tp, fp, tn, fn

    def rates(tp, fp, tn, fn):
        tpr = tp / (tp + fn) if (tp + fn) else float("nan")
        tnr = tn / (tn + fp) if (tn + fp) else float("nan")
        fpr = fp / (fp + tn) if (fp + tn) else float("nan")
        prec = tp / (tp + fp) if (tp + fp) else float("nan")
        f1 = (2 * prec * tpr / (prec + tpr)) if (prec == prec and tpr == tpr and (prec + tpr)) else float("nan")
        return dict(tpr=tpr, tnr=tnr, fpr=fpr, precision=prec, f1=f1)

    per_class = {}
    discrimination_classes = [c for c in ALL_CLASSES if c != "E1b_generic_recon_control"]
    for cls in discrimination_classes:
        subset = [r for r in rows if r[0] == cls]
        tp, fp, tn, fn = confusion(subset)
        per_class[cls] = {**rates(tp, fp, tn, fn), "tp": tp, "fp": fp, "tn": tn, "fn": fn, "n": len(subset)}

    overall_subset = [r for r in rows if r[0] in discrimination_classes]
    tp, fp, tn, fn = confusion(overall_subset)
    overall = {**rates(tp, fp, tn, fn), "tp": tp, "fp": fp, "tn": tn, "fn": fn, "n": len(overall_subset)}

    # bootstrap CIs on overall TPR / FPR (per-episode correctness as 0/1)
    pos_correct = [1.0 if (calc) else 0.0 for cls, v, ip, calc, _ in overall_subset if ip]
    neg_correct = [0.0 if (calc) else 1.0 for cls, v, ip, calc, _ in overall_subset if not ip]
    overall["tpr_ci"] = _ci(pos_correct, boot, rng)
    overall["tnr_ci"] = _ci(neg_correct, boot, rng)

    # ---- (C) confounder stress test: flag-rate on confounder episodes (want 0) ----
    conf = {}
    for cls in CONFOUNDER_CLASSES:
        subset = [r for r in rows if r[0] == cls and r[1] == "confounder"]
        flagged = sum(1 for r in subset if r[3])
        conf[cls] = {"n": len(subset), "calc_flagged": flagged, "calc_fpr": flagged / len(subset) if subset else float("nan")}

    # ---- (D) naive baseline vs calculus on all NEGATIVE episodes (benign+confounder) ----
    neg = [r for r in rows if not r[2] and r[0] in discrimination_classes]
    naive_fp = sum(1 for r in neg if r[4])
    calc_fp = sum(1 for r in neg if r[3])
    baseline = {
        "negatives": len(neg),
        "naive_false_positives": naive_fp,
        "naive_fpr": naive_fp / len(neg) if neg else float("nan"),
        "calculus_false_positives": calc_fp,
        "calculus_fpr": calc_fp / len(neg) if neg else float("nan"),
    }

    # ---- E1b ambiguity control: correct abstention rate (both variants -> negative) ----
    e1b = [r for r in rows if r[0] == "E1b_generic_recon_control"]
    e1b_abstained = sum(1 for r in e1b if not r[3])
    e1b_result = {"n": len(e1b), "abstained": e1b_abstained,
                  "abstention_rate": e1b_abstained / len(e1b) if e1b else float("nan")}

    return {"n_per_variant": n, "seed": seed, "bootstrap_reps": boot,
            "per_class": per_class, "overall": overall, "confounder": conf,
            "baseline": baseline, "e1b_control": e1b_result, "rows": rows}


def write_outputs(out_dir: Path, res: Dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    # metrics.csv (per-class)
    with (out_dir / "metrics.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["class", "n", "tp", "fp", "tn", "fn", "tpr", "tnr", "fpr", "precision", "f1"])
        for cls, m in res["per_class"].items():
            w.writerow([cls, m["n"], m["tp"], m["fp"], m["tn"], m["fn"],
                        f"{m['tpr']:.3f}", f"{m['tnr']:.3f}", f"{m['fpr']:.3f}",
                        f"{m['precision']:.3f}", f"{m['f1']:.3f}"])

    o = res["overall"]; b = res["baseline"]
    def pct(x): return f"{100*x:.1f}%" if x == x else "n/a"
    lines = []
    lines.append("# Evaluation metrics (generated)\n")
    lines.append(f"Episodes per variant: **{res['n_per_variant']}**  |  bootstrap reps: {res['bootstrap_reps']}  |  seed: {res['seed']}\n")
    lines.append("## (B) Discrimination under ground truth\n")
    lines.append("Five discriminable classes (E1b is the ambiguity control, reported separately).\n")
    lines.append("| class | n | TPR | TNR | FPR | precision | F1 |")
    lines.append("|---|---|---|---|---|---|---|")
    for cls, m in res["per_class"].items():
        lines.append(f"| {cls} | {m['n']} | {pct(m['tpr'])} | {pct(m['tnr'])} | {pct(m['fpr'])} | {pct(m['precision'])} | {m['f1']:.3f} |")
    lines.append(f"| **overall** | {o['n']} | {pct(o['tpr'])} | {pct(o['tnr'])} | {pct(o['fpr'])} | {pct(o['precision'])} | {o['f1']:.3f} |")
    lines.append("")
    lines.append(f"Overall TPR 95% CI: [{pct(o['tpr_ci'][0])}, {pct(o['tpr_ci'][1])}]  |  "
                 f"Overall TNR 95% CI: [{pct(o['tnr_ci'][0])}, {pct(o['tnr_ci'][1])}]\n")

    lines.append("## (C) Confounder stress test\n")
    lines.append("Same anti-deception markers as the attack, but the gating context removed. "
                 "A correct calculus keeps these **below** the floor (flag rate 0).\n")
    lines.append("| gated relation | confounder episodes | flagged | flag rate |")
    lines.append("|---|---|---|---|")
    for cls, m in res["confounder"].items():
        lines.append(f"| {cls} | {m['n']} | {m['calc_flagged']} | {pct(m['calc_fpr'])} |")
    lines.append("")

    lines.append("## (D) Naive baseline vs. relation-gated calculus\n")
    lines.append("On all negative episodes (benign + confounder). The naive detector flags any "
                 "anti-deception-relevant marker regardless of relation.\n")
    lines.append(f"- negative episodes: **{b['negatives']}**")
    lines.append(f"- naive baseline false positives: **{b['naive_false_positives']}** (FPR {pct(b['naive_fpr'])})")
    lines.append(f"- relation-gated calculus false positives: **{b['calculus_false_positives']}** (FPR {pct(b['calculus_fpr'])})\n")

    e = res["e1b_control"]
    lines.append("## E1b ambiguity control\n")
    lines.append(f"Generic reconnaissance, observationally identical whether benign or adversarial. "
                 f"Correct behaviour is abstention (stay below floor) for both.\n")
    lines.append(f"- episodes: **{e['n']}**  |  abstained (correct): **{e['abstained']}**  |  abstention rate: {pct(e['abstention_rate'])}\n")
    (out_dir / "metrics.md").write_text("\n".join(lines), encoding="utf-8")

    # raw per-episode rows for full reproducibility
    with (out_dir / "episodes.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["class", "variant", "intent_positive", "calculus_flagged", "naive_flagged"])
        for cls, variant, ip, calc, naive in res["rows"]:
            w.writerow([cls, variant, ip, calc, naive])
    print((out_dir / "metrics.md").read_text(encoding="utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200, help="episodes per variant per class")
    ap.add_argument("--seed", type=int, default=20260625)
    ap.add_argument("--bootstrap", type=int, default=2000)
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "results"))
    args = ap.parse_args()
    res = evaluate(args.n, args.seed, args.bootstrap)
    write_outputs(Path(args.out_dir), res)


if __name__ == "__main__":
    main()

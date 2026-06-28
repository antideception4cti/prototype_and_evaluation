"""
cti_object_builder

Minimal CTI-object layer for the ADI evidence model current.
It consumes an EvidenceEngine result and emits a compact, STIX-mappable
intermediate object with calculated confidence, actionability, shareability,
and explicit non-shareable deception context.

This file is deliberately small: it does not create full STIX bundles and it
does not validate anti-deception intent. It turns the already-bounded evidence
result into a shareable CTI representation.
"""
from __future__ import annotations

import hashlib
import math
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

# implementation family names -> conceptual roles used in the paper.
ROLE_MAP = {
    "D0": "D",
    "E1a": "E1a",
    "E1b": "E1b",
    "E2": "E2",
    "E3a": "E3a",
    "E3b": "E3b",
    "E4": "E4",
    "E5a": "E5",
    "E5b": "E5",
    "M1": "M",
    "M2": "M",
}

EVIDENTIAL_ROLE = {
    "D": "Direct",
    "E1a": "Proxy",
    "E1b": "Weak",
    "E2": "Proxy",
    "E3a": "Proxy",
    "E3b": "Meta",
    "E4": "Derived",
    "E5": "Weak",
    "R": "Rel.",
    "M": "Mod.",
}

BOUNDARY = {
    "D": "Direct deception interaction; not anti-deception by itself.",
    "E1a": "Source-grounded environment validation proxy.",
    "E1b": "Generic host reconnaissance; weak context only.",
    "E2": "Human-presence or environment-age proxy; source-dependent.",
    "E3a": "Active protocol or honeypot probing proxy.",
    "E3b": "Technical fingerprint metadata; correlation support, not anti-deception by itself.",
    "E4": "Artifact or structural plausibility evidence; derived and domain-dependent.",
    "E5": "Operational constraint context; weak and often ordinary workflow.",
    "R": "Relation-supported interpretation; requires linkage, order, and profile gates.",
    "M": "Modifier for confidence/actionability only.",
}

PROFILE_RELIABILITY = {
    "cowrie_shell": 0.45,
    "honeypot_pcap": 0.55,
    "full_system": 0.75,
    "decoy_instrumented": 0.85,
    "testbed": 0.95,
}

FAMILY_SPECIFICITY = {
    "D": 0.75,
    "E1a": 0.85,
    "E1b": 0.25,
    "E2": 0.80,
    "E3a": 0.85,
    "E3b": 0.55,
    "E4": 0.65,
    "E5": 0.30,
    "M": 0.20,
    "R": 0.75,
}

# Numeric interpretation confidence for the headline status.
STATUS_NUMERIC = {
    "none": 0,
    "not_supported": 0,
    "observed_marker": 25,
    "weak_context": 25,
    "weak_proxy": 50,
    "sequence_supported": 75,
    "strong_proxy": 75,
    "testbed_grounded": 95,
    "technical_fingerprint": 45,
    "direct_deception_interaction": 65,
    "feedback_signal": 25,
    "cautious_derived": 35,
}

# Hard caps prevent weak context from becoming high confidence through volume alone.
STATUS_CAP = {
    "none": 20,
    "not_supported": 20,
    "observed_marker": 35,
    "weak_context": 35,
    "weak_proxy": 60,
    "sequence_supported": 80,
    "strong_proxy": 80,
    "testbed_grounded": 95,
    "technical_fingerprint": 50,
    "direct_deception_interaction": 75,
    "feedback_signal": 35,
    "cautious_derived": 45,
}

ACTION_BY_SCORE = [(75, "high"), (45, "medium"), (1, "low"), (0, "none")]


def _sha8(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]


def _label_from_score(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _families(result: Dict[str, Any]) -> List[str]:
    fams = []
    for f in result.get("findings", []):
        fam = ROLE_MAP.get(f.get("family"), f.get("family"))
        if fam and fam not in fams:
            fams.append(fam)
    return fams


def _headline_status(result: Dict[str, Any]) -> str:
    status = result.get("session_epistemic_status") or "none"
    off = set(result.get("off_ladder_tags") or [])
    # If the ladder status is none but the result contains useful off-ladder CTI,
    # calculate confidence against that off-ladder interpretation.
    if status in {"none", "not_supported"}:
        if "direct_deception_interaction" in off:
            return "direct_deception_interaction"
        if "technical_fingerprint" in off:
            return "technical_fingerprint"
    # Direct attack interaction without anti-deception is still a CTI object.
    stream = result.get("signal_stream")
    direct = result.get("direct_signal")
    if status in {"none", "not_supported"} and stream == "attack_interaction" and direct:
        return "direct_deception_interaction"
    return status


def calculate_confidence(result: Dict[str, Any]) -> Dict[str, Any]:
    """Return ordinal confidence with an auditable calculation basis.

    Formula:
      raw = .45*status + .25*sensor_reliability + .20*evidence_specificity
            + .10*interaction_depth + relation_bonus
      confidence = min(raw, status_cap)

    The status cap is the important safety gate: weak context cannot become high
    confidence through command volume or sensor quality alone.
    """
    status = _headline_status(result)
    profile = result.get("profile", "unknown")
    fams = _families(result)
    command_count = int((result.get("facts") or {}).get("command_count") or result.get("command_count") or 0)
    if command_count == 0:
        # The old adapters keep command_count in facts, but most result objects do not.
        # Use finding count as a conservative fallback, not as equivalent depth.
        command_count = min(len(result.get("findings", [])), 3)

    status_component = STATUS_NUMERIC.get(status, 0)
    sensor_component = 100 * PROFILE_RELIABILITY.get(profile, 0.50)
    specificity_component = 100 * max((FAMILY_SPECIFICITY.get(f, 0.25) for f in fams), default=0.10)
    depth_component = 100 * min(math.log1p(max(command_count, 0)) / math.log1p(20), 1.0)
    relation_bonus = min(10 * len(result.get("relations_fired") or []), 20)

    raw = (0.45 * status_component +
           0.25 * sensor_component +
           0.20 * specificity_component +
           0.10 * depth_component +
           relation_bonus)
    cap = STATUS_CAP.get(status, 60)
    score = int(round(min(raw, cap)))
    return {
        "score": score,                       # STIX-compatible 0..100 confidence field
        "level": _label_from_score(score),    # paper-facing ordinal label
        "basis": {
            "headline_status": status,
            "status_component": round(status_component, 1),
            "sensor_reliability": round(sensor_component, 1),
            "evidence_specificity": round(specificity_component, 1),
            "interaction_depth": round(depth_component, 1),
            "relation_bonus": relation_bonus,
            "status_cap": cap,
            "formula": "min(.45*status + .25*sensor + .20*specificity + .10*depth + relation_bonus, status_cap)",
        },
    }


def calculate_shareability(result: Dict[str, Any], *, exact_values_included: bool = False) -> Dict[str, Any]:
    """Compute shareability and the non-shareable deception context.

    Shareability measures risk of revealing local deception logic, not legal
    classification. The builder assumes sanitized observables by default.
    """
    fams = set(_families(result))
    rels = set(result.get("relations_fired") or [])
    status = _headline_status(result)
    stream = result.get("signal_stream", "baseline")

    risk = 15
    reasons = []
    non_shareable = ["raw logs", "sensor identity", "internal source path"]

    if stream in {"attack_interaction", "combined"} or "D" in fams:
        risk += 20
        reasons.append("direct decoy interaction can reveal deployed deception assets")
        non_shareable += ["exact decoy name or object id", "decoy placement", "credential/token values"]
    if "E4" in fams:
        risk += 25
        reasons.append("artifact plausibility evidence can reveal naming and structure assumptions")
        non_shareable += ["internal naming conventions", "account/role structure", "file or document templates"]
    if any(r.startswith("R3") for r in rels):
        risk += 10
        reasons.append("suppression relation can reveal observable follow-up expectations")
        non_shareable += ["expected follow-up behavior", "observation-window design"]
    if any(r.startswith("R2") for r in rels):
        risk += 20
        reasons.append("decoy traversal can reveal graph or reference design")
        non_shareable += ["decoy graph design", "embedded reference relationships"]
    if any(r.startswith("R4") for r in rels) or status == "testbed_grounded":
        risk += 25
        reasons.append("counterfactual avoidance exposes matched decoy/baseline design")
        non_shareable += ["matched real-twin identity", "ground-truth labels", "counterfactual baseline"]
    if exact_values_included:
        risk += 40
        reasons.append("exact local values are included")
        non_shareable += ["exact usernames", "exact URLs", "exact file names", "exact credential material"]
    if fams == {"E3b"}:
        risk = max(0, risk - 20)
        reasons.append("technical fingerprint metadata is usually shareable after sensor removal")

    risk = max(0, min(100, risk))
    if exact_values_included:
        level = "internal_only"
    elif risk >= 75:
        level = "restricted"
    elif risk >= 35:
        level = "community"
    else:
        level = "public"

    # De-duplicate while preserving order.
    seen = set()
    non_shareable_dedup = []
    for x in non_shareable:
        if x not in seen:
            non_shareable_dedup.append(x); seen.add(x)

    return {
        "level": level,
        "risk_score": risk,
        "rationale": reasons or ["no deception-specific deployment detail required for recipient use"],
        "shareable_fields": [
            "indicator_family", "evidence_roles", "epistemic_status",
            "confidence", "actionability", "defensive_use", "recommended_action",
        ],
        "non_shareable_context": non_shareable_dedup,
    }


def _actionability(result: Dict[str, Any], confidence_score: int) -> Dict[str, Any]:
    status = _headline_status(result)
    stream = result.get("signal_stream", "baseline")
    fams = set(_families(result))

    if status in {"weak_context", "observed_marker", "none", "not_supported"}:
        level = "low" if confidence_score > 0 else "none"
        use = "situational awareness or clustering only"
        action = "retain as context; do not escalate as anti-deception evidence"
    elif "E3b" in fams and not result.get("has_anti_deception_evidence"):
        level = "medium"
        use = "toolchain correlation and hunting for recurring fingerprints"
        action = "hunt for the same technical fingerprint across sensors"
    elif result.get("has_anti_deception_evidence"):
        level = "high" if confidence_score >= 70 else "medium"
        use = "hunt for comparable validation or avoidance behavior; harden comparable assets or decoys"
        action = "search for the same evidence-role sequence and review exposed artifact classes"
    elif stream == "attack_interaction":
        level = "medium"
        use = "triage direct decoy interaction and hunt for comparable credential or payload use"
        action = "investigate related direct interaction indicators"
    else:
        level = _label_from_score(confidence_score)
        use = "contextual enrichment"
        action = "retain for correlation"
    return {"level": level, "defensive_use": use, "recommended_action": action}


def _evidence_roles(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for finding in result.get("findings", []):
        fam_impl = finding.get("family")
        role = ROLE_MAP.get(fam_impl, fam_impl)
        out.append({
            "role": role,
            "implementation_family": fam_impl,
            "evidential_role": EVIDENTIAL_ROLE.get(role, "Unknown"),
            "epistemic_status": finding.get("epistemic_status"),
            "observables": finding.get("evidence", [])[:5],
            "boundary": BOUNDARY.get(role, "No boundary text registered."),
        })
    # Relation objects are included explicitly because current treats R as a role.
    for rel in result.get("relations_fired") or []:
        out.append({
            "role": "R",
            "implementation_family": rel,
            "evidential_role": "Rel.",
            "epistemic_status": "relation_supported",
            "observables": [rel],
            "boundary": BOUNDARY["R"],
        })
    return out


def build_cti_object(
    result: Dict[str, Any],
    *,
    dataset: Optional[str] = None,
    session_id: Optional[str] = None,
    artifact_type: str = "deception_telemetry_session",
    exact_values_included: bool = False,
) -> Dict[str, Any]:
    """Build a compact STIX-mappable CTI object from one engine result."""
    confidence = calculate_confidence(result)
    shareability = calculate_shareability(result, exact_values_included=exact_values_included)
    action = _actionability(result, confidence["score"])
    stream = result.get("signal_stream", "baseline")
    has_ad = bool(result.get("has_anti_deception_evidence"))

    object_seed = f"{dataset or ''}:{session_id or ''}:{stream}:{result.get('session_epistemic_status','')}"
    object_id = f"x-deception-cti--{_sha8(object_seed)}"

    if has_ad and stream == "combined":
        indicator_family = "combined"
    elif has_ad:
        indicator_family = "anti_deception"
    elif stream == "attack_interaction":
        indicator_family = "direct_attack"
    else:
        indicator_family = "context"

    return {
        "type": "x-deception-cti-object",
        "spec_version": "2.1-compatible",
        "id": object_id,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": dataset,
        "session_id": session_id,
        "artifact_type": artifact_type,
        "indicator_family": indicator_family,
        "signal_stream": stream,
        "direct_signal": result.get("direct_signal"),
        "epistemic_status": _headline_status(result),
        "has_anti_deception_evidence": has_ad,
        "evidence_roles": _evidence_roles(result),
        "relations_fired": result.get("relations_fired", []),
        "off_ladder_tags": result.get("off_ladder_tags", []),
        "confidence": confidence,
        "actionability": action["level"],
        "defensive_use": action["defensive_use"],
        "recommended_action": action["recommended_action"],
        "shareability": shareability,
        "stix_mapping": {
            "observations": "observed-data",
            "recurring_patterns": "indicator or attack-pattern with custom properties",
            "interpretation_and_caveats": "report/note/opinion/custom properties",
            "defensive_response": "course-of-action",
            "confidence": "STIX confidence 0..100",
            "distribution_control": "marking-definition/TLP plus non_shareable_context redaction",
        },
    }

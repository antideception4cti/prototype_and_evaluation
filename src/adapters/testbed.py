"""
adapter_testbed — maps ONE testbed session (server-side events.jsonl lines)
to EvidenceEngine inputs for the `testbed` profile.

The testbed is the only profile that can satisfy R2/R3/R4: it has a decoy graph
(is_decoy + twin_id), payload_visibility (the server sees whether a use/download
happened), and comparable twins with exposure evidence (catalog enumeration).
Object-axis families (D0, E4) are asserted from server facts, not shell regex.
"""
from __future__ import annotations
from typing import Any, Dict, List

PLAUSIBILITY = {"owner", "created_days_ago", "last_used_days_ago", "naming_scheme", "members"}


def label_testbed(engine, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    ev = sorted(events, key=lambda e: e.get("ts", 0))
    decoy_touched = any(e.get("is_decoy") for e in ev if e.get("object_id"))
    decoy_views = [e for e in ev if e.get("action_type") == "view_metadata" and e.get("is_decoy")]
    plaus_on_decoy = any(set(e.get("fields_accessed", [])) & PLAUSIBILITY for e in decoy_views)
    decoy_used = any(e.get("action_type") == "use" and e.get("is_decoy") for e in ev)
    baseline_used = any(e.get("action_type") == "use" and e.get("is_decoy") is False for e in ev)
    fingerprinted = any(e.get("action_type") == "fingerprint" for e in ev)
    env_check = any(e.get("action_type") == "environment_check" for e in ev)
    canary_dl = any(e.get("action_type") == "download" and e.get("is_decoy") for e in ev)
    aborted = any(e.get("outcome") in {"aborted", "suppressed", "avoided"}
                  or e.get("action_type") in {"abort", "suppress", "avoid"}
                  for e in ev)
    enumerated = any(e.get("action_type") == "enumerate" for e in ev)
    preceding_check = env_check or fingerprinted or bool(decoy_views) or canary_dl

    # object-axis families asserted from server facts
    asserted: Dict[str, List[str]] = {}
    if decoy_touched:
        asserted["D0"] = ["d0:decoy_touched"]
    if plaus_on_decoy:
        asserted["E4"] = ["e4:plausibility_fields_on_decoy"]
    if fingerprinted:
        asserted["E3a"] = ["e3a:service_fingerprint"]
    if env_check:
        asserted["E1b"] = ["e1b:host_env_check"]

    # the counterfactual-avoidance ground truth: looked at decoy, used the twin
    avoidance = decoy_touched and (not decoy_used) and baseline_used

    distinct_decoys = len({e.get("object_id") for e in ev if e.get("is_decoy") and e.get("object_id")})

    relation_context = {
        "same_actor": True, "event_order": True, "full_event_order": True,
        # R2 needs an ACTUAL decoy->referenced-object traversal (breadcrumb chain),
        # not just touching one decoy. Matched-pair playbooks don't traverse -> R2 off.
        "decoy_graph": True,
        "known_reference_relation": distinct_decoys >= 2,
        # R3 inputs: the server CAN see the payload stage -> payload_visibility True
        "preceding_check": preceding_check,
        # R3 is post-check suppression, not mere post-check absence. Without this
        # explicit gate, benign check-only traces and breadcrumb traversal are
        # incorrectly promoted to sequence-supported anti-deception evidence.
        "suppression_evidence": aborted,
        "payload_visibility": True,
        "observation_window": True,
        # R4 inputs: comparable twin + exposure evidence (catalog) + ground truth
        "comparable_object": True,
        "ground_truth": True,
        "exposure_evidence": enumerated or bool(decoy_views),
        "decoy_touched": decoy_touched,
        "counterfactual_avoidance": avoidance,
    }
    # Only known decoy interaction belongs to the direct deception stream.
    # Non-decoy setup/enumeration in the controlled testbed is baseline/context.
    direct_signal = "object_interaction" if decoy_touched else "connection_or_protocol_observation"
    facts = {"direct_signal": direct_signal, "command_count": 0}
    res = engine.label([], facts, profile="testbed",
                       relation_context=relation_context, asserted_families=asserted)
    res["avoidance_ground_truth"] = avoidance
    return res

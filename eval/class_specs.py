"""
class_specs.py — the six discrimination classes as *parameterised* episode
generators, each grounded in a published procedure.

Every class produces three variant kinds:
  * benign     : surface-similar to the attack but without the gating relation
  * attack     : the anti-deception episode (ground-truth positive)
  * confounder : the SAME anti-deception markers as `attack`, but with the
                 semantic gating context removed (no suppression / no comparable
                 twin / no decoy graph). Tests that markers ALONE never reach the
                 floor — the anti-circularity core.

The episode is returned as keyword arguments for EvidenceEngine.label():
    dict(commands, facts, profile, relation_context, asserted_families, intent)
`intent` is the ground-truth class kept OUT of the engine; it is used only to
score the engine afterwards.

PROVENANCE (the procedures are adapted from the literature, not invented):
  R1 multistage environment probe   <- sandbox/VM-evasion check sequences
                                        [afianian2019malware; mitre_attack_t1497_001]
  E3a honeypot/protocol probe        <- honeypot fingerprinting via protocol/banner
                                        [vetterl2018bitter; srinivasa2023gotta]
  E2 wear-and-tear environment age   <- absence-of-usage sandbox checks
                                        [miramirkhani2017spotless; mitre_attack_t1497_002]
  E4/R3 plausibility-then-suppress   <- honeytoken/artifact plausibility inspection
                                        [reti2020rabbit; aggarwal2021decoys]
  R2 breadcrumb traversal            <- references in networks of decoy elements
                                        [reti2020rabbit]
  R4 counterfactual decoy avoidance  <- two-sided deception / choosing the real twin
                                        [aggarwal2021decoys; ferguson2019tularosa]
  E1b generic reconnaissance (control)<- ordinary recon; deliberately ambiguous
                                        [cowrie]
"""
from __future__ import annotations
import random
from typing import Any, Dict, List

PROFILE = "testbed"  # the ground-truth setting; ceilings are highest here

# neutral filler that trips no marker (verified against the registry patterns)
_FILLER = ["ls", "pwd", "cd /var", "echo test", "mkdir tmp1", "true", "clear"]

# marker command fragments per family (used to build episodes)
_E1A = ["systemd-detect-virt", "dmidecode -t system", "cat /proc/1/cgroup", "lspci"]
_E1B = ["whoami", "uname -a", "id", "hostname", "nproc"]
_E2  = ["cat ~/.bash_history", "last", "w", "ls -la /var/log/wtmp"]
_E3A = ["grep cowrie /etc/passwd", "cat /etc/issue | grep -i honeypot", "ls /home | grep kippo"]
_E4  = ["stat /home/svc_backup/credentials.txt", "ls -la /home/svc_remote", "chage -l svc_backup"]


def _noise(rng: random.Random, n: int) -> List[str]:
    return [rng.choice(_FILLER) for _ in range(n)]


def _shuffle(rng: random.Random, core: List[str], noise_n: int) -> List[str]:
    cmds = list(core) + _noise(rng, noise_n)
    rng.shuffle(cmds)
    return cmds


def build_episode(class_name: str, variant: str, rng: random.Random) -> Dict[str, Any]:
    """Return engine kwargs + ground-truth intent for one parameterised episode."""
    noise_n = rng.randint(0, 4)
    base = dict(profile=PROFILE, asserted_families={}, relation_context={
        "same_actor": True, "event_order": True, "full_event_order": True})
    base["facts"] = {}

    # ----- environment, content-gated classes -----
    if class_name == "R1_multistage_env_probe":
        if variant == "attack":   # two distinct hard-probe families in one actor trace
            core = [rng.choice(_E1A), rng.choice(_E3A)]
            intent = "anti_deception"
        else:                     # benign: a single generic-recon command
            core = [rng.choice(_E1B)]
            intent = "benign"
        cmds = _shuffle(rng, core, noise_n)
        base["commands"] = cmds
        base["facts"] = {"commands": cmds, "command_count": len(cmds), "direct_signal": "command_execution"}
        return {**base, "intent": intent}

    if class_name == "E3a_honeypot_probe":
        if variant == "attack":
            core = [rng.choice(_E3A)]
            intent = "anti_deception"
        else:
            core = [rng.choice(_E1B)]
            intent = "benign"
        cmds = _shuffle(rng, core, noise_n)
        base["commands"] = cmds
        base["facts"] = {"commands": cmds, "command_count": len(cmds), "direct_signal": "command_execution"}
        return {**base, "intent": intent}

    if class_name == "E1b_generic_recon_control":
        # ambiguity control: BOTH variants are generic recon, must stay below floor
        core = rng.sample(_E1B, k=rng.randint(1, 3))
        cmds = _shuffle(rng, core, noise_n)
        base["commands"] = cmds
        base["facts"] = {"commands": cmds, "command_count": len(cmds), "direct_signal": "command_execution"}
        # intent encodes the *designed* role of the episode, but observables are identical
        return {**base, "intent": "anti_deception" if variant == "attack" else "benign"}

    # ----- object, semantically-gated classes (D0/E4 asserted from server facts) -----
    base["commands"] = _noise(rng, noise_n)
    base["facts"] = {"commands": base["commands"], "command_count": len(base["commands"]),
                     "direct_signal": "decoy_interaction"}

    if class_name == "R3_plausibility_then_suppress":
        base["asserted_families"] = {"E4": ["e4:plausibility_fields_on_decoy"]}
        if variant == "attack":      # inspected plausibility, then aborted (server saw it)
            base["relation_context"].update({"preceding_check": True, "suppression_evidence": True,
                                             "payload_visibility": True, "observation_window": True})
            intent = "anti_deception"
        elif variant == "confounder":  # same E4 marker, but NO suppression evidence / no payload visibility
            base["relation_context"].update({"preceding_check": True, "suppression_evidence": False,
                                             "payload_visibility": False, "observation_window": True})
            intent = "benign"
        else:                         # benign: inspected metadata, then USED it (no suppression)
            base["relation_context"].update({"preceding_check": True, "suppression_evidence": False,
                                             "payload_visibility": True, "observation_window": True})
            intent = "benign"
        return {**base, "intent": intent}

    if class_name == "R2_breadcrumb_traversal":
        base["asserted_families"] = {"D0": ["d0:decoy_touched"], "E4": ["e4:plausibility_fields_on_decoy"]}
        if variant == "attack":       # followed a decoy reference to another decoy
            base["relation_context"].update({"decoy_graph": True, "known_reference_relation": True})
            intent = "anti_deception"
        elif variant == "confounder": # touched decoys but NO reference relation (no traversal)
            base["relation_context"].update({"decoy_graph": True, "known_reference_relation": False})
            intent = "benign"
        else:                         # benign: touched a single decoy, no graph
            base["relation_context"].update({"decoy_graph": False, "known_reference_relation": False})
            intent = "benign"
        return {**base, "intent": intent}

    if class_name == "R4_decoy_avoidance":
        base["asserted_families"] = {"D0": ["d0:decoy_touched"]}
        if variant == "attack":       # inspected decoy, chose the real twin (counterfactual)
            base["relation_context"].update({"comparable_object": True, "ground_truth": True,
                                             "exposure_evidence": True, "counterfactual_avoidance": True})
            intent = "anti_deception"
        elif variant == "confounder": # touched decoy, but no comparable twin / no counterfactual
            base["relation_context"].update({"comparable_object": False, "ground_truth": True,
                                             "exposure_evidence": False, "counterfactual_avoidance": False})
            intent = "benign"
        else:                         # benign: used the decoy directly (fell for it)
            base["relation_context"].update({"comparable_object": True, "ground_truth": True,
                                             "exposure_evidence": True, "counterfactual_avoidance": False})
            intent = "benign"
        return {**base, "intent": intent}

    raise ValueError(f"unknown class {class_name!r}")


# classes that have a meaningful confounder (semantically-gated relations)
CONFOUNDER_CLASSES = {"R3_plausibility_then_suppress", "R2_breadcrumb_traversal", "R4_decoy_avoidance"}
ALL_CLASSES = [
    "R1_multistage_env_probe", "E3a_honeypot_probe", "R3_plausibility_then_suppress",
    "R2_breadcrumb_traversal", "R4_decoy_avoidance", "E1b_generic_recon_control",
]

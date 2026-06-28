# Testbed Playbooks and Literature Rationale

The playbooks implement the current conceptual evidence model in executable form. The conceptual roles are D, E1a, E1b, E2, E3a, E3b, E4, E5, R, and M. The implementation uses granular internal families where helpful: D0 maps to D, E5a/E5b map to E5, M1/M2 map to M, and R1-R4 map to R.

## Playbook details

### pb_env_validation

Expected: `weak_context`, no anti-deception evidence.

Event: one environment check against host metadata.

Reason: Generic host discovery is common in ordinary attacker workflows and in honeypot command logs. It may become relevant only when tied to a stronger environment-authenticity check or relation pattern. This corresponds to E1b, not E1a.

Literature basis: MITRE ATT&CK T1497 documents environment and sandbox checks; Afianian et al. survey malware dynamic-analysis evasion; Cowrie shows feasibility of command telemetry but does not make generic discovery deception-specific.

### pb_fingerprint

Expected: `weak_proxy`, anti-deception evidence.

Event: one active service fingerprinting event.

Reason: Active service and protocol fingerprinting can reveal low- or medium-interaction honeypots. It is stronger than generic reconnaissance because it targets implementation differences.

Literature basis: Vetterl and Clayton show Internet-scale honeypot fingerprinting; Srinivasa et al. describe multistage honeypot fingerprinting; Uitto et al. and Chaudhry et al. survey anti-honeypot methods; HASSH and Dulaunoy et al. support SSH fingerprint metadata for CTI correlation.

### pb_plausibility_suppress

Expected: `sequence_supported`, anti-deception evidence.

Events: decoy metadata inspection followed by explicit abort.

Reason: Artifact plausibility checks are derived evidence. They are not sufficient by themselves. They become sequence-supported when the testbed sees the check and the subsequent suppression/abort under payload visibility.

Literature basis: Miramirkhani et al. show wear-and-tear artifacts as an evasion vector; Reti et al. show structured decoy reference networks; Aggarwal et al. study two-sided deception. The relation gate prevents metadata inspection alone from becoming an intent claim.

### pb_lowrisk_probe

Expected: `none`, no anti-deception evidence.

Event: non-decoy catalog enumeration.

Reason: Enumeration without a decoy fact, hard probe, suppression, traversal, or counterfactual selection does not support anti-deception.

Literature basis: This is a boundary control derived from the paper's interpretation discipline: ordinary discovery must not be promoted without evidence specificity or relation support.

### pb_decoy_avoidance

Expected: `testbed_grounded`, anti-deception evidence.

Events: catalog exposure, decoy metadata view, use of comparable non-decoy twin, no decoy use.

Reason: Counterfactual avoidance can only be claimed when the environment knows that the actor saw both alternatives and chose the real twin. Public honeypot logs cannot support this claim.

Literature basis: Aggarwal et al. motivate two-sided deception and comparison between real and decoy appearance. Reti et al. motivate decoy structures and references. The testbed adds the missing ground truth.

### pb_adaptation

Expected: `none`, no anti-deception evidence.

Events: delay and retry without modeled relation evidence.

Reason: Timing and adaptation-like behavior are modifiers. Without a supported relation, they adjust confidence or actionability only if another evidence role exists. They do not independently establish anti-deception.

Literature basis: MITRE ATT&CK T1497.003 describes time-based evasion; Afianian et al. and Uitto et al. survey timing and evasion behaviors. The model keeps timing as M rather than a standalone positive claim.

### pb_direct_use

Expected: ladder `none`, direct CTI object, no anti-deception evidence.

Event: direct use of a decoy credential/account.

Reason: Direct decoy interaction is useful CTI and suspicious by construction, but it says what the actor did with a decoy, not whether the actor validated or avoided deception.

Literature basis: MITRE D3FEND decoy objects, decoy files, decoy credentials, and decoy session tokens provide the decoy vocabulary. Cowrie and honeypot work support the telemetry claim.

### pb_benign_recon

Expected: `weak_context`, no anti-deception evidence.

Event: generic environment check with benign-like context.

Reason: This is the refusal case. The model retains the observation but refuses the anti-deception label.

Literature basis: Same boundary as E1b: generic reconnaissance is not enough without stronger evidence or relation support.

## Multi-layer traces

### ep_vm_aware_avoidance

Expected: `testbed_grounded`, anti-deception evidence.

Mechanism: combines environment check, active fingerprinting, decoy metadata inspection, suppression, and use of the real twin. This exercises R1, R3, and R4.

### ep_probe_plausibility

Expected: `sequence_supported`, anti-deception evidence.

Mechanism: artifact plausibility check followed by explicit suppression. This exercises R3.

### ep_breadcrumb_traversal

Expected: `sequence_supported`, anti-deception evidence.

Mechanism: traversal across two known decoy objects. This exercises R2.

### ep_direct_use_control

Expected: ladder `none`, direct CTI object, no anti-deception evidence.

Mechanism: direct decoy interaction only. This tests the D boundary.

### ep_benign_recon

Expected: `weak_context`, no anti-deception evidence.

Mechanism: generic environment check only. This tests the E1b refusal boundary.

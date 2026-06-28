# CTI Object Calculation Rationale and Sources

The CTI object layer is intentionally deterministic and narrow. It does not claim calibrated probability. It computes an ordinal confidence score and a shareability boundary from the evidence result emitted by the engine.

## Confidence

The object uses a STIX-compatible 0..100 integer confidence field. The score is calculated as:

```text
confidence = min(
  .45 * epistemic_status_component
+ .25 * telemetry_profile_reliability
+ .20 * evidence_specificity
+ .10 * interaction_depth
+ relation_bonus,
  epistemic_status_cap
)
```

The cap is the safety mechanism. Weak context cannot become high confidence because of volume alone.

Source basis:

- OASIS STIX defines `confidence` as an integer in the 0..100 range.
- Schlette et al. motivate transparent CTI quality dimensions and metrics rather than opaque analyst assertions.
- The paper's evidence model separates evidence specificity, telemetry observability, relation support, and interpretation boundary.

The exact weights are a design operationalization, not a literature-derived statistical calibration. They are chosen to make the scoring auditable and conservative:

```text
45% epistemic status      because evidence strength is the primary claim boundary
25% telemetry reliability because Cowrie, PCAP, full-system, and testbed sources support different claims
20% evidence specificity  because E3a/E1a/E2 are more specific than E1b/E5
10% interaction depth     because more interaction helps but must not dominate
relation bonus            because relation support is the main path from marker to evidence
status cap                because epistemic status bounds the maximum confidence
```

## Shareability

Shareability is not the same as TLP. TLP controls distribution. The object additionally identifies which fields would reveal deception logic and must be withheld or generalized.

The shareability risk score starts at 15 and increases when evidence exposes local deception design:

```text
+20 direct decoy interaction / D
+25 artifact or structural plausibility / E4
+10 suppression relation / R3
+20 decoy traversal / R2
+25 counterfactual avoidance / R4 or testbed_grounded
+40 exact local values included
-20 E3b-only technical metadata
```

Levels:

```text
0-34    public
35-74   community
75-100  restricted
exact values included -> internal_only
```

Source basis:

- FIRST TLP defines sharing audiences and explicitly states that TLP is not a formal classification or content-redaction scheme.
- OASIS STIX supports markings and object-level confidence, but does not decide which deception details are safe to disclose.
- The deception-to-CTI contribution therefore adds `non_shareable_context` as an explicit object field.

## Actionability

Actionability is derived from the evidence decision:

```text
weak_context / observed_marker -> low, retain as context
E3b-only metadata              -> medium, hunt/correlate fingerprints
positive anti-deception        -> medium or high, hunt for comparable validation or avoidance
direct attack interaction      -> medium, triage direct decoy use and related credentials/payloads
```

This is a representation layer. It is not an operational validation that a given CTI platform will interpret the custom fields uniformly.

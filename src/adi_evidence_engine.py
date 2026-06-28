"""
adi_evidence_engine — interprets evidence_registry.yaml.

ONE labeling core for all telemetry profiles. It emits EVIDENCE FINDINGS with an
explicit epistemic_status; it never infers intent. The same marker yields a
different status depending on the telemetry profile (the profile caps the
achievable ladder rank). Relations R1..R4 are gated on mandatory fields:
R3 is never inferred from absence; R4 is testbed-only.

Public API:
    eng = EvidenceEngine("evidence_registry.yaml")
    result = eng.label(commands, facts, profile, relation_context)
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

TRIVIAL_DIRECT = {"connection_or_protocol_observation", "credential_guessing"}


def _load_yaml(path: str) -> Dict[str, Any]:
    import yaml
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


class EvidenceEngine:
    def __init__(self, taxonomy_path: str):
        self.doc = _load_yaml(taxonomy_path)
        self.version = self.doc["taxonomy_version"]
        self.families = self.doc["families"]
        self.profiles = self.doc["telemetry_profiles"]
        self.relations = self.doc["relations"]
        self.ladder = self.doc["epistemic_status"]["ladder"]
        self.off_ladder = set(self.doc["epistemic_status"]["off_ladder"])
        self.markers = [(m["id"], m["family"], re.compile(m["pattern"]))
                        for m in self.doc["markers"]]
        # reverse map rank -> canonical ladder status for downgrading on cap
        self._rank_to_status = {0: "not_supported", 1: "weak_context",
                                2: "weak_proxy", 3: "strong_proxy", 4: "testbed_grounded"}

    # ----- helpers ---------------------------------------------------------
    def _rank(self, status: str) -> Optional[int]:
        return self.ladder.get(status)  # None for off-ladder

    def _cap(self, status: str, ceiling: int) -> str:
        r = self._rank(status)
        if r is None:                       # off-ladder tag: pass through
            return status
        if r <= ceiling:
            return status
        return self._rank_to_status[ceiling]

    # ----- marker matching -------------------------------------------------
    def _match_markers(self, commands: List[str], facts: Dict[str, Any]) -> Dict[str, List[str]]:
        """family -> list of evidence strings (marker_id:command)."""
        hits: Dict[str, List[str]] = {}
        for cmd in commands:
            c = cmd or ""
            for mid, fam, rx in self.markers:
                if rx.search(c):
                    hits.setdefault(fam, []).append(f"{mid}:{c[:60]}")
        # protocol-fact family: E3b fingerprint (banner / KEX / hassh)
        if int(facts.get("client_version_count", 0) or 0) or int(facts.get("client_kex_count", 0) or 0):
            kind = "kex/hassh" if int(facts.get("client_kex_count", 0) or 0) else "banner"
            hits.setdefault("E3b", []).append(f"e3b_fingerprint:{kind}")
        return hits

    # ----- relation evaluation (gated) ------------------------------------
    def _fired_relations(self, present_families: set, facts: Dict[str, Any],
                         profile: str, rc: Dict[str, Any]) -> Dict[str, str]:
        """Return {relation_id: emitted_status} for relations whose mandatory
        fields are satisfied. rc = relation_context provided by the adapter."""
        fired: Dict[str, str] = {}
        env_fams = {f for f in present_families
                    if self.families.get(f, {}).get("axis") == "environment"
                    and f != "E3b"}

        # R1 multistage probe: needs a HARD probe (E3a honeypot/protocol probe or
        # E1a instrumentation check) plus >=2 distinct env families. Generic
        # discovery alone (E1b/E2) is NOT a multistage probe and never triggers R1.
        hard_probe = bool({"E3a", "E1a"} & env_fams)
        if rc.get("same_actor", True) and hard_probe and len(env_fams) >= 2:
            fired["R1_multistage_probe"] = self.relations["R1_multistage_probe"]["emits"]

        # R2 decoy traversal: needs a decoy graph + known reference relation.
        if all(rc.get(k) for k in self.relations["R2_decoy_traversal"]["requires"]):
            fired["R2_decoy_traversal"] = self.relations["R2_decoy_traversal"]["emits"]

        # R3 post-check suppression: NEVER from absence. Requires payload_visibility.
        r3 = self.relations["R3_post_check_suppression"]
        if all(rc.get(k) for k in r3["requires"]):
            fired["R3_post_check_suppression"] = r3["emits"]
        # else: not fired. (A check + no payload without payload_visibility = nothing.)

        # R4 counterfactual avoidance: testbed only, full ground truth.
        r4 = self.relations["R4_counterfactual_avoidance"]
        if profile == "testbed" and all(rc.get(k) for k in r4["requires"]):
            fired["R4_counterfactual_avoidance"] = r4["emits"]

        return fired

    # ----- main ------------------------------------------------------------
    def label(self, commands: List[str], facts: Dict[str, Any],
              profile: str, relation_context: Optional[Dict[str, Any]] = None,
              asserted_families: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
        if profile not in self.profiles:
            raise ValueError(f"unknown profile {profile!r}; have {sorted(self.profiles)}")
        rc = relation_context or {}
        prof = self.profiles[profile]
        ceiling = int(prof["max_ladder_rank"])
        observable = set(prof["observable_families"])

        marker_hits = self._match_markers(commands, facts)
        # families asserted directly from structured / non-shell telemetry
        # (object-axis decoy facts, full-system syscalls, IAM audit, ...).
        for fam, ev in (asserted_families or {}).items():
            marker_hits.setdefault(fam, []).extend(ev)
        if rc.get("decoy_touched"):
            marker_hits.setdefault("D0", []).append("d0:decoy_object_touched")

        present = {f for f in marker_hits if f in observable}
        fired = self._fired_relations(present, facts, profile, rc)
        fired_relset = set(fired)

        findings: List[Dict[str, Any]] = []
        for fam in sorted(present):
            spec = self.families[fam]
            status = spec["alone_status"]
            best = self._rank(status)
            best = -1 if best is None else best
            # any fired relation that promotes this family lifts it to the
            # relation's emitted status; take the strongest (max ladder rank).
            for rel_id, emits in fired.items():
                if fam in self.relations[rel_id].get("promotes", []):
                    er = self._rank(emits)
                    if er is None:
                        continue
                    label = emits
                    # a weak-strength family never exceeds weak_proxy, even when
                    # sequenced; only medium/strong families ride a relation higher.
                    if spec["strength"] == "weak" and er > 2:
                        er, label = 2, "weak_proxy"
                    if er > best:
                        status, best = label, er
            status = self._cap(status, ceiling)
            findings.append({
                "family": fam,
                "axis": spec["axis"],
                "strength": spec["strength"],
                "epistemic_status": status,
                "evidence": marker_hits[fam][:5],
            })

        # ----- aggregate -----
        # A finding is anti-deception EVIDENCE only at weak_proxy or above (rank>=2).
        # rank-1 findings (observed_marker / weak_context) are "observed but
        # ambiguous" and explicitly do NOT count as anti-deception evidence.
        ladder_findings = [f for f in findings if self._rank(f["epistemic_status"]) is not None]
        max_rank = max((self._rank(f["epistemic_status"]) for f in ladder_findings), default=0)
        session_status = (max((f["epistemic_status"] for f in ladder_findings),
                              key=lambda s: self._rank(s), default="none")
                          if ladder_findings else "none")
        has_ad = max_rank >= 2
        observed_only = sorted({f["family"] for f in ladder_findings
                                if self._rank(f["epistemic_status"]) == 1})

        off = sorted({f["epistemic_status"] for f in findings
                      if self._rank(f["epistemic_status"]) is None})

        direct = facts.get("direct_signal", "connection_or_protocol_observation")
        if has_ad and direct not in TRIVIAL_DIRECT:
            stream = "combined"           # the bidirectional case
        elif has_ad:
            stream = "anti_deception"
        elif direct not in TRIVIAL_DIRECT:
            stream = "attack_interaction"
        else:
            stream = "baseline"

        return {
            "taxonomy_version": self.version,
            "profile": profile,
            "findings": findings,
            "relations_fired": sorted(fired_relset),
            "session_epistemic_status": session_status,   # the headline (ladder)
            "off_ladder_tags": off,                        # e.g. technical_fingerprint, direct_deception_interaction
            "observed_markers": observed_only,             # rank-1, ambiguous, NOT counted as evidence
            "has_anti_deception_evidence": has_ad,         # True only at weak_proxy+ (rank>=2)
            "decoy_interaction": "D0" in present,
            "signal_stream": stream,
            "direct_signal": direct,
            "facts": facts,
            "command_count": facts.get("command_count", 0),
        }


if __name__ == "__main__":
    eng = EvidenceEngine(str(Path(__file__).resolve().parents[1] / "evidence_registry.yaml"))
    print("loaded", eng.version, "| families:", len(eng.families),
          "| markers:", len(eng.markers), "| profiles:", sorted(eng.profiles))

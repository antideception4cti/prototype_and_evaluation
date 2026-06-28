#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from adi_evidence_engine import EvidenceEngine
from adapters.testbed import label_testbed
from cti_object_builder import build_cti_object


def read_jsonl(path: Path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def assert_eq(a, b, msg):
    if a != b:
        raise AssertionError(f"{msg}: got {a!r}, expected {b!r}")


def main():
    registry = ROOT / "evidence_registry.yaml"
    engine = EvidenceEngine(str(registry))
    assert "R3_post_check_suppression" in engine.relations
    assert "suppression_evidence" in engine.relations["R3_post_check_suppression"]["requires"]

    expected = {
        "pb_env_validation": ("weak_context", False),
        "pb_fingerprint": ("weak_proxy", True),
        "pb_plausibility_suppress": ("sequence_supported", True),
        "pb_lowrisk_probe": ("none", False),
        "pb_decoy_avoidance": ("testbed_grounded", True),
        "pb_adaptation": ("none", False),
        "pb_direct_use": ("none", False),
        "pb_benign_recon": ("weak_context", False),
    }
    for stem, (status, has_ad) in expected.items():
        result = label_testbed(engine, read_jsonl(ROOT / "data" / "testbed" / "playbooks" / f"{stem}.jsonl"))
        assert_eq(result["session_epistemic_status"], status, stem)
        assert_eq(result["has_anti_deception_evidence"], has_ad, stem)
        obj = build_cti_object(result, dataset="testbed_playbooks", session_id=stem)
        for key in ["confidence", "shareability", "actionability", "recommended_action", "evidence_roles"]:
            assert key in obj, f"missing CTI key {key} for {stem}"
        assert 0 <= obj["confidence"]["score"] <= 100
        assert obj["shareability"]["level"] in {"public", "community", "restricted", "internal_only"}

    direct = label_testbed(engine, read_jsonl(ROOT / "data" / "testbed" / "playbooks" / "pb_direct_use.jsonl"))
    obj = build_cti_object(direct, dataset="testbed_playbooks", session_id="pb_direct_use")
    assert_eq(obj["indicator_family"], "direct_attack", "direct-use object should be direct_attack")
    assert "non_shareable_context" in obj["shareability"]

    print("PASS smoke and semantic tests")

if __name__ == "__main__":
    main()

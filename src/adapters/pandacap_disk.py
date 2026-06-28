"""
adapter_pandacap_disk — turns the on-disk artifacts of ONE PANDAcap session
(extracted from its qcow2: .bash_history, authorized_keys, writable-dir listing)
into a bidirectional CTI object.

PANDAcap instruments every session: the base image carries an operator prep
history (the vmshrink-prep.sh sequence ending in `poweroff`, dated before the
honeypot went live) and an operator ed25519 key whose comment is the session
number. This adapter strips that baseline and surfaces only what the ATTACKER
added, then splits the result into the two CTI directions:

  * forward / attack-interaction : persistence keys (attributed where known),
        loader/dropper beacons, staged payloads  -> rich, shareable IoCs
  * anti-deception               : the evidence engine run over the residual
        attacker commands         -> for commodity botnets, provably empty

So the honest field result is concrete: real adversaries are observed and named,
the forward stream is rich, and the anti-deception stream is measured to be empty
rather than assumed.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from adi_evidence_engine import EvidenceEngine

# --- the PANDAcap operator baseline we must strip (seen identically across sessions) ---
_OPERATOR_PREP_PREFIXES = (
    "apt-get", "dpkg -l", "cat vmshrink-prep.sh", "./vmshrink-prep.sh", "ls", "poweroff")
_OPERATOR_KEY_COMMENT = re.compile(r"^\d{3,4}$")          # operator key comment == session number
_OPERATOR_KEY_HINT = "id_ed25519"

# --- attacker IoC signatures (attributed from public reporting) ---
_PERSISTENCE_KEYS = {
    "mdrfckr": ("Outlaw / Dota cryptomining botnet",
                "SSH brute-force -> authorized_keys persistence -> XMRig/Monero; Romanian-origin, active since 2018"),
}
_LOADER_MARKERS = {
    re.compile(r"ZIGAZAGA\d*"): ("ZIGAZAGA loader botnet",
                                 "echo-marker verify-then-execute; wget/curl/perl-fallback stage loader, documented since 2019"),
}
_DROPPER_PATTERNS = {
    re.compile(r"cat\s+/dev/stdin\s*\|\s*sh"): "stdin_piped_payload",
    re.compile(r"\|\s*(sh|bash)\b"): "piped_shell_execution",
    re.compile(r"\b(wget|curl)\b.*(dota|tddwrt|\.tar\.gz|\.sh)"): "remote_payload_fetch",
    re.compile(r"rm\s+-rf\s+\.ssh.*authorized_keys", re.S): "authorized_keys_overwrite",
}


def _strip_operator_history(lines: List[str]) -> List[str]:
    """Return attacker commands: everything AFTER the last operator-prep line."""
    last_op = -1
    for i, ln in enumerate(lines):
        s = ln.strip()
        if any(s.startswith(p) for p in _OPERATOR_PREP_PREFIXES):
            last_op = i
    return [ln.strip() for ln in lines[last_op + 1:] if ln.strip()]


def _classify_keys(authorized_keys: str, session_id: str) -> List[Dict[str, str]]:
    out = []
    for ln in (authorized_keys or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        comment = parts[-1] if len(parts) >= 3 else ""
        # operator instrumentation key?
        if comment == session_id or _OPERATOR_KEY_COMMENT.match(comment) or _OPERATOR_KEY_HINT in ln:
            out.append({"role": "operator_baseline", "comment": comment})
            continue
        attribution, behaviour = _PERSISTENCE_KEYS.get(comment, ("unattributed persistence key", ""))
        out.append({"role": "attacker_persistence", "comment": comment,
                    "attribution": attribution, "behaviour": behaviour})
    return out


def label_pandacap_disk(engine: EvidenceEngine, bundle: Dict[str, Any]) -> Dict[str, Any]:
    sid = str(bundle.get("session_id", "?"))
    residual = _strip_operator_history(bundle.get("bash_history", []))
    keys = _classify_keys(bundle.get("authorized_keys", ""), sid)

    # ---- forward / attack-interaction stream (the rich IoCs) ----
    forward: Dict[str, Any] = {"persistence": [], "loader": [], "dropper_actions": []}
    attributions = set()
    for k in keys:
        if k["role"] == "attacker_persistence":
            forward["persistence"].append(k)
            if k.get("attribution"):
                attributions.add(k["attribution"])
    joined = "\n".join(residual)
    # botnets split marker strings across quote boundaries (e.g. "Z""IGAZAGA148""8")
    # to defeat naive grep; the shell concatenates at runtime, so we do too.
    normalized = joined.replace('"', '').replace("'", '')
    for rx, (attr, behav) in _LOADER_MARKERS.items():
        if rx.search(normalized):
            forward["loader"].append({"signature": rx.pattern, "attribution": attr, "behaviour": behav})
            attributions.add(attr)
    for rx, tag in _DROPPER_PATTERNS.items():
        if rx.search(normalized):
            forward["dropper_actions"].append(tag)

    # ---- anti-deception stream (the evidence engine over residual commands) ----
    facts = {"direct_signal": "post_auth_commands", "command_count": len(residual)}
    rc = {"same_actor": True, "event_order": True, "payload_visibility": True}   # full-system: payload stage visible
    ad = engine.label(residual, facts, profile="full_system", relation_context=rc)

    has_forward = bool(forward["persistence"] or forward["loader"] or forward["dropper_actions"])
    return {
        "session_id": sid,
        "attacker_commands": residual,
        "forward_cti": forward,
        "attributions": sorted(attributions),
        "anti_deception_status": ad["session_epistemic_status"],
        "has_anti_deception_evidence": ad["has_anti_deception_evidence"],
        "anti_deception_families": [f["family"] for f in ad["findings"]],
        # the bidirectional verdict, made explicit:
        "bidirectional": {"forward_stream": "rich" if has_forward else "empty",
                          "anti_deception_stream": "present" if ad["has_anti_deception_evidence"] else "empty"},
    }


# --------------------------------------------------------------------------- #
# Self-test on the REAL artifacts recovered from the qcow2 images.
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    eng = EvidenceEngine(str(Path(__file__).parents[2] / "evidence_registry.yaml"))

    # session 0008 — exactly as recovered from pandahoney.0008.qcow2
    s0008 = {
        "session_id": "0008",
        "bash_history": ["apt-get update", "apt-get dist-upgrade", "apt-get clean",
                         "apt-get upgrade", "apt-get -s dist-upgrade", "dpkg -l | grep linux-imag",
                         "ls", "cat vmshrink-prep.sh", "./vmshrink-prep.sh -help", "apt-get clean",
                         "./vmshrink-prep.sh -var -homedirs -swap /root", "poweroff",
                         'echo "Z""IGAZAGA148""8"', "cat /dev/stdin | sh"],
        "authorized_keys": "# id_ed25519.pub\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO+RX9GC2tNXXvVPH7v4ZiQnBAtvo+ineQ/jur1zAGUh 0008",
    }
    # an mdrfckr session (0015/0020/...): operator history unchanged, attacker overwrote authorized_keys
    s_mdr = {
        "session_id": "0015",
        "bash_history": ["apt-get update", "ls", "cat vmshrink-prep.sh",
                         "./vmshrink-prep.sh -var -homedirs -swap /root", "poweroff"],
        "authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr",
    }
    for b in (s0008, s_mdr):
        r = label_pandacap_disk(eng, b)
        print(f"\n=== session {r['session_id']} ===")
        print(f"  attacker commands : {r['attacker_commands']}")
        print(f"  forward IoCs      : persistence={[k.get('attribution') for k in r['forward_cti']['persistence']]} "
              f"loader={[l['attribution'] for l in r['forward_cti']['loader']]} "
              f"actions={r['forward_cti']['dropper_actions']}")
        print(f"  attribution       : {r['attributions']}")
        print(f"  anti-deception    : {r['anti_deception_status']} (has_AD={r['has_anti_deception_evidence']})")
        print(f"  BIDIRECTIONAL     : forward={r['bidirectional']['forward_stream']}, "
              f"anti_deception={r['bidirectional']['anti_deception_stream']}")

"""
adapter_cowrie — maps ONE Cowrie session (list of event dicts) to the
EvidenceEngine inputs for the `cowrie_shell` profile.

Key honesty constraint encoded here: a shell honeypot cannot prove that the
payload stage was reachable, so payload_visibility=False. R3 (post-check
suppression) therefore NEVER fires from a Cowrie session — which is exactly the
old ADI-7 "validation_then_abort" overclaim, now structurally impossible.
There is no decoy graph and no comparable twin, so R2/R4 cannot fire either.
"""
from __future__ import annotations
from typing import Any, Dict, List


def _command_text(e: Dict[str, Any]):
    """Cowrie stores the command in `input`, but some (anonymised) exports put it
    in `message` as 'CMD: <command>'. Handle both."""
    cmd = e.get("input")
    if cmd:
        return cmd
    msg = e.get("message") or ""
    if msg.startswith("CMD: "):
        return msg[5:]
    return None


def _facts(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    eids = [e.get("eventid", "") for e in events]
    commands = [c for e in events
                if e.get("eventid") == "cowrie.command.input"
                for c in [_command_text(e)] if c]
    login_ok = eids.count("cowrie.login.success")
    login_fail = eids.count("cowrie.login.failed")
    cv = sum(1 for e in events if e.get("ssh_client_version")) + eids.count("cowrie.client.version")
    kex = sum(1 for e in events if e.get("hassh")) + eids.count("cowrie.client.kex")
    dl = eids.count("cowrie.session.file_download")
    if commands:
        direct = "command_execution"
    elif login_ok:
        direct = "credential_use"
    elif login_fail:
        direct = "credential_guessing"
    elif cv or kex:
        direct = "connection_or_protocol_observation"
    else:
        direct = "connection_or_protocol_observation"
    return {
        "commands": commands,
        "client_version_count": cv, "client_kex_count": kex,
        "login_success_count": login_ok, "login_failed_count": login_fail,
        "command_count": len(commands), "file_download_count": dl,
        "direct_signal": direct,
    }


def label_cowrie(engine, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    f = _facts(events)
    relation_context = {
        "same_actor": True,        # one session = one actor
        "event_order": True,
        "payload_visibility": False,   # <-- the gate that kills the ADI-7 overclaim
        # no decoy graph, no comparable twin, no ground truth in public honeypot data
    }
    return engine.label(f["commands"], f, profile="cowrie_shell",
                        relation_context=relation_context)

"""
Tetragon Policy-Based Detector Simulator.

Grounded in the TracingPolicy examples shipped with cilium/tetragon
(https://github.com/cilium/tetragon/tree/main/examples/tracingpolicy).

Tetragon is not rule-based in the Falco sense — it executes eBPF programs
attached to kprobes/LSM hooks based on user-written policies. The "default"
behavior is therefore what the shipped example policies cover.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional


@dataclass
class TetragonDecision:
    attack: str
    detected: bool
    policy_name: Optional[str]
    rationale: str


TETRAGON_POLICIES = {
    "bash_reverse_shell_devtcp": TetragonDecision(
        attack="Bash reverse shell via /dev/tcp",
        detected=False,
        policy_name=None,
        rationale="No shipped reverse-shell policy. Generic execve examples log "
                  "but do not flag; operator would need custom TracingPolicy.",
    ),
    "python_dup2_reverse_shell": TetragonDecision(
        attack="Python dup2(sock,0/1/2) reverse shell",
        detected=False,
        policy_name=None,
        rationale="No dup2-based fd-redirection policy in examples.",
    ),
    "read_etc_shadow": TetragonDecision(
        attack="Read /etc/shadow from container",
        detected=True,
        policy_name="file-monitoring.yaml",
        rationale="Shipped file_monitoring_filtered policy includes /etc/shadow "
                  "in watched paths.",
    ),
    "fork_bomb": TetragonDecision(
        attack="Fork bomb",
        detected=False,
        policy_name=None,
        rationale="Per-event model; no rate/burst correlation in examples.",
    ),
    "unshare_user_ns": TetragonDecision(
        attack="unshare -U -r inside container",
        detected=False,
        policy_name=None,
        rationale="No shipped unshare()/namespace-creation policy.",
    ),
    "ptrace_traceme": TetragonDecision(
        attack="ptrace(PTRACE_TRACEME)",
        detected=False,
        policy_name=None,
        rationale="No shipped ptrace policy; users must author kprobe on ptrace.",
    ),
    "cross_container_lateral": TetragonDecision(
        attack="Cross-container TCP on uncalibrated port",
        detected=False,
        policy_name=None,
        rationale="tcp-connect.yaml logs all connects but has no per-edge baseline "
                  "for alerting. Requires operator-authored allowlist.",
    ),
    "log4shell_jndi_ldap": TetragonDecision(
        attack="Log4Shell JNDI LDAP egress",
        detected=False,
        policy_name=None,
        rationale="No policy for LDAP egress from JVM containers.",
    ),
    "ssrf_multi_stage": TetragonDecision(
        attack="Multi-stage SSRF across time",
        detected=False,
        policy_name=None,
        rationale="Tetragon is per-event; no temporal correlation primitive.",
    ),
    "read_proc_environ": TetragonDecision(
        attack="Read /proc/self/environ",
        detected=False,
        policy_name=None,
        rationale="/proc/*/environ not in default file_monitoring path set.",
    ),
    "volume_burst_calibrated_edge": TetragonDecision(
        attack="Write burst on calibrated edge",
        detected=False,
        policy_name=None,
        rationale="No rate/volume detection in shipped policies.",
    ),
    "sensitive_file_exfil_novel_channel": TetragonDecision(
        attack="Credential read + novel outbound channel",
        detected=True,
        policy_name="file-monitoring.yaml",
        rationale="Catches /etc/shadow stage; outbound stage invisible.",
    ),
    "shell_spawn_lateral": TetragonDecision(
        attack="Shell spawn + lateral connection",
        detected=False,
        policy_name=None,
        rationale="No shipped shell-in-container or lateral-connect policy.",
    ),
}


def evaluate(attack_ids: List[str]) -> List[TetragonDecision]:
    return [TETRAGON_POLICIES[a] for a in attack_ids if a in TETRAGON_POLICIES]


def metrics(decisions: List[TetragonDecision], gt: List[bool]) -> dict:
    tp = sum(1 for d, g in zip(decisions, gt) if d.detected and g)
    fp = sum(1 for d, g in zip(decisions, gt) if d.detected and not g)
    fn = sum(1 for d, g in zip(decisions, gt) if not d.detected and g)
    tn = sum(1 for d, g in zip(decisions, gt) if not d.detected and not g)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-10)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1,
            "detected": f"{tp}/{tp+fn}"}


if __name__ == "__main__":
    out = Path("results/paper/tetragon_decisions.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump({k: asdict(v) for k, v in TETRAGON_POLICIES.items()}, f, indent=2)
    print(f"Wrote {out}")

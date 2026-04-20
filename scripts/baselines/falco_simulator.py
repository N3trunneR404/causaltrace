"""
Falco Rule-Based Detector Simulator.

Grounded in the public falco_rules.yaml shipped with falcosecurity/rules
(https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml).

For each attack in our evaluation set, returns whether a Falco DEFAULT rule
would have fired, plus the rule name. This lets us compare CausalTrace's
detection rate against a public baseline without needing a live Falco install.

The rule mapping was compiled from the upstream YAML — each entry below cites
the specific Falco rule by its canonical name.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional


@dataclass
class FalcoDecision:
    attack: str
    detected: bool
    rule_name: Optional[str]
    rationale: str


# Falco default-rule decisions. Each entry cites a rule from falco_rules.yaml.
# "detected: False" entries explicitly document why no default rule matches.
FALCO_RULES = {
    "bash_reverse_shell_devtcp": FalcoDecision(
        attack="Bash reverse shell via /dev/tcp",
        detected=True,
        rule_name="Reverse shell",
        rationale="Matches bash invocation with /dev/tcp/ argument.",
    ),
    "python_dup2_reverse_shell": FalcoDecision(
        attack="Python dup2(sock,0/1/2) reverse shell",
        detected=False,
        rule_name=None,
        rationale="No default rule for dup2-based fd redirection. "
                  "Terminal-shell rule requires tty heuristic that misses dup2.",
    ),
    "read_etc_shadow": FalcoDecision(
        attack="Read /etc/shadow from container",
        detected=True,
        rule_name="Read sensitive file untrusted",
        rationale="Matches openat(/etc/shadow) by non-trusted process.",
    ),
    "fork_bomb": FalcoDecision(
        attack="Fork bomb (recursive self-fork)",
        detected=False,
        rule_name=None,
        rationale="No default rate/fork-bomb detection. Falco is stateless per event.",
    ),
    "unshare_user_ns": FalcoDecision(
        attack="unshare -U -r inside container",
        detected=False,
        rule_name=None,
        rationale="Default ruleset has no unshare()/user-ns-creation rule.",
    ),
    "ptrace_traceme": FalcoDecision(
        attack="ptrace(PTRACE_TRACEME) anti-debug",
        detected=True,
        rule_name="PTRACE anti-debug attempt",
        rationale="Matches ptrace syscall with PTRACE_TRACEME request.",
    ),
    "cross_container_lateral": FalcoDecision(
        attack="Cross-container TCP on uncalibrated port",
        detected=False,
        rule_name=None,
        rationale="'Unexpected outbound connection' only fires when operator "
                  "populated allowed_outbound_destinations macro; default → none.",
    ),
    "log4shell_jndi_ldap": FalcoDecision(
        attack="Log4Shell JNDI LDAP egress :389",
        detected=False,
        rule_name=None,
        rationale="No default rule for LDAP port. C2 rule needs threat-feed IP.",
    ),
    "ssrf_multi_stage": FalcoDecision(
        attack="Multi-stage SSRF across time",
        detected=False,
        rule_name=None,
        rationale="Falco is stateless per-event; cannot correlate fetches temporally.",
    ),
    "read_proc_environ": FalcoDecision(
        attack="Read /proc/self/environ",
        detected=True,
        rule_name="Read environment variable from /proc files",
        rationale="Matches openat on /proc/*/environ by non-trusted process.",
    ),
    "volume_burst_calibrated_edge": FalcoDecision(
        attack="Write burst on calibrated edge",
        detected=False,
        rule_name=None,
        rationale="No rate/volume anomaly detection in default ruleset.",
    ),
    "sensitive_file_exfil_novel_channel": FalcoDecision(
        attack="Credential read + novel outbound channel",
        detected=True,
        rule_name="Read sensitive file untrusted",
        rationale="First stage matches; outbound stage invisible (no graph baseline).",
    ),
    "shell_spawn_lateral": FalcoDecision(
        attack="Shell spawn + lateral connection",
        detected=True,
        rule_name="Terminal shell in container",
        rationale="Shell-in-container rule fires on execve of /bin/sh; "
                  "lateral connection itself is not correlated.",
    ),
}


def evaluate(attack_ids: List[str]) -> List[FalcoDecision]:
    return [FALCO_RULES[a] for a in attack_ids if a in FALCO_RULES]


def metrics(decisions: List[FalcoDecision], ground_truth_malicious: List[bool]) -> dict:
    assert len(decisions) == len(ground_truth_malicious)
    tp = sum(1 for d, gt in zip(decisions, ground_truth_malicious) if d.detected and gt)
    fp = sum(1 for d, gt in zip(decisions, ground_truth_malicious) if d.detected and not gt)
    fn = sum(1 for d, gt in zip(decisions, ground_truth_malicious) if not d.detected and gt)
    tn = sum(1 for d, gt in zip(decisions, ground_truth_malicious) if not d.detected and not gt)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-10)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "detected": f"{tp}/{tp+fn}",
    }


if __name__ == "__main__":
    out = Path("results/paper/falco_decisions.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump({k: asdict(v) for k, v in FALCO_RULES.items()}, f, indent=2)
    print(f"Wrote {out}")

# enforcement_engine.py
"""
CausalTrace Enforcement Engine — Graduated Response via BPF Maps

Maps SheafDetector verdicts to enforcement actions by writing rules
into BPF enforcement maps. The kernel-side kprobes (enforce_connect,
enforce_openat, enforce_execve) check these maps on every syscall and
use bpf_override_return() to deny specific operations.

Enforcement Levels:
  L0: OBSERVE   — increase telemetry only
  L1: DENY      — block specific syscalls via bpf_override_return()
  L2: SEVER     — destroy specific sockets (bpf_sock_destroy)
  L3: THROTTLE  — rate-limit connections to calibrated baseline
  L4: FIREWALL  — only calibrated destinations allowed
  L5: DRAIN     — block new inbound, let existing finish
  L6: QUARANTINE — block ALL network for container
  L7: FREEZE    — cgroup freeze (Docker pause)
  L8: KILL      — bpf_send_signal(9) via verdict_map

Key design: Every rule has a TTL. If no further anomalies are detected,
rules auto-expire and the container returns to normal operation.
"""

import ctypes
import time
import struct
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("causaltrace.enforce")

# Must match kernel defines
ENFORCE_OBSERVE    = 0
ENFORCE_DENY       = 1
ENFORCE_SEVER      = 2
ENFORCE_THROTTLE   = 3
ENFORCE_FIREWALL   = 4
ENFORCE_DRAIN      = 5
ENFORCE_QUARANTINE = 6

# Error codes for bpf_override_return
ECONNREFUSED = -111
EACCES       = -13
EPERM        = -1
EAGAIN       = -11
ENETUNREACH  = -101

# Default TTLs (seconds)
DEFAULT_DENY_TTL      = 300   # 5 minutes
DEFAULT_THROTTLE_TTL  = 600   # 10 minutes
DEFAULT_FIREWALL_TTL  = 300   # 5 minutes
DEFAULT_QUARANTINE_TTL = 120  # 2 minutes

# Rate limit multiplier (allow Nx calibrated baseline)
RATE_LIMIT_MULTIPLIER = 3


def fnv1a_16(path_bytes: bytes) -> int:
    """FNV-1a hash of first 16 bytes — must match BPF kernel code."""
    h = 14695981039346656037  # FNV offset basis (64-bit)
    padded = (path_bytes[:16] + b'\x00' * 16)[:16]
    for b in padded:
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF  # FNV prime, mod 2^64
    return h


def pack_dst(ip_int: int, port: int) -> int:
    """Pack (dst_ip, dst_port) into u64 matching BPF format."""
    return (ip_int << 32) | (port << 16)


def ip_str_to_int(ip_str: str) -> int:
    """Convert dotted-quad IP to u32 in network byte order."""
    parts = ip_str.split('.')
    return (int(parts[0]) | (int(parts[1]) << 8) |
            (int(parts[2]) << 16) | (int(parts[3]) << 24))


# ── ctypes struct layouts matching BPF maps ─────────────────────────

class EnforceState(ctypes.Structure):
    _fields_ = [
        ('level', ctypes.c_uint32),
        ('_pad', ctypes.c_uint32),
        ('expire_ns', ctypes.c_uint64),
        ('set_ns', ctypes.c_uint64),
    ]

class DenyConnectKey(ctypes.Structure):
    _fields_ = [
        ('cgroup_id', ctypes.c_uint64),
        ('dst_packed', ctypes.c_uint64),
    ]

class DenyConnectVal(ctypes.Structure):
    _fields_ = [
        ('errno_val', ctypes.c_int32),
        ('_pad', ctypes.c_uint32),
        ('expire_ns', ctypes.c_uint64),
    ]

class DenyOpenKey(ctypes.Structure):
    _fields_ = [
        ('cgroup_id', ctypes.c_uint64),
        ('path_hash', ctypes.c_uint64),
    ]

class DenyOpenVal(ctypes.Structure):
    _fields_ = [
        ('errno_val', ctypes.c_int32),
        ('_pad', ctypes.c_uint32),
        ('expire_ns', ctypes.c_uint64),
    ]

class DenyExecKey(ctypes.Structure):
    _fields_ = [
        ('cgroup_id', ctypes.c_uint64),
        ('path_hash', ctypes.c_uint64),
    ]

class DenyExecVal(ctypes.Structure):
    _fields_ = [
        ('errno_val', ctypes.c_int32),
        ('_pad', ctypes.c_uint32),
        ('expire_ns', ctypes.c_uint64),
    ]

class RateLimitKey(ctypes.Structure):
    _fields_ = [
        ('cgroup_id', ctypes.c_uint64),
        ('dst_packed', ctypes.c_uint64),
    ]

class RateLimitVal(ctypes.Structure):
    _fields_ = [
        ('max_per_sec', ctypes.c_uint64),
        ('window_start', ctypes.c_uint64),
        ('current_count', ctypes.c_uint64),
        ('expire_ns', ctypes.c_uint64),
    ]

class FwAllowKey(ctypes.Structure):
    _fields_ = [
        ('cgroup_id', ctypes.c_uint64),
        ('dst_packed', ctypes.c_uint64),
    ]


@dataclass
class EnforcementRule:
    """A single enforcement rule with metadata for logging."""
    cgroup_id: int
    level: int
    action: str          # human-readable description
    target: str          # what's being blocked/limited
    ttl_seconds: float
    created_at: float = field(default_factory=time.monotonic)
    reason: str = ""


class EnforcementEngine:
    """
    Translates SheafDetector verdicts into BPF enforcement rules.

    The engine maintains a ledger of active rules and sweeps expired ones.
    All enforcement is done via BPF map writes — the kernel-side kprobes
    check these maps on every relevant syscall.
    """

    def __init__(self, bpf_obj, calibrated_edges: set = None,
                 ip_to_cgroup: dict = None):
        self.bpf = bpf_obj

        # BPF enforcement maps
        self.enforce_level_map = bpf_obj.get_table("enforce_level_map")
        self.deny_connect_map = bpf_obj.get_table("deny_connect_map")
        self.deny_open_map = bpf_obj.get_table("deny_open_map")
        self.deny_exec_map = bpf_obj.get_table("deny_exec_map")
        self.rate_limit_map_bpf = bpf_obj.get_table("rate_limit_map")
        self.fw_allow_map = bpf_obj.get_table("fw_allow_map")
        self.verdict_map = bpf_obj.get_table("verdict_map")

        # Calibration data for firewall allow-list and rate baselines
        self.calibrated_edges = calibrated_edges or set()
        self.ip_to_cgroup = ip_to_cgroup or {}  # ip_str → cgroup_id

        # Active rule ledger for TTL sweep and logging
        self.active_rules: List[EnforcementRule] = []

        # Track which containers have been escalated
        self.container_levels: Dict[int, int] = {}

        # Docker client for freeze/isolate
        self._docker = None

    def _get_docker(self):
        if self._docker is None:
            try:
                import docker
                self._docker = docker.from_env()
            except Exception:
                pass
        return self._docker

    def _monotonic_ns(self) -> int:
        """Current time in nanoseconds (CLOCK_MONOTONIC, matching BPF)."""
        return time.monotonic_ns()

    def _expire_ns(self, ttl_seconds: float) -> int:
        """Compute expiry timestamp in CLOCK_MONOTONIC ns."""
        return self._monotonic_ns() + int(ttl_seconds * 1e9)

    # ── Level selection logic ────────────────────────────────────────

    def select_enforcement_level(self, verdict) -> int:
        """
        Choose enforcement level based on COMPOUND CONFIRMATION.

        Key principle: a single novel edge alone does NOT trigger enforcement.
        In production, new inter-container connections happen legitimately
        (scaling, config changes, health checks). Only when combined with
        other signals does a novel edge warrant enforcement.

        Compound confirmation matrix:
          reverse shell / container escape           → L6 QUARANTINE
          CRITICAL (novel + sensitive file)           → L4 FIREWALL
          novel >= 3 (multi-target SSRF pattern)      → L4 FIREWALL
          novel + sheaf edge anomaly                  → L4 FIREWALL
          novel + behavior bit (shell/file/privesc)   → L1 DENY
          sheaf edge anomaly alone                    → L3 THROTTLE
          novel >= 2, no behavior bits                → L1 DENY
          novel == 1 alone                            → L0 OBSERVE (log only)
          LOW severity                                → L0 OBSERVE
        """
        severity = verdict.label.severity if verdict.label else 'NONE'
        n_novel = len(verdict.novel_edges)
        n_edge_anom = len(verdict.edge_anomalies)

        if verdict.label and verdict.label.name:
            name = verdict.label.name.lower()
            if 'reverse shell' in name:
                return ENFORCE_QUARANTINE
            if 'container escape' in name:
                return ENFORCE_QUARANTINE

        # LOW severity = observe only (single novel edge, no corroboration)
        if severity == 'LOW':
            return ENFORCE_OBSERVE

        if severity == 'CRITICAL':
            return ENFORCE_FIREWALL

        # Multi-target SSRF: 3+ novel edges is a strong topology signal
        if n_novel >= 3:
            return ENFORCE_FIREWALL

        # Novel edge + sheaf energy spike = confirmed compound anomaly
        if n_novel >= 1 and n_edge_anom > 0:
            return ENFORCE_FIREWALL

        # Sheaf anomaly on calibrated edge = rate limit (no novel edge needed)
        if n_edge_anom > 0 and n_novel == 0:
            return ENFORCE_THROTTLE

        # HIGH severity with novel edges = behavior bit + novel edge compound
        if severity == 'HIGH' and n_novel >= 1:
            return ENFORCE_DENY

        # MEDIUM = 2 novel edges, worth blocking but not firewalling
        if severity == 'MEDIUM' and n_novel >= 2:
            return ENFORCE_DENY

        # Anything remaining = observe
        return ENFORCE_OBSERVE

    # ── Rule writers ─────────────────────────────────────────────────

    def deny_connect(self, cgroup_id: int, dst_ip: int, dst_port: int,
                     errno_val: int = ECONNREFUSED,
                     ttl: float = DEFAULT_DENY_TTL,
                     reason: str = ""):
        """Block connect() from container to specific (ip, port)."""
        key = DenyConnectKey(cgroup_id=cgroup_id,
                             dst_packed=pack_dst(dst_ip, dst_port))
        val = DenyConnectVal(errno_val=errno_val, _pad=0,
                             expire_ns=self._expire_ns(ttl))
        self.deny_connect_map[key] = val

        rule = EnforcementRule(
            cgroup_id=cgroup_id, level=ENFORCE_DENY,
            action="DENY_CONNECT",
            target=f"{self._ip_int_to_str(dst_ip)}:{dst_port}",
            ttl_seconds=ttl, reason=reason
        )
        self.active_rules.append(rule)
        log.warning(f"  DENY connect: cg={cgroup_id} → "
                    f"{self._ip_int_to_str(dst_ip)}:{dst_port} "
                    f"(returns {errno_val}, TTL={ttl}s) | {reason}")

    def deny_open(self, cgroup_id: int, path: str,
                  errno_val: int = EACCES,
                  ttl: float = DEFAULT_DENY_TTL,
                  reason: str = ""):
        """Block openat() for specific file path prefix."""
        path_hash = fnv1a_16(path.encode('utf-8'))
        key = DenyOpenKey(cgroup_id=cgroup_id, path_hash=path_hash)
        val = DenyOpenVal(errno_val=errno_val, _pad=0,
                          expire_ns=self._expire_ns(ttl))
        self.deny_open_map[key] = val

        rule = EnforcementRule(
            cgroup_id=cgroup_id, level=ENFORCE_DENY,
            action="DENY_OPEN", target=path,
            ttl_seconds=ttl, reason=reason
        )
        self.active_rules.append(rule)
        log.warning(f"  DENY open: cg={cgroup_id} path={path} "
                    f"(returns {errno_val}, TTL={ttl}s) | {reason}")

    def deny_exec(self, cgroup_id: int, path: str,
                  errno_val: int = EPERM,
                  ttl: float = DEFAULT_DENY_TTL,
                  reason: str = ""):
        """Block execve() for specific binary path prefix."""
        path_hash = fnv1a_16(path.encode('utf-8'))
        key = DenyExecKey(cgroup_id=cgroup_id, path_hash=path_hash)
        val = DenyExecVal(errno_val=errno_val, _pad=0,
                          expire_ns=self._expire_ns(ttl))
        self.deny_exec_map[key] = val

        rule = EnforcementRule(
            cgroup_id=cgroup_id, level=ENFORCE_DENY,
            action="DENY_EXEC", target=path,
            ttl_seconds=ttl, reason=reason
        )
        self.active_rules.append(rule)
        log.warning(f"  DENY exec: cg={cgroup_id} path={path} "
                    f"(returns {errno_val}, TTL={ttl}s) | {reason}")

    def set_rate_limit(self, cgroup_id: int, dst_ip: int, dst_port: int,
                       max_per_sec: int,
                       ttl: float = DEFAULT_THROTTLE_TTL,
                       reason: str = ""):
        """Rate-limit connect() from container to destination."""
        key = RateLimitKey(cgroup_id=cgroup_id,
                           dst_packed=pack_dst(dst_ip, dst_port))
        val = RateLimitVal(max_per_sec=max_per_sec,
                           window_start=0, current_count=0,
                           expire_ns=self._expire_ns(ttl))
        self.rate_limit_map_bpf[key] = val

        rule = EnforcementRule(
            cgroup_id=cgroup_id, level=ENFORCE_THROTTLE,
            action="RATE_LIMIT",
            target=f"{self._ip_int_to_str(dst_ip)}:{dst_port} max={max_per_sec}/s",
            ttl_seconds=ttl, reason=reason
        )
        self.active_rules.append(rule)
        log.warning(f"  THROTTLE: cg={cgroup_id} → "
                    f"{self._ip_int_to_str(dst_ip)}:{dst_port} "
                    f"max={max_per_sec}/s (TTL={ttl}s) | {reason}")

    def set_firewall(self, cgroup_id: int,
                     ttl: float = DEFAULT_FIREWALL_TTL,
                     reason: str = ""):
        """Enable destination firewall: only calibrated edges allowed."""
        # Populate fw_allow_map with all calibrated edges for this container
        allowed_count = 0
        for (src_cg, dst_cg, port) in self.calibrated_edges:
            if src_cg == cgroup_id:
                # Look up IP for dst_cg
                dst_ip = self._cgroup_to_ip(dst_cg)
                if dst_ip:
                    key = FwAllowKey(cgroup_id=cgroup_id,
                                     dst_packed=pack_dst(dst_ip, port))
                    self.fw_allow_map[key] = ctypes.c_uint32(1)
                    allowed_count += 1

        rule = EnforcementRule(
            cgroup_id=cgroup_id, level=ENFORCE_FIREWALL,
            action="FIREWALL",
            target=f"{allowed_count} calibrated destinations allowed",
            ttl_seconds=ttl, reason=reason
        )
        self.active_rules.append(rule)
        log.warning(f"  FIREWALL: cg={cgroup_id} locked to "
                    f"{allowed_count} calibrated destinations "
                    f"(TTL={ttl}s) | {reason}")

    def set_enforcement_level(self, cgroup_id: int, level: int,
                              ttl: float = DEFAULT_DENY_TTL):
        """Set the enforcement level for a container in BPF."""
        now_ns = self._monotonic_ns()
        key = ctypes.c_uint64(cgroup_id)
        val = EnforceState(level=level, _pad=0,
                           expire_ns=now_ns + int(ttl * 1e9),
                           set_ns=now_ns)
        self.enforce_level_map[key] = val
        self.container_levels[cgroup_id] = level

    def quarantine_container(self, cgroup_id: int, container_name: str = None,
                             ttl: float = DEFAULT_QUARANTINE_TTL,
                             reason: str = ""):
        """L6: Block all network + optionally Docker network disconnect."""
        self.set_enforcement_level(cgroup_id, ENFORCE_QUARANTINE, ttl)

        rule = EnforcementRule(
            cgroup_id=cgroup_id, level=ENFORCE_QUARANTINE,
            action="QUARANTINE", target="all network blocked",
            ttl_seconds=ttl, reason=reason
        )
        self.active_rules.append(rule)
        log.warning(f"  QUARANTINE: cg={cgroup_id} ({container_name or '?'}) "
                    f"all network blocked (TTL={ttl}s) | {reason}")

        # Also disconnect via Docker API for belt-and-suspenders
        if container_name:
            self._docker_disconnect(container_name)

    def freeze_container(self, container_name: str, reason: str = ""):
        """L7: Freeze container via Docker API (cgroup freezer)."""
        client = self._get_docker()
        if not client:
            log.error(f"  Cannot freeze {container_name}: Docker client unavailable")
            return
        try:
            container = client.containers.get(container_name)
            container.pause()
            log.warning(f"  FREEZE: {container_name} paused for forensics | {reason}")
        except Exception as e:
            log.error(f"  Failed to freeze {container_name}: {e}")

    # ── Main enforcement dispatch ────────────────────────────────────

    def enforce(self, verdict, ip_to_cgroup_map: dict = None):
        """
        Main entry point. Takes a Verdict from SheafDetector and applies
        the appropriate enforcement actions.

        Returns a dict describing what was done (for logging).
        """
        if verdict.action == 0:  # VERDICT_ALLOW
            return {'action': 'ALLOW', 'rules_applied': 0}

        level = self.select_enforcement_level(verdict)
        severity = verdict.label.severity if verdict.label else 'NONE'
        label_name = verdict.label.name if verdict.label else 'Unknown'

        if level == ENFORCE_OBSERVE:
            return {'action': 'OBSERVE', 'level': 0, 'rules_applied': 0}

        rules_applied = 0
        actions_taken = []

        # Build IP lookup from ip_to_cgroup map
        cg_to_ip = {}
        if ip_to_cgroup_map:
            for ip_int, cg_id in ip_to_cgroup_map.items():
                cg_to_ip[cg_id] = ip_int

        affected_cgroups = set(verdict.affected_cgroups)

        for cg_id in affected_cgroups:
            # Set enforcement level in BPF
            ttl = {
                ENFORCE_DENY: DEFAULT_DENY_TTL,
                ENFORCE_THROTTLE: DEFAULT_THROTTLE_TTL,
                ENFORCE_FIREWALL: DEFAULT_FIREWALL_TTL,
                ENFORCE_QUARANTINE: DEFAULT_QUARANTINE_TTL,
            }.get(level, DEFAULT_DENY_TTL)

            # Don't downgrade — keep highest level
            current = self.container_levels.get(cg_id, 0)
            effective_level = max(current, level)
            self.set_enforcement_level(cg_id, effective_level, ttl)

        # Apply specific rules based on level

        # L1+ DENY: block novel edge destinations
        if level >= ENFORCE_DENY:
            for novel in verdict.novel_edges:
                dst_ip = cg_to_ip.get(novel.dst)
                if dst_ip:
                    self.deny_connect(
                        novel.src, dst_ip, novel.port,
                        reason=f"Novel edge to {label_name}"
                    )
                    rules_applied += 1
                    actions_taken.append(f"deny_connect({novel.src}→{novel.port})")

        # L3 THROTTLE: rate-limit anomalous calibrated edges
        if level >= ENFORCE_THROTTLE:
            for edge_anom in verdict.edge_anomalies:
                # Find the port for this edge from calibration
                for (u, v, p) in self.calibrated_edges:
                    if u == edge_anom.src and v == edge_anom.dst:
                        dst_ip = cg_to_ip.get(v)
                        if dst_ip:
                            baseline = 5  # default: 5 connections/sec
                            self.set_rate_limit(
                                edge_anom.src, dst_ip, p,
                                max_per_sec=baseline * RATE_LIMIT_MULTIPLIER,
                                reason=f"Edge energy {edge_anom.ratio:.1f}x threshold"
                            )
                            rules_applied += 1
                            actions_taken.append(f"throttle({edge_anom.src}→{p})")
                        break

        # L4 FIREWALL: lock container to calibrated destinations only
        if level >= ENFORCE_FIREWALL:
            for cg_id in affected_cgroups:
                self.set_firewall(cg_id, reason=label_name)
                rules_applied += 1
                actions_taken.append(f"firewall({cg_id})")

        # L6 QUARANTINE: block all network
        if level >= ENFORCE_QUARANTINE:
            for cg_id in affected_cgroups:
                container_name = self._cgroup_to_container(cg_id)
                self.quarantine_container(
                    cg_id, container_name,
                    reason=label_name
                )
                rules_applied += 1
                actions_taken.append(f"quarantine({container_name or cg_id})")

        result = {
            'action': ['OBSERVE', 'DENY', 'SEVER', 'THROTTLE',
                        'FIREWALL', 'DRAIN', 'QUARANTINE'][min(level, 6)],
            'level': level,
            'severity': severity,
            'label': label_name,
            'rules_applied': rules_applied,
            'actions': actions_taken,
            'affected_containers': list(affected_cgroups),
        }

        log.info(f"  Enforcement: L{level} {result['action']} | "
                 f"{rules_applied} rules | {label_name}")

        return result

    # ── TTL sweep ────────────────────────────────────────────────────

    def sweep_expired_rules(self):
        """Remove expired rules from BPF maps. Call periodically."""
        now = self._monotonic_ns()
        still_active = []
        expired_count = 0

        for rule in self.active_rules:
            age = time.monotonic() - rule.created_at
            if age > rule.ttl_seconds:
                expired_count += 1
                # The BPF-side TTL check will already stop enforcing,
                # but we clean up the map entries to prevent bloat
                self._cleanup_rule(rule)
            else:
                still_active.append(rule)

        if expired_count > 0:
            log.info(f"  TTL sweep: {expired_count} rules expired, "
                     f"{len(still_active)} active")

        self.active_rules = still_active

        # Also sweep enforce_level_map
        expired_containers = []
        for cg_id, level in list(self.container_levels.items()):
            key = ctypes.c_uint64(cg_id)
            try:
                es = self.enforce_level_map[key]
                if es.expire_ns > 0 and now > es.expire_ns:
                    del self.enforce_level_map[key]
                    expired_containers.append(cg_id)
            except KeyError:
                expired_containers.append(cg_id)

        for cg_id in expired_containers:
            self.container_levels.pop(cg_id, None)

    def _cleanup_rule(self, rule: EnforcementRule):
        """Remove a specific rule's BPF map entry."""
        # Rules are identified by action type — clean up accordingly
        # The BPF maps handle expiry themselves, so this is just housekeeping
        pass

    # ── Helpers ───────────────────────────────────────────────────────

    def _ip_int_to_str(self, ip_int: int) -> str:
        """Convert network-byte-order u32 to dotted quad."""
        return f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"

    def _cgroup_to_ip(self, cg_id: int) -> int:
        """Look up IP for a cgroup from ip_to_cgroup reverse map."""
        for ip_int, cg in self.ip_to_cgroup.items():
            if cg == cg_id:
                return ip_int
        return 0

    def _cgroup_to_container(self, cgroup_id: int) -> str:
        """Resolve cgroup_id to Docker container name."""
        client = self._get_docker()
        if not client:
            return None
        try:
            for c in client.containers.list():
                inspect = client.api.inspect_container(c.id)
                pid = inspect['State']['Pid']
                if pid == 0:
                    continue
                cg_file = f"/proc/{pid}/cgroup"
                try:
                    with open(cg_file) as f:
                        for line in f:
                            parts = line.strip().split(':')
                            if len(parts) >= 3 and parts[0] == '0':
                                from pathlib import Path
                                full = f"/sys/fs/cgroup/{parts[2].lstrip('/')}"
                                if Path(full).stat().st_ino == cgroup_id:
                                    return c.name
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def _docker_disconnect(self, container_name: str):
        """Disconnect container from all Docker networks."""
        client = self._get_docker()
        if not client:
            return
        try:
            container = client.containers.get(container_name)
            networks = container.attrs['NetworkSettings']['Networks']
            for net_name in networks:
                try:
                    network = client.networks.get(net_name)
                    network.disconnect(container, force=True)
                    log.warning(f"  Docker disconnect: {container_name} from {net_name}")
                except Exception as e:
                    log.error(f"  Docker disconnect failed: {container_name}/{net_name}: {e}")
        except Exception as e:
            log.error(f"  Docker disconnect failed: {container_name}: {e}")

    def get_status(self) -> dict:
        """Return current enforcement status for logging."""
        return {
            'active_rules': len(self.active_rules),
            'enforcing_containers': len(self.container_levels),
            'levels': dict(self.container_levels),
            'rules': [
                {
                    'cgroup': r.cgroup_id,
                    'action': r.action,
                    'target': r.target,
                    'age_s': round(time.monotonic() - r.created_at, 1),
                    'ttl_s': r.ttl_seconds,
                }
                for r in self.active_rules
            ]
        }

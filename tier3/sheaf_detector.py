# sheaf_detector.py
import json
import os
import time as _time_mod
import numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    from signal_extractor import extract_signal_74, BigramSketch
    from whitener import FeatureWhitener
    from ema_buffer import EMASignalBuffer
    from calibrate import SheafCalibrator
except ImportError:
    from .signal_extractor import extract_signal_74, BigramSketch
    from .whitener import FeatureWhitener
    from .ema_buffer import EMASignalBuffer
    from .calibrate import SheafCalibrator

# Signal log path — set CAUSALTRACE_SIGNAL_LOG env var to override
_SIGNAL_LOG_PATH = os.environ.get(
    "CAUSALTRACE_SIGNAL_LOG",
    os.path.join(os.path.dirname(__file__), "..", "results", "marathon", "signals.jsonl")
)
_signal_log_fh = None

def _get_signal_log():
    global _signal_log_fh
    if _signal_log_fh is None:
        os.makedirs(os.path.dirname(os.path.abspath(_SIGNAL_LOG_PATH)), exist_ok=True)
        _signal_log_fh = open(_SIGNAL_LOG_PATH, "a", buffering=1)
    return _signal_log_fh

VERDICT_ALLOW = 0
VERDICT_KILL = 1

@dataclass
class EdgeAnomaly:
    src: int    # src cgroup_id
    dst: int    # dst cgroup_id
    lag: int    # temporal lag that produced max energy
    energy: float
    threshold: float
    ratio: float = 0.0  # energy / threshold

@dataclass
class NovelEdgeAlert:
    src: int
    dst: int
    port: int
    severity: str = "HIGH"

@dataclass
class AttackLabel:
    name: str
    mitre_ids: List[str]
    severity: str    # CRITICAL, HIGH, MEDIUM, LOW, NONE
    
@dataclass
class EigenmodeResult:
    total_energy: float
    dominant_modes: List[int]
    mode_energies: List[float]
    
@dataclass
class Verdict:
    action: int                              # VERDICT_ALLOW or VERDICT_KILL
    affected_cgroups: List[int] = field(default_factory=list)
    rayleigh: float = 0.0
    global_threshold: float = 0.0
    edge_anomalies: List[EdgeAnomaly] = field(default_factory=list)
    novel_edges: List[NovelEdgeAlert] = field(default_factory=list)
    label: Optional[AttackLabel] = None
    eigenmodes: Optional[EigenmodeResult] = None
    reason: str = ""


class SheafDetector:
    """
    Runtime sheaf Laplacian detector.
    
    Called every ~5 second detection cycle with:
    - Current bigram sketches from BPF maps
    - Current container behavior bitfields from BPF maps
    - Recent connection events from telemetry ring buffer
    - Internal state: EMA buffers and signal history deques
    """
    
    def __init__(self, cal: SheafCalibrator):
        self.cal = cal
        # Guarded EMA (α=0.02, 30s pristine streak). Blend only during
        # confirmed-clean cycles so attacks can't poison the baseline.
        self.ema_buffer = EMASignalBuffer(alpha=0.02, d=74)
        # Signal history for multi-lag detection: 3 windows per container
        self.signal_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=3))
        self.eigenmode_analyzer = None  # initialized after calibration

        # Novel edge accumulator: track novel edges across a sliding window
        # so multi-stage attacks that produce 1 novel edge per cycle
        # accumulate to compound confirmation
        self.novel_edge_window: deque = deque(maxlen=6)  # ~30s at 5s interval
        
    def setup_eigenmode_analyzer(self):
        """
        Build sheaf Laplacian matrix and compute eigendecomposition.
        Called once after calibration data is loaded.
        
        The sheaf Laplacian L_F is a block matrix with blocks:
          (L_F)_{vv} = sum_{e: v◁e} F_{v◁e}^T @ F_{v◁e}
          (L_F)_{uv} = -F_{u◁e}^T @ F_{v◁e}  if e=(u,v) in E
        
        For n containers with d-dimensional signals:
          L_F is (n*d) × (n*d) = (3*74) × (3*74) = 222 × 222
        """
        try:
            from eigenmode_analyzer import SheafEigenmodeAnalyzer
            # Build L_F from restriction maps (lag=0 only for eigendecomposition)
            L_F = self._build_laplacian()
            if L_F is not None:
                self.eigenmode_analyzer = SheafEigenmodeAnalyzer(L_F)
                print("Eigenmode analyzer initialized")
        except Exception as e:
            print(f"Warning: Could not initialize eigenmode analyzer: {e}")
    
    def _build_laplacian(self) -> Optional[np.ndarray]:
        """Build the sheaf Laplacian matrix from lag=0 restriction maps."""
        containers = sorted(set(
            cg for (u, v, lag) in self.cal.restriction_maps if lag == 0
            for cg in [u, v]
        ))
        n = len(containers)
        if n < 2:
            return None
        
        cg_to_idx = {cg: i for i, cg in enumerate(containers)}
        d = self.cal.d
        L_F = np.zeros((n * d, n * d), dtype=np.float64)
        
        for (u, v, lag), (F_u, F_v) in self.cal.restriction_maps.items():
            if lag != 0:
                continue
            i_u = cg_to_idx.get(u)
            i_v = cg_to_idx.get(v)
            if i_u is None or i_v is None:
                continue
            
            # Diagonal blocks: F_{v◁e}^T @ F_{v◁e}
            L_F[i_u*d:(i_u+1)*d, i_u*d:(i_u+1)*d] += F_u.T @ F_u
            L_F[i_v*d:(i_v+1)*d, i_v*d:(i_v+1)*d] += F_v.T @ F_v
            # Off-diagonal blocks: -F_{u◁e}^T @ F_{v◁e}
            L_F[i_u*d:(i_u+1)*d, i_v*d:(i_v+1)*d] -= F_u.T @ F_v
            L_F[i_v*d:(i_v+1)*d, i_u*d:(i_u+1)*d] -= F_v.T @ F_u
        
        return L_F
    
    def _compute_edge_energy(self, F_u: np.ndarray, x_u: np.ndarray,
                              F_v: np.ndarray, x_v: np.ndarray,
                              cov_inv: Optional[np.ndarray]) -> float:
        """Compute Mahalanobis edge energy: (F_u @ x_u - F_v @ x_v)^T Σ^-1 (...)"""
        diff = F_u @ x_u - F_v @ x_v   # (k,)
        if cov_inv is not None:
            return float(diff @ cov_inv @ diff)
        return float(np.dot(diff, diff))   # fallback to L2
    
    def detect_cycle(self,
                     current_sketches: Dict[int, BigramSketch],
                     current_behaviors: Dict[int, dict],
                     current_connections: List[dict]) -> Verdict:
        """
        Main detection cycle. Called every ~5 seconds.
        
        Parameters:
          current_sketches: {cg_id: BigramSketch} — read from bigram_sketch_map
          current_behaviors: {cg_id: dict} — read from container_behavior map
          current_connections: [{'src_cg', 'dst_cg', 'dst_port'}, ...] from telemetry_rb
        """
        
        # ── Stage 1: Novel-edge detection ─────────────────────────────
        # Check for connections on uncalibrated (src, dst, port) tuples.
        # These are flagged immediately — calibration defines what is "normal".
        novel_alerts = []
        for conn in current_connections:
            key = (conn['src_cg'], conn['dst_cg'], conn['dst_port'])
            if key not in self.cal.calibrated_edges:
                novel_alerts.append(NovelEdgeAlert(
                    src=conn['src_cg'],
                    dst=conn['dst_cg'],
                    port=conn['dst_port']
                ))

        # Accumulate novel edges across detection cycles (~30s sliding window).
        # Multi-stage attacks (e.g., SSRF) may produce 1 novel edge per cycle —
        # accumulation lets compound confirmation trigger across cycles.
        import time as _time
        now = _time.monotonic()
        for alert in novel_alerts:
            self.novel_edge_window.append((now, alert))

        # Evict entries older than 30 seconds
        while self.novel_edge_window and (now - self.novel_edge_window[0][0]) > 30.0:
            self.novel_edge_window.popleft()

        # Windowed novel edges: all unique (src, dst) pairs in the window
        windowed_novel = [entry[1] for entry in self.novel_edge_window]
        windowed_unique = {(a.src, a.dst) for a in windowed_novel}
        
        # ── Stage 2: Signal extraction and whitening ───────────────────
        raw_signals: Dict[int, np.ndarray] = {}
        ema_signals: Dict[int, np.ndarray] = {}
        
        for cg_id, sketch in current_sketches.items():
            x_raw = extract_signal_74(sketch, self.cal.cal_stats)
            
            whitener = self.cal.whitener.get(cg_id)
            if whitener:
                x_white = whitener.transform(x_raw)
            else:
                x_white = x_raw  # uncalibrated container — use raw
            
            raw_signals[cg_id] = x_white
            ema_signals[cg_id] = self.ema_buffer.update(cg_id, x_white)
            self.signal_history[cg_id].append(x_white)
        
        # ── Stage 3: Sheaf Laplacian spectral test (dual path + multi-lag) ──
        edge_alerts = []
        total_raw_energy = 0.0
        total_ema_energy = 0.0
        
        calibrated_pairs = set((u, v) for (u, v, lag) in self.cal.restriction_maps)
        
        for (u, v) in calibrated_pairs:
            if u not in raw_signals or v not in raw_signals:
                continue
            
            x_u_raw = raw_signals[u]
            x_v_raw = raw_signals[v]
            x_u_ema = ema_signals[u]
            x_v_ema = ema_signals[v]
            
            # Multi-lag: try lags 0, 1, 2; take maximum energy
            max_raw_energy = 0.0
            max_ema_energy = 0.0
            best_lag = 0
            
            for lag in [0, 1, 2]:
                if (u, v, lag) not in self.cal.restriction_maps:
                    continue
                F_u, F_v = self.cal.restriction_maps[(u, v, lag)]
                cov_inv = self.cal.edge_cov_inv.get((u, v, lag))
                
                # Raw path: use current signals
                raw_e = self._compute_edge_energy(F_u, x_u_raw, F_v, x_v_raw, cov_inv)
                if raw_e > max_raw_energy:
                    max_raw_energy = raw_e
                    best_lag = lag
                
                # EMA path: for lag, use history if available
                if lag == 0:
                    ema_e = self._compute_edge_energy(F_u, x_u_ema, F_v, x_v_ema, cov_inv)
                    max_ema_energy = max(max_ema_energy, ema_e)
            
            total_raw_energy += max_raw_energy
            total_ema_energy += max_ema_energy
            
            # Per-edge threshold check (4-sigma on calibration residuals)
            tau_raw = max(
                self.cal.edge_thresholds.get((u, v, lag), float('inf'))
                for lag in [0, 1, 2]
            )
            tau_ema = self.cal.ema_edge_thresholds.get((u, v), tau_raw * 0.7)
            
            if max_raw_energy > tau_raw or max_ema_energy > tau_ema:
                edge_alerts.append(EdgeAnomaly(
                    src=u, dst=v, lag=best_lag,
                    energy=max_raw_energy, threshold=tau_raw,
                    ratio=max_raw_energy / max(tau_raw, 1e-10)
                ))
        
        # Global Rayleigh quotient (raw path)
        x_global = np.concatenate([
            raw_signals[cg] for cg in sorted(raw_signals.keys())
            if cg in raw_signals
        ]) if raw_signals else np.array([])
        
        x_norm_sq = float(np.dot(x_global, x_global)) if len(x_global) > 0 else 0.0
        rayleigh = total_raw_energy / max(x_norm_sq, 1e-10)
        
        # ── Stage 4: Eigenmode analysis ───────────────────────────────
        eigenmode_result = None
        if self.eigenmode_analyzer is not None and len(x_global) > 0:
            try:
                eigenmode_result = self.eigenmode_analyzer.analyze(x_global)
            except Exception:
                pass
        
        # ── Stage 5: Semantic label from behavior bits + topology ──────
        # COMPLETELY SEPARATE from sheaf math — reads behavior bitfields + novel edges
        # Pass both current-cycle alerts and windowed unique count for compound confirmation
        label = self._compute_semantic_label(
            current_behaviors, edge_alerts, rayleigh,
            novel_alerts, windowed_unique_count=len(windowed_unique)
        )
        
        # ── Stage 5b: Signal logging (for paper analysis) ─────────────
        try:
            log_record = {
                "ts": _time_mod.time(),
                "rayleigh": rayleigh,
                "global_threshold": self.cal.global_threshold or 0.0,
                "n_containers": len(raw_signals),
                "n_novel_edges": len(novel_alerts),
                "n_edge_alerts": len(edge_alerts),
                "per_container": {
                    str(cg): raw_signals[cg].tolist()
                    for cg in sorted(raw_signals.keys())
                },
                "per_edge_energy": {
                    f"{a.src}->{a.dst}@lag{a.lag}": {"energy": a.energy, "threshold": a.threshold, "ratio": a.ratio}
                    for a in edge_alerts
                },
            }
            _get_signal_log().write(json.dumps(log_record) + "\n")
        except Exception:
            pass  # never let logging kill the detector

        # ── Stage 6: Verdict ───────────────────────────────────────────
        # Compound confirmation: only enforce when severity >= MEDIUM.
        # LOW = single novel edge without corroborating signals → observe only.
        # This prevents false positives from legitimate new connections.
        global_threshold = self.cal.global_threshold or float('inf')

        # Behavior bits with HIGH/CRITICAL severity fire independently of geometric signal.
        # Direct kernel observations don't need sheaf corroboration.
        behavior_triggered = (label is not None and
                              label.severity in ('HIGH', 'CRITICAL') and
                              not novel_alerts and not edge_alerts and
                              rayleigh <= global_threshold)

        # Pristine gate for guarded EMA (Phase 5B): a cycle is pristine when
        # none of the anomaly signals fired AND no HIGH/CRITICAL behavior bit.
        pristine = not (
            novel_alerts or edge_alerts or rayleigh > global_threshold
            or behavior_triggered
        )
        self.ema_buffer.tick(pristine)

        if novel_alerts or edge_alerts or rayleigh > global_threshold or behavior_triggered:
            affected = set()
            for a in novel_alerts:
                affected.update([a.src, a.dst])
            for a in edge_alerts:
                affected.update([a.src, a.dst])

            reason_parts = []
            if novel_alerts:
                win_info = f" (window={len(windowed_unique)})" if len(windowed_unique) > len(novel_alerts) else ""
                reason_parts.append(f"{len(novel_alerts)} novel edge(s){win_info}")
            if edge_alerts:
                reason_parts.append(f"{len(edge_alerts)} anomalous edge(s)")
            if rayleigh > global_threshold:
                reason_parts.append(f"Rayleigh={rayleigh:.3f}>τ={global_threshold:.3f}")

            # LOW severity = observe only (no enforcement)
            severity = label.severity if label else 'NONE'
            action = VERDICT_ALLOW if severity == 'LOW' else VERDICT_KILL

            return Verdict(
                action=action,
                affected_cgroups=list(affected),
                rayleigh=rayleigh,
                global_threshold=global_threshold,
                edge_anomalies=edge_alerts,
                novel_edges=novel_alerts,
                label=label,
                eigenmodes=eigenmode_result,
                reason="; ".join(reason_parts)
            )
        
        return Verdict(action=VERDICT_ALLOW)
    
    def _compute_semantic_label(self, behaviors: Dict[int, dict],
                                 edge_alerts: List[EdgeAnomaly],
                                 rayleigh: float,
                                 novel_alerts: Optional[List[NovelEdgeAlert]] = None,
                                 windowed_unique_count: int = 0) -> AttackLabel:
        """
        Map invariant bit patterns + graph topology to MITRE ATT&CK labels.

        READS FROM: container_behavior.flags (invariant bits from kernel)
                     novel_alerts (uncalibrated connections from Tier 2)
                     windowed_unique_count (accumulated unique novel pairs over ~30s window)
        NOT FROM: sheaf signal vector (those are continuous, not discrete)

        Priority order: first matching rule wins.
        """
        novel_alerts = novel_alerts or []
        # Use the larger of current-cycle count or windowed count
        # so multi-cycle attacks still compound
        effective_novel_count = max(len(novel_alerts), windowed_unique_count)

        # Collect all set bits across all containers in the potential attack chain
        chain_bits = set()
        for cg_id, beh in behaviors.items():
            flags = beh.get('flags', 0)
            for i in range(8):
                if flags & (1 << i):
                    chain_bits.add(i)

        # bit 6 = BIT_FD_REDIRECT, bit 1 = BIT_LATERAL_CONNECT
        if 6 in chain_bits and 1 in chain_bits:
            return AttackLabel("Reverse shell with lateral movement",
                               ["T1059.004", "T1021.004"], "CRITICAL")

        # bit 2 = BIT_SENSITIVE_FILE, bit 5 = BIT_LARGE_TRANSFER
        if 2 in chain_bits and 5 in chain_bits:
            return AttackLabel("Credential theft → data exfiltration",
                               ["T1003", "T1048"], "CRITICAL")

        # Novel edges + sensitive file read = data exfiltration
        if 2 in chain_bits and effective_novel_count >= 1:
            return AttackLabel("Data exfiltration via novel channel",
                               ["T1041", "T1048"], "CRITICAL")

        # bit 3 = BIT_NS_PROBE, bit 4 = BIT_PRIVESC
        if 3 in chain_bits and 4 in chain_bits:
            return AttackLabel("Container escape attempt",
                               ["T1611"], "HIGH")

        # bit 7 = BIT_FORK_ACCEL
        if 7 in chain_bits:
            return AttackLabel("Fork bomb / resource exhaustion",
                               ["T1499.001"], "HIGH")

        # bit 0 = BIT_SHELL_SPAWN, bit 1 = BIT_LATERAL_CONNECT
        if 0 in chain_bits and 1 in chain_bits:
            return AttackLabel("Shell spawn with lateral connection",
                               ["T1059", "T1021"], "HIGH")

        # bit 0 = BIT_SHELL_SPAWN with novel edges = cryptominer/implant
        if 0 in chain_bits and effective_novel_count >= 1:
            return AttackLabel("Suspicious execution with novel connection",
                               ["T1059", "T1496"], "HIGH")

        # ── Compound confirmation for novel edges ────────────────────
        # A single novel edge alone is NOT sufficient for enforcement.
        # In production, new connections happen legitimately:
        #   - New service replica joins the cluster
        #   - Service starts using a new port (health check, metrics)
        #   - Load balancer reconfigures routing
        #
        # Novel edge ONLY triggers enforcement when compounded with:
        #   1. Another signal (behavior bit, sheaf energy spike), OR
        #   2. Multiple novel edges simultaneously (SSRF pattern), OR
        #   3. Novel edge to a destination with suspicious port (C2 ports)
        #
        # External end-user connections are already invisible here —
        # ip_to_cgroup only maps container IPs, so external traffic
        # never reaches the novel-edge detector.

        # Multiple novel edges (3+) = strong topology signal (multi-target SSRF)
        # Uses windowed count so SSRF stages across cycles still compound
        if effective_novel_count >= 3:
            return AttackLabel("Trust boundary violation (multi-target SSRF)",
                               ["T1090", "T1071"], "HIGH")

        # Novel edge + sheaf energy spike = confirmed anomaly
        if effective_novel_count >= 1 and edge_alerts:
            return AttackLabel("Novel connection with anomalous coupling",
                               ["T1071"], "HIGH")

        # 2 novel edges (within window) without behavior bits = suspicious but not critical
        if effective_novel_count >= 2:
            return AttackLabel("Multiple uncalibrated connections",
                               ["T1071"], "MEDIUM")

        # Single novel edge in window, no behavior bits, no sheaf spike = observe only
        # This avoids false positives from legitimate new connections
        if effective_novel_count == 1:
            return AttackLabel("Uncalibrated connection (monitoring)",
                               [], "LOW")

        # ── Single-bit behavior detections (independent of geometric signal) ──
        # These are direct kernel observations — no compound confirmation needed.
        if 2 in chain_bits:   # BIT_SENSITIVE_FILE: open(/etc/shadow), /proc/1/environ
            return AttackLabel("Sensitive file access (credential read)",
                               ["T1003", "T1552.001"], "HIGH")
        if 4 in chain_bits:   # BIT_PRIVESC: unshare --user (namespace escape attempt)
            return AttackLabel("Privilege escalation via namespace",
                               ["T1611", "T1068"], "HIGH")
        if 5 in chain_bits:   # BIT_PTRACE: ptrace(PTRACE_TRACEME)
            return AttackLabel("Process injection via ptrace",
                               ["T1055", "T1055.008"], "HIGH")
        if 3 in chain_bits:   # BIT_NS_PROBE: namespace recon
            return AttackLabel("Container namespace probing",
                               ["T1082", "T1611"], "MEDIUM")
        if 0 in chain_bits:   # BIT_SHELL_SPAWN: unusual shell execution
            return AttackLabel("Unexpected shell execution",
                               ["T1059"], "MEDIUM")

        # Sheaf anomaly without any invariant bits: unknown attack
        if edge_alerts or rayleigh > 0:
            return AttackLabel("Unknown anomalous inter-container coupling",
                               [], "MEDIUM")

        return AttackLabel("Normal", [], "NONE")

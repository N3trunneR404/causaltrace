# daemon_main.py
"""
CausalTrace Tier 3 Sheaf Daemon — Main Loop

Runs every DETECTION_INTERVAL seconds.
Reads BPF maps, runs detection pipeline, writes verdicts.

Usage:
  sudo python3 daemon_main.py --mode monitor    # log only, no enforcement
  sudo python3 daemon_main.py --mode enforce    # write verdict_map
  sudo python3 daemon_main.py --calibrate       # run calibration phase
"""
import time, argparse, logging, json, ctypes
from collections import defaultdict, deque
from pathlib import Path

# BCC import — requires sudo and BCC installation
from bcc import BPF

# CausalTrace modules
from signal_extractor import BigramSketch, CalibrationStats
from calibrate import SheafCalibrator
from sheaf_detector import SheafDetector, VERDICT_KILL, VERDICT_ALLOW
from ema_buffer import EMASignalBuffer
from enforcement_engine import EnforcementEngine
from trust_promoter import TrustPromoter
from ringbuf_monitor import RingBufferMonitor

DETECTION_INTERVAL = 5.0    # seconds between detection cycles
CALIBRATION_DIR = "calibration"
STALENESS_TTL = 10.0        # seconds: drop data older than this (GIL death spiral prevention)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("causaltrace")


class CausalTraceDaemon:
    def __init__(self, bpf_obj: BPF, mode: str = "monitor"):
        self.bpf = bpf_obj
        self.mode = mode   # "monitor" or "enforce"
        
        # BPF maps (accessed via BCC Python API)
        self.bigram_sketch_map = bpf_obj.get_table("bigram_sketch_map")
        self.container_behavior = bpf_obj.get_table("container_behavior")
        self.verdict_map = bpf_obj.get_table("verdict_map")
        
        # Calibration and detection
        self.cal = self._load_calibration()
        self.detector = SheafDetector(self.cal) if self.cal else None

        if self.detector:
            self.detector.setup_eigenmode_analyzer()

        # Enforcement engine (surgical syscall denial via BPF maps)
        ip_to_cg = {}
        try:
            ip_map = bpf_obj.get_table("ip_to_cgroup")
            for k, v in ip_map.items():
                ip_to_cg[k.value] = v.value
        except Exception:
            pass

        calibrated_edges = self.cal.calibrated_edges if self.cal else set()
        self.enforcer = EnforcementEngine(
            bpf_obj,
            calibrated_edges=calibrated_edges,
            ip_to_cgroup=ip_to_cg
        )

        # L4-stability trust promoter (Phase 3). Advances client_trust so the
        # Compound Enforcement Gate can pick Case B vs Case C per client IP.
        self.trust_promoter = TrustPromoter(bpf_obj)
        self._promotion_totals = {
            'observed_new': 0,
            'calibrated_new': 0,
            'cycles': 0,
        }

        # Ring buffer backpressure monitor (Phase 4). Reads ringbuf_stats
        # each cycle; logs shed/loss deltas. alerts_fail is critical.
        self.ringbuf_monitor = RingBufferMonitor(bpf_obj)

        # Connection event buffer (collected from telemetry ring buffer)
        self.recent_connections: deque = deque(maxlen=1000)

        # Results logging — CAUSALTRACE_RESULTS_DIR overrides default location
        import os as _os
        results_dir = Path(_os.environ.get("CAUSALTRACE_RESULTS_DIR", "results/causaltrace"))
        results_dir.mkdir(parents=True, exist_ok=True)
        self.results_log = open(results_dir / "verdicts.jsonl", 'a')
    
    def _load_calibration(self) -> SheafCalibrator:
        """Load calibration data from disk. Returns None if not calibrated."""
        cal_path = Path(CALIBRATION_DIR)
        if not (cal_path / "edge_thresholds.json").exists():
            log.warning("No calibration found. Run with --calibrate first.")
            return None
        
        import pickle
        cal = SheafCalibrator()
        
        with open(cal_path / "pca.pkl", 'rb') as f:
            cal.pca = pickle.load(f)
        with open(cal_path / "whiteners.pkl", 'rb') as f:
            cal.whitener = pickle.load(f)
        with open(cal_path / "edge_thresholds.json") as f:
            raw = json.load(f)
            cal.edge_thresholds = {eval(k): v for k, v in raw.items()}
        with open(cal_path / "global_threshold.json") as f:
            cal.global_threshold = json.load(f)['global']
        with open(cal_path / "calibrated_edges.json") as f:
            cal.calibrated_edges = set(tuple(e) for e in json.load(f))

        # Load restriction maps (CCA matrices) from npz — critical for Rayleigh quotient
        # NOTE: calibrate.py has a variable shadowing bug: the inner loop
        #   `for k, v in [('u', Fu), ('v', Fv)]` shadows the outer edge-dst `v`,
        # so NPZ keys are `F_{src}_{matrix_str}_{lag}_{side}` NOT `F_{src}_{dst}_{lag}_{side}`.
        # We recover by: split-from-right to get (prefix, lag, side), extract src from prefix,
        # then use calibrated_edges.json to find the matching dst for each src.
        import numpy as np
        restriction_path = cal_path / "restriction_maps.npz"
        if restriction_path.exists():
            data = np.load(str(restriction_path))
            # Build src→dst lookup from calibrated edges (edges are (src, dst, port) triples)
            src_to_dst = {}
            for edge in cal.calibrated_edges:
                src, dst = int(edge[0]), int(edge[1])
                if src not in src_to_dst:
                    src_to_dst[src] = dst  # use first dst seen for this src

            # Group keys by (src, lag) using right-split parsing
            groups = {}  # (src, lag) → {'u': key, 'v': key}
            for k in data.files:
                parts = k.rsplit('_', 2)  # [prefix, lag_str, side]
                if len(parts) != 3:
                    continue
                prefix, lag_str, side = parts
                if side not in ('u', 'v'):
                    continue
                try:
                    lag = int(lag_str)
                except ValueError:
                    continue
                # prefix = "F_{src}_{matrix_str}"
                pfx_parts = prefix.split('_', 2)  # ['F', src_str, rest]
                if len(pfx_parts) < 2:
                    continue
                try:
                    src = int(pfx_parts[1])
                except ValueError:
                    continue
                groups.setdefault((src, lag), {})[side] = k

            # Reconstruct restriction_maps using src→dst lookup
            for (src, lag), sides in groups.items():
                if 'u' not in sides or 'v' not in sides:
                    continue
                dst = src_to_dst.get(src)
                if dst is None:
                    continue
                Fu = data[sides['u']]
                Fv = data[sides['v']]
                cal.restriction_maps[(src, dst, lag)] = (Fu, Fv)

            log.info(f"Restriction maps loaded: {len(cal.restriction_maps)} (u,v,lag) entries")
        else:
            log.warning("restriction_maps.npz not found — Rayleigh quotient will be 0")

        # Load edge_cov_inv.npz if present (written by recalibrate_thresholds.py)
        cov_inv_path = cal_path / "edge_cov_inv.npz"
        if cov_inv_path.exists():
            cov_data = np.load(str(cov_inv_path))
            for k in cov_data.files:
                # keys: "COV_{u}_{v}_{lag}"
                parts = k.split('_')
                if len(parts) == 4 and parts[0] == 'COV':
                    try:
                        u_id = int(parts[1])
                        v_id = int(parts[2])
                        lag  = int(parts[3])
                        cal.edge_cov_inv[(u_id, v_id, lag)] = cov_data[k]
                    except ValueError:
                        pass
            log.info(f"edge_cov_inv loaded: {len(cal.edge_cov_inv)} entries")

        from signal_extractor import CalibrationStats
        cal.cal_stats = CalibrationStats(
            pca_components=cal.pca.components_,
            pca_mean=cal.pca.mean_
        )

        log.info(f"Calibration loaded: {len(cal.calibrated_edges)} edges, "
                 f"global_threshold={cal.global_threshold:.4f}")
        return cal
    
    def _read_bigram_sketches(self) -> dict:
        """Read all bigram sketches from BPF map."""
        sketches = {}
        for key, value in self.bigram_sketch_map.items():
            cg_id = key.value
            # Convert BPF struct to Python BigramSketch
            import numpy as np
            counters = np.array([[value.counters[r * 128 + c]
                                   for c in range(128)]
                                  for r in range(4)], dtype=np.uint32)
            sketches[cg_id] = BigramSketch(
                counters=counters,
                prev_idx=value.prev_idx,
                total_count=value.total_count,
                window_start=value.window_start
            )
        return sketches
    
    def _read_container_behaviors(self) -> dict:
        """Read all behavior bitfields from BPF map."""
        behaviors = {}
        for key, value in self.container_behavior.items():
            cg_id = key.value
            behaviors[cg_id] = {
                'flags': value.flags,
                'bit_ts': [value.bit_ts[i] for i in range(8)],
                'conn_dst_cg': value.conn_dst_cg,
                'conn_port': value.conn_port
            }
        return behaviors
    
    def _setup_telemetry_callback(self):
        """Register callback for telemetry ring buffer (connection events)."""
        try:
            def handle_connection(ctx, data, size):
                try:
                    import ctypes as ct
                    class AlertT(ct.Structure):
                        _fields_ = [
                            ('type', ct.c_uint32),
                            ('pid', ct.c_uint32),
                            ('cgroup_id', ct.c_uint64),
                            ('timestamp', ct.c_uint64),
                            ('flags', ct.c_uint64),
                            ('extra', ct.c_uint64),
                        ]
                    event = ct.cast(data, ct.POINTER(AlertT)).contents
                    if event.type == 100:
                        self.recent_connections.append({
                            'src_cg': int(event.cgroup_id),
                            'dst_cg': int(event.flags),
                            'dst_port': int(event.extra & 0xFFFF),
                            'timestamp': int(event.timestamp)
                        })
                except Exception:
                    pass
            self.bpf["telemetry_rb"].open_ring_buffer(handle_connection)
        except Exception as e:
            log.warning(f"Telemetry ring buffer setup failed: {e}")
    
    def run_detection_cycle(self):
        """Single detection cycle."""
        cycle_start = time.monotonic()

        # Poll ring buffer for new connection events
        self.bpf.ring_buffer_poll(timeout=100)

        # ── Ring buffer backpressure (Phase 4) ─────────────────────────
        try:
            rbd = self.ringbuf_monitor.scan()
            if rbd.has_alert_loss():
                log.error(f"ringbuf: LOST {rbd.alerts_fail} ALERT(S) "
                          f"(ok={rbd.alerts_ok}, near_full={rbd.alerts_near_full}) "
                          f"— consumer is too slow")
            elif rbd.has_concern():
                log.warning(f"ringbuf: telemetry shed={rbd.telemetry_shed} "
                            f"fail={rbd.telemetry_fail} ok={rbd.telemetry_ok} | "
                            f"alerts near_full={rbd.alerts_near_full} "
                            f"ok={rbd.alerts_ok}")
        except Exception as e:
            log.debug(f"ringbuf monitor scan failed: {e}")

        # ── Trust promotion (Phase 3) ──────────────────────────────────
        # Run BEFORE detection so enforcement sees the latest trust levels.
        try:
            pm = self.trust_promoter.scan_and_promote()
            self._promotion_totals['observed_new']   += pm.observed_new
            self._promotion_totals['calibrated_new'] += pm.calibrated_new
            self._promotion_totals['cycles']         += 1
            if pm.observed_new or pm.calibrated_new:
                log.info(f"trust: +{pm.observed_new} OBSERVED, "
                         f"+{pm.calibrated_new} CALIBRATED "
                         f"(ips={pm.ips_with_flows}, burned={pm.burned_seen}, "
                         f"scanned={pm.scanned})")
            # Periodic totals every 12 cycles (~1 min at 5s interval)
            if self._promotion_totals['cycles'] % 12 == 0:
                log.info(f"trust totals: "
                         f"obs_total={self._promotion_totals['observed_new']}, "
                         f"cal_total={self._promotion_totals['calibrated_new']}")
        except Exception as e:
            log.warning(f"trust promoter scan failed: {e}")
        
        # Staleness check: if we're behind, drop stale data and resync
        # BPF timestamps use bpf_ktime_get_ns() = CLOCK_MONOTONIC
        now_ns = time.monotonic_ns()
        fresh_connections = [
            c for c in self.recent_connections
            if (now_ns - c['timestamp']) / 1e9 < STALENESS_TTL
        ]
        
        if len(fresh_connections) < len(self.recent_connections):
            dropped = len(self.recent_connections) - len(fresh_connections)
            if dropped > 10:
                log.warning(f"Dropped {dropped} stale connection events (daemon behind)")
        
        # Read current BPF state
        sketches = self._read_bigram_sketches()
        behaviors = self._read_container_behaviors()
        
        if not sketches:
            return  # No container data yet
        
        if self.detector is None:
            log.debug("No calibration loaded — running in observation mode only")
            return
        
        # Run sheaf detection pipeline
        verdict = self.detector.detect_cycle(
            current_sketches=sketches,
            current_behaviors=behaviors,
            current_connections=list(fresh_connections)
        )
        
        # Clear processed connections
        self.recent_connections.clear()
        
        # ── Enforcement Engine ─────────────────────────────────────────
        # Build ip→cgroup lookup for enforcement rules
        ip_to_cg = {}
        try:
            ip_map = self.bpf.get_table("ip_to_cgroup")
            for k, v in ip_map.items():
                ip_to_cg[k.value] = v.value
        except Exception:
            pass

        if self.mode == "enforce" and verdict.action == VERDICT_KILL:
            enforce_result = self.enforcer.enforce(verdict, ip_to_cg)
        else:
            enforce_result = {'action': 'ALLOW' if verdict.action == VERDICT_ALLOW else 'MONITOR',
                              'level': 0, 'rules_applied': 0}

        # Periodic TTL sweep (every cycle)
        self.enforcer.sweep_expired_rules()

        # Log result
        severity = verdict.label.severity if verdict.label else 'NONE'

        log_entry = {
            'timestamp': time.time(),
            'action': enforce_result['action'],
            'enforcement_level': enforce_result.get('level', 0),
            'rules_applied': enforce_result.get('rules_applied', 0),
            'rayleigh': verdict.rayleigh,
            'global_threshold': verdict.global_threshold,
            'edge_anomalies': len(verdict.edge_anomalies),
            'novel_edges': len(verdict.novel_edges),
            'label': verdict.label.name if verdict.label else None,
            'mitre': verdict.label.mitre_ids if verdict.label else [],
            'severity': severity,
            'reason': verdict.reason,
            'enforcement_actions': enforce_result.get('actions', []),
        }

        if verdict.action == VERDICT_KILL:
            log.warning(f"ATTACK DETECTED [{severity}]: "
                       f"{verdict.label.name if verdict.label else 'Unknown'} | "
                       f"L{enforce_result.get('level', 0)} {enforce_result['action']} | "
                       f"Containers: {verdict.affected_cgroups} | "
                       f"Rayleigh: {verdict.rayleigh:.3f} | "
                       f"Rules: {enforce_result.get('rules_applied', 0)} | "
                       f"Reason: {verdict.reason}")

        self.results_log.write(json.dumps(log_entry) + '\n')
        self.results_log.flush()
        
        # Timing check
        elapsed = time.monotonic() - cycle_start
        if elapsed > DETECTION_INTERVAL:
            log.warning(f"Detection cycle took {elapsed:.2f}s (>{DETECTION_INTERVAL}s) — "
                       f"consider reducing container count or using multiprocessing")
    
    def run(self):
        """Main loop."""
        log.info(f"CausalTrace Tier 3 running in {self.mode} mode")
        log.info(f"Detection interval: {DETECTION_INTERVAL}s")
        
        self._setup_telemetry_callback()
        
        while True:
            cycle_start = time.monotonic()
            try:
                self.run_detection_cycle()
            except KeyboardInterrupt:
                log.info("Shutting down...")
                break
            except Exception as e:
                log.error(f"Detection cycle error: {e}", exc_info=True)
            
            # Sleep for remainder of interval
            elapsed = time.monotonic() - cycle_start
            sleep_time = max(0, DETECTION_INTERVAL - elapsed)
            time.sleep(sleep_time)

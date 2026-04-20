# tier3/verdict_writer.py
"""
Verdict Writer — writes sheaf daemon verdicts to BPF verdict_map
and to the structured results log.

The verdict_map is the ONLY path by which Tier 3 decisions become
kernel enforcement. The dispatcher reads this map on every container
syscall and calls bpf_send_signal(9) if the cgroup is flagged.

Design constraint: verdicts are persistent until explicitly cleared.
Once a cgroup is flagged KILL, it will be killed on every subsequent
syscall until the map entry is removed. This is intentional — an
attacker cannot escape by quickly spawning a new process.

Clearing verdicts: done on container restart (Docker event listener
calls unregister_container() which clears the map entry).
"""
import ctypes, json, time, logging
from pathlib import Path
from dataclasses import asdict

log = logging.getLogger("causaltrace.verdict")

VERDICT_ALLOW = 0
VERDICT_KILL  = 1


class VerdictWriter:
    def __init__(self, bpf_obj, results_dir: str = "results/causaltrace",
                 mode: str = "monitor"):
        """
        bpf_obj: BPF object from BCC (already loaded)
        results_dir: directory for JSON log output
        mode: "monitor" (log only) or "enforce" (write verdict_map)
        """
        self.verdict_map = bpf_obj.get_table("verdict_map")
        self.mode = mode

        Path(results_dir).mkdir(parents=True, exist_ok=True)
        log_path = Path(results_dir) / "verdicts.jsonl"
        self.log_file = open(log_path, 'a', buffering=1)  # line-buffered

        log.info(f"VerdictWriter: mode={mode}, log={log_path}")

    def write(self, verdict) -> None:
        """
        Process a verdict from SheafDetector.detect_cycle().
        - If KILL and mode=enforce: writes to verdict_map
        - Always: writes structured log entry
        """
        ts = time.time()

        log_entry = {
            "timestamp":       ts,
            "action":          "KILL" if verdict.action == VERDICT_KILL else "ALLOW",
            "mode":            self.mode,
            "rayleigh":        round(verdict.rayleigh, 6),
            "global_tau":      round(verdict.global_threshold, 6),
            "novel_edges":     len(verdict.novel_edges),
            "edge_anomalies":  len(verdict.edge_anomalies),
            "affected_cgroups": verdict.affected_cgroups,
            "label":           verdict.label.name if verdict.label else None,
            "severity":        verdict.label.severity if verdict.label else "NONE",
            "mitre":           verdict.label.mitre_ids if verdict.label else [],
            "reason":          verdict.reason,
        }

        # Add edge anomaly details
        if verdict.edge_anomalies:
            log_entry["edge_details"] = [
                {
                    "src": a.src, "dst": a.dst, "lag": a.lag,
                    "energy": round(a.energy, 4),
                    "threshold": round(a.threshold, 4),
                    "ratio": round(a.ratio, 3),
                }
                for a in verdict.edge_anomalies
            ]

        # Add novel edge details
        if verdict.novel_edges:
            log_entry["novel_edge_details"] = [
                {"src": n.src, "dst": n.dst, "port": n.port}
                for n in verdict.novel_edges
            ]

        # Add eigenmode fingerprint if available
        if verdict.eigenmodes:
            log_entry["eigenmodes"] = {
                "total_energy":   round(verdict.eigenmodes.total_energy, 4),
                "dominant_modes": verdict.eigenmodes.dominant_modes,
                "mode_energies":  [round(e, 4) for e in verdict.eigenmodes.mode_energies],
            }

        # Write to log
        self.log_file.write(json.dumps(log_entry) + "\n")

        if verdict.action == VERDICT_KILL:
            label_str = verdict.label.name if verdict.label else "Unknown"
            log.warning(
                f"ATTACK: {label_str} | "
                f"cgroups={verdict.affected_cgroups} | "
                f"rayleigh={verdict.rayleigh:.3f} | "
                f"{verdict.reason}"
            )

            if self.mode == "enforce":
                for cg_id in verdict.affected_cgroups:
                    self._kill_cgroup(cg_id)
            else:
                log.info("  (monitor mode — verdict not enforced)")

    def _kill_cgroup(self, cgroup_id: int) -> None:
        """Write VERDICT_KILL for a cgroup to the BPF verdict_map."""
        try:
            key = ctypes.c_uint64(cgroup_id)
            val = ctypes.c_uint32(VERDICT_KILL)
            self.verdict_map[key] = val
            log.info(f"  verdict_map[{cgroup_id}] = KILL (kernel will enforce on next syscall)")
        except Exception as e:
            log.error(f"  Failed to write verdict for cgroup {cgroup_id}: {e}")

    def clear_verdict(self, cgroup_id: int) -> None:
        """
        Clear a KILL verdict for a cgroup (e.g., after container restart).
        Called by DockerEventListener on container stop/die.
        """
        try:
            key = ctypes.c_uint64(cgroup_id)
            del self.verdict_map[key]
            log.info(f"  verdict_map[{cgroup_id}] cleared")
        except Exception:
            pass   # Entry may not exist — that's fine

    def close(self):
        self.log_file.close()

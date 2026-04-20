# infra/cgroup_snapshot.py
"""
Phase 7D — Cgroup snapshot for restart-stable container attribution.

Problem:
  cgroup IDs are stable while a container exists but change when the
  container is recreated (docker compose down/up, a crash, etc.).
  Calibration learned the sheaf structure against a specific set of
  (cgroup_id, container_name) pairs. If the daemon restarts without
  remembering those mappings, the verdict log loses its human-readable
  labels and analysis scripts treat "the same" container as a new one.

Solution:
  At daemon start, walk Docker's running containers, read each one's
  cgroup id, and write the mapping to calibration/cgroup_snapshot.json.
  The file is rewritten on each daemon start — it always reflects the
  current live state, plus a `first_seen_ns` timestamp per container
  that is preserved across snapshots when the cgroup id is unchanged.

This module is optional: if Docker is not installed, Python-docker isn't
available, or there are no containers, we return an empty snapshot and
the daemon keeps running. It's strictly additive observability.
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, Any

log = logging.getLogger("causaltrace.cgroup_snapshot")

SNAPSHOT_FILE = "cgroup_snapshot.json"


def _cgroup_id_for_pid(pid: int) -> int:
    """Read the cgroup v2 inode number for a PID. Returns 0 on failure."""
    try:
        # /proc/<pid>/cgroup line looks like "0::/system.slice/..."
        with open(f"/proc/{pid}/cgroup") as f:
            for line in f:
                parts = line.strip().split(":", 2)
                if len(parts) == 3 and parts[0] == "0":
                    cgpath = "/sys/fs/cgroup" + parts[2]
                    # The cgroup_id that bpf_get_current_cgroup_id returns
                    # is the inode number of the cgroup directory.
                    import os
                    try:
                        return os.stat(cgpath).st_ino
                    except OSError:
                        return 0
    except Exception:
        return 0
    return 0


def take_snapshot(calibration_dir: str = "calibration") -> Dict[str, Any]:
    """
    Snapshot running Docker containers to <calibration_dir>/cgroup_snapshot.json.

    Returns the snapshot dict. Never raises — on any error, returns {}
    and logs a warning. The daemon continues either way.
    """
    out: Dict[str, Any] = {
        "captured_ns": time.monotonic_ns(),
        "captured_wallclock": time.time(),
        "containers": {},
    }
    try:
        import docker  # docker-py, already a dep in calibrate_runner
    except Exception as e:
        log.warning(f"docker library unavailable; skipping snapshot ({e})")
        return out

    try:
        client = docker.from_env()
        running = client.containers.list()
    except Exception as e:
        log.warning(f"cannot enumerate docker containers: {e}")
        return out

    # Load previous snapshot so we can preserve first_seen_ns when a
    # container's cgroup id is unchanged.
    prev_path = Path(calibration_dir) / SNAPSHOT_FILE
    prev_containers: Dict[str, Any] = {}
    if prev_path.exists():
        try:
            prev_containers = json.loads(prev_path.read_text()).get("containers", {})
        except Exception:
            prev_containers = {}

    for c in running:
        try:
            inspect = client.api.inspect_container(c.id)
            pid = inspect.get("State", {}).get("Pid", 0)
            if not pid:
                continue
            cg_id = _cgroup_id_for_pid(pid)
            if not cg_id:
                continue
            name = c.name
            entry = {
                "cgroup_id": cg_id,
                "pid": pid,
                "image": c.image.tags[0] if c.image.tags else "<untagged>",
                "status": c.status,
            }
            # Preserve first_seen_ns if cgroup id is unchanged.
            prev = prev_containers.get(name)
            if prev and prev.get("cgroup_id") == cg_id and "first_seen_ns" in prev:
                entry["first_seen_ns"] = prev["first_seen_ns"]
            else:
                entry["first_seen_ns"] = out["captured_ns"]
            out["containers"][name] = entry
        except Exception as e:
            log.warning(f"skip container {c.name}: {e}")

    # Write the fresh snapshot.
    try:
        Path(calibration_dir).mkdir(parents=True, exist_ok=True)
        target = Path(calibration_dir) / SNAPSHOT_FILE
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(out, indent=2))
        tmp.replace(target)  # atomic
        log.info(f"cgroup snapshot: {len(out['containers'])} container(s) "
                 f"written to {target}")
    except Exception as e:
        log.warning(f"could not write snapshot: {e}")

    return out


def load_snapshot(calibration_dir: str = "calibration") -> Dict[str, Any]:
    """Return the last persisted snapshot, or {} if none."""
    p = Path(calibration_dir) / SNAPSHOT_FILE
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception as e:
        log.warning(f"cannot parse {p}: {e}")
        return {}


def cgroup_id_to_name(snapshot: Dict[str, Any]) -> Dict[int, str]:
    """Build reverse lookup: cgroup_id → container name."""
    lookup: Dict[int, str] = {}
    for name, entry in (snapshot.get("containers") or {}).items():
        cg = entry.get("cgroup_id")
        if cg:
            lookup[int(cg)] = name
    return lookup


if __name__ == "__main__":
    # Standalone invocation: useful for ops troubleshooting.
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(description="Snapshot Docker container cgroup IDs.")
    p.add_argument("--dir", default="calibration",
                   help="calibration directory to write snapshot into")
    args = p.parse_args()
    snap = take_snapshot(args.dir)
    print(json.dumps(snap, indent=2))

#!/usr/bin/env python3
# supervisor.py
"""
Phase 7B — CausalTrace supervisor.

Launches loader.py as a child process and keeps it running in the face
of crashes. Responsibilities:

  1. Run preflight once (fail-fast if the environment is broken).
  2. spawn loader.py with the supplied args.
  3. On unexpected exit (non-zero), wait with exponential backoff and
     respawn, up to MAX_CRASHES within CRASH_WINDOW seconds — beyond
     that we stop, assuming a permanent fault.
  4. On SIGTERM/SIGINT: forward to the child, wait GRACE seconds, SIGKILL
     if needed, then clean up stale BPF pins left under /sys/fs/bpf/causaltrace.

Explicit non-goals:
  - We do NOT tear down TC filters here; loader.py's atexit handler
    already does that. The supervisor only cleans up if loader crashed
    hard (SIGKILL / OOM) and couldn't run its own atexit hooks.

Usage:
  sudo python3 supervisor.py -- --mode enforce
  sudo python3 supervisor.py -- --calibrate

Everything after the `--` is passed verbatim to loader.py.
"""

import argparse
import logging
import os
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path

LOADER_CMD   = [sys.executable, "loader.py"]
PIN_DIR      = Path("/sys/fs/bpf/causaltrace")
LOG_DIR      = Path(os.environ.get("CAUSALTRACE_LOG_DIR", "results/causaltrace"))
MAX_CRASHES  = 5             # give up after N crashes
CRASH_WINDOW = 600.0         # ...within this many seconds
GRACE_S      = 8.0           # SIGTERM -> SIGKILL grace window
BACKOFF_BASE = 2.0           # initial backoff; doubles each crash, capped
BACKOFF_CAP  = 60.0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [supervisor] %(levelname)s %(message)s",
)
log = logging.getLogger("causaltrace.supervisor")


class GracefulExit(Exception):
    """Raised from signal handlers to unwind the main loop cleanly."""


def _install_signal_handlers(state: dict) -> None:
    def handler(signum, _frame):
        log.info(f"received signal {signum}; initiating graceful shutdown")
        state["shutdown"] = True
        child = state.get("child")
        if child and child.poll() is None:
            try:
                child.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT,  handler)


def _run_preflight() -> bool:
    pf = Path("scripts/preflight.sh")
    if not pf.exists():
        log.warning("preflight.sh missing; skipping preflight")
        return True
    rc = subprocess.call(["bash", str(pf)])
    return rc == 0


def _cleanup_stale_pins() -> None:
    """Called when the child crashed without running its atexit. TC filters
    attached to veths are independently pinned under PIN_DIR and must be
    removed so the next loader can re-pin without EBUSY."""
    if not PIN_DIR.exists():
        return
    try:
        entries = list(PIN_DIR.iterdir())
    except Exception as e:
        log.warning(f"cannot list {PIN_DIR}: {e}")
        return
    for p in entries:
        try:
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink(missing_ok=True)
            log.info(f"removed stale pin {p}")
        except Exception as e:
            log.warning(f"could not remove {p}: {e}")


def _wait_with_interrupts(state: dict, seconds: float) -> None:
    """Sleep `seconds`, but wake immediately if a shutdown was requested."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if state.get("shutdown"):
            return
        time.sleep(min(0.5, deadline - time.monotonic()))


def _terminate_child(child: subprocess.Popen) -> int:
    """SIGTERM, then SIGKILL after GRACE_S. Return the final exit code."""
    if child.poll() is not None:
        return child.returncode
    try:
        child.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        return child.returncode or 0
    deadline = time.monotonic() + GRACE_S
    while time.monotonic() < deadline:
        if child.poll() is not None:
            return child.returncode
        time.sleep(0.25)
    log.warning(f"child did not exit in {GRACE_S}s — SIGKILL")
    try:
        child.kill()
    except ProcessLookupError:
        pass
    child.wait(timeout=2.0)
    return child.returncode or -9


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="CausalTrace supervisor: keeps loader.py running.")
    p.add_argument("--no-preflight", action="store_true",
                   help="skip preflight checks (not recommended)")
    p.add_argument("loader_args", nargs=argparse.REMAINDER,
                   help="args forwarded to loader.py (prefix with --)")
    args = p.parse_args(argv)

    forward = [a for a in args.loader_args if a != "--"]

    if not args.no_preflight:
        if not _run_preflight():
            log.error("preflight FAILED — refusing to start loader")
            return 1

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    state = {"child": None, "shutdown": False}
    _install_signal_handlers(state)

    crash_history = []     # timestamps of recent crashes
    crash_count   = 0

    while not state["shutdown"]:
        cmd = LOADER_CMD + forward
        log.info(f"spawning: {' '.join(cmd)}")
        try:
            child = subprocess.Popen(cmd)
        except Exception as e:
            log.error(f"could not spawn loader: {e}")
            return 2
        state["child"] = child

        rc = child.wait()
        state["child"] = None

        if state["shutdown"]:
            rc = _terminate_child(child) if child.poll() is None else rc
            log.info(f"shutdown path: child rc={rc}")
            break

        now = time.monotonic()
        # Trim crash history to the sliding window
        crash_history = [t for t in crash_history if now - t < CRASH_WINDOW]

        if rc == 0:
            log.info("loader exited cleanly (rc=0); not restarting")
            return 0

        crash_history.append(now)
        crash_count += 1
        log.warning(f"loader crashed rc={rc} "
                    f"({len(crash_history)}/{MAX_CRASHES} within "
                    f"{int(CRASH_WINDOW)}s)")

        # After a crash, clean up any pins left behind before respawning.
        _cleanup_stale_pins()

        if len(crash_history) >= MAX_CRASHES:
            log.error(f"loader crashed {MAX_CRASHES} times within "
                      f"{int(CRASH_WINDOW)}s — giving up. "
                      f"Check loader logs in {LOG_DIR}")
            return 3

        # Exponential backoff based on recent crash count, capped.
        backoff = min(BACKOFF_CAP, BACKOFF_BASE * (2 ** (len(crash_history) - 1)))
        log.info(f"backing off {backoff:.1f}s before respawn")
        _wait_with_interrupts(state, backoff)

    log.info("supervisor exiting")
    return 0


if __name__ == "__main__":
    sys.exit(main())

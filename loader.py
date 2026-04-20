# loader.py
"""
CausalTrace BCC Loader
Must run as root (sudo).

Usage:
  sudo python3 loader.py --mode monitor     # alert only, no enforcement
  sudo python3 loader.py --mode enforce     # graduated response active
  sudo python3 loader.py --calibrate        # calibration mode
  sudo python3 loader.py --cleanup          # detach stale BPF programs

BPF Lifecycle:
  - Signal handlers (SIGTERM, SIGINT) trigger clean shutdown
  - atexit hook ensures BPF detach even on unexpected exit
  - --cleanup flag removes any stale programs from prior crashed runs
  - BCC auto-detaches when BPF object is garbage collected
"""
import os, sys, ctypes, argparse, time, threading, logging, signal, atexit
from pathlib import Path
from bcc import BPF

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S,%f")

KERNEL_DIR = Path(__file__).parent / "kernel"
BPF_SRC = KERNEL_DIR / "causaltrace_bcc.c"

TAIL_CALL_MAP = {
    56:  "handle_fork",
    435: "handle_fork",
    59:  "handle_execve",
    2:   "handle_file_open",   # open(path, flags)      — rdi = path
    257: "handle_file",        # openat(dirfd, path, …) — rsi = path
    105: "handle_privesc",
    308: "handle_privesc",
    272: "handle_privesc",
    101: "handle_privesc",
    33:  "handle_dup2",
    292: "handle_dup2",
}

# Global reference for cleanup
_bpf_obj = None
_shutting_down = False


def cleanup_bpf():
    """Detach all BPF programs and close the BPF object.
    Called on normal exit, SIGTERM, SIGINT."""
    global _bpf_obj, _shutting_down
    if _shutting_down:
        return
    _shutting_down = True
    if _bpf_obj is not None:
        print("\n[cleanup] Detaching BPF programs...")
        try:
            _bpf_obj.detach_kprobe(event="tcp_v4_connect")
            _bpf_obj.detach_kretprobe(event="tcp_v4_connect")
            print("[cleanup] Probe B kprobes detached")
        except Exception:
            pass
        # Enforcement kprobes
        for event in ["__x64_sys_connect", "__x64_sys_openat", "__x64_sys_execve"]:
            try:
                _bpf_obj.detach_kprobe(event=event)
            except Exception:
                pass
        print("[cleanup] Enforcement kprobes detached")
        try:
            _bpf_obj.cleanup()
            print("[cleanup] BPF object cleaned up")
        except Exception:
            pass
        _bpf_obj = None
    print("[cleanup] Done — no stale BPF programs remain")


def signal_handler(signum, frame):
    """Handle SIGTERM/SIGINT for clean shutdown."""
    sig_name = signal.Signals(signum).name
    print(f"\n[signal] Received {sig_name} — shutting down cleanly")
    cleanup_bpf()
    sys.exit(0)


def run_cleanup_only():
    """Standalone cleanup: find and report stale CausalTrace BPF programs."""
    import subprocess
    result = subprocess.run(
        ["bpftool", "prog", "list"],
        capture_output=True, text=True
    )
    stale = []
    for line in result.stdout.split('\n'):
        if any(name in line for name in [
            'sys_enter', 'handle_fork', 'handle_execve', 'handle_file',
            'handle_privesc', 'handle_dup2', 'trace_connect'
        ]):
            prog_id = line.split(':')[0].strip()
            stale.append((prog_id, line.strip()))

    if not stale:
        print("No stale CausalTrace BPF programs found.")
        return

    print(f"Found {len(stale)} stale BPF programs:")
    for pid, desc in stale:
        print(f"  {desc}")
    print("\nThese will be automatically cleaned when their owning process exits.")
    print("If processes are dead, programs are orphaned and will clear on reboot.")
    print("To force-clear: kill any remaining loader.py processes")

    # Try to find owning PIDs
    for line in result.stdout.split('\n'):
        if 'pids' in line.lower():
            print(f"  {line.strip()}")


def load_bpf(enforce=False):
    global _bpf_obj
    src = BPF_SRC.read_text()
    enforce_val = "1" if enforce else "0"
    print(f"Compiling eBPF programs (ENFORCE_MODE={enforce_val})...")
    b = BPF(text=src, cflags=[
        "-Wno-unused-variable",
        "-Wno-unused-function",
        "-Wno-address-of-packed-member",
        f"-DENFORCE_MODE={enforce_val}",
    ])
    print("  Compilation successful")
    _bpf_obj = b
    return b


def setup_tail_calls(b):
    prog_array = b.get_table("prog_array")
    for nr, fn_name in TAIL_CALL_MAP.items():
        try:
            fn = b.load_func(fn_name, BPF.RAW_TRACEPOINT)
            prog_array[ctypes.c_uint32(nr)] = ctypes.c_int(fn.fd)
            print(f"  syscall {nr:3d} -> {fn_name}")
        except Exception as e:
            print(f"  WARN: syscall {nr} -> {fn_name}: {e}")


def attach_probes(b, enforce=False):
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")
    print("  Probe B: tcp_v4_connect attached")

    # Accept-side attribution for the Compound Gate's trust lookup
    try:
        b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")
        print("  Accept: inet_csk_accept kretprobe attached")
    except Exception as e:
        print(f"  WARN: inet_csk_accept kretprobe failed ({e}); trust-gating degrades to Case C for all anomalies")

    # L4 byte accumulation for trust promotion (Phase 3)
    try:
        b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
        b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg_entry")
        b.attach_kretprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg_return")
        print("  L4 stability: tcp_sendmsg + tcp_recvmsg hooks attached")
    except Exception as e:
        print(f"  WARN: L4 stability hooks failed ({e}); trust promotion will not advance past OBSERVED")

    if enforce:
        # Enforcement kprobes — surgical syscall denial via bpf_override_return()
        b.attach_kprobe(event="__x64_sys_connect", fn_name="enforce_connect")
        print("  Enforce: __x64_sys_connect kprobe attached")
        b.attach_kprobe(event="__x64_sys_openat", fn_name="enforce_openat")
        print("  Enforce: __x64_sys_openat kprobe attached")
        b.attach_kprobe(event="__x64_sys_execve", fn_name="enforce_execve")
        print("  Enforce: __x64_sys_execve kprobe attached")


def populate_host_ns(b):
    ns_inum = os.stat("/proc/self/ns/mnt").st_ino
    b.get_table("host_ns")[ctypes.c_uint32(0)] = ctypes.c_uint32(ns_inum)
    print(f"  Host NS inode: {ns_inum}")


# ------------------------------------------------------------------ #
#  TC DROP ATTACHMENT — Phase 2                                      #
# ------------------------------------------------------------------ #
#  Attaches tc_drop_ingress + tc_drop_egress classifier programs to  #
#  every monitored container's host-side veth, so the Compound Gate  #
#  can sever an attacker's TCP flow without killing the container.   #
# ------------------------------------------------------------------ #
import subprocess as _subp
import re as _re

TC_PIN_DIR = "/sys/fs/bpf/causaltrace"
TC_INGRESS_PIN = f"{TC_PIN_DIR}/tc_drop_ingress"
TC_EGRESS_PIN = f"{TC_PIN_DIR}/tc_drop_egress"


def _pin_prog(fd, path):
    """Pin a BPF program fd to bpffs via ctypes bpf_obj_pin syscall."""
    # Ensure parent dir is a mounted bpffs (normally /sys/fs/bpf is).
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        os.unlink(path)
    # Use libbpf's bpf_obj_pin — ships with iproute2/libbpf which is already present.
    try:
        import ctypes.util
        libbpf_path = ctypes.util.find_library("bpf")
        if not libbpf_path:
            # Fall back to the common install path
            libbpf_path = "libbpf.so.1"
        libbpf = ctypes.CDLL(libbpf_path, use_errno=True)
        libbpf.bpf_obj_pin.argtypes = [ctypes.c_int, ctypes.c_char_p]
        libbpf.bpf_obj_pin.restype = ctypes.c_int
        r = libbpf.bpf_obj_pin(fd, path.encode())
        if r != 0:
            err = ctypes.get_errno()
            raise OSError(err, f"bpf_obj_pin({path}) returned {r}")
    except (OSError, AttributeError) as e:
        # Fallback: bpftool
        _subp.run(["bpftool", "prog", "pin", "fd", str(fd), path], check=True)


def _find_container_veth(container_name):
    """Given a docker container name, return its host-side veth interface
    (e.g., 'vethXXXXXXX') or None if the container is not running."""
    try:
        pid = _subp.check_output(
            ["docker", "inspect", "-f", "{{.State.Pid}}", container_name],
            stderr=_subp.DEVNULL,
        ).decode().strip()
        if pid == "0" or not pid:
            return None
    except _subp.CalledProcessError:
        return None

    # Read eth0's peer ifindex from inside the container's netns
    try:
        out = _subp.check_output(
            ["nsenter", "-t", pid, "-n", "ip", "link", "show", "eth0"],
            stderr=_subp.DEVNULL,
        ).decode()
    except _subp.CalledProcessError:
        return None

    m = _re.search(r"eth0@if(\d+):", out)
    if not m:
        return None
    peer_idx = m.group(1)

    # Find matching interface on the host
    host_links = _subp.check_output(["ip", "-o", "link", "show"]).decode()
    for line in host_links.splitlines():
        # Format: "12: vethXXXX@if11: <BROADCAST,..."
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        if parts[0].strip() == peer_idx:
            name_field = parts[1].strip().split("@")[0]
            return name_field
    return None


def _attach_tc_to_veth(veth, pin_ingress, pin_egress):
    """Attach pinned TC programs to a single veth via `tc` CLI."""
    # clsact qdisc (idempotent — delete first, then add)
    _subp.run(["tc", "qdisc", "del", "dev", veth, "clsact"],
              stderr=_subp.DEVNULL, check=False)
    _subp.run(["tc", "qdisc", "add", "dev", veth, "clsact"], check=True)
    _subp.run(["tc", "filter", "add", "dev", veth, "ingress",
               "bpf", "direct-action", "pinned", pin_ingress], check=True)
    _subp.run(["tc", "filter", "add", "dev", veth, "egress",
               "bpf", "direct-action", "pinned", pin_egress], check=True)


def setup_tc_drop(b, container_names=None):
    """Load tc_drop_ingress/egress from the BCC object, pin them, and attach
    them to every monitored container's host-side veth.

    container_names: list of docker container names to monitor. If None,
        discovers all running containers and attaches to each.

    Returns list of (container, veth) tuples actually attached to.
    Failures are logged but don't halt the loader — TC attach is an
    enforcement optimization, not a correctness prereq. The Compound Gate
    falls back to SIGKILL when drop_ip_list entries don't actually reach
    a live TC filter (which happens when TC attach is skipped).
    """
    try:
        fn_in = b.load_func("tc_drop_ingress", BPF.SCHED_CLS)
        fn_out = b.load_func("tc_drop_egress", BPF.SCHED_CLS)
    except Exception as e:
        print(f"  WARN: TC programs failed to load ({e}); drop_ip_list is write-only")
        return []

    try:
        _pin_prog(fn_in.fd, TC_INGRESS_PIN)
        _pin_prog(fn_out.fd, TC_EGRESS_PIN)
    except Exception as e:
        print(f"  WARN: bpf_obj_pin failed ({e}); TC attach skipped — SIGKILL fallback in effect")
        return []

    if container_names is None:
        try:
            out = _subp.check_output(
                ["docker", "ps", "--format", "{{.Names}}"],
                stderr=_subp.DEVNULL,
            ).decode()
            container_names = [n for n in out.splitlines() if n.strip()]
        except _subp.CalledProcessError:
            container_names = []

    attached = []
    for cname in container_names:
        veth = _find_container_veth(cname)
        if not veth:
            print(f"  WARN: no veth found for container {cname} (not running?)")
            continue
        try:
            _attach_tc_to_veth(veth, TC_INGRESS_PIN, TC_EGRESS_PIN)
            attached.append((cname, veth))
            print(f"  TC drop: {cname} -> {veth} (ingress+egress)")
        except _subp.CalledProcessError as e:
            print(f"  WARN: tc attach {cname}/{veth} failed: {e}")

    if not attached and container_names:
        print("  WARN: No TC filters attached — Compound Gate Case A/C will SIGKILL "
              "instead of session-drop. Run `docker compose up` first.")

    return attached


def detach_tc_drop(attached):
    """Remove clsact qdisc from each veth and unlink pinned programs."""
    for cname, veth in attached:
        _subp.run(["tc", "qdisc", "del", "dev", veth, "clsact"],
                  stderr=_subp.DEVNULL, check=False)
    for path in (TC_INGRESS_PIN, TC_EGRESS_PIN):
        if os.path.exists(path):
            try:
                os.unlink(path)
            except OSError:
                pass


def setup_alerts_callback(b, excluded_cgroups: set = None):
    """Non-workload cgroups (observability stack, docker infra) are excluded
    from the printed alert stream. They still get processed by Tier 3 so the
    sheaf detector sees the full graph, but they do not inflate FPR counts."""
    excluded = excluded_cgroups or set()
    def handle_alert(ctx, data, size):
        class AlertT(ctypes.Structure):
            _fields_ = [
                ('type', ctypes.c_uint32), ('pid', ctypes.c_uint32),
                ('cgroup_id', ctypes.c_uint64), ('timestamp', ctypes.c_uint64),
                ('flags', ctypes.c_uint64), ('extra', ctypes.c_uint64),
            ]
        evt = ctypes.cast(data, ctypes.POINTER(AlertT)).contents
        if evt.cgroup_id in excluded:
            return
        names = {
            1: "FORK_BOMB", 2: "REVERSE_SHELL", 3: "SENSITIVE_FILE",
            4: "PRIVESC", 5: "FD_REDIRECT", 6: "FORK_ACCEL",
            7: "TWO_HOP", 8: "NS_ESCAPE",
            20: "ENFORCE_DENY", 21: "ENFORCE_THROTTLE"
        }
        name = names.get(evt.type, f"TYPE_{evt.type}")
        print(f"[ALERT] {name} | cgroup={evt.cgroup_id} | pid={evt.pid} | "
              f"flags=0x{evt.flags:04x}")
    b["alerts_rb"].open_ring_buffer(handle_alert)


def load_excluded_cgroups() -> set:
    """Cgroups for observability/infra containers that should not contribute
    to the workload FPR accounting. Resolved from live docker inspect so the
    set is always current, not baked into a snapshot."""
    import json as _json
    excluded_names = {"ct-prometheus", "ct-grafana", "ct-nginx",
                      "ct-postgres", "ct-redis"}
    result = set()
    try:
        import subprocess as _sp
        out = _sp.run(["docker", "ps", "--format", "{{.Names}}"],
                      capture_output=True, text=True, timeout=5).stdout
        for name in out.splitlines():
            if name not in excluded_names:
                continue
            pid = _sp.run(["docker", "inspect", "--format", "{{.State.Pid}}", name],
                          capture_output=True, text=True, timeout=5).stdout.strip()
            if not pid:
                continue
            cgroup_path = Path(f"/proc/{pid}/cgroup")
            if not cgroup_path.exists():
                continue
            # cgroup id = inode of the scope directory
            scope = cgroup_path.read_text().strip().split(":")[-1]
            scope_dir = Path(f"/sys/fs/cgroup{scope}")
            if scope_dir.exists():
                result.add(scope_dir.stat().st_ino)
    except Exception as e:
        print(f"[warn] excluded-cgroup resolution failed: {e}")
    return result


def main():
    parser = argparse.ArgumentParser(description="CausalTrace Loader")
    parser.add_argument("--mode", choices=["monitor", "enforce"],
                        default="monitor")
    parser.add_argument("--calibrate", action="store_true")
    parser.add_argument("--cleanup", action="store_true",
                        help="Check for and report stale BPF programs")
    args = parser.parse_args()

    if args.cleanup:
        if os.geteuid() != 0:
            print("ERROR: Must run as root (sudo)")
            sys.exit(1)
        run_cleanup_only()
        return

    if os.geteuid() != 0:
        print("ERROR: Must run as root (sudo)")
        sys.exit(1)

    # Register cleanup handlers BEFORE loading BPF
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    atexit.register(cleanup_bpf)

    print("=" * 60)
    print("  CausalTrace -- eBPF Loader")
    print("=" * 60)

    # Calibrate = monitor only; enforce mode = graduated response active
    enforce = (not args.calibrate) and (args.mode == "enforce")
    b = load_bpf(enforce=enforce)

    print("\nSetting up infrastructure...")
    populate_host_ns(b)
    setup_tail_calls(b)
    attach_probes(b, enforce=enforce)
    excluded_cg = load_excluded_cgroups()
    if excluded_cg:
        print(f"Excluded {len(excluded_cg)} non-workload cgroups from alert FPR accounting: {sorted(excluded_cg)}")
    setup_alerts_callback(b, excluded_cgroups=excluded_cg)
    tc_attached = setup_tc_drop(b)
    atexit.register(detach_tc_drop, tc_attached)

    mode_desc = 'CALIBRATE' if args.calibrate else args.mode.upper()
    print(f"\nMode: {mode_desc}")
    if enforce:
        print("  Enforcement engine: bpf_override_return() for surgical syscall denial")
        print("  Levels: L1=DENY, L3=THROTTLE, L4=FIREWALL, L6=QUARANTINE")
        print("  Kernel: fork-bomb/reverse-shell=immediate KILL")
        print("  Everything else: Tier 3 decides level, BPF enforces via override_return")
    print("Monitoring container syscalls... (Ctrl+C to stop)\n")

    # Docker event listener
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        from infra.docker_event_listener import DockerEventListener
        listener = DockerEventListener(b)
        t = threading.Thread(target=listener.run, daemon=True)
        t.start()
    except Exception as e:
        print(f"  Docker listener: {e}")

    # Phase 7D: take a cgroup-id snapshot so restart-stable container
    # attribution survives daemon restarts.
    try:
        from infra.cgroup_snapshot import take_snapshot
        take_snapshot("calibration")
    except Exception as e:
        print(f"  cgroup snapshot: {e}")

    if args.calibrate:
        sys.path.insert(0, str(Path(__file__).parent / "tier3"))
        try:
            from calibrate_runner import run_calibration
            run_calibration(b)
        except ImportError as e:
            print(f"Calibration import error: {e}")
            print("Running kernel-only mode...")
            while True:
                try:
                    b.ring_buffer_poll(timeout=1000)
                except KeyboardInterrupt:
                    break
    else:
        sys.path.insert(0, str(Path(__file__).parent / "tier3"))
        try:
            from daemon_main import CausalTraceDaemon
            daemon = CausalTraceDaemon(b, mode=args.mode)
            daemon.run()
        except ImportError as e:
            print(f"Tier 3 import error: {e}")
            print("Running kernel-only mode (Tier 1+2 active)...")
            while True:
                try:
                    b.ring_buffer_poll(timeout=1000)
                except KeyboardInterrupt:
                    break

    # Clean shutdown
    cleanup_bpf()


if __name__ == "__main__":
    main()

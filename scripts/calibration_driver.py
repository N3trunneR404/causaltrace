#!/usr/bin/env python3
"""
scripts/calibration_driver.py — synthetic inter-container traffic for calibration.

Purpose:
    During the calibration window the CausalTrace sheaf needs every monitored
    container pair to accumulate enough aligned signal windows for CCA to produce
    a well-conditioned restriction map. Relying on wrk alone only exercises the
    ingress tier (nginx → webapps). This driver goes further: it pokes every
    production container on every port likely to be open, in a randomised order,
    for the full duration of calibration.

    It runs alongside wrk (scripts/generate_normal_traffic.sh) during the Stage C
    window of marathon.sh. Traffic shape:

      * HTTP GETs on 8080 (app tier), 80 (nginx), 9090 (prometheus), 3000 (grafana)
      * TCP probes on 5432 (postgres), 6379 (redis)
      * Payload sizes randomised in [64, 2048] bytes so bigram sketches see variety

Design choices:
    * Source IP is the HOST — not the legit_client, not the attacker. That is
      fine for calibration: Probe B only attributes remote → local cgroup based
      on the LISTENING side, not the originating side. What matters is that
      every monitored cgroup sees incoming TCP connects.
    * Pairs discovered dynamically: the driver does a `docker inspect` to find
      every running container whose name starts with 'ct-' and its IP on the
      prod network. No hardcoded topology.
    * Concurrency kept modest: default 8 worker threads, each picks a random
      (src, dst) cgroup pair every cycle. This produces realistic bursty
      traffic rather than a flat grid.

Usage:
    python3 scripts/calibration_driver.py --duration 1800
    python3 scripts/calibration_driver.py --duration 3600 --workers 16 --verbose
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import List

log = logging.getLogger("calibrate_driver")

# Ports we know are open in the testbed stack.
PROBE_PORTS = {
    "http":        8080,
    "nginx":       80,
    "prometheus":  9090,
    "grafana":     3000,
    "postgres":    5432,
    "redis":       6379,
}


@dataclass
class Target:
    name: str
    ip:   str
    open_ports: List[int]


# ─── Discovery ─────────────────────────────────────────────────────────────

def discover_targets(net_prefix: str = "10.88.0.",
                     exclude: tuple = ("ct_legit_client", "ct_attacker")) -> List[Target]:
    """Return every ct-* container with an IP on the prod subnet."""
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--format", "{{.Names}}"], text=True
        ).strip().splitlines()
    except Exception as exc:
        log.error("docker ps failed: %s", exc)
        return []
    targets: List[Target] = []
    for name in out:
        if name in exclude:
            continue
        try:
            ip = subprocess.check_output(
                ["docker", "inspect", "-f",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name],
                text=True,
            ).strip().split()
        except Exception:
            continue
        prod_ip = next((a for a in ip if a.startswith(net_prefix)), None)
        if not prod_ip:
            continue
        open_ports = _probe_ports(prod_ip)
        if open_ports:
            targets.append(Target(name=name, ip=prod_ip, open_ports=open_ports))
    return targets


def _probe_ports(ip: str, timeout: float = 0.5) -> List[int]:
    """Return the subset of PROBE_PORTS that are actually listening."""
    opened = []
    for port in PROBE_PORTS.values():
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            opened.append(port)
        except OSError:
            continue
    return opened


# ─── Traffic generation ────────────────────────────────────────────────────

def _drive_http(ip: str, port: int, payload_bytes: int) -> None:
    """Single short-lived HTTP GET. Reads response so tcp_close sees bytes_rx."""
    try:
        with socket.create_connection((ip, port), timeout=2.0) as s:
            req = (f"GET / HTTP/1.1\r\nHost: {ip}\r\n"
                   f"User-Agent: cal-driver\r\n"
                   f"X-Pad: {'x' * max(0, payload_bytes - 64)}\r\n"
                   "Connection: close\r\n\r\n").encode()
            s.sendall(req)
            # Drain up to 4 KB; we only need bytes_rx > 0 for trust accounting.
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                chunk = s.recv(2048)
                if not chunk:
                    break
    except OSError:
        pass


def _drive_raw_tcp(ip: str, port: int) -> None:
    """Bare TCP connect+close for Postgres/Redis (don't send SQL)."""
    try:
        with socket.create_connection((ip, port), timeout=1.5) as s:
            # Nudge a few bytes to force a TCP data segment — satisfies the
            # 5120-byte trust threshold over enough repetitions.
            s.sendall(b"\x00" * 32)
            try:
                s.recv(512)
            except OSError:
                pass
    except OSError:
        pass


def _worker(stop_ev: threading.Event, targets: List[Target],
            period: float, jitter: float) -> None:
    """Each worker picks a random target and a random open port every cycle."""
    rng = random.Random()
    while not stop_ev.is_set():
        tgt = rng.choice(targets)
        port = rng.choice(tgt.open_ports)
        payload = rng.randint(64, 2048)
        if port in (80, 8080, 9090, 3000):
            _drive_http(tgt.ip, port, payload)
        else:
            _drive_raw_tcp(tgt.ip, port)
        time.sleep(period + rng.random() * jitter)


# ─── Entry point ──────────────────────────────────────────────────────────

def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Drive synthetic traffic across all monitored containers.")
    p.add_argument("--duration",  type=int,   default=1800, help="seconds")
    p.add_argument("--workers",   type=int,   default=8,    help="concurrency")
    p.add_argument("--period",    type=float, default=0.5,  help="seconds between requests per worker")
    p.add_argument("--jitter",    type=float, default=0.5,  help="max random jitter added per cycle")
    p.add_argument("--report",    type=str,   default=None, help="write summary JSON here")
    p.add_argument("--verbose",   action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=(logging.DEBUG if args.verbose else logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    targets = discover_targets()
    if len(targets) < 2:
        log.error("only %d target(s) discovered — calibration cannot proceed",
                  len(targets))
        return 1

    log.info("discovered %d targets:", len(targets))
    for t in targets:
        log.info("  %-18s %-13s ports=%s", t.name, t.ip, t.open_ports)

    stop_ev = threading.Event()
    threads = [
        threading.Thread(
            target=_worker,
            args=(stop_ev, targets, args.period, args.jitter),
            daemon=True,
        )
        for _ in range(args.workers)
    ]
    for th in threads:
        th.start()

    log.info("driving for %d s (%d workers, period=%.2fs jitter=%.2fs)",
             args.duration, args.workers, args.period, args.jitter)

    start = time.monotonic()
    try:
        while time.monotonic() - start < args.duration:
            time.sleep(5)
            elapsed = int(time.monotonic() - start)
            if elapsed and elapsed % 60 == 0:
                log.info("  calibration driver @ t+%ds (%d workers active)",
                         elapsed, sum(1 for th in threads if th.is_alive()))
    except KeyboardInterrupt:
        log.info("interrupt")
    finally:
        stop_ev.set()
        for th in threads:
            th.join(timeout=2)

    if args.report:
        with open(args.report, "w") as f:
            json.dump({
                "duration_s": args.duration,
                "workers":    args.workers,
                "targets":    [{"name": t.name, "ip": t.ip,
                                "ports": t.open_ports} for t in targets],
            }, f, indent=2)
        log.info("wrote report to %s", args.report)

    log.info("calibration driver exit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

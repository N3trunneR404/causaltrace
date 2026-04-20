# Operations runbook

Short playbook for running CausalTrace outside of the author's laptop.

## One-time setup

```bash
sudo bash install.sh
```

Installs apt deps, creates the venv, mounts `/sys/fs/bpf`, installs the
logrotate config, and prints next steps.

## Calibrate

Representative normal traffic must be running while calibration samples
are collected. The bundled generator is enough for the testbed:

```bash
bash scripts/generate_normal_traffic.sh &   # keep in another terminal
sudo ./venv/bin/python loader.py --calibrate
```

Duration is controlled by `calibration.duration_seconds` in
`config/causaltrace.yaml` (default 600 s). Always validate before
enforcing:

```bash
./venv/bin/python -m tier3.calibration_driver ./calibration
```

The validator exits 0 on CLEAN and 1 on FAIL; see its output for the
exact invariant that was violated.

## Run

```bash
sudo ./venv/bin/python supervisor.py -- --mode enforce
```

The supervisor runs preflight first, spawns the loader, and respawns on
crash with exponential backoff (up to 5 crashes in 10 min before
giving up). SIGTERM to the supervisor gives the loader 8 s to clean up
TC filters and BPF pins before SIGKILL.

Monitor mode is useful for CI and for shakedown runs on a new host:

```bash
sudo ./venv/bin/python supervisor.py -- --mode monitor
```

## What to watch

* `results/causaltrace/verdicts.jsonl` — one JSON per detection cycle
  that emitted a non-ALLOW action. Includes `label`, `reason`,
  `affected_cgroups`, `rayleigh`, and `enforcement_actions`.
* `results/causaltrace/supervisor.log` — supervisor events (spawn,
  crash, backoff).
* `ringbuf_stats` via `bpftool map dump` — six counters showing
  telemetry shed / alert loss in real time. Any non-zero `alerts_fail`
  is a critical signal that the consumer is falling behind.

## Incident response on a hit

1. Read the latest verdict from `verdicts.jsonl`. Every alert carries
   `affected_cgroups`, `label`, and `reason`.
2. Map the cgroup IDs to container names via
   `calibration/cgroup_snapshot.json`.
3. If `enforcement_actions` shows a TC drop, the attacker IP is now in
   `drop_ip_list` with a 5 min TTL (see `drop_ttl_seconds`). Nothing to
   do — the flow is already severed.
4. If `enforcement_actions` shows a SIGKILL, the offending PID is gone.
   Pull the corresponding fd/exec context from Tier 1's invariant
   record (alert type + `extra` field in `alerts_rb`).
5. Decide whether to extend the drop (manual entry into `drop_ip_list`
   via `bpftool map update`) or heal (no action; the TTL sweeps it).

## Daily operations

* **Log volume**: verdicts.jsonl is bounded by logrotate
  (`config/causaltrace.logrotate`, 14 days). Plan for ~1 MB/day per
  monitored host under typical load.
* **Re-calibration cadence**: re-calibrate when the workload mix
  changes materially (new service, new upstream dependency, major
  traffic pattern shift). The validator will catch when stale
  calibration starts producing false positives (edge thresholds get
  tripped on legitimate traffic).
* **Upgrades**: the BPF program is recompiled at loader startup; there
  is no separate `make`. Kernel upgrades only require re-running
  preflight; the kernel ABI surfaces we touch are all stable BPF
  helpers.

## Tear-down

```bash
sudo systemctl stop causaltrace    # if you installed a unit file
# or simply:
sudo kill -TERM <supervisor_pid>
```

The supervisor's SIGTERM handler forwards to the loader, which
unattaches TC filters and unpins BPF objects before exit. If the
supervisor is SIGKILLed, `scripts/preflight.sh` on next boot will
detect stale pins under `/sys/fs/bpf/causaltrace/` and warn; the
supervisor cleans them up automatically on respawn.

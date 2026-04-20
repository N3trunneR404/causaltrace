# CausalTrace — Quickstart for Independent Verification

This guide is written for the project supervisor. It takes you from a fresh Ubuntu machine to independently verified attack detection in under 20 minutes using the pre-calibrated artifacts from the published marathon run.

---

## What you will verify

1. CausalTrace loads cleanly on your machine (no BPF errors).
2. The 22-container testbed starts and passes connectivity checks.
3. When you fire any of the 11 attack scenarios manually, CausalTrace issues a `KILL` or `ALERT` verdict with the correct MITRE label — without you having to calibrate anything.
4. The committed marathon results (`results/marathon/`) match the reported detection counts.

---

## Prerequisites

- Ubuntu 22.04 or 24.04 (bare metal or KVM — not WSL/macOS)
- Linux kernel ≥ 5.8 (`uname -r` to check; 6.x is fine)
- `sudo` access
- ~8 GB free disk, 4 GB RAM

---

## Step 1 — Get the code

```bash
git clone https://github.com/ShubhankarBhattacharya/causaltrace.git
cd causaltrace
```

---

## Step 2 — Install dependencies (one command)

```bash
sudo bash install.sh
```

Expected last line: `Install complete.`

This installs BCC 0.31, clang, Docker, iproute2, bpftool, and sets up the Python venv. Safe to run more than once.

---

## Step 3 — Activate the Python environment

```bash
source venv/bin/activate
```

---

## Step 4 — Start the testbed

```bash
docker compose up -d
sudo bash scripts/setup_routes.sh
bash scripts/preflight.sh
```

Expected last line: `All checks passed`.

If any container fails to start, run `docker compose logs <service-name>` to diagnose.

---

## Step 5 — Start CausalTrace (using pre-calibrated data)

The `calibration/` directory already contains the restriction maps, PCA whitener, and thresholds from the marathon run. No calibration step needed.

```bash
sudo python3 supervisor.py -- --mode enforce
```

You should see within a few seconds:

```
[loader] BPF programs loaded
[loader] 22 containers registered
[tier3]  Calibration artifacts loaded from calibration/
[tier3]  Sheaf detector armed — Rayleigh τ=0.780
[tier3]  Cycle 1: R=0.012 (below threshold, all quiet)
```

Leave this terminal running.

---

## Step 6 — Fire an attack and watch it get detected

Open a second terminal:

```bash
cd causaltrace

# Option A: interactive menu
bash attacks/interactive_menu.sh

# Option B: fire directly
bash attacks/scenario_2_reverse_shell.sh        # dup2 reverse shell
bash attacks/scenario_7_cross_container.sh      # cross-container lateral movement
bash attacks/scenario_9_ssrf_rce.sh             # SSRF → pivot → RCE
bash attacks/scenario_11_fileless_memfd.sh      # fileless memfd (OOD payload)
```

In the first terminal (CausalTrace output) you will see a verdict like:

```
KILL     Reverse shell attempt                   R=4821.332  ['T1059']
```

or for cross-container / SSRF chains:

```
ALERT    Cross-container lateral movement        R=19043.871 ['T1021']
```

---

## Step 7 — Verify the committed marathon results

All 775 attack injections and 791 verdicts from the marathon run are in `results/marathon/`. Verify the detection counts with one command:

```bash
python3 scripts/marathon_analyze.py results/marathon/
```

Expected output (excerpt):

```
CausalTrace  154/155  TPR=99.4%  [96, 100]
Falco tuned  109/155  TPR=70.3%  [63, 77]
Tetragon tuned  2/155  TPR=1.3%  [0, 5]
```

To inspect individual verdicts:

```bash
# Show all KILL/ALERT verdicts with labels
python3 -c "
import json
for line in open('results/marathon/results_fast/verdicts.jsonl'):
    v = json.loads(line)
    if v['action'] in ('KILL','ALERT','BLOCK'):
        print(v['action'], v.get('label',''), v.get('mitre',[]))
" | head -40
```

To cross-reference injections with verdicts:

```bash
# Show each injection and the verdict that followed it
python3 -c "
import json
attacks = [json.loads(l) for l in open('results/marathon/attacks.jsonl')]
verdicts = [json.loads(l) for l in open('results/marathon/results_fast/verdicts.jsonl')]
for a in attacks[:10]:
    ts = a['ts_inject']
    hit = next((v for v in verdicts if abs(v['timestamp']-ts) < 30 and v['action'] in ('KILL','ALERT','BLOCK')), None)
    print(f\"{a['attack_id']:4s}  injected={ts:.0f}  {'DETECTED: '+hit['label'] if hit else 'MISSED'}\")
"
```

---

## Step 8 — Reproduce calibration from scratch (optional)

If you want to run the full calibration yourself instead of using the committed artifacts:

```bash
# Make sure testbed is running (Step 4)
sudo bash run_calibration.sh 1800    # 30 minutes
# New artifacts overwrite calibration/ — then restart:
sudo python3 supervisor.py -- --mode enforce
```

Results will differ slightly from the committed artifacts (different cgroup IDs, slightly different traffic timings) but detection rates on all scenarios should remain ≥99%.

---

## Troubleshooting

**`loader.py: invalid mem access`**  
Kernel is older than 5.8 or BCC version mismatch. Run `uname -r` and `python3 -c "import bcc; print(bcc.__version__)"`.

**`docker compose up -d` fails with network conflict**  
Another Docker network is using `10.88.0.0/24`. Edit `docker-compose.yml` to use a different subnet.

**`preflight.sh` fails on connectivity check**  
`sudo bash scripts/setup_routes.sh` must run after every reboot — it adds the inter-bridge forwarding rule that Docker does not persist.

**Verdicts stream is empty after firing an attack**  
Check that `supervisor.py` is still running in the first terminal. If it crashed, re-read `loader.log` and look for BPF verifier errors.

**`scenario_7_cross_container.sh` exits 0 but no verdict**  
The cross-container scenario requires the `ct_attacker` container and `ct_legit_client` container to be running. `docker ps | grep ct_attacker` and `docker ps | grep ct_legit_client`.

---

## File index for the committed marathon run

| Path | What it contains |
|---|---|
| `calibration/restriction_maps.npz` | CCA R matrices per edge (k=15) |
| `calibration/pca.pkl` | PCA whitener for 50-dim projection |
| `calibration/whiteners.pkl` | Per-container per-edge whitening |
| `calibration/edge_thresholds.json` | Per-edge Mahalanobis threshold τ |
| `calibration/global_threshold.json` | Global Rayleigh threshold τ_global=0.780 |
| `calibration/calibrated_edges.json` | Edge graph (22-container mesh) |
| `results/marathon/attacks.jsonl` | 775 injection records with timestamps |
| `results/marathon/results_fast/verdicts.jsonl` | 791 CausalTrace verdicts |
| `results/marathon/results_fast/signals.jsonl` | Per-cycle d=74 signal vectors |
| `results/marathon/falco_tuned.jsonl` | Falco tuned-rules alerts |
| `results/marathon/tetragon_tuned.jsonl` | Tetragon CTEval-policy events |
| `results/marathon/loader.log` | Tier-1 SIGKILL / TC-drop log |
| `results/marathon/detection_timeline.json` | Injection → first-detection latency |

All figures referenced in the thesis are in `BTech_Project_Report/figures/`.

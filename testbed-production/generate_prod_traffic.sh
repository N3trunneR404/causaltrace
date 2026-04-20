#!/bin/bash
# generate_prod_traffic.sh — Normal traffic generator for production testbed
# Generates realistic inter-service call patterns for sheaf calibration.
#
# Usage: bash testbed-production/generate_prod_traffic.sh [duration_seconds]

DURATION=${1:-2700}
END_TIME=$((SECONDS + DURATION))

echo "CausalTrace Production — Normal Traffic Generator"
echo "Duration: $((DURATION / 60)) minutes"
echo ""

CYCLE=0
while [ $SECONDS -lt $END_TIME ]; do
    CYCLE=$((CYCLE + 1))

    # Pattern 1: Client → nginx-lb → webapp (HTTP GET with normal User-Agent)
    curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0" \
        http://localhost:8080/ > /dev/null 2>&1

    # Pattern 2: Client → nginx-lb → webapp (POST)
    curl -s -X POST -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" \
        -d '{"action":"browse"}' http://localhost:8080/ > /dev/null 2>&1

    # Pattern 3: API gateway health check
    curl -s http://10.88.0.13:8000/ > /dev/null 2>&1

    # Pattern 4: Product service (creates api-gw → product edge)
    curl -s http://10.88.0.14:8080/ > /dev/null 2>&1

    # Pattern 5: Order → payment flow (creates order → payment edge)
    curl -s http://10.88.0.16:8080/ > /dev/null 2>&1
    curl -s http://10.88.0.17:8080/ > /dev/null 2>&1

    # Pattern 6: user-service → LDAP on port 389 (LEGITIMATE — must be calibrated)
    # This is CRITICAL: the attacker uses port 1389, this uses 389
    docker exec ct-user nc -z -w1 10.88.0.25 389 2>/dev/null || true

    # Pattern 7: inventory → kafka
    docker exec ct-inventory nc -z -w1 10.88.0.23 9092 2>/dev/null || true

    # Every 30 seconds: burst of concurrent requests (train CCA that bursts are normal)
    if [ $((CYCLE % 6)) -eq 0 ]; then
        for j in $(seq 1 5); do
            curl -s -A "ApacheBench/2.3" http://localhost:8080/ > /dev/null 2>&1 &
        done
        wait
    fi

    # Progress report every 60 seconds
    if [ $((CYCLE % 12)) -eq 0 ]; then
        ELAPSED=$SECONDS
        REMAINING=$((END_TIME - SECONDS))
        echo "  [${ELAPSED}s] Cycle $CYCLE | ${REMAINING}s remaining"
    fi

    sleep 5
done

echo ""
echo "Traffic generation complete ($CYCLE cycles)"

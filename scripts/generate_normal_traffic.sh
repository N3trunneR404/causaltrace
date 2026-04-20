#!/bin/bash
# generate_normal_traffic.sh — Calibration traffic generator
#
# Generates realistic normal traffic patterns for sheaf calibration.
# Run for 30-60 minutes while loader.py --calibrate is active.
#
# Usage:
#   bash scripts/generate_normal_traffic.sh [duration_seconds]
#   bash scripts/generate_normal_traffic.sh 1800   # 30 minutes

DURATION=${1:-1800}
END_TIME=$((SECONDS + DURATION))

echo "CausalTrace — Normal Traffic Generator"
echo "Duration: $((DURATION / 60)) minutes"
echo "Press Ctrl+C to stop early"
echo ""

CYCLE=0
while [ $SECONDS -lt $END_TIME ]; do
    CYCLE=$((CYCLE + 1))

    # Pattern 1: Web→API health check (creates Web→API edge)
    curl -s http://localhost:8080/api/health > /dev/null 2>&1

    # Pattern 2: Web→API→DB query chain (creates API→DB edge)
    curl -s http://localhost:8080/api/db/query > /dev/null 2>&1

    # Pattern 3: Direct web page (no cross-container)
    curl -s http://localhost:8080/ > /dev/null 2>&1

    # Every 30 seconds: burst of 5 concurrent requests (CCA must learn bursts are normal)
    if [ $((CYCLE % 6)) -eq 0 ]; then
        for j in $(seq 1 5); do
            curl -s http://localhost:8080/api/health > /dev/null 2>&1 &
        done
        wait
    fi

    # Progress report every 60 seconds
    if [ $((CYCLE % 12)) -eq 0 ]; then
        ELAPSED=$((SECONDS))
        REMAINING=$((END_TIME - SECONDS))
        echo "  [${ELAPSED}s] Cycle $CYCLE | ${REMAINING}s remaining"
    fi

    sleep 5
done

echo ""
echo "Traffic generation complete ($CYCLE cycles)"
echo "Calibration data should now be sufficient."

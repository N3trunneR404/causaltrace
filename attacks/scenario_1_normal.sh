#!/bin/bash
# Scenario 1: Normal Traffic (60 seconds)
# Expected: NO alerts, NO kills. Verifies zero false positive rate.
set -e
echo "=== SCENARIO 1: Normal Traffic (60s) ==="
echo "Expected: ALLOW (no detection)"

for i in $(seq 1 12); do
    curl -s http://localhost:8080/ > /dev/null
    curl -s http://localhost:8080/api/health > /dev/null
    curl -s http://localhost:8080/api/db/query > /dev/null
    sleep 5
done

echo "=== Scenario 1 complete ==="

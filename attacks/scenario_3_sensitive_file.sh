#!/bin/bash
# Scenario 3: Sensitive File Access
# Expected: ALERT_SENSITIVE_FILE
set -e
echo "=== SCENARIO 3: Sensitive File Access ==="

echo "Reading /etc/shadow in ct-webapp-a..."
docker exec ct-webapp-a cat /etc/shadow 2>&1 || true
echo "  Exit code: $?"

echo "Reading /etc/passwd in ct-webapp-a..."
docker exec ct-webapp-a cat /etc/passwd > /dev/null 2>&1 || true

echo "Probing /proc/1/ns in ct-webapp-a..."
docker exec ct-webapp-a ls -la /proc/1/ns/ 2>&1 || true

echo "=== Scenario 3 complete ==="

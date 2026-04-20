#!/bin/bash
# Scenario 5: Namespace Escape Attempt
# Expected: ALERT_SENSITIVE_FILE (for /proc/1/ns) + ALERT_NS_ESCAPE (for setns)
set -e
echo "=== SCENARIO 5: Namespace Escape ==="

echo "Reading /proc/1/ns/mnt (namespace probe)..."
docker exec ct-webapp-a cat /proc/1/ns/mnt 2>&1 || true

echo "Attempting nsenter (setns syscall)..."
docker exec ct-webapp-a nsenter -t 1 -m -p -- whoami 2>&1 || true
echo "  Exit code: $?"

echo "=== Scenario 5 complete ==="

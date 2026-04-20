#!/bin/bash
# Scenario 3-EVADE — /etc/shadow read with syscall noise interleaving.
# Same premise as 2a-evade: pollute bigram frequencies so a pure frequency
# detector misses the attack. The file handler invariant still fires on
# the sensitive-path read regardless of noise.
set -e
echo "=== SCENARIO 3-EVADE: shadow read + syscall noise ==="

docker exec ct-webapp-a bash -c "
python3 - <<'PY'
import os, time
# Noise burst before each sensitive access.
for _ in range(80):
    os.getpid(); time.time(); os.getuid()
try:
    with open('/etc/shadow', 'rb') as f:
        f.read(256)
except Exception: pass
for _ in range(80):
    os.getpid(); os.getppid(); time.time()
try:
    with open('/etc/passwd', 'rb') as f:
        f.read(256)
except Exception: pass
for _ in range(80):
    os.getpid(); time.time()
try:
    os.listdir('/proc/1/ns')
except Exception: pass
PY
" 2>&1 || true
echo "=== Scenario 3-evade complete ==="

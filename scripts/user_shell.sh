#!/usr/bin/env bash
# scripts/user_shell.sh — spin up a one-off legitimate-user container on the prod
# network. Source IP = 10.88.0.200. This IP is eligible for trust=2 promotion
# once it completes ≥1 L4-stable connection during calibration.
set -euo pipefail

IP="${USER_IP:-10.88.0.200}"

cat <<EOF
══════════════════════════════════════════════
  CausalTrace Legitimate User Shell
  Your IP : $IP (trust=2 after calibration)
  Network : ct_prod_net
  Try: curl http://10.88.0.10/
══════════════════════════════════════════════
EOF

exec docker run --rm -it \
  --network ct_prod_net \
  --ip "$IP" \
  --name ct_legit_user \
  curlimages/curl:8.5.0 /bin/sh

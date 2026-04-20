#!/usr/bin/env bash
# scripts/setup_routes.sh — stitch ct_prod_net and ct_attack_net so packets
# cross-bridge while retaining source IPs. Idempotent; safe to rerun.
#
# What this does:
#   1. Host IP forwarding on.
#   2. Punch DOCKER-USER iptables rules to ACCEPT between 10.88.0.0/24 and 10.88.1.0/24.
#   3. Remove any masquerade rule that would SNAT cross-bridge traffic.
#   4. Seed ct_attacker's routing table (in case the container's ENTRYPOINT was skipped).

set -euo pipefail

echo "[setup_routes] enabling ip_forward"
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Accept between the two subnets (both directions).
for chain in DOCKER-USER; do
  if ! iptables -C "$chain" -s 10.88.1.0/24 -d 10.88.0.0/24 -j ACCEPT 2>/dev/null; then
    iptables -I "$chain" 1 -s 10.88.1.0/24 -d 10.88.0.0/24 -j ACCEPT
    echo "[setup_routes] iptables $chain: ACCEPT 10.88.1.0/24 -> 10.88.0.0/24"
  fi
  if ! iptables -C "$chain" -s 10.88.0.0/24 -d 10.88.1.0/24 -j ACCEPT 2>/dev/null; then
    iptables -I "$chain" 1 -s 10.88.0.0/24 -d 10.88.1.0/24 -j ACCEPT
    echo "[setup_routes] iptables $chain: ACCEPT 10.88.0.0/24 -> 10.88.1.0/24"
  fi
done

# Drop any lingering MASQUERADE that would SNAT cross-bridge hops.
# enable_ip_masquerade=false in compose already prevents new ones; this cleans residue.
while iptables -t nat -C POSTROUTING -s 10.88.1.0/24 ! -o docker0 -j MASQUERADE 2>/dev/null; do
  iptables -t nat -D POSTROUTING -s 10.88.1.0/24 ! -o docker0 -j MASQUERADE
  echo "[setup_routes] removed residual MASQUERADE for 10.88.1.0/24"
done
while iptables -t nat -C POSTROUTING -s 10.88.0.0/24 ! -o docker0 -j MASQUERADE 2>/dev/null; do
  iptables -t nat -D POSTROUTING -s 10.88.0.0/24 ! -o docker0 -j MASQUERADE
  echo "[setup_routes] removed residual MASQUERADE for 10.88.0.0/24"
done

# Docker 27+/nft inserts per-container drop rules in `raw prerouting` that drop any
# packet to 10.88.0.x unless it entered via the prod bridge. That blocks cross-bridge
# traffic from the attacker. Flush every rule in ip raw PREROUTING that references
# a 10.88.* destination — the testbed is fully isolated on this host so the outside-
# world protection they provide is not needed.
if command -v nft >/dev/null 2>&1; then
  # Get a snapshot with handles and delete matching rules by handle.
  for handle in $(nft -a list chain ip raw PREROUTING 2>/dev/null \
                  | awk '/ip daddr 10\.88\./ {for(i=1;i<=NF;i++) if($i=="handle") print $(i+1)}'); do
    nft delete rule ip raw PREROUTING handle "$handle" 2>/dev/null || true
  done
  echo "[setup_routes] flushed ip raw PREROUTING drops for 10.88.* addresses"
fi

# Seed attacker container's route if it's up.
if docker inspect ct_attacker >/dev/null 2>&1; then
  docker exec ct_attacker sh -c '
    ip route add 10.88.0.0/24 via 10.88.1.1 2>/dev/null || true
  ' || true
  echo "[setup_routes] ct_attacker route seeded"
fi

echo "[setup_routes] done"

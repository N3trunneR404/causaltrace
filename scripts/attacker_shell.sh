#!/usr/bin/env bash
# scripts/attacker_shell.sh — drop into the ct_attacker container.
# Your source IP inside the shell is 10.88.1.100 (trust=0 by default).
# All attack scripts in attacks/ are mounted at /attacks (read-only).
set -euo pipefail

if ! docker inspect ct_attacker >/dev/null 2>&1; then
  echo "ct_attacker is not running. Run 'make up' first."
  exit 1
fi

cat <<'EOF'
══════════════════════════════════════════════
  CausalTrace Attacker Simulation Shell
  Your IP : 10.88.1.100   (UNTRUSTED)
  Targets : 10.88.0.0/24  (prod mesh)

  Quick start:
    bash /attacks/interactive_menu.sh          # numbered picker
    bash /attacks/scenario_2_reverse_shell.sh  # direct
    bash /attacks/scenario_7_cross_container.sh

  In a second terminal, watch verdicts live:
    make monitor
══════════════════════════════════════════════
EOF

exec docker exec -it ct_attacker /bin/bash

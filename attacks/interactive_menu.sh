#!/usr/bin/env bash
# attacks/interactive_menu.sh — numbered picker. Run inside ct_attacker
# or on the host. Picks a scenario and invokes it against the prod mesh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

print_menu() {
  cat <<'EOF'
══════════════════════════════════════════════
  CausalTrace Attack Picker
══════════════════════════════════════════════
   1) S2   Reverse shell (bash + python)
   2) S2a  Reverse shell + entropy evasion
   3) S3   /etc/shadow sensitive-file read
   4) S3a  Sensitive file + entropy evasion
   5) S4   Fork bomb
   6) S5   Namespace escape (unshare user+mount)
   7) S6   Privilege escalation (ptrace / setuid)
   8) S7   Cross-container lateral movement
   9) S8   Log4Shell-style chain (JNDI → revshell)
  10) S9   SSRF → RCE → reverse shell
  11) S10  Container escape (mount /proc/1/root)
  12) S11  Fileless memfd_create zero-day (OOD)
   a) Run ALL scenarios end-to-end (run_all.sh)
   q) Quit
EOF
}

pick() {
  case "$1" in
    1)  bash "$HERE/scenario_2_reverse_shell.sh" ;;
    2)  bash "$HERE/scenario_2a_evade.sh" ;;
    3)  bash "$HERE/scenario_3_sensitive_file.sh" ;;
    4)  bash "$HERE/scenario_3_evade.sh" ;;
    5)  bash "$HERE/scenario_4_fork_bomb.sh" ;;
    6)  bash "$HERE/scenario_5_ns_escape.sh" ;;
    7)  bash "$HERE/scenario_6_privesc.sh" ;;
    8)  bash "$HERE/scenario_7_cross_container.sh" ;;
    9)  bash "$HERE/scenario_8_log4shell.sh" ;;
    10) bash "$HERE/scenario_9_ssrf_rce.sh" ;;
    11) bash "$HERE/scenario_10_container_escape.sh" ;;
    12) bash "$HERE/scenario_11_fileless_memfd.sh" ;;
    a|A) bash "$HERE/run_all.sh" ;;
    q|Q) exit 0 ;;
    *) echo "unknown choice: $1" >&2 ;;
  esac
}

if [[ $# -ge 1 ]]; then
  pick "$1"; exit
fi

while true; do
  print_menu
  read -rp "Choice: " choice
  pick "$choice"
  echo
done

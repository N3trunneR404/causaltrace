#!/bin/bash
# activate.sh — CausalTrace environment setup
# Source this file: source activate.sh

export CAUSALTRACE_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$CAUSALTRACE_HOME/tier3:$CAUSALTRACE_HOME/infra:$CAUSALTRACE_HOME:$PYTHONPATH"

echo "CausalTrace environment activated"
echo "  CAUSALTRACE_HOME=$CAUSALTRACE_HOME"
echo "  PYTHONPATH includes tier3/ and infra/"
echo ""
echo "Quick start:"
echo "  docker compose up -d                            # start testbed"
echo "  bash scripts/test_connectivity.sh               # verify connectivity"
echo "  bash scripts/generate_normal_traffic.sh 1800 &  # start calibration traffic"
echo "  sudo python3 loader.py --calibrate              # run calibration (30 min)"
echo "  sudo python3 loader.py --mode enforce           # start enforcement"
echo "  bash attacks/run_all.sh                         # run evaluation"

#!/bin/bash
# run_calibration.sh — Full calibration pipeline (requires sudo)
# Usage: sudo bash run_calibration.sh [duration_seconds]
#
# This script:
#   1. Starts traffic generator in background
#   2. Loads BPF programs, registers containers
#   3. Runs calibration and saves artifacts to calibration/
#   4. Stops traffic generator when done
#
# After this completes, run attacks and analysis with:
#   sudo bash run_attacks.sh
#   python3 scripts/results_analysis.py results/causaltrace/verdicts.jsonl

DURATION=${1:-1800}   # default 30 minutes; use 420 for 7 min quick test
CALIBRATION_DIR="calibration"

echo "============================================================"
echo "  CausalTrace — Calibration Runner"
echo "  Duration: $((DURATION / 60)) min  |  Container IPs confirmed"
echo "============================================================"

cd "$(dirname "$0")"

# Check containers are up
for c in ct-web ct-api ct-db; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        echo "ERROR: Container $c is not running. Run: docker compose up -d"
        exit 1
    fi
done

# Start traffic generator
echo "Starting traffic generator (${DURATION}s)..."
bash scripts/generate_normal_traffic.sh $DURATION > /tmp/causaltrace_traffic.log 2>&1 &
TRAFFIC_PID=$!
echo "  Traffic PID: $TRAFFIC_PID"

# Give traffic 5 seconds to start before loading BPF
sleep 5

# Run calibration
echo "Loading BPF and running calibration..."
python3 -c "
import sys, os, logging, ctypes, struct, socket, time
sys.path.insert(0, '.')
sys.path.insert(0, 'tier3')
os.chdir('$(pwd)')
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

from loader import *

b = load_bpf()
populate_host_ns(b)
setup_tail_calls(b)
attach_probes(b)

containers = {
    'ct-web': {'ip': '10.88.0.10', 'cgroup_id': 15920},
    'ct-api': {'ip': '10.88.0.20', 'cgroup_id': 15834},
    'ct-db':  {'ip': '10.88.0.30', 'cgroup_id': 15748},
}

ip_to_cgroup     = b.get_table('ip_to_cgroup')
bigram_sketch_map = b.get_table('bigram_sketch_map')
container_behavior = b.get_table('container_behavior')
verdict_map      = b.get_table('verdict_map')

for name, info in containers.items():
    cg = info['cgroup_id']
    ip_int = struct.unpack('!I', socket.inet_aton(info['ip']))[0]
    ip_to_cgroup[ctypes.c_uint32(ip_int)]       = ctypes.c_uint64(cg)
    bigram_sketch_map[ctypes.c_uint64(cg)]       = bigram_sketch_map.Leaf()
    container_behavior[ctypes.c_uint64(cg)]      = container_behavior.Leaf()
    verdict_map[ctypes.c_uint64(cg)]             = ctypes.c_uint32(0)
    print(f'  Registered {name}: cgroup={cg} ip={info[\"ip\"]}')

print('')
from calibrate_runner import run_calibration
run_calibration(b, duration_s=${DURATION}, sample_interval=5.0)
print('Calibration complete.')
"

STATUS=$?
kill $TRAFFIC_PID 2>/dev/null
wait $TRAFFIC_PID 2>/dev/null

if [ $STATUS -eq 0 ]; then
    echo ""
    echo "Calibration artifacts saved to ${CALIBRATION_DIR}/"
    ls -lh ${CALIBRATION_DIR}/ 2>/dev/null
    echo ""
    echo "Next step: sudo bash run_attacks.sh"
else
    echo "Calibration FAILED (exit $STATUS)"
fi

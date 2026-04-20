#!/bin/bash
# run_all.sh — Run all 7 attack scenarios with scenario tagging
# The daemon reads /tmp/causaltrace_current_scenario to tag log entries
#
# Usage:
#   sudo python3 loader.py --mode enforce &   # start daemon first
#   bash attacks/run_all.sh                     # then run this
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results/causaltrace"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo " CausalTrace — Full Evaluation Run"
echo "=========================================="
echo "Results: $RESULTS_DIR"
echo ""

# Clean scenario tag
echo "0" > /tmp/causaltrace_current_scenario

for i in 1 2 3 4 5 6 7 8 9 10 11; do
    SCENARIO_FILE=$(ls ${SCRIPT_DIR}/scenario_${i}_*.sh 2>/dev/null | head -1)
    if [ -z "$SCENARIO_FILE" ]; then
        echo "WARNING: scenario_${i}_*.sh not found, skipping"
        continue
    fi

    echo ""
    echo "────────────────────────────────────────"
    echo " Running Scenario $i"
    echo "────────────────────────────────────────"

    # Signal daemon to tag verdicts with this scenario number
    echo "$i" > /tmp/causaltrace_current_scenario

    # Run scenario, capture output
    bash "$SCENARIO_FILE" 2>&1 | tee "$RESULTS_DIR/scenario_${i}.log"

    # Wait for Tier 3 detection cycle to complete
    sleep 7

    # Clear tag
    echo "0" > /tmp/causaltrace_current_scenario

    echo ""
    echo "Scenario $i complete. Sleeping 5s before next..."
    sleep 5
done

echo ""
echo "=========================================="
echo " All scenarios complete"
echo "=========================================="
echo ""
echo "To analyze results:"
echo "  python3 scripts/results_analysis.py results/causaltrace/verdicts.jsonl"
echo ""

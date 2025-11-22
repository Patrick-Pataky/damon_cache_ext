#!/bin/bash
# Interactive run script (Figure 9)
set -eu -o pipefail

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	echo "Please switch to the cache_ext kernel and try again."
	exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
POLICY_PATH="$BASE_DIR/policies"
FILES_PATH=$(realpath "$BASE_DIR/../linux")
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=3

mkdir -p "$RESULTS_PATH"

# Run Benchmark on TinyLFU
python3 "$BENCH_PATH/bench_interactive.py" \
	--cpu 4 \
	--policy-loader "$POLICY_PATH/cache_ext_fifo.out" \
	--results-file "$RESULTS_PATH/interactive_results.json" \
	--data-dir "$FILES_PATH" \
	--iterations "$ITERATIONS"

echo "Interactive benchmark completed. Results saved to $RESULTS_PATH."

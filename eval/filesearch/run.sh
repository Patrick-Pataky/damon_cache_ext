#!/bin/bash
# File search run script (Figure 9)
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
RESULTS_PATH=${1:-"$BASE_DIR/results"}

ITERATIONS=3

mkdir -p "$RESULTS_PATH"

pushd "$POLICY_PATH"
make clean
make CACHE_SIZE_BITS=18
popd

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Baseline and cache_ext and damon
python3 "$BENCH_PATH/bench_filesearch.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_mru.out" \
	--results-file "$RESULTS_PATH/filesearch_results.json" \
	--data-dir "$FILES_PATH" \
	--iterations "$ITERATIONS"

# Baseline and tinylfu (mru)
python3 "$BENCH_PATH/bench_filesearch.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_tiny_mru.out" \
	--results-file "$RESULTS_PATH/filesearch_results_tiny_mru.json" \
	--data-dir "$FILES_PATH" \
	--iterations "$ITERATIONS"

echo "File search benchmark completed. Results saved to $RESULTS_PATH."

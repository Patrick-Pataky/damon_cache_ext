#!/bin/bash
# File search run script (DAMON version)
set -eu -o pipefail

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
FILES_PATH=$(realpath "$BASE_DIR/../linux")
RESULTS_PATH=${1:-"$BASE_DIR/results"}

ITERATIONS=3

mkdir -p "$RESULTS_PATH"

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Baseline and DAMON
python3 "$BENCH_PATH/bench_filesearch_damon.py" \
	--cpu 8 \
	--results-file "$RESULTS_PATH/filesearch_results_damon.json" \
	--data-dir "$FILES_PATH" \
	--iterations "$ITERATIONS"

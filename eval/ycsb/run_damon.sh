#!/bin/bash
# YCSB run script (DAMON version)
set -eu -o pipefail

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
YCSB_PATH="$BASE_DIR/My-YCSB"
DB_PATH=$(realpath "$BASE_DIR/../leveldb")
RESULTS_PATH=${1:-"$BASE_DIR/results"}

ITERATIONS=3

mkdir -p "$RESULTS_PATH"

# Build correct My-YCSB version
cd "$YCSB_PATH/build"
# git checkout master # Assuming we are on the right branch or don't want to change it
# make clean # Optional
make -j run_leveldb

cd -

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Baseline and DAMON
python3 "$BENCH_PATH/bench_leveldb_damon.py" \
    --cpu 8 \
    --leveldb-db "$DB_PATH" \
    --bench-binary-dir "$YCSB_PATH/build" \
    --benchmark "ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f" \
    --results-file "$RESULTS_PATH/ycsb_results_damon.json" \
    --iterations "$ITERATIONS"

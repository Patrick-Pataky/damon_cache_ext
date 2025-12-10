#!/bin/bash
# Twitter trace run script (DAMON version)
set -eu -o pipefail

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
YCSB_PATH="$BASE_DIR/My-YCSB"
DB_DIRS=$(realpath "$BASE_DIR/../")
RESULTS_PATH=${1:-"$BASE_DIR/results"}
TWITTER_TRACES_DIR="$BASE_DIR/../twitter-traces" # Assuming this is where traces are

ITERATIONS=3

CLUSTERS=(17 18 24 34 52)

mkdir -p "$RESULTS_PATH"

# Build correct My-YCSB version (leveldb-latency branch)
cd "$YCSB_PATH/build"
# git checkout leveldb-latency # Assuming we are on the right branch or don't want to change it
# make clean # Optional
make -j run_leveldb

cd -

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Construct benchmark list
BENCHMARKS=""
for CLUSTER in "${CLUSTERS[@]}"; do
    BENCHMARKS+="twitter_cluster_${CLUSTER}_bench,"
done
# Remove trailing comma
BENCHMARKS=${BENCHMARKS%,}

# Baseline and DAMON
python3 "$BENCH_PATH/bench_twitter_trace_damon.py" \
    --cpu 8 \
    --leveldb-db "$DB_DIRS/leveldb_db" \
    --bench-binary-dir "$YCSB_PATH/build" \
    --benchmark "$BENCHMARKS" \
    --twitter-traces-dir "$TWITTER_TRACES_DIR" \
    --results-file "$RESULTS_PATH/twitter_results_damon.json" \
    --iterations "$ITERATIONS"

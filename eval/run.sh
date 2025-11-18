#!/usr/bin/env bash

# Runs the entire set of benchmarks

set -euo pipefail

BENCHMARKS=(
    "cpu-overhead"
    "filesearch"
    "get-scan"
    "isolation"
    "twitter"
    "ycsb"
)

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../")
STATUS_PATH="$BASE_DIR/eval/status"

NOW=$(date +"%Y_%m_%d_%Hh%Mm%S")

mkdir -p results/"$NOW"
echo "" > "$STATUS_PATH"
echo "Benchmark run started at $(date)" >> "$STATUS_PATH"

STARTTIME=$(date +%s)

for BENCHMARK in "${BENCHMARKS[@]}"; do
    echo "Running benchmark: $BENCHMARK" >> "$STATUS_PATH"
    bash "$BASE_DIR/eval/$BENCHMARK/run.sh" "$BASE_DIR/results/$NOW"
    echo "Completed benchmark: $BENCHMARK" >> "$STATUS_PATH"
    echo "-----------------------------------" >> "$STATUS_PATH"
done

ENDTIME=$(date +%s)

echo "All benchmarks completed. Results are stored in results/$NOW." >> "$STATUS_PATH"
echo "Benchmark run ended at $(date)" >> "$STATUS_PATH"
echo "- Time taken: $((ENDTIME - STARTTIME)) seconds." >> "$STATUS_PATH"

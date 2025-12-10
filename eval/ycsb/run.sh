#!/bin/bash
# YCSB run script (Figure 9 and Table 5)
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
YCSB_PATH="$BASE_DIR/My-YCSB"
DB_PATH=$(realpath "$BASE_DIR/../leveldb")
RESULTS_PATH=${1:-"$BASE_DIR/results"}

ITERATIONS=3

POLICIES=(
	"cache_ext_lhd"
	"cache_ext_s3fifo"
	"cache_ext_sampling"
	"cache_ext_fifo"
	"cache_ext_mru"
	"cache_ext_mglru"
)

mkdir -p "$RESULTS_PATH"

pushd "$POLICY_PATH"
make clean
make CACHE_SIZE_BITS=18
popd

# Build correct My-YCSB version
cd "$YCSB_PATH/build"
git checkout master
make clean
make -j run_leveldb

cd -

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Baseline and cache_ext
for POLICY in "${POLICIES[@]}"; do
	echo "Running policy: ${POLICY}"
	python3 "$BENCH_PATH/bench_leveldb.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/${POLICY}.out" \
		--results-file "$RESULTS_PATH/ycsb_results.json" \
		--leveldb-db "$DB_PATH" \
		--fadvise-hints "" \
		--iterations "$ITERATIONS" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f,uniform,uniform_read_write

	# TinyLFU version
	TINY_POLICY=$(echo "$POLICY" | sed 's/cache_ext_/cache_ext_tiny_/')
	echo "Running policy: ${TINY_POLICY}"
	python3 "$BENCH_PATH/bench_leveldb.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/${TINY_POLICY}.out" \
		--results-file "$RESULTS_PATH/ycsb_results.json" \
		--leveldb-db "$DB_PATH" \
		--fadvise-hints "" \
		--iterations "$ITERATIONS" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f,uniform,uniform_read_write
done

# Enable MGLRU
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

# MGLRU
# TODO: Remove --policy-loader requirement when using --default-only
echo "Running baseline MGLRU"
python3 "$BENCH_PATH/bench_leveldb.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/${POLICY}.out" \
	--results-file "$RESULTS_PATH/ycsb_results_mglru.json" \
	--leveldb-db "$DB_PATH" \
	--fadvise-hints "" \
	--iterations "$ITERATIONS" \
	--bench-binary-dir "$YCSB_PATH/build" \
	--benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f,uniform,uniform_read_write \
	--default-only

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# # DAMON_RECLAIM with baseline and cache_ext
# if ! source "$BASE_DIR/utils/activate-damon.sh"; then
# 	echo "Failed to source activate-damon.sh. Please check the script."
# 	exit 1
# fi

# damon_reclaim_enable

# for param in 1 2 3; do
# 	echo "Setting DAMON_RECLAIM config profile c$param"
# 	damon_reclaim_set_config "$param"

# 	# Baseline and cache_ext
# 	for POLICY in "${POLICIES[@]}"; do
# 		# Due to time constraints, only run DAMON_RECLAIM with cache_ext_lhd
# 		if [[ "$POLICY" != "cache_ext_lhd" ]]; then
# 			continue
# 		fi

# 		echo "Running policy: ${POLICY}"
# 		python3 "$BENCH_PATH/bench_leveldb.py" \
# 			--cpu 8 \
# 			--policy-loader "$POLICY_PATH/${POLICY}.out" \
# 			--results-file "$RESULTS_PATH/ycsb_results_damon_$param.json" \
# 			--leveldb-db "$DB_PATH" \
# 			--fadvise-hints "" \
# 			--iterations "$ITERATIONS" \
# 			--bench-binary-dir "$YCSB_PATH/build" \
# 			--benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f,uniform,uniform_read_write
# 	done
# done

# damon_reclaim_disable

echo "YCSB benchmark completed. Results saved to $RESULTS_PATH."

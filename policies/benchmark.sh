#!/bin/bash
set -e

# Configuration
TEST_DIR="/home/ubuntu/linux" # Adjust if needed, needs to be the watched dir
CGROUP_PATH="/sys/fs/cgroup/cache_ext_test"
RESULT_DIR="results_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULT_DIR"

# Ensure cgroup exists and has limit
if [ ! -d "$CGROUP_PATH" ]; then
    echo "Creating cgroup..."
    sudo cgdelete memory:cache_ext_test
    sudo cgcreate -g memory:cache_ext_test
fi

# Set limit (e.g., 1GB)
echo $((1 << 30)) | sudo tee "$CGROUP_PATH/memory.max" > /dev/null

echo "Starting Filesearch Benchmark..."
echo "Results will be saved to $RESULT_DIR"

# Check if cache_ext_tinylfu is running
if ! pgrep -f "cache_ext_tinylfu" > /dev/null; then
    echo "WARNING: cache_ext_tinylfu does not seem to be running!"
    echo "Please start it in another terminal with:"
    echo "  sudo ./cache_ext_tinylfu.out --watch_dir $TEST_DIR --cgroup_path $CGROUP_PATH"
    read -p "Press Enter to continue anyway (or Ctrl-C to abort)..."
fi

sudo sync
sudo sh -c 'echo 1 > /proc/sys/vm/drop_caches'
sudo swapoff -a

# Run filesearch inside the cgroup
echo "Running filesearch (rg)..."
START_TIME=$(date +%s%N)
sudo taskset -c 0-7 cgexec -g memory:cache_ext_test \
    /bin/bash -c 'for i in {1..10}; do rg write /home/ubuntu/linux > /dev/null; done'
END_TIME=$(date +%s%N)

DURATION=$(( (END_TIME - START_TIME) / 1000000 ))
echo "Benchmark finished. Duration: ${DURATION} ms"
echo "Duration: ${DURATION} ms" > "$RESULT_DIR/result.txt"

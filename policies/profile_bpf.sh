#!/bin/bash
set -e

# Enable BPF stats
sudo sysctl -w kernel.bpf_stats_enabled=1 > /dev/null

echo "Starting BPF Profiling..."
echo "Please ensure the policy is RUNNING in another terminal."

# Capture initial stats
echo "Capturing initial stats..."
sudo bpftool prog show --json > bpf_stats_start.json

# Run the benchmark
./benchmark.sh

# Capture final stats
echo "Capturing final stats..."
sudo bpftool prog show --json > bpf_stats_end.json

# Disable BPF stats (optional, clean up)
# sudo sysctl -w kernel.bpf_stats_enabled=0 > /dev/null

echo "Analysis:"
# Simple python script to diff the stats
python3 analyze_stats.py

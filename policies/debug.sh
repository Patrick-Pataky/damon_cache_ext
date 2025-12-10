#!/bin/bash

# ------------------------------------------
# Executes the filesearch benchmark 1 time -
# ------------------------------------------

# Choices: fifo, get_scan, lhd, mglru, mru,
#          s3fifo, sampling, tinylfu
POLICY="tinylfu"

cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P

CMD1='bash -c "sudo dmesg -w | tee dmesg"'

CMD2="bash -c \"
sleep 5
sudo ./cache_ext_${POLICY}.out \
	    --watch_dir /home/ubuntu/linux \
	    --cgroup_path /sys/fs/cgroup/cache_ext_test
\""

CMD3='bash -c "
sudo sync
sudo sh -c '\''echo 1 > /proc/sys/vm/drop_caches'\'' 
sudo swapoff -a

sudo cgdelete memory:cache_ext_test
sudo cgcreate -g memory:cache_ext_test
sudo sh -c '\''echo $((1<<30)) > /sys/fs/cgroup/cache_ext_test/memory.max'\''

sleep 5

sudo taskset -c 0-7 cgexec -g memory:cache_ext_test \
	    /bin/bash -c '\''for i in {1..10}; do rg write /home/ubuntu/linux > /dev/null; done'\'' &

watch -n 0.5 -x free -h
"'

CMD4='bash -c "sudo cat /sys/kernel/debug/tracing/trace_pipe | tee trace"'

sudo tmux new-session -d -s multisession
sudo tmux split-window -h -t multisession
sudo tmux split-window -v -t multisession:0.0   # bottom-left
sudo tmux split-window -v -t multisession:0.1   # bottom-right

sudo tmux send-keys -t multisession:0.0 "$CMD1" C-m   # top-left
sudo tmux send-keys -t multisession:0.2 "$CMD2" C-m   # bottom-left
sudo tmux send-keys -t multisession:0.1 "$CMD3" C-m   # top-right
sudo tmux send-keys -t multisession:0.3 "$CMD4" C-m   # bottom-right

sudo tmux attach -t multisession

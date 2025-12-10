#!/bin/bash
# enable-mglru.sh

if [ ! -f /sys/kernel/mm/lru_gen/enabled ]; then
    echo "MGLRU not present, cannot enable."
    exit 1
fi

echo 'y' | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null

# Check that it was successfully enabled
lru_val=$(cat /sys/kernel/mm/lru_gen/enabled)
[[ "$lru_val" == "0x0007" ]]

#!/bin/bash

# Check if argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <number>"
    exit 1
fi

# Check if the argument is a number
if ! [[ $1 =~ ^[0-9]+$ ]]; then
    echo "Error: Argument is not a valid number."
    echo "Usage: $0 <number>"
    exit 1
fi

num="$1"

# Execute commands
./link_skb.sh eth0 0
rm /sys/fs/bpf/xdp/globals/conntrack_map_sc
./link_skb.sh eth0 1
./server_in $num
#!/bin/bash

# Check if argument is provided
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <interface> <number>"
    exit 1
fi

interface="$1"
num="$2"

# Check if the second argument is a number
if ! [[ $num =~ ^[0-9]+$ ]]; then
    echo "Error: Second argument is not a valid number."
    echo "Usage: $0 <interface> <number>"
    exit 1
fi

# Execute commands
./link.sh "$interface" 0
rm /sys/fs/bpf/xdp/globals/conntrack_map_sc
./link.sh "$interface" 1
./server_in "$num"
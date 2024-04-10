#!/bin/bash

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <interface> <file.o> [1]"
    exit 1
fi

interface=$1
file=$2

if [ "$#" -eq 2 ]; then
    ip link set "$interface" xdpgeneric off
    exit 0
fi

if [ "$3" -eq 1 ]; then
    ip link set "$interface" xdpgeneric object "./$file"
else
    echo "Usage: $0 <interface> <file.o> [1]"
    exit 1
fi

#!/bin/bash

if [ $# -ne 1 ]; then
    echo "usage: $0 <x>"
    exit 1
fi

x="$1"

if ! [[ "$x" =~ ^[0-9]+$ ]]; then
    echo "erro： Not a integer"
    exit 1
fi

ethtool -L enp6s0f0 combined "$x"
ethtool -L enp6s0f1 combined "$x"

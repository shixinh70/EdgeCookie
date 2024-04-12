#!/bin/bash


if [ $# -ne 3 ]; then
    echo "Usage: $0 <interface> <file.o> <1|0>"
    exit 1
fi

INTERFACE=$1
FILE=$2
ACTION=$3

if [ "$ACTION" -eq 1 ]; then
    tc qdisc add dev $INTERFACE clsact
    tc filter add dev $INTERFACE egress bpf direct-action obj $FILE sec prog
elif [ "$ACTION" -eq 0 ]; then
    tc qdisc del dev $INTERFACE clsact
else
    echo "Invalid action: $ACTION (must be 1 or 0)"
    exit 1
fi

exit 0

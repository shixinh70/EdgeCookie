#!/bin/bash


if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <eth> <0|1>"
    exit 1
fi


eth="$1"
option="$2"


if [ "$option" != "0" ] && [ "$option" != "1" ]; then
    echo "Option must be 0 or 1"
    exit 1
fi

if [ "$option" -eq 0 ]; then
 
    echo "Turning off xdpgeneric and deleting tc qdisc for $eth"
    ip link set "$eth" xdpdrv off
    tc qdisc del dev "$eth" clsact
elif [ "$option" -eq 1 ]; then
 
    echo "Setting xdpgeneric object and adding tc qdisc for $eth"
    ip link set "$eth" xdpdrv object "server_in_kern.o"
    tc qdisc add dev "$eth" clsact
    tc filter add dev "$eth" egress bpf direct-action obj "server_en_kern.o" sec prog
fi

exit 0

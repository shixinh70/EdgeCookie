#!/bin/bash


interface=$(ip addr show | grep "inet 172.19.0.3" | awk '{print $NF}')

if [ -n "$interface" ]; then
    ip link set "$interface" address 00:00:00:00:00:02
    arp -s 172.19.0.2 00:00:00:00:00:12
    echo "Set $interface mac 00:00:00:00:00:02"
else
    echo "Interface not found"
fi

#!/bin/bash
  
# find interface of 172.20.0.3
interface=$(ip addr show | grep "inet 172.20.0.3" | awk '{print $NF}')

# Set interface mac and add static arp
if [ -n "$interface" ]; then
    ip link set "$interface" address 00:00:00:00:00:03
    arp -s 172.20.0.2 00:00:00:00:00:11
    echo "Set $interface addr  00:00:00:00:00:01"
else
    echo "No such interface"
fi

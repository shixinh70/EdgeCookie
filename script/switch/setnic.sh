#!/bin/bash

interface_172_18=$(ip addr show | grep "inet 172.18.0.2" | awk '{print $NF}')
interface_172_19=$(ip addr show | grep "inet 172.19.0.2" | awk '{print $NF}')

if [ -n "$interface_172_18" ]; then
    ip link set "$interface_172_18" address 00:00:00:00:00:11
    echo 2 | sudo tee /sys/class/net/$interface_172_18/napi_defer_hard_irqs
    echo 200000 | sudo tee /sys/class/net/$interface_172_18/gro_flush_timeout
    arp -s 172.18.0.3 00:00:00:00:00:01
    echo "Set $interface_172_18 addr 00:00:00:00:00:11"
    echo "Enable $interface_172_18 busy polling"
else
    echo "Interface not found"
fi

if [ -n "$interface_172_19" ]; then
    arp -s 172.19.0.3 00:00:00:00:00:02
    ip link set "$interface_172_19" address 00:00:00:00:00:12
    echo 2 | sudo tee /sys/class/net/$interface_172_19/napi_defer_hard_irqs
    echo 200000 | sudo tee /sys/class/net/$interface_172_19/gro_flush_timeout
    echo "Set $interface_172_19 addr 00:00:00:00:00:12"
    echo "Enable $interface_172_19 busy polling"
else
    echo "Interface not found"
fi

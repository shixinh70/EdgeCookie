#!/bin/bash

# 检查参数数量是否正确
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <eth> <0|1>"
    exit 1
fi

# 获取参数
eth="$1"
option="$2"

# 检查第二个参数是否为 0 或 1
if [ "$option" != "0" ] && [ "$option" != "1" ]; then
    echo "Option must be 0 or 1"
    exit 1
fi

# 根据第二个参数执行相应操作
if [ "$option" -eq 0 ]; then
    # 执行关闭 xdpgeneric 和删除 tc qdisc 的操作
    echo "Turning off xdpgeneric and deleting tc qdisc for $eth"
    ip link set "$eth" xdpdrv off
    tc qdisc del dev "$eth" clsact
elif [ "$option" -eq 1 ]; then
    # 执行第二种操作
    echo "Setting xdpgeneric object and adding tc qdisc for $eth"
    ip link set "$eth" xdpdrv object "server_in_kern.o"
    tc qdisc add dev "$eth" clsact
    tc filter add dev "$eth" egress bpf direct-action obj "server_en_kern.o" sec prog
fi

exit 0

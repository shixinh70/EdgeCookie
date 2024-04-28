#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <interfacename>"
    exit 1
fi

interface="$1"
prev_rx_packets=0
prev_tx_packets=0
prev_rx_missed_errors=0

while true; do
    stats=$(ethtool -S "$interface")

    rx_packets=$(echo "$stats" | awk '/rx_packets/{print $2}')
    tx_packets=$(echo "$stats" | awk '/tx_packets/{print $2}')
    rx_missed_errors=$(echo "$stats" | awk '/rx_missed_errors/{print $2}')

    delta_rx_packets=$((rx_packets - prev_rx_packets))
    delta_tx_packets=$((tx_packets - prev_tx_packets))
    delta_rx_missed_errors=$((rx_missed_errors - prev_rx_missed_errors))

    echo "Delta rx_packets: $delta_rx_packets"
    echo "Delta tx_packets: $delta_tx_packets"
    echo "Delta rx_missed_errors: $delta_rx_missed_errors"

    prev_rx_packets=$rx_packets
    prev_tx_packets=$tx_packets
    prev_rx_missed_errors=$rx_missed_errors

    sleep 1
done


#!/bin/bash

echo 2 | sudo tee /sys/class/net/enp6s0f0/napi_defer_hard_irqs
echo 2 | sudo tee /sys/class/net/enp6s0f1/napi_defer_hard_irqs
echo 2 | sudo tee /sys/class/net/enp6s0f2/napi_defer_hard_irqs
echo 200000 | sudo tee /sys/class/net/enp6s0f0/gro_flush_timeout
echo 200000 | sudo tee /sys/class/net/enp6s0f1/gro_flush_timeout
echo 200000 | sudo tee /sys/class/net/enp6s0f2/gro_flush_timeout
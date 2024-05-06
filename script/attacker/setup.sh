#!/bin/bash

interface=$(ip addr show | grep "inet 10.20.0.3" | awk '{print $NF}')

# Update apt and install dependencies
sudo apt update
sudo apt-get install -y build-essential cmake linux-headers-$(uname -r) pciutils libnuma-dev libtbb-dev

# Clone repository and set ownership
git clone https://github.com/emmericp/MoonGen.git
git clone https://github.com/shixinh70/HTSCookie_server.git
cp ./HTSCookie_server/script/attacker/gen-traffic.lua ./

# Set the NIC
sudo ip addr flush "$interface"

# Build and setup
cd ./MoonGen
sudo ./build.sh
sudo ./setup-hugetlbfs.sh
#!/bin/bash

interface=$(ip addr show | grep "inet 10.20.0.2" | awk '{print $NF}')

# Update apt and install dependencies
sudo apt update
sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386 linux-tools-$(uname -r) linux-headers-$(uname -r) linux-tools-common linux-tools-generic tcpdump m4 libelf-dev zlib1g-dev libmnl-dev msr-tools -y


# Clone repository and set ownership
git clone https://github.com/shixinh70/HTSCookie_server.git
sudo chown shixinh: -R /data

# Build
cd ./HTSCookie_server
make

# Setup inteface
sudo ./script/switch/setup_interface.sh "$interface"
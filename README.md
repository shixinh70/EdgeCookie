# Building 實驗環境
## CloudLab拓樸圖
![Topo](https://hackmd.io/_uploads/ryKjbjIn0.jpg)

### Client (C220g51 with ubuntu 20.04)
#### 1. Dependency
```
apt update && apt install apache2-utils tcpdump \
netperf curl wget mtr msr-tools -y
```

### Server (C220g5 with ubuntu 20.04)
#### 1. Dependency
```bash
apt update && apt install apache2 tcpdump netperf linux-tools-common curl wget \
linux-cloud-tools-$(uname -r) clang llvm libelf-dev libpcap-dev build-essential \
libc6-dev-i386 linux-tools-$(uname -r) linux-headers-$(uname -r) linux-tools-generic \
m4 zlib1g-dev libmnl-dev msr-tools -y
```

#### 2. TC hook rediect IF setup, and XDP mode setup
Modify the ./EdgeCookie/examples/address.h
```cpp
/* If XDP running in Native(Driver) mode, then set XDP_DRV to 1.
   Use command "ip -a" to find the ID of Server's Interface (for experience).
   Set the SERVER_IF to the ID    */

#define XDP_DRV 1
#define SERVER_IF 2
```

#### 3. Build
```bash
make
```

#### 4. Usage
```basb
## Unload XDP and TC
./EdgeCookie/examples/htscookie/link.sh <Interfcae> 0
## Load XDP and TC
./EdgeCookie/examples/htscookie/link.sh <Interfcae> 1
## Set SmartCookie's Bloomfilter flow number
```

##### 5. Modify apache2's index size
```bash
truncate -s <size_bytes> /var/www/html/index.html
```

### Switch agnet(C220g2 ubuntu20.04)
#### 1. Dependency
```bash
sudo apt update && \
sudo apt install clang llvm libelf-dev libpcap-dev \
build-essential libc6-dev-i386 linux-tools-$(uname -r) \
linux-headers-$(uname -r) linux-tools-common linux-tools-generic \
tcpdump m4 libelf-dev zlib1g-dev libmnl-dev msr-tools -y
```

#### 2. NIC Setup
```bash
## set multi-queue to 1
./script/switch/setup_interface <interface>
## enable busypolling
./script/switch/enable_busypolling <interface>
```



#### 3. MAC Address Setup
Modify the ./EdgeCookie/examples/address.h
```c
/*   Fill in the Client, Server, Attacker IF's MAC.
     And the pair interface on the switch    */
...
#define CLIENT_MAC "3c:fd:fe:b3:15:dc"
#define SERVER_MAC "3c:fd:fe:b0:f2:c0"
#define ATTACKER_MAC "3c:fd:fe:b0:f1:78"
#define CLIENT_R_MAC "90:e2:ba:aa:fe:2c"
#define SERVER_R_MAC "90:e2:ba:aa:fe:2d"
#define ATTACKER_R_MAC "90:e2:ba:aa:fe:2c"
...

## Fill the interface's order of switch agent's running command
## EX: ./switch_agent -i <CLIENT_R_IF> -i <SERVER_R_IF>
## Then it should be setup like:
#define CLIENT_R_IF_ORDER 0
#define SERVER_R_IF_ORDER 1
```
#### 4. Build
```bash
make
```

### Adversary (c220g5 with ubuntu 18.04)
#### 1. Dependency

```bash
apt update && apt-get install -y build-essential cmake \
linux-headers-$(uname -r) pciutils libnuma-dev libtbb-dev
```
#### 2. Build Moongen
```bash
git clone https://github.com/emmericp/MoonGen.git \
&& ip addr flush dev $(ip addr show | grep "inet 10.18.0.4" | awk '{print $NF}') \
&& cd ./MoonGen \
&& ./build.sh \
&& ./setup-hugetlbfs.sh \
&& ./libmoon/deps/dpdk/usertools/dpdk-devbind.py --status
```
#### 3. Clone EdgeCookie (Copy out gen-traffic.lua)
```bash
git clone https://github.com/shixinh70/EdgeCookie.git \
&& cp ./EdgeCookie/script/attacker/gen-traffic.lua ./
```
#### 4. Modify gen-traffic.lua file

```cpp
// ETH_SRC should be adversary's IF MAC
// ETH_DST should be the pair IF on the switch agent

local ETH_SRC = "3c:fd:fe:b4:fb:2c"
local ETH_DST = "90:e2:ba:b3:75:c0"
```
#### 5. Moongen Usage
```cpp
// Working directory = "./Moongen"
./build/Moongen ../gen-traffic.lua <IF_TX> <IF_RX> [options]
```

### Common setup

#### 1. CPU setup
##### Turn off C-state, turbo boost and fix CPU frequency
```bash
./script/fix_irq.sh
```
##### Turn off hyper-threading
```bash
echo off | sudo tee /sys/devices/system/cpu/smt/control
```
#### 2. Manual ARP setup 
**TOPO**
![TOPO](https://hackmd.io/_uploads/S1d-N3InR.jpg)


```bash
## Example
## In Client
arp -s <IP_CS> <MAC_CS>
## In Switch Agent
arp -s <IP_C> <MAC_C>
arp -s <IP_S> <MAC_S>
## IN Server
arp -s <IP_SS> <MAC_SS>
```
# Experiment Related
## Suggest setup
### 1. Combind all the interface's queue to 1, including server and client.
```bash
ethtool -L <interface> combined 1
```
### 2. Do not fix the CPU frequency of switch_agent for better performace, but fix the server and client's.

### 3. Do not fix the CPU frequency of server when observing the MIPS. 
## Effectiveness of EdgeCookie
### 1. Adversary: Launch DDoS attack by Moongen
```bash
## Example
## syn flood at 1Mpps rates with random src IP.
## Warning: The src IP's first 8bit should be the experiment
##          network's domain (e.g., 10.x.x.x).

./build/MoonGen ../gen_traffic.lua 1 1 -p 1 -f 16777210
```
### 2. Switch agent: Running EdgeCookie/SmartCookie switch_agent

```bash
## Example
## Running EdgeCookie with busypoll mode,
## and with apache2's TCP options
## and caculate SYN cookie with HARAKAv2 
./examples/htscookie/switch_agent -i enp6s0f0 -i enp6s0f0 -B -- -c -h HARAKA

## Running SmartCookie with busypoll mode,
## with 579600 flows in the Bloomfilter.
./examples/smartcookie/switch_agent -i enp6s0f0 -i enp6s0f0 -B -- -f 579600

```
### 3. Server: Caculate (M)IPS of every cores
```bash
## Get all the total instructions of all cores for 10 sec
perf stat -e instructions -a sleep 10
```
### 4. Result: Collect the Avg IPS of server
## Throughput
### 1. Adversary: Launch DDoS attack by Moongen
### 2. Switch agent: Running EdgeCookie/SmartCookie switch_agent, and collect the TX/RX throughput

## Latency under the flood
### 1. Adversary: Launch DDoS attack by Moongen
### 2. Switch agent: Running EdgeCookie/SmartCookie switch_agent
### 3. Client: Use curl tools to collect the Latency
```bash
## Run the script to get the latency
## curl server for N request and output the Avg Latency.
./EdgeCookie/script/client/curl_time.sh <N>
```

## Latency Related to File Size and Polling Method
### 1. Switch agent: Running EdgeCookie/SmartCookie switch_agent with/without Busypoll.
### 2. Server: Adjust the apache2 index size.
### 3. Client: Use curl tools to collect the Latency.
### 3.1 Client: Get the composition of latency
```bash
## curl server for N request and parse the Latency
./EdgeCookie/script/client/parse_time.sh <N>
```

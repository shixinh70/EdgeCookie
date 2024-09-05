# EdgeCookie - A solution to mitigate SYN flood and ACK flood attacks by leveraging eBPF

TCP SYN flood is a famous DDoS attack that exploits the creation of numerous half-opened connections to exhaust resources of a server. Researchers are still actively working on resolving this issue. ACK flood, on the other hand, utilizes a large number of ACK packets carrying data to flood the server's network, causing service disruption for regular users. However, ACK flood attacks are less common compared to SYN flood attacks because they are limited by the TCP three-way handshake mechanism and cannot effectively amplify traffic like UDP reflection attacks. Therefore, it is difficult to saturate the line with ACK flood attacks. However, in 2021, Kevin Bock and others discovered vulnerabilities in many middleboxes in the network that could be exploited for reflective ACK flood attacks, with astonishing amplification factors. This makes this new type of ACK flood attack an increasingly significant threat.

To address both SYN flood and ACK flood attacks, we propose an architecture that utilizes eBPF programs running on both the border gateway and the server, which are gateway agent and server agent, to verify and tag the traffic flow. The goal is to promptly filter out attack traffic to avoid impacting other legitimate users on the network.

When a client wants to establish a connection with the protected server, the gateway agent acts as a SYN proxy, employing SYN cookie mechanisms to perform initial client validation. If the client is deemed legitimate, the connection is forwarded to the server agent. Then the server agent establishes a connection with the server behind it, ultimately synchronizing the two independent connections.

For all ACK packets sent by the server, the server agent inserts a special hybrid cookie into the TCP timestamp value field. Due to TCP protocol specifications, when the receiver needs to reply to packets carrying TCP timestamp values, it must place the timestamp value in the timestamp echo field of the response packet. Therefore, the gateway agent can verify the timestamp echo field of ACK packets to determine whether both end-host have completed the connection establishment process, enabling packet filtering without the need to store any TCP states.

# The router agent typically build on [XSNKF library](https://github.com/FedeParola/xsknf)

# Building
## Experiment TOPO
![Topo](https://github.com/user-attachments/assets/957e2285-97b1-4d12-a157-01b969a799c0)
### Client (C220g5 with ubuntu 20.04)
#### Dependency
```
apt update && apt install apache2-utils tcpdump \
netperf curl wget mtr msr-tools -y
```

### Server (C220g5 with ubuntu 20.04)
#### Dependency
```
apt update && apt install apache2 tcpdump netperf linux-tools-common curl wget \
linux-cloud-tools-$(uname -r) clang llvm libelf-dev libpcap-dev build-essential \
libc6-dev-i386 linux-tools-$(uname -r) linux-headers-$(uname -r) linux-tools-generic \
m4 zlib1g-dev libmnl-dev msr-tools -y
```

#### TC hook rediect IF setup, and XDP mode setup
Modify the ./EdgeCookie/examples/address.h
```cpp=
/* If XDP running in Native(Driver) mode, then set XDP_DRV to 1.
   Use command "ip -a" to find the ID of Server's Interface (for experience).
   Set the SERVER_IF to the ID    */

#define XDP_DRV 1
#define SERVER_IF 2
```

#### Build
```bash=
make
```

#### Usage
```basb=
## Unload XDP and TC
./EdgeCookie/examples/htscookie/link.sh <Interfcae> 0
## Load XDP and TC
./EdgeCookie/examples/htscookie/link.sh <Interfcae> 1
## Set SmartCookie's Bloomfilter flow number
```

##### Modify apache2's index size
```bash=
truncate -s <size_bytes> /var/www/html/index.html
```

### Switch agnet(C220g2 ubuntu20.04)
#### Dependency
```bash=
sudo apt update && \
sudo apt install clang llvm libelf-dev libpcap-dev \
build-essential libc6-dev-i386 linux-tools-$(uname -r) \
linux-headers-$(uname -r) linux-tools-common linux-tools-generic \
tcpdump m4 libelf-dev zlib1g-dev libmnl-dev msr-tools -y
```

#### NIC Setup
```bash=
## set multi-queue to 1
./script/switch/setup_interface <interface>
## enable busypolling
./script/switch/enable_busypolling <interface>
```



#### MAC Address Setup
Modify the ./EdgeCookie/examples/address.h
```cpp=
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
#### Build
```bash=
make
```

### Adversary (c220g5 with ubuntu 18.04)
#### Dependency

```bash=
apt update && apt-get install -y build-essential cmake \
linux-headers-$(uname -r) pciutils libnuma-dev libtbb-dev
```
#### Build Moongen
```bash=
git clone https://github.com/emmericp/MoonGen.git \
&& ip addr flush dev $(ip addr show | grep "inet 10.18.0.4" | awk '{print $NF}') \
&& cd ./MoonGen \
&& ./build.sh \
&& ./setup-hugetlbfs.sh \
&& ./libmoon/deps/dpdk/usertools/dpdk-devbind.py --status
```
#### Clone EdgeCookie (Copy out gen-traffic.lua)
```bash=
git clone https://github.com/shixinh70/EdgeCookie.git \
&& cp ./EdgeCookie/script/attacker/gen-traffic.lua ./
```
#### Modify gen-traffic.lua file

```cpp=
// ETH_SRC should be adversary's IF MAC
// ETH_DST should be the pair IF on the switch agent

local ETH_SRC = "3c:fd:fe:b4:fb:2c"
local ETH_DST = "90:e2:ba:b3:75:c0"
```
#### Moongen Usage
```cpp=
// Working directory = "./Moongen"
./build/Moongen ../gen-traffic.lua <IF_TX> <IF_RX> [options]
```

### Common setup

#### CPU setup
##### Turn off C-state, turbo boost and fix CPU frequency
```bash=
./script/fix_irq.sh
```
##### Turn off hyper-threading
```bash=
echo off | sudo tee /sys/devices/system/cpu/smt/control
```
#### Manual ARP setup 
**TOPO**
![htscookie_light-第 35 页 (1)](https://github.com/user-attachments/assets/d34b5f26-61c4-4ea3-8b00-64bd74384fd3)

```bash=
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
```bash=
ethtool -L <interface> combined 1
```
### 2. Do not fix the CPU frequency of switch_agent for better performace, but fix the server and client's.

### 3. Do not fix the CPU frequency of server when observing the MIPS. 
## Effectiveness of EdgeCookie
### 1. Adversary: Launch DDoS attack by Moongen
```bash=
## Example
## syn flood at 1Mpps rates with random src IP.
## Warning: The src IP's first 8bit should be the experiment
##          network's domain (e.g., 10.x.x.x).

./build/MoonGen ../gen_traffic.lua 1 1 -p 1 -f 16777210
```
### 2. Switch agent: Running EdgeCookie/SmartCookie switch_agent

```bash=
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
```bash=
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
```bash=
## Run the script to get the latency
## curl server for N request and output the Avg Latency.
./EdgeCookie/script/client/curl_time.sh <N>
```

## Latency Related to File Size and Polling Method
### 1. Switch agent: Running EdgeCookie/SmartCookie switch_agent with/without Busypoll.
### 2. Server: Adjust the apache2 index size.
### 3. Client: Use curl tools to collect the Latency.
### 3.1 Client: Get the composition of latency
```bash=
## curl server for N request and parse the Latency
./EdgeCookie/script/client/parse_time.sh <N>
```

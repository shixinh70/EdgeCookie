# Dependency
```
sudo apt update
sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386 \
linux-tools-$(uname -r) linux-headers-$(uname -r) linux-tools-common linux-tools-generic \
tcpdump m4 libelf-dev zlib1g-dev libmnl-dev msr-tools -y
```
# Build
```
cd ./HTSCookie_server
make
```
If you want to turn on the debug message, you can make with (currently not working)
```
make CFLAGS=-DDEBUGALL=1      // For all the debug message
make CFLAGS=-DDEBUGSA=1       // For the switch_agent debug message
make CFLAGS=-DDEBUGSERVER=1   // For the server_in and server_en debug message
```
## Switch agent and sever_ingress, server_egress

Both example include switch_agent, server_in.o, server_en.o
### switch_agent
Before compile this application, please manully set the `MAC` ,`IP` , and the `interfaces' order` in [./example/common/address.h](./example/common/address.h)
Take the example below, the eth0's order will be 0 and eth1 will be 1.  
CLIENT_R_MAC is the MAC of router's interface which conneted to client.

### server_in.o and server_en.o
Before compile ebpf object file, please manully set the `redirect interface` of server, and the `XDP mode` correspond with swtich_agent 
also in [./example/common/address.h](./example/common/address.h)  
You can bind the ebpf by the link.sh or /link_skb.sh script.  
Usage:
```
sudo ./link.sh <interfcae> <1|0>  -- 1 for load and 0 for unload 
```



# XSKNF library and XSKNF-specifict application arguments

A typical application based on XSKNF can be called with a set of XSKNF-specific arguments, followed by a double hypen (`--`), followed by a set of application-specific arguments (in a similar way to how DPDK applications are invoked).

The following arguments are currently supported by the XSKNF library:

```
-i, --iface=n[:m]   Interface to operate on (a copy mode between copy (c) or zero-copy (z)
                    can optionally be specified). Can be repeated multiple times
-p, --poll          Use poll syscall
-S, --xdp-skb=n     Use XDP skb-mode
-f, --frame-size=n  Set the frame size (must be a power of two in aligned mode, default is 4096)
-u, --unaligned     Enable unaligned chunk placement
-b, --batch-size=n  Batch size for sending or receiving packets. Default is 64
-B, --busy-poll     Busy poll
-M  --mode          Working mode (AF_XDP, XDP, COMBINED)
-w  --workers=n     Number of packet processing workers
```
And the application-specific argumemnts, take HTScookie as a example:
```
-h, --hash-type     'HARAKA', 'HSIPHASH', 'OFF' for hash function of the Hash cookie, default HARAKA
-s, --tcp-csum      'ON', 'OFF', Turn on/off recompute TCP csum, default ON
-t, --timestamp     'ON', 'OFF', Turn on/off parsing timestamp, default ON
-k  --change-key    Enable switch_agent to validate two cookies, default OFF
-p, --pressure      Receive a SYN packet and caculate syncookie then DROP
-f, --foward        Only foward packet to the corresponding interface
-d, --drop          Only drop packet after receive the packet
-q, --quiet         Do not display any stats
-x, --extra-stats   Display extra statistics
-a, --app-stats     Display application (syscall) statistics
```
For example it can be run in the follwing way:
```
sudo ./switch_agent -i eth0 -i eth1 -S -- -h HSIPHASH -q
```
This command tells XSKNF to use interfaces `ens1f0` and `ens1f1` (`-i`), and XDP running in a SKB mode.  
Application will print no periodic statistics (`-q`) and calculate the syncookie by Hafl-siphash (`-h HSIPHASH`).




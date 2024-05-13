# HTSCookie - Switch agent and sever_ingress, server_egress

## Application setup

Before compile this application, please manully set the MAC ,IP , and the interfaces' order in [./switch_agent.h](./switch_agent.h) .
Take the example below, the eth0's order will be 0 and eth1 will be 1.

CLIENT_R_MAC is the MAC of router's interface which conneted to client. 

A typical application based on XSKNF can be called with a set of XSKNF-specific arguments, followed by a double hypen (`--`), followed by a set of application-specific arguments (in a similar way to how DPDK applications are invoked).

The following arguments are currently supported by the library:

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
And the arguments are currently supported by the HTSCookie switch agent application:
```
-h, --hash-type     'HARAKA', 'HSIPHASH', 'OFF' for hash function of the Hash cookie, default HARAKA
-s, --tcp-csum      'ON', 'OFF', Turn on/off recompute TCP csum, default ON
-t, --timestamp     'ON', 'OFF', Turn on/off parsing timestamp, default ON
-k  --change-key    Enable switch_agent to validate two cookies
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
This command tells XSKNF to use interfaces `ens1f0` and `ens1f1` (`-i`), and XDP running in a SKB mode. Application will print no periodic statistics (`-q`) and calculate the syncookie by Hafl-siphash (`-h HSIPHASH`).



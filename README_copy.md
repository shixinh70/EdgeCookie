# EdgeCookie - A solution to mitigate SYN flood and ACK flood attacks by leveraging eBPF

TCP SYN flood is a famous DDoS attack that exploits the creation of numerous half-opened connections to exhaust resources of a server. Researchers are still actively working on resolving this issue. ACK flood, on the other hand, utilizes a large number of ACK packets carrying data to flood the server's network, causing service disruption for regular users. However, ACK flood attacks are less common compared to SYN flood attacks because they are limited by the TCP three-way handshake mechanism and cannot effectively amplify traffic like UDP reflection attacks. Therefore, it is difficult to saturate the line with ACK flood attacks. However, in 2021, Kevin Bock and others discovered vulnerabilities in many middleboxes in the network that could be exploited for reflective ACK flood attacks, with astonishing amplification factors. This makes this new type of ACK flood attack an increasingly significant threat.

To address both SYN flood and ACK flood attacks, we propose an architecture that utilizes eBPF programs running on both the border gateway and the server, which are gateway agent and server agent, to verify and tag the traffic flow. The goal is to promptly filter out attack traffic to avoid impacting other legitimate users on the network.

When a client wants to establish a connection with the protected server, the gateway agent acts as a SYN proxy, employing SYN cookie mechanisms to perform initial client validation. If the client is deemed legitimate, the connection is forwarded to the server agent. Then the server agent establishes a connection with the server behind it, ultimately synchronizing the two independent connections.

For all ACK packets sent by the server, the server agent inserts a special hybrid cookie into the TCP timestamp value field. Due to TCP protocol specifications, when the receiver needs to reply to packets carrying TCP timestamp values, it must place the timestamp value in the timestamp echo field of the response packet. Therefore, the gateway agent can verify the timestamp echo field of ACK packets to determine whether both end-host have completed the connection establishment process, enabling packet filtering without the need to store any TCP states.

# The router agent typically build on [XSNKF library](https://github.com/FedeParola/xsknf)

## XSKNF - Speed up development of AF_XDP-based NFs (Modified from [XSNKF](https://github.com/FedeParola/xsknf))

The XSKNF library speeds up the development of AF_XDP based network functions taking care of all aspects related to AF_XDP buffers and rings management and threading aspects.
The programmer just has to write a packet processing function that receives a single packet in input, processes it and provides a verdict.

### Building

The library relies on **libbpf** and **libxdp** that are included as submodules and automatically updated when building.

The **libelf**, **libz**, and **libmnl** libraries are required and can be installed in Ubuntu with the following command:
```
sudo apt install libelf-dev zlib1g-dev libmnl-dev
```

Run `make` in the main project folder to build the library under [./src](https://github.com/FedeParola/xsknf/tree/master/src)

### Application setup

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

The [macswap](https://github.com/FedeParola/xsknf/tree/master/examples/macswap) example provides a very basic example of how to use the library. For example it can be run in the follwing way:
```
sudo ./macswap -i ens1f0 -i ens1f1 -- -q
```
This command tells XSKNF to use interfaces `ens1f0` and `ens1f1` (`-i`) and the application not to print periodic statistics (`-q`).

### Paper

For the tests of the paper *Comparing User Space and In-Kernel Packet Processing for Edge Data Centers* please refer to the [tests]([./tests](https://github.com/FedeParola/xsknf/tree/master/tests)) folder.

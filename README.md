# HTScookie - A solution to mitigate SYN flood and ACK flood attacks by leveraging eBPF.

TCP SYN flood is a famous DDoS attack that exploits the creation of numerous half-opened connections to exhaust resources of a server. Researchers are still actively working on resolving this issue. ACK flood, on the other hand, utilizes a large number of ACK packets carrying data to flood the server's network, causing service disruption for regular users. However, ACK flood attacks are less common compared to SYN flood attacks because they are limited by the TCP three-way handshake mechanism and cannot effectively amplify traffic like UDP reflection attacks. Therefore, it is difficult to saturate the line with ACK flood attacks. However, in 2021, Kevin Bock and others discovered vulnerabilities in many middleboxes in the network that could be exploited for reflective ACK flood attacks, with astonishing amplification factors. This makes this new type of ACK flood attack an increasingly significant threat.

To address both SYN flood and ACK flood attacks, we propose an architecture that utilizes eBPF programs running on both the border gateway and the server, which are gateway agent and server agent, to verify and tag the traffic flow. The goal is to promptly filter out attack traffic to avoid impacting other legitimate users on the network.

When a client wants to establish a connection with the protected server, the gateway agent acts as a SYN proxy, employing SYN cookie mechanisms to perform initial client validation. If the client is deemed legitimate, the connection is forwarded to the server agent. Then the server agent establishes a connection with the server behind it, ultimately synchronizing the two independent connections.

For all ACK packets sent by the server, the server agent inserts a special hybrid cookie into the TCP timestamp value filed. Due to TCP protocol specifications, when the receiver needs to reply to packets carrying TCP timestamp values, it must place the timestamp value in the timestamp echo field of the response packet. Therefore, the gateway agent can verify the timestamp echo field of ACK packets to determine whether both end-host have completed the connection establishment process, enabling packet filtering without the need to store any TCP states.

# The router agent typically build on XSNKF library.



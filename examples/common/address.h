#ifndef ADDRESS_H
#define ADDRESS_H

/*  Manully set the address information 
    ***_R_F mean the argument order of
    ./swith_agent -i <order0> -i <order1>   */
#define CLIENT_MAC "02:42:ac:12:00:03"
#define SERVER_MAC "02:42:ac:13:00:03"
#define ATTACKER_MAC "00:00:00:00:03"
#define CLIENT_R_MAC "02:42:ac:12:00:02"
#define SERVER_R_MAC "02:42:ac:13:00:02"
#define ATTACKER_R_MAC "00:00:00:00:13"
#define CLIENT_IP ("172.18.0.3")
#define SERVER_IP ("172.19.0.3")
#define ATTACKER_IP ("10.20.0.3")
#define CLIENT_R_IF_ORDER 0
#define SERVER_R_IF_ORDER 1
#define ATTACKER_R_IF_ORDER 0


/*  For server_en, XDP_DRV set to 1 if bind to xdp-drive mode
    Check the server's interface by ip addr show, then set
    SERVER_IF to that number    */
#define XDP_DRV 0
#define SERVER_IF 28



#endif
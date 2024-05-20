#ifndef ADDRESS_H
#define ADDRESS_H

/*  Manully set the address information 
    ***_R_F mean the argument order of
    ./swith_agent -i <order0> -i <order1>   */
#define CLIENT_MAC "3c:fd:fe:b3:15:c8"
#define SERVER_MAC "3c:fd:fe:b4:fe:8c"
#define ATTACKER_MAC "3c:fd:fe:b3:13:44"
#define CLIENT_R_MAC "90:e2:ba:b3:75:a0"
#define SERVER_R_MAC "90:e2:ba:b3:75:c1"
#define ATTACKER_R_MAC "90:e2:ba:b3:75:a0"
#define CLIENT_IP ("10.18.0.3")
#define SERVER_IP ("10.19.0.3")
#define ATTACKER_IP ("10.18.0.4")
#define CLIENT_R_IF_ORDER 0
#define SERVER_R_IF_ORDER 1
#define ATTACKER_R_IF_ORDER 0


/*  For server_en, XDP_DRV set to 1 if bind to xdp-drive mode
    Check the server's interface by ip addr show, then set
    SERVER_IF to that number    */
#define XDP_DRV 1
#define SERVER_IF 2



#endif
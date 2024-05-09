#include <stdint.h>
#include "immintrin.h"
#include "../common/statistics.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <xsknf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include "timestamp.h"
#include "haraka.h"
#include "csum.h"
#include "murmur.h"
#include "timeit.h"
#include "pthread.h"
#include "fnv.h"

#define MSTONS 1000000
#define TS_START bpf_ntohl(0x01010000)


#define DEBUG 1

#define DEBUG_PRINT(fmt, ...) \
	if (DEBUG)                \
	printf(fmt, ##__VA_ARGS__)

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

struct common_synack_opt
{
	uint32_t MSS;
	uint16_t SackOK;
	struct tcp_opt_ts ts;
} __attribute__((packed));

struct eth_mac_t
{
    uint8_t buf[6];
}__attribute__((packed));

struct global_data {
    int client_r_if_order;
    int server_r_if_order;
    int attacker_r_if_order;
	int workers_num;
};

struct pkt_5tuple {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t salt[5];
} __attribute__((packed));






#pragma once
#include <stdint.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct tcp_opt_ts
{
	uint8_t kind;
	uint8_t length;
	uint32_t tsval;
	uint32_t tsecr;
} __attribute__((packed));

// parse_timestamp's offset from tcp's basic 20 bytes header
// Return offset
__u32 parse_timestamp(struct tcphdr *tcp);



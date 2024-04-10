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

__u64 u1_mac = 0x030012ac4202;
__u64 u2_mac = 0x030013ac4202;
__u64 reth1_mac = 0x020012ac4202;
__u64 reth2_mac = 0x020013ac4202;


#define DEBUG 0
#define DEBUG_PRINT(fmt, ...) \
	if (DEBUG)                \
	printf(fmt, ##__VA_ARGS__)
#define RETH1 0
#define RETH2 1
#define TS_START bpf_ntohl(0x01010000)


#define PERF 1
#ifdef PERF
#define START_TIMER(NAME) \
    struct timespec NAME##_start_time, NAME##_end_time; \
    clock_gettime(CLOCK_MONOTONIC, &NAME##_start_time);
#define END_TIMER(NAME) \
    clock_gettime(CLOCK_MONOTONIC, &NAME##_end_time); \
    unsigned long long NAME##_elapsed_ns = (NAME##_end_time.tv_sec - NAME##_start_time.tv_sec) * 1000000000ULL + (NAME##_end_time.tv_nsec - NAME##_start_time.tv_nsec); \
    printf("%s elapsed time: %llu ns\n", #NAME, NAME##_elapsed_ns);
#else
#define START_TIMER(NAME)
#define END_TIMER(NAME)
#endif



#define NUMROUNDS 5
#define u64 unsigned long
#define u128 __m128i

u128 rc[40];

#define LOAD(src) _mm_load_si128((u128 *)(src))
#define STORE(dest,src) _mm_storeu_si128((u128 *)(dest),src)

#define AES2(s0, s1, rci) \
  s0 = _mm_aesenc_si128(s0, rc[rci]); \
  s1 = _mm_aesenc_si128(s1, rc[rci + 1]); \
  s0 = _mm_aesenc_si128(s0, rc[rci + 2]); \
  s1 = _mm_aesenc_si128(s1, rc[rci + 3]);

#define AES2_4x(s0, s1, s2, s3, rci) \
  AES2(s0[0], s0[1], rci); \
  AES2(s1[0], s1[1], rci); \
  AES2(s2[0], s2[1], rci); \
  AES2(s3[0], s3[1], rci);

#define AES2_8x(s0, s1, s2, s3, s4, s5, s6, s7, rci) \
  AES2_4x(s0, s1, s2, s3, rci); \
  AES2_4x(s4, s5, s6, s7, rci);

#define AES4(s0, s1, s2, s3, rci) \
  s0 = _mm_aesenc_si128(s0, rc[rci]); \
  s1 = _mm_aesenc_si128(s1, rc[rci + 1]); \
  s2 = _mm_aesenc_si128(s2, rc[rci + 2]); \
  s3 = _mm_aesenc_si128(s3, rc[rci + 3]); \
  s0 = _mm_aesenc_si128(s0, rc[rci + 4]); \
  s1 = _mm_aesenc_si128(s1, rc[rci + 5]); \
  s2 = _mm_aesenc_si128(s2, rc[rci + 6]); \
  s3 = _mm_aesenc_si128(s3, rc[rci + 7]); \

#define AES4_4x(s0, s1, s2, s3, rci) \
  AES4(s0[0], s0[1], s0[2], s0[3], rci); \
  AES4(s1[0], s1[1], s1[2], s1[3], rci); \
  AES4(s2[0], s2[1], s2[2], s2[3], rci); \
  AES4(s3[0], s3[1], s3[2], s3[3], rci);

#define AES4_8x(s0, s1, s2, s3, s4, s5, s6, s7, rci) \
  AES4_4x(s0, s1, s2, s3, rci); \
  AES4_4x(s4, s5, s6, s7, rci);

#define MIX2(s0, s1) \
  tmp = _mm_unpacklo_epi32(s0, s1); \
  s1 = _mm_unpackhi_epi32(s0, s1); \
  s0 = tmp;

#define MIX4(s0, s1, s2, s3) \
  tmp  = _mm_unpacklo_epi32(s0, s1); \
  s0 = _mm_unpackhi_epi32(s0, s1); \
  s1 = _mm_unpacklo_epi32(s2, s3); \
  s2 = _mm_unpackhi_epi32(s2, s3); \
  s3 = _mm_unpacklo_epi32(s0, s2); \
  s0 = _mm_unpackhi_epi32(s0, s2); \
  s2 = _mm_unpackhi_epi32(s1, tmp); \
  s1 = _mm_unpacklo_epi32(s1, tmp);

#define TRUNCSTORE(out, s0, s1, s2, s3) \
  *(u64*)(out) = (u64*)(s0)[1]; \
  *(u64*)(out + 8) = (u64*)(s1)[1]; \
  *(u64*)(out + 16) = (u64*)(s2)[0]; \
  *(u64*)(out + 24) = (u64*)(s3)[0];

void load_constants();

const uint64_t syn_1_mask = 0x0008000400000002;
const uint64_t syn_2_mask_1 = 0x0000070100000002;
const uint32_t syn_2_mask_2 = 0x08010100;
const uint64_t syn_3_mask_1 = 0x0000070100000002;
const uint32_t syn_3_mask_2 = 0x08000400;
const uint64_t ack_1_mask = 0x000000000080101;
const uint64_t synack_1_mask = ack_1_mask;
const uint64_t synack_2_mask_1 = syn_2_mask_1;
const uint32_t synack_2_mask_2 = syn_3_mask_2;
const uint64_t synack_3_mask = 0x0008010100000004;
const uint64_t synack_4_mask_1 = syn_2_mask_1;
const uint32_t synack_4_mask_2 = syn_2_mask_2;

struct PseudoHead{
  uint8_t zero;
  uint8_t type;
  uint16_t  len;
  uint32_t src_ip;
  uint32_t dst_ip;
};

struct tcp_opt_ts
{
	uint8_t kind;
	uint8_t length;
	uint32_t tsval;
	uint32_t tsecr;
} __attribute__((packed));

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
	int action;
	int double_macswap;
};

struct pkt_5tuple {
  uint32_t seq;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t sand[16];
} __attribute__((packed));


#define SIPROUND          \
	do                    \
	{                     \
		v0 += v1;         \
		v2 += v3;         \
		v1 = rol(v1, 5);  \
		v3 = rol(v3, 8);  \
		v1 ^= v0;         \
		v3 ^= v2;         \
		v0 = rol(v0, 16); \
		v2 += v1;         \
		v0 += v3;         \
		v1 = rol(v1, 13); \
		v3 = rol(v3, 7);  \
		v1 ^= v2;         \
		v3 ^= v0;         \
		v2 = rol(v2, 16); \
	} while (0)



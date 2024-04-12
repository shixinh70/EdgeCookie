#pragma once
#include <stdint.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

struct PseudoHead{
  uint8_t zero;
  uint8_t type;
  uint16_t  len;
  uint32_t src_ip;
  uint32_t dst_ip;
};


uint32_t CalSum(const uint8_t* buf, int len);
uint32_t CalPseudoHeadSum(const struct iphdr* pIpHead, uint8_t type);
uint16_t cksumIp(struct iphdr* pIpHead);
uint16_t cksumTcp(struct iphdr* pIpHead, struct tcphdr* pTcpHead);
uint16_t csum_fold(uint32_t csum);
uint32_t csum_unfold(uint16_t n);
uint32_t csum_add(uint32_t csum, uint32_t addend);
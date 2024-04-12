#include "csum.h"

uint32_t CalSum(const uint8_t* buf, int len) {

  uint32_t sum = 0;
  const uint8_t* p = buf;
  
  for(; len > 1; len -= 2) {
    sum += (*p << 8)+ *(p + 1);
    p += 2;
  }
  if (len == 1)
    sum += *p << 8;  // 
    //sum += *p;  // 
  return sum;
}

uint32_t CalPseudoHeadSum(const struct iphdr* pIpHead, uint8_t type) {
  struct PseudoHead head;
  head.zero = 0;
  head.type = type; 
  head.len = bpf_htons((bpf_ntohs(pIpHead->tot_len) - pIpHead->ihl * 4));
  head.src_ip = pIpHead->saddr;
  head.dst_ip = pIpHead->daddr;
  return CalSum((uint8_t*)&head, sizeof(struct PseudoHead));
}

uint16_t cksumIp(struct iphdr* pIpHead){
  pIpHead->check = 0;
  uint32_t ckSum = CalSum((uint8_t*)pIpHead, pIpHead->ihl * 4);
  ckSum = (ckSum >> 16) + (ckSum & 0xffff);
  ckSum += ckSum >> 16;
  return bpf_htons((uint16_t)~ckSum);
}
uint16_t cksumTcp(struct iphdr* pIpHead, struct tcphdr* pTcpHead){
	
	pTcpHead->check = 0;
	uint32_t ckSum = CalPseudoHeadSum(pIpHead, 0x06);
	ckSum += CalSum((uint8_t*)pTcpHead, 
		bpf_ntohs(pIpHead->tot_len) - pIpHead->ihl * 4);
	ckSum = (ckSum >> 16) + (ckSum & 0xffff);
	ckSum += ckSum >> 16;
	
	return bpf_htons((uint16_t)~ckSum);
	
}


uint16_t csum_fold(uint32_t csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return csum;
}

uint32_t csum_unfold(uint16_t n)
{
	return (uint32_t)n;
}

uint32_t csum_add(uint32_t csum, uint32_t addend)
{
	csum += addend;
	return csum + (csum < addend);
}

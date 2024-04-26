
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#define RETH1 10
#define RETH2 12

struct global_data {
	int action;
	int double_macswap;
};

struct xdp_cpu_stats {
	unsigned long rx_npkts;
	unsigned long tx_npkts;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct xdp_cpu_stats);
	__uint(max_entries, 1);
} xdp_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 32);
} xsks SEC(".maps");

struct global_data global = {0};

SEC("xdp") int handle_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/*
	 * Need to send the at least one packet to user space for busy polling to
	 * work in combined mode.
	 * In pure XDP the redirect will fail and the packet will be sent back.
	 */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){
		struct iphdr *ip = (struct iphdr*)(eth + 1);
		if ((void *)(ip + 1) > data_end) {
			return XDP_ABORTED;
		}
		
		if(ip->protocol == IPPROTO_TCP){

			
			if(ctx->ingress_ifindex == RETH1)
				return bpf_redirect_map(&xsks, 0, XDP_PASS);
			else if (ctx->ingress_ifindex == RETH2)
				//return XDP_PASS;
				return bpf_redirect_map(&xsks, 1, XDP_PASS);
		}
	}
	

	return XDP_PASS;
}

SEC("tc") int handle_tc(struct __sk_buff *skb)
{
	// void *data = (void *)(long)skb->data;
	// void *data_end = (void *)(long)skb->data_end;

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

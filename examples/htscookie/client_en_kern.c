#include "server.h"
#include "address.h"
__u32 max_rtt = 0 ;
char _license[] SEC("license") = "GPL";

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u32);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} rtt_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRY);
        __type(key, struct map_key_t);
        __type(value, struct map_val_t);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack_map SEC(".maps");

// main router logic
SEC("prog") int xdp_router(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct hdr_cursor cur;
    struct ethhdr* eth;
    struct iphdr* ip;
    struct tcphdr* tcp;


    /* Parse header */
    cur.pos = data;
    int ether_proto = parse_ethhdr(&cur,data_end,&eth);
    if(ether_proto == -1) return TC_ACT_SHOT;
    
    if (bpf_htons(ether_proto) == ETH_P_IP) {

        int ip_proto = parse_iphdr(&cur, data_end, &ip);
        if(ip_proto == -1) return TC_ACT_SHOT;
        if(ip_proto == IPPROTO_TCP){
        

            int tcphdr_len = parse_tcphdr(&cur, data_end, &tcp);
            if(tcphdr_len == -1) return TC_ACT_SHOT;
            if(DEBUG){
                __u16* ptr ; 
                ptr = ((void*)tcp) + 12;
                if((void*)ptr + 4 > data_end) return XDP_DROP;
                __u16 tcp_old_flag = *ptr;
                tcp_old_flag = bpf_ntohs(tcp_old_flag);
                tcp_old_flag &= 0x00ff;
                DEBUG_PRINT("TC: TCP packet in, seq = %u, ack = %u, ", bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));
                DEBUG_PRINT("flag = %u, opt_len = %u\n", tcp_old_flag, tcp->doff * 4);
            }
            

            /*  Outbound packet with option */
            if(tcphdr_len >= 32){

                struct tcp_opt_ts* ts;
                int opt_ts_offset = parse_timestamp(&cur,tcp,data_end,&ts);
                if(opt_ts_offset == -1) return TC_ACT_SHOT;

                if(tcp->syn){
                    struct map_key_t key = {
                        .src_ip = ip->daddr,
                        .dst_ip = ip->saddr,
                        .src_port = tcp->dest,
                        .dst_port = tcp->source
                    };
                    struct map_val_t val;
                    val.ts_val_s = ts->tsval;
                    bpf_map_update_elem(&conntrack_map,&key,&val,BPF_ANY);
                }
                else{
                    struct map_key_t key = {
                        .src_ip = ip->daddr,
                        .dst_ip = ip->saddr,
                        .src_port = tcp->dest,
                        .dst_port = tcp->source
                    };
                    struct map_val_t val;
                    struct map_val_t* val_p = bpf_map_lookup_elem(&conntrack_map,&key);
                    if(val_p) {
                        DEBUG_PRINT ("TC: Connection exist in map!\n");
                    }
                    else {
                        DEBUG_PRINT ("TC: Connection not exist in map, Drop!\n");
                        return TC_ACT_SHOT;
                    }
                    // Read val from pinned map;
                    if( bpf_probe_read_kernel(&val,sizeof(val),val_p) != 0){
                        DEBUG_PRINT ("TC: Read map_val fail!\n");
                        return TC_ACT_SHOT;
                    }
                    uint32_t old_tsval = val.ts_val_s;
                    uint32_t new_tsval = val.hybrid_cookie;
                    val.ts_val_s = ts->tsval;
                    ts->tsval = val.hybrid_cookie;
                    uint64_t tcp_csum = tcp->check;
                    tcp_csum = bpf_csum_diff(&old_tsval, 4, &new_tsval, 4, ~tcp_csum);
                    tcp->check = csum_fold_helper_64(tcp_csum);
                }
            }

            
            else{
                /*  TODO: Disable tcp option packets */
            }
        } 
    }
    return TC_ACT_OK;
}

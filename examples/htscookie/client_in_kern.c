#include "server.h"

#define DROPTEST 0
#define DROP_THRESH 5000000



uint8_t init = 0;
static __u16 map_cookies[65536];
static __u32 map_seeds[65536];

char _license[] SEC("license") = "GPL";

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRY);
        __type(key, struct map_key_t);
        __type(value, struct map_val_t);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack_map SEC(".maps");


/*  Main router logic   */
SEC("prog") int xdp_router(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor cur;
    struct ethhdr* eth;
    struct iphdr* ip;
    struct tcphdr* tcp;
    if(!init){
        for(int i = 0; i < 65536 ;i++){
            map_cookies[i] = i;
            map_seeds[i] = i;
        }
        init = 1;
    }

    /*  Parse header   */
    cur.pos = data;
    int ether_proto = parse_ethhdr(&cur,data_end,&eth);
    if(ether_proto == -1)
        return XDP_DROP;
    
    if (bpf_htons(ether_proto) == ETH_P_IP) {

        int ip_proto = parse_iphdr(&cur, data_end, &ip);
        if(ip_proto == -1)
            return XDP_DROP;

        if(ip_proto == IPPROTO_TCP){
            int tcphdr_len = parse_tcphdr(&cur, data_end, &tcp);
            if(tcphdr_len == -1) return XDP_DROP;

            if(tcphdr_len >= 32){ 
                struct tcp_opt_ts* ts;

                if(tcp->ack){
                    int opt_ts_offset = parse_timestamp(&cur,tcp,data_end,&ts);
                    if(opt_ts_offset == -1) return XDP_DROP;
                    struct map_key_t key = {
                            .src_ip = ip->saddr,
                            .dst_ip = ip->daddr,
                            .src_port = tcp->source,
                            .dst_port = tcp->dest
                        };
                    
                    struct map_val_t val ;
                    struct map_val_t* val_p = bpf_map_lookup_elem(&conntrack_map,&key);
                    
                    if(val_p) {
                            DEBUG_PRINT ("SERVER_IN: Connection exist in map!\n");
                        }
                    if( bpf_probe_read_kernel(&val,sizeof(val),val_p) != 0){
                            DEBUG_PRINT ("SERVER_IN: Read map_val fail!\n");
                            return XDP_DROP;
                        }

                    uint32_t new_tsecr = val.ts_val_s;
                    uint32_t old_tsecr = ts->tsecr;
                    val.hybrid_cookie = ts->tsecr;
                    ts->tsecr = val.ts_val_s;
                    bpf_map_update_elem(&conntrack_map, &key, &val, BPF_EXIST);


                    __u64 tcp_csum = tcp->check;
                    tcp_csum = bpf_csum_diff(&old_tsecr, 4, &new_tsecr, 4, ~tcp_csum);
                    tcp->check = csum_fold_helper_64(tcp_csum);

                }

            }
            else{
                /*  TODO: If disable timestamp*/
            }
        }
        /*  Else, not tcp packet just pass*/ 
    }
    return XDP_PASS;
}
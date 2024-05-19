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
            

                /*  Outbound syn-ack from server to client.
                    Convert to ack and send back to server */
                if(tcp->ack && tcp->syn){

                    struct tcp_opt_ts* ts;
                    int opt_ts_offset = parse_timestamp(&cur,tcp,data_end,&ts);
                    if(opt_ts_offset == -1) return TC_ACT_SHOT;

                    
                    DEBUG_PRINT("TC: Update delta = detla(%u) - SYNACK's seg(%u) - 1= %u\n", 
                                val.delta, bpf_htonl(tcp->seq) ,val.delta - (tcp->seq + (bpf_htonl(1))));
                    
                
                    val.delta = val.delta - bpf_ntohl(tcp->seq) - 1;
                    val.ts_val_s = ts->tsval;

                    
                    bpf_map_update_elem(&conntrack_map,&key,&val,BPF_EXIST);
                    tcp->window = bpf_htons(0x1F6); // 502
                
                    ip->saddr ^= ip->daddr;
                    ip->daddr ^= ip->saddr;
                    ip->saddr ^= ip->daddr;


                    tcp->source ^= tcp->dest;
                    tcp->dest ^= tcp->source;
                    tcp->source ^= tcp->dest;
        

                    tcp->seq ^= tcp->ack_seq;
                    tcp->ack_seq ^= tcp->seq;
                    tcp->seq ^= tcp->ack_seq;
                    tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->ack_seq) + 1);
                   
                    
                    ts->tsval ^= ts->tsecr;
                    ts->tsecr ^= ts->tsval;
                    ts->tsval ^= ts->tsecr;
                    if(XDP_DRV)
                        tcp->syn = 0;
                    tcp->check = 0;

                    
                    struct eth_mac_t mac_tmp;
                    __builtin_memcpy(&mac_tmp, eth->h_source, 6);
                    __builtin_memcpy(eth->h_source, eth->h_dest, 6);
                    __builtin_memcpy(eth->h_dest, &mac_tmp, 6);
                    
                    /*  Csum will be calculate after TC, so current csum is wrong
                        must recompute the csum before redirect    */
                    __u64 tcp_csum_tmp = 0;
                    if(((void*)tcp)+ 36 > data_end){
                        return TC_ACT_SHOT;
                    }

                    /*  Use the variable length won't pass varifier, so use const number.
                        Apache2's synack header_len are 36 bits*/
                    ipv4_l4_csum(tcp, 36, &tcp_csum_tmp, ip);
                    tcp->check = tcp_csum_tmp;
                    DEBUG_PRINT("TC: Redirect ACK (from SYNACK) packet back to Ingress interface  \n");
                    return bpf_redirect(SERVER_IF,BPF_F_INGRESS);
                    
                }
                else if (tcp->rst){
                    tcp->seq = bpf_htonl(bpf_ntohl(tcp->seq) + val.delta);
                    bpf_map_update_elem(&conntrack_map,&key,&val,BPF_EXIST);
                }

                /*  For outbound ack, do tcp handover and store the server's
                    timestamp and replace it by hybrid cookie.  */
                else {
                    struct tcp_opt_ts* ts;
                    int opt_ts_offset = parse_timestamp(&cur,tcp,data_end,&ts);
                    if(opt_ts_offset == -1) return TC_ACT_SHOT;
                    
                    /*  Keep observe the max rtt by calculate the the diff of server's ack.
                        If detect cookie changed (by the 2 bits counter), then reset statics.   */
                    uint8_t pkt_cookie_head = (bpf_ntohl(val.hybrid_cookie)) >> 30;
                    uint8_t cur_cookie_head = val.cur_cookie_head;
                    if(cur_cookie_head != pkt_cookie_head){
                        cur_cookie_head = (cur_cookie_head + 1) %4;
                        val.cur_cookie_head = cur_cookie_head;
                        max_rtt = 0;
                    }
                    
                    /*  Calculate rtt   */
                    uint32_t rtt = 0;
                    rtt = bpf_ntohl(ts->tsval) - bpf_ntohl(val.ts_val_s);
                    if(rtt > max_rtt){
                        int zero = 0;
                        max_rtt = rtt;
                        bpf_map_update_elem(&rtt_map,&zero,&rtt,BPF_ANY);
                    }
                    
                    /*  Store server's timestamp and put hybrid cookie  */
                    val.ts_val_s = ts->tsval;
                    ts->tsval = val.hybrid_cookie;

                    /*  Tcp handover   */
                    tcp->seq = bpf_htonl(bpf_ntohl(tcp->seq) + val.delta);
                    bpf_map_update_elem(&conntrack_map,&key,&val,BPF_EXIST);
                    DEBUG_PRINT ("TC: Send out Ack packet seg = %u, ack = %u, delta = %u\n",
                                bpf_ntohl(tcp->seq),bpf_ntohl(tcp->ack_seq), val.delta);
                }
            }

            
            else{
                /*  TODO: Disable tcp option packets */
            }
        } 
    }
    return TC_ACT_OK;
}

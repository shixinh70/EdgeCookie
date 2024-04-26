#include "server.h"
//uint8_t cur_cookie_head = 0;
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
            

                // if SYN-ACK packet (from server)
                // Swap ip address, port, timestamp, mac, and redirect to server_in
                if(tcp->ack && tcp->syn){

                    struct tcp_opt_ts* ts;
                    int opt_ts_offset = parse_timestamp(&cur,tcp,data_end,&ts);
                    if(opt_ts_offset == -1) return TC_ACT_SHOT;

                    //DEBUG_PRINT ("TC: SYNACK packet ingress! csum = %x\n",bpf_ntohs(tcp->check));
                    DEBUG_PRINT("TC: Update delta = detla(%u) - SYNACK's seg(%u) - 1= %u\n", 
                                val.delta, bpf_htonl(tcp->seq) ,val.delta - (tcp->seq + (bpf_htonl(1))));
                    // Modify delta (need to check the byte order problem)
                    
                    val.delta = val.delta - bpf_ntohl(tcp->seq) - 1;
                    val.ts_val_s = ts->tsval;

                    //BPF_EXIST will update an existing element (may have bug)
                    bpf_map_update_elem(&conntrack_map,&key,&val,BPF_EXIST);
                    tcp->window = bpf_htons(0x1F6); // 502
                    // Swap ip
                    ip->saddr ^= ip->daddr;
                    ip->daddr ^= ip->saddr;
                    ip->saddr ^= ip->daddr;

                    // Swap port and convert to ack packet
                    //__u64 tcp_csum = tcp->check;
                    // __u32* ptr ; 
                    // ptr = ((void*)tcp) + 12;
                    // if((void*)ptr + 4 > data_end) return TC_ACT_SHOT;
                       
                    // __u32 tcp_old_flag = *ptr;
                    // tcp->syn = 0;tcp->ack = 1;tcp->ece = 1;
                    // __u32 tcp_new_flag = *ptr;
                    

                    tcp->source ^= tcp->dest;
                    tcp->dest ^= tcp->source;
                    tcp->source ^= tcp->dest;
                    //DEBUG_PRINT("TC: SYNACK seg = %u, ack = %u\n",bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));
                    
                    //__u32 rx_seg = tcp->seq;
                    //__u32 rx_ack = tcp->ack_seq;

                    tcp->seq ^= tcp->ack_seq;
                    tcp->ack_seq ^= tcp->seq;
                    tcp->seq ^= tcp->ack_seq;

                    tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->ack_seq) + 1 );
                    //DEBUG_PRINT("TC: ACK seg = %u, ack = %u\n",bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));

                    // tcp_csum = bpf_csum_diff(&tcp_old_flag, 4, &tcp_new_flag, 4, ~tcp_csum);
                    // tcp_csum = bpf_csum_diff(&rx_seg, 4, &tcp->seq, 4, tcp_csum);
                    // tcp_csum = bpf_csum_diff(&rx_ack, 4, &tcp->ack_seq, 4, tcp_csum);
                    // __u16 tcp_csum_16 = csum_fold_helper_64(tcp_csum) ;
                    // DEBUG_PRINT("%x\n",bpf_htonl(tcp_csum_16));
                    // tcp->check = tcp_csum_16;
                    

                    // Swap tsval and tsecr. Do we need to change the ts order to NOP NOP TS ?
                    
                    ts->tsval ^= ts->tsecr;
                    ts->tsecr ^= ts->tsval;
                    ts->tsval ^= ts->tsecr;
                    tcp->syn = 0;
                    tcp->check = 0;

                    
                    
                    // Swap mac.
                    // OS compute checksum after tc hook.
                    // current tcp.check was wrong, so can't use incremental way to compute,
                    // must recompute.
                    struct eth_mac_t mac_tmp;
                    __builtin_memcpy(&mac_tmp, eth->h_source, 6);
                    __builtin_memcpy(eth->h_source, eth->h_dest, 6);
                    __builtin_memcpy(eth->h_dest, &mac_tmp, 6);
                    



                    // Apache2 SYNACK len 36
                    __u64 tcp_csum_tmp = 0;
                    if(((void*)tcp)+ 36 > data_end){
                        DEBUG_PRINT("TC: DROP!!! if(((void*)tcp)+ 40 > data_end)\n");
                        return TC_ACT_SHOT;
                    } 
                    ipv4_l4_csum(tcp, 36, &tcp_csum_tmp, ip); // Use fixed 36 bytes
                    //DEBUG_PRINT("TC: SYNACK TO ACK! csum = %x\n",bpf_ntohs(tcp_csum_tmp));
                    tcp->check = tcp_csum_tmp;
                    DEBUG_PRINT("TC: Redirect ACK (from SYNACK) packet back to Ingress interface  \n");
                    return bpf_redirect(4,BPF_F_INGRESS);
                    
                }
                else if (tcp->rst){
                    //DEBUG_PRINT("TC:  It's a Reset packet\n");
                    tcp->seq = bpf_htonl(bpf_ntohl(tcp->seq) + val.delta);
                    bpf_map_update_elem(&conntrack_map,&key,&val,BPF_EXIST);
                }

                // if ack packet (server's ack packet)
                // update val.tsval = tsval
                // tsval = cookie (from here, cookie not longer be TS_START, but cookie)
                // Router use TS==cookie to validate ACK packet.
                else {
                    struct tcp_opt_ts* ts;
                    int opt_ts_offset = parse_timestamp(&cur,tcp,data_end,&ts);
                    if(opt_ts_offset == -1) return TC_ACT_SHOT;
                    
                    // If seed had change, the head 2 bits of hybrid_cookie will increase
                    // then reset max_rtt stastics.
                    uint8_t pkt_cookie_head = (bpf_ntohl(val.hybrid_cookie)) >> 30;
                    uint8_t cur_cookie_head = val.cur_cookie_head;
                    if(cur_cookie_head != pkt_cookie_head){
                        //bpf_printk("TC: Detect change seed by cookiehead, max_rtt = %u\n",max_rtt);
                        cur_cookie_head = (cur_cookie_head + 1) %4;
                        val.cur_cookie_head = cur_cookie_head;
                        max_rtt = 0;
                    }
                    // store server's tsval and put hybrid cookie in the tsval
                    uint32_t rtt = 0;
                    rtt = bpf_ntohl(ts->tsval) - bpf_ntohl(val.ts_val_s);
                    if(rtt > max_rtt){
                        int zero = 0;
                        max_rtt = rtt;
                        bpf_map_update_elem(&rtt_map,&zero,&rtt,BPF_ANY);
                    }
                    //bpf_printk("TC: Max Rtt is %u ms\n",max_rtt);
                    
                    val.ts_val_s = ts->tsval;
                    ts->tsval = val.hybrid_cookie;

                    // Modify seq#
                    tcp->seq = bpf_htonl(bpf_ntohl(tcp->seq) + val.delta);
                    bpf_map_update_elem(&conntrack_map,&key,&val,BPF_EXIST);
                    DEBUG_PRINT ("TC: Send out Ack packet seg = %u, ack = %u, delta = %u\n",
                                bpf_ntohl(tcp->seq),bpf_ntohl(tcp->ack_seq), val.delta);
                }
            }

            // tcphdr len < 32
            else{
                //DEBUG_PRINT("TC: No options TCP packet ingress, Foward\n");
            }
        } 
    }
    return TC_ACT_OK;
}

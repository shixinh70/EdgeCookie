#include "server.h"
#include "address.h"

__u32 max_rtt = 0 ;
char _license[] SEC("license") = "GPL";

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_CONNECTION);
        __type(key, struct map_key_t);
        __type(value, struct map_val_t);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack_map_sc SEC(".maps");

// main router logic
SEC("prog") int xdp_router(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct hdr_cursor cur;
    struct ethhdr* eth;
    struct iphdr* ip;
    struct tcphdr* tcp;

    // Parse packet, can be optimize
    cur.pos = data;
    int ether_proto = parse_ethhdr(&cur,data_end,&eth);
    if(ether_proto == -1){
        DEBUG_PRINT("TC: Parse eth fail!, DROP!\n");
        return TC_ACT_SHOT;
    }
    
    if (bpf_htons(ether_proto) == ETH_P_IP) {

        int ip_proto = parse_iphdr(&cur, data_end, &ip);
        if(ip_proto == -1){
            DEBUG_PRINT("TC: Parse ip fail!, DROP!\n");
            return TC_ACT_SHOT;
        } 
        if(ip_proto == IPPROTO_TCP){
        
            int tcphdr_len = parse_tcphdr(&cur, data_end, &tcp);
            if(tcphdr_len == -1){
                DEBUG_PRINT("TC: Parse tcp fail!, DROP!\n");
                return TC_ACT_SHOT;
            }
           
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
            
            struct tcp_opt_ts* ts = NULL;
            if(tcphdr_len > 32){
                int opt_ts_offset = parse_timestamp(&cur,tcp,data_end,&ts);

                if(opt_ts_offset == -1){
                    DEBUG_PRINT("TC: Parse timestamp fail!, DROP!\n");
                    return TC_ACT_SHOT;
                }
                
            }

            //Find the connection data.
            struct map_key_t key = {
                    .src_ip = ip->daddr,
                    .dst_ip = ip->saddr,
                    .src_port = tcp->dest,
                    .dst_port = tcp->source
                };
            struct map_val_t val;
            struct map_val_t* val_p = bpf_map_lookup_elem(&conntrack_map_sc,&key);
            if(val_p) {
                DEBUG_PRINT ("TC: Connection exist in map!\n");
            }
            else {
                DEBUG_PRINT ("TC: Connection not exist in map, Drop!\n");
                return TC_ACT_SHOT;
            }
            // Read val from pinned map;
            if( bpf_probe_read_kernel(&val,sizeof(val),val_p) != 0){
                DEBUG_PRINT ("TC: Read map_val fail!, Drop!\n");
                return TC_ACT_SHOT;
            }
        

            // Synack from server, convert to ack, and update delta
            if(tcp->ack && tcp->syn){
                                
                val.delta = val.delta - bpf_ntohl(tcp->seq) - 1;
                if(ts){
                    val.ts_val_s = ts->tsval;
                    tcp->window = bpf_htons(0x1F6); // 502
                    ts->tsval ^= ts->tsecr;
                    ts->tsecr ^= ts->tsval;
                    ts->tsval ^= ts->tsecr;
                }
                bpf_map_update_elem(&conntrack_map_sc,&key,&val,BPF_EXIST);

                // Swap src and dst
                
                ip->saddr ^= ip->daddr;
                ip->daddr ^= ip->saddr;
                ip->saddr ^= ip->daddr;
                
                tcp->source ^= tcp->dest;
                tcp->dest ^= tcp->source;
                tcp->source ^= tcp->dest;
         
                tcp->seq ^= tcp->ack_seq;
                tcp->ack_seq ^= tcp->seq;
                tcp->seq ^= tcp->ack_seq;

                tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->ack_seq) + 1 );
           
                
                if(XDP_DRV)
                    tcp->syn = 0;
                tcp->check = 0;

                
                
                // Swap mac.
                struct eth_mac_t mac_tmp;
                __builtin_memcpy(&mac_tmp, eth->h_source, 6);
                __builtin_memcpy(eth->h_source, eth->h_dest, 6);
                __builtin_memcpy(eth->h_dest, &mac_tmp, 6);
                

                /*  OS compute checksum after tc hook.
                    current tcp check was wrong, so can't use incremental way to compute,
                    must recompute.*/
                __u64 tcp_csum_tmp = 0;
                
                /*  For the option version, Apache2 synack's header_len = 36
                    and the no option version, will return 20+4 (Mss)*/
                if(ts){
                    if(((void*)tcp)+ 36 > data_end){
                        DEBUG_PRINT("TC: Tcp with options csum fail, Drop!\n");
                        return TC_ACT_SHOT;
                    }
                    ipv4_l4_csum(tcp, 36, &tcp_csum_tmp, ip); 
                }
                else{
                    if(((void*)tcp)+ 24 > data_end){
                        DEBUG_PRINT("TC: Tcp without options csum fail, Drop!\n");
                        return TC_ACT_SHOT;
                    }
                    ipv4_l4_csum(tcp, 24, &tcp_csum_tmp, ip); 
                }
                  
                tcp->check = tcp_csum_tmp;
                return bpf_redirect(SERVER_IF,BPF_F_INGRESS);


                /*  This part always fail, Switch agent won't get the tag packet,
                    and still have no idea to deal with it, and some how we cant 
                direct memory access the packet (write and read) after clone it.   */
            
                // __u16 new_flags_n = bpf_htons(0x6050);  //doff = 6, ECE = 1
                // bpf_skb_store_bytes(skb, 14+20+12, &new_flags_n, sizeof(new_flags_n),0);
                // bpf_skb_store_bytes(skb, 14+12, &pkt_ip_src, sizeof(pkt_ip_src),0);
                // bpf_skb_store_bytes(skb, 14+16, &pkt_ip_dst, sizeof(pkt_ip_dst),0);
            }

            /*  For the outbound ack packet and others, eg. RST, 
                Just handover the seq_num and store the server's 
                timestamp   */
            else {

                // Store server's timestamp
                if(ts){
                    val.ts_val_s = ts->tsval;
                    bpf_map_update_elem(&conntrack_map_sc,&key,&val,BPF_EXIST);

                }

                // Modify seq#
                tcp->seq = bpf_htonl(bpf_ntohl(tcp->seq) + val.delta);
                //ts->tsval = 2;
            }
            
        } 
    }
    return TC_ACT_OK;
}

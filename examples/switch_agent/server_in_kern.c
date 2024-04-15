#include "server.h"
uint64_t init = 0;
__u16 map_cookies[65536] = {0};
__u32 dropcnt = 0;
__u32 hash_seed = 1234;
__u32 testcnt = 0;
char _license[] SEC("license") = "GPL";

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRY);
        __type(key, struct map_key_t);
        __type(value, struct map_val_t);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u32);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} rtt_map SEC(".maps");



#define DROP_THRESH 100
// main router logic
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
        }
        init = 1;
    }
    cur.pos = data;
    int ether_proto ;
    ether_proto = parse_ethhdr(&cur,data_end,&eth);
    if(ether_proto == -1) return XDP_DROP;
    
    if (bpf_htons(ether_proto) == ETH_P_IP) {

        int ip_proto = parse_iphdr(&cur, data_end, &ip);
        if(ip_proto == -1) return XDP_DROP;
        if(ip_proto == IPPROTO_TCP){
            
                
            int tcphdr_len = parse_tcphdr(&cur, data_end, &tcp);
            if(tcphdr_len == -1) return XDP_DROP;




            if(DEBUG){
                __u16* ptr ; 
                ptr = ((void*)tcp) + 12;
                if((void*)ptr + 4 > data_end) return XDP_DROP;
                __u16 tcp_old_flag = *ptr;
                tcp_old_flag = bpf_ntohs(tcp_old_flag);
                tcp_old_flag &= 0x00ff;
                DEBUG_PRINT("SERVER_IN:  TCP packet in, seq = %u, ack = %u, ", bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));
                DEBUG_PRINT("flag = %u, IP_totlen = %u, tcphdr_len = %u\n", 
                            tcp_old_flag, bpf_ntohs(ip->tot_len), tcp->doff * 4);
            }
            if(DROPTEST){
                testcnt ++;
                //bpf_printk("%d\n",testcnt);
                if(testcnt >= DROP_THRESH){
                    //bpf_printk ("SERVER_IN: Start change hash_seed!\n");

                    ip->saddr ^= ip->daddr;
                    ip->daddr ^= ip->saddr;
                    ip->saddr ^= ip->daddr;

                    // tcp->source ^= tcp->dest;
                    // tcp->dest ^= tcp->source;
                    // tcp->source ^= tcp->dest;

                    // Send packet with ECE flag
                    tcp->ece = 1;

                    struct eth_mac_t mac_tmp;
                    __builtin_memcpy(&mac_tmp, eth->h_source, 6);
                    __builtin_memcpy(eth->h_source, eth->h_dest, 6);
                    __builtin_memcpy(eth->h_dest, &mac_tmp, 6);

                    __u32* rtt_p;
                    __u32 zero = 0;
                    rtt_p = bpf_map_lookup_elem(&rtt_map,&zero);
                    if(!rtt_p){
                        DEBUG_PRINT ("SERVER_IN: Look up rtt_map fail!\n");
                        return XDP_DROP;
                    }

                    __u16 cookie_key = MurmurHash2(&ip->saddr,4,hash_seed);
                    //if(cookie_key > 65535) return XDP_DROP;
                    __u16 new_cookie = (bpf_get_prandom_u32() % 0xffff);
                    //if(new_cookie > 65535) return XDP_DROP;
                    map_cookies[cookie_key] = new_cookie;
                    __u32 new_seed = bpf_get_prandom_u32();
                    hash_seed = new_seed;
                    tcp->source = cookie_key;
                     tcp->dest = new_cookie;
                    tcp->seq = new_seed;
                    tcp->ack_seq = *rtt_p;
                    dropcnt = 0;
                    testcnt = 0;
                    cookie_key ++;
                    return XDP_TX;
                    
                }
            }



            
            if(tcphdr_len >= 32){ // Timestamp need 12 byte (Nop Nop timestamp)

                
                struct tcp_opt_ts* ts;
                //DEBUG_PRINT("SERVER_IN: TCP packet (with options) ingress\n");
                // This parse timestamp may can be optimize
                // Switch agent have parse the timestamp so can put the ts type
                // in some un-used header field.
                if(tcp->ack && (!tcp->syn)){
                    int opt_ts_offset = parse_timestamp(&cur,tcp,data_end,&ts);
                    if(opt_ts_offset == -1) return XDP_DROP;   
                    __u32 tsecr = ts->tsecr;
                    void* tcp_header_end = (void*)tcp + (tcp->doff*4);
                    if(tcp_header_end > data_end) return XDP_DROP;
                    // Ack packet which TS == TS_START and no payload (Pass router's cookie check).
                    // Insert new connection 
                    DEBUG_PRINT("tsecr = %d TS_START = %d\n",tsecr, TS_START);
                    if (tsecr == TS_START && (tcp_header_end == data_end)){
                        DEBUG_PRINT("SERVER_IN: Packet tsecr == TS_START, and NO payload, Create conntrack\n");
                        struct map_key_t key = {
                            .src_ip = ip->saddr,
                            .dst_ip = ip->daddr,
                            .src_port = tcp->source,
                            .dst_port = tcp->dest
                        };
                        // struct map_val_t* val = bpf_map_lookup_elem (&conntrack_map, &key);
                        // if(val == NULL) DEBUG_PRINT("No connection in conntrack_map, create new one\n");
                        // else DEBUG_PRINT("Find connection in conntrack_map, update old one\n");
                        // Update and Create val are same function;
                        // Then store the ack for compute ack delta.
                        struct map_val_t val = {.delta = bpf_ntohl(tcp->ack_seq),
                                                .ts_val_s = ts->tsval,
                                                .hash_cookie = bpf_htonl(bpf_ntohl(tcp->ack_seq) - 1)
                                                };
                                         
                        bpf_map_update_elem(&conntrack_map, &key, &val, BPF_ANY);
                        DEBUG_PRINT("SERVER_IN: Update delta = %u\n",val.delta);
                        // Change ACK packet to SYN packet (seq = seq -1 , ack = 0, tsecr = 0);
                        // Store some message for compute TCP csum
                        __u32 old_tcp_seq = tcp->seq;
                        __u32 old_tcp_ack = tcp->ack_seq;
                        __u64 tcp_csum = tcp->check;
                        __u32 old_tcp_tsecr = ts->tsecr;
                        __u32* ptr ; 
                        ptr = ((void*)tcp) + 12;
                       

                        // if(((void*)tcp) + 12 > data_end) return XDP_DROP;
                        // DEBUG_PRINT("ffffffff\n");

                        if((void*)ptr + 4 > data_end) return XDP_DROP;
                       
                        __u32 tcp_old_flag = *ptr;
                        tcp->ack = 0;tcp->syn = 1;
                        __u32 tcp_new_flag = *ptr;

                        tcp->seq -= bpf_htonl(1);
                        tcp->ack_seq = 0;
                        ts->tsecr = 0;
                        
                        //Compute TCP checksum
                        tcp_csum = bpf_csum_diff(&tcp_old_flag, 4, &tcp_new_flag, 4, ~tcp_csum);
                        tcp_csum = bpf_csum_diff(&old_tcp_seq, 4, &tcp->seq, 4, tcp_csum);
                        tcp_csum = bpf_csum_diff(&old_tcp_ack, 4, 0, 0, tcp_csum);
                        tcp_csum = bpf_csum_diff(&old_tcp_tsecr, 4, 0, 0, tcp_csum);
                        tcp->check = csum_fold_helper_64(tcp_csum);

                    }
                    // Packet for transmit data (payload != 0)
                    // If ack packet not use for create connection, modify delta and replace cookie to server' ts 
                    
                    // Packet TSecr == TS_START (client's request) or other ack.
                    else{      
                        DEBUG_PRINT("SERVER_IN: Packet is not used for create connection\n");
                        
                        // Find pin_map (key = 4 turple); Q: key's order?
                        struct map_key_t key = {
                                .src_ip = ip->saddr,
                                .dst_ip = ip->daddr,
                                .src_port = tcp->source,
                                .dst_port = tcp->dest
                            };
                        struct map_val_t val;
                        struct map_val_t* val_p = bpf_map_lookup_elem(&conntrack_map,&key);
                        if(val_p) {
                            DEBUG_PRINT ("SERVER_IN: Connection exist in map!\n");
                        }
                        else {
                            DEBUG_PRINT ("SERVER_IN: Connection not exist in map!\n");
                            dropcnt ++;
                            DEBUG_PRINT ("SERVER_IN: Current dropcnt = %u\\%d \n",dropcnt,DROP_THRESH);

                            // Change seed logic
                            if(0){
                                DEBUG_PRINT ("SERVER_IN: Start change hash_seed!\n");

                                ip->saddr ^= ip->daddr;
                                ip->daddr ^= ip->saddr;
                                ip->saddr ^= ip->daddr;

                                // tcp->source ^= tcp->dest;
                                // tcp->dest ^= tcp->source;
                                // tcp->source ^= tcp->dest;

                                // Send packet with ECE flag
                                tcp->ece = 1;

                                struct eth_mac_t mac_tmp;
                                __builtin_memcpy(&mac_tmp, eth->h_source, 6);
                                __builtin_memcpy(eth->h_source, eth->h_dest, 6);
                                __builtin_memcpy(eth->h_dest, &mac_tmp, 6);

                                __u32* rtt_p;
                                __u32 zero = 0;
                                rtt_p = bpf_map_lookup_elem(&rtt_map,&zero);
                                if(!rtt_p){
                                    DEBUG_PRINT ("SERVER_IN: Look up rtt_map fail!\n");
                                    return XDP_DROP;
                                }
                                __u16 cookie_key = MurmurHash2(&ip->saddr,4,hash_seed);
                                __u16 new_cookie = (bpf_get_prandom_u32() % 0xffff);
                                map_cookies[cookie_key] = new_cookie;
                                __u32 new_seed = bpf_get_prandom_u32();
                                hash_seed = new_seed;
                                tcp->source = cookie_key;
                                tcp->dest = new_cookie;
                                tcp->seq = new_seed;
                                tcp->ack_seq = *rtt_p;
                                dropcnt = 0;
                                return XDP_TX;
                                
                            }
                            return XDP_DROP;
                        }
                        // Read val from pinned map;
                        if( bpf_probe_read_kernel(&val,sizeof(val),val_p) != 0){
                            DEBUG_PRINT ("SERVER_IN: Read map_val fail!\n");
                            return XDP_DROP;
                        }

                        __u32 rx_ack_seq = tcp->ack_seq;
                        __u32 new_ack_seq;
                        __u32 rx_tsecr = ts->tsecr;
                        __u64 tcp_csum = tcp->check;

                        int modify = 0; 
                        if(val.cur_hash_seed != hash_seed){
                            __u32 hybrid_cookie = bpf_ntohl(val.hybrid_cookie);
                            if(val.cur_hash_seed == 0){
                                
                            DEBUG_PRINT("TC: flow.Cur_hash_seed == 0, init hybrid cookie\n");
                            hybrid_cookie = get_hybrid_cookie(val.hash_cookie,ip->saddr,hash_seed);
                            hybrid_cookie &= 0x3fffffff; // mask out leftest 2 bits
                            //hybrid_cookie += 0x40000000; //0100
                            }
                            else{
                                DEBUG_PRINT("TC: Cur hybrid cookie outdated, udpate new map cookie\n");
                                uint32_t new_map_cookie = get_map_cookie(ip->saddr,hash_seed);
                                hybrid_cookie = ((hybrid_cookie & 0xffff0000) | new_map_cookie);
                            }  
                            hybrid_cookie += 0x40000000; //0100
                            val.hybrid_cookie = bpf_htonl(hybrid_cookie);
                            

                            val.cur_hash_seed = hash_seed;
                            modify =1;
                        }

                        new_ack_seq = bpf_htonl(bpf_ntohl(tcp->ack_seq) - val.delta);
                        tcp->ack_seq = new_ack_seq; // Ack delta
                        __u32 new_tsecr = val.ts_val_s;
                        ts->tsecr = new_tsecr; // convert cookie to server's ts_val
                        if(modify)
                            bpf_map_update_elem(&conntrack_map,&key,&val,BPF_EXIST);
                        
                        DEBUG_PRINT("SERVER_IN: Packet (after ack -= delta) seq = %u, ack = %u\n",bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));
                        tcp_csum = bpf_csum_diff(&rx_ack_seq, 4, &new_ack_seq, 4, ~tcp_csum);
                        tcp_csum = bpf_csum_diff(&rx_tsecr, 4, &new_tsecr, 4, tcp_csum);
                        tcp->check = csum_fold_helper_64(tcp_csum);
                        
                    }
                }

                // if synack at server_in, must be redirect synack from server_en
                // conver to ack packet.
                else if(tcp->ack && tcp->syn){

                    
                    __u64 tcp_csum = tcp->check;
                    __u32* ptr ; 

                    ptr = ((void*)tcp) + 12;
                    if((void*)ptr + 4 > data_end) return XDP_DROP;
            
                    __u32 tcp_old_flag = *ptr;
                    tcp->syn = 0;
                    __u32 tcp_new_flag = *ptr;
                    DEBUG_PRINT("SERVER_IN: SYN ACK redirect back to server_in, conver it to ack\n");
                    tcp_csum = bpf_csum_diff(&tcp_old_flag, 4, &tcp_new_flag, 4, ~tcp_csum);
                    tcp->check = csum_fold_helper_64(tcp_csum);
                    
                
                }
            
            }
            else{
                //DEBUG_PRINT("SERVER_IN: No options TCP packet ingress, Foward\n");

            }
        } 
    }
    return XDP_PASS;
}
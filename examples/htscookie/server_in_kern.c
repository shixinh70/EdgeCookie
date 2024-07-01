#include "server.h"

#define DROPTEST 0
#define DROP_THRESH 5000000



uint8_t init = 0;
static __u16 map_cookies[65536];
static __u32 map_seeds[65536];
static __u32 dropcnt ;
static __u32 testcnt ;
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


static inline uint32_t rol(uint32_t word, uint32_t shift){
	return (word<<shift) | (word >> (32 - shift));
}
#define SIPROUND \
	do { \
	v0 += v1; v2 += v3; v1 = rol(v1, 5); v3 = rol(v3,8); \
	v1 ^= v0; v3 ^= v2; v0 = rol(v0, 16); \
	v2 += v1; v0 += v3; v1 = rol(v1, 13); v3 = rol(v3, 7); \
	v1 ^= v2; v3 ^= v0; v2 = rol(v2, 16); \
	} while (0)

static const int c0 = 0x70736575;
static const int c1 = 0x6e646f6d;
static const int c2 = 0x6e657261;
static const int c3 = 0x79746573;


static uint32_t hsiphash(uint32_t src, uint64_t key){
	int key0 = (key >> 32);
    int key1 = key & 0xffffffff;
	//initialization 
	int v0 = c0 ^ key0;
	int v1 = c1 ^ key1;
	int v2 = c2 ^ key0;
	int v3 = c3 ^ key1; 
	
	//first message 
	v3 = v3 ^ bpf_ntohl(src);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ bpf_ntohl(src); 

	//finalization
	v2 = v2 ^ 0xFF; 
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;

	uint32_t hash = (v0^v1)^(v2^v3);
    return hash;
}

static __always_inline __u16 get_hash_cookie(__u32 hash_cookie){
	return (hash_cookie >> 16) ^ (hash_cookie & 0xffff);
}

static __always_inline __u16 get_cookie_key(__u32 ipaddr){

	uint16_t seed_key = ipaddr & 0xffff;
	__u32 cookie_key = hsiphash(ipaddr,map_seeds[seed_key]);
    cookie_key = (cookie_key >> 16) ^ (cookie_key & 0xffff);
    return cookie_key;
}

static __always_inline __u16 get_map_cookie(__u32 ipaddr){
	return get_cookie_key(ipaddr);
}

static __always_inline __u16 set_map_cookie(__u32 ipaddr, __u16 new_cookie){

	__u16 cookie_key = get_cookie_key(ipaddr);
    map_cookies[cookie_key] = new_cookie;
	return new_cookie;
}

static __always_inline __u32 get_hybrid_cookie(__u32 syn_cookie, __u32 ipaddr, __u32 salt){

	__u32 hash_cookie = get_hash_cookie(syn_cookie);
	__u32 map_cookie = get_map_cookie(ipaddr);
	return (hash_cookie << 16) | map_cookie;

}

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

            /*  Test change cookie protocol, if recieve packet > thresh, then start change cookie */
            if(DROPTEST){
                testcnt ++;
                if(testcnt >= DROP_THRESH){
                    //bpf_printk ("SERVER_IN: Start change hash_seed!\n");
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

                 
                    __u16 seed_key = (ip->saddr) & 0xffff;
                    __u16 cookie_key = get_cookie_key(ip->saddr);
                    /*  Generate New map_cookie and map_seed    */
                    __u16 new_cookie = (bpf_get_prandom_u32() & 0xffff);
                    __u32 new_seed = bpf_get_prandom_u32();

                    set_map_cookie(ip->saddr,new_cookie);
                    map_seeds[seed_key] = new_seed;


                    ip->saddr ^= ip->daddr;
                    ip->daddr ^= ip->saddr;
                    ip->saddr ^= ip->daddr;

                    /*  Store new info into some tcp header */
                    tcp->source = cookie_key;
                    tcp->dest = new_cookie;
                    tcp->window = seed_key;
                    tcp->seq = new_seed;
                    tcp->ack_seq = *rtt_p;
                    tcp->ece = 1;
                    testcnt = 0;

                    /* Send to switch_agent*/
                    return XDP_TX;
                }
            }

            /*  Packet with option  */
            if(tcphdr_len >= 32){ 
                struct tcp_opt_ts* ts;

                /*  Inbound ack packets */
                if(tcp->ack && (!tcp->syn)){

                    /*  Parse timestamp */
                    int opt_ts_offset = parse_timestamp(&cur,tcp,data_end,&ts);
                    if(opt_ts_offset == -1) return XDP_DROP;

                    __u32 tsecr = ts->tsecr;
                    void* tcp_header_end = (void*)tcp + (tcp->doff*4);
                    if(tcp_header_end > data_end) return XDP_DROP;


                    /*  Ack packet's timestamp == TS_START, 
                        1. Third ACK of three way handshake
                        2. First request of client  */

                    /*  Situation 1. which has no payload. insert new connection    */
                    if (tsecr == TS_START && (tcp_header_end == data_end) && (!(tcp->fin))){
                        DEBUG_PRINT("SERVER_IN: Packet tsecr == TS_START, and NO payload, Create conntrack\n");
                        struct map_key_t key = {
                            .src_ip = ip->saddr,
                            .dst_ip = ip->daddr,
                            .src_port = tcp->source,
                            .dst_port = tcp->dest
                        };

                        
                        /*  Store ack for later compute delta, and store syncookie  */
                        struct map_val_t val = {.delta = bpf_ntohl(tcp->ack_seq),
                                                .hash_cookie = bpf_htonl(bpf_ntohl(tcp->ack_seq) - 1)
                                                };
                                         
                        bpf_map_update_elem(&conntrack_map, &key, &val, BPF_ANY);
                        DEBUG_PRINT("SERVER_IN: Update delta = %u\n",val.delta);

                        /*  Conver ack to syn  and set proper seq# ack# */
                        __u32 old_tcp_seq = tcp->seq;
                        __u32 old_tcp_ack = tcp->ack_seq;
                        __u64 tcp_csum = tcp->check;
                        __u32 old_tcp_tsecr = ts->tsecr;
                        __u32* flag_ptr ; 
                        __u32 old_win = tcp->window;
                        __u32 new_win = bpf_htons(64240);
                        tcp->window = bpf_htons(64240);

                        flag_ptr = ((void*)tcp) + 12;
                        if((void*)flag_ptr + 4 > data_end) return XDP_DROP;
                       
                        __u32 tcp_old_flag = *flag_ptr;
                        tcp->ack = 0;tcp->syn = 1;
                        __u32 tcp_new_flag = *flag_ptr;

                        tcp->seq = bpf_htonl(bpf_ntohl(tcp->seq)-1);
                        tcp->ack_seq = 0;
                        ts->tsecr = 0;
                        
                        /*  Compute TCP csum    */
                        tcp_csum = bpf_csum_diff(&tcp_old_flag, 4, &tcp_new_flag, 4, ~tcp_csum);
                        tcp_csum = bpf_csum_diff(&old_tcp_seq, 4, &tcp->seq, 4, tcp_csum);
                        tcp_csum = bpf_csum_diff(&old_win, 4, &new_win, 4, tcp_csum);
                        tcp_csum = bpf_csum_diff(&old_tcp_ack, 4, 0, 0, tcp_csum);
                        tcp_csum = bpf_csum_diff(&old_tcp_tsecr, 4, 0, 0, tcp_csum);
                        tcp->check = csum_fold_helper_64(tcp_csum);

                    }

                    /*  Ack Packet transmit data    */
                    else{      
                        DEBUG_PRINT("SERVER_IN: Packet is not used for create connection\n"); 
                        uint16_t seed_key = ip->saddr & 0xffff;
                        struct map_key_t key = {
                                .src_ip = ip->saddr,
                                .dst_ip = ip->daddr,
                                .src_port = tcp->source,
                                .dst_port = tcp->dest
                            };
                        struct map_val_t val;
                        struct map_val_t* val_p = bpf_map_lookup_elem(&conntrack_map,&key);

                        /*  Flow exist */
                        if(val_p) {
                            DEBUG_PRINT ("SERVER_IN: Connection exist in map!\n");
                        }

                        /*  Flow not exist  */
                        else {
                            if(ts->tsecr == TS_START){
                                /*  TODO: Conver ack to syn then insert new connection and doing
                                    handshaking with server */    
                            }
                            else{
                                /*  Malicious ack packet, if packet volumn > thresh, then start change cookie   */
                                DEBUG_PRINT ("SERVER_IN: Connection not exist in map!\n");
                                dropcnt ++;
                                DEBUG_PRINT ("SERVER_IN: Current dropcnt = %u\\%d \n",dropcnt,DROP_THRESH);
                                
                                /*  Change cookie logic */
                                if(dropcnt >= DROP_THRESH){
                                    //bpf_printk ("SERVER_IN: Start change hash_seed!\n");
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

                                
                                    __u16 seed_key = (ip->saddr) & 0xffff;
                                    __u16 cookie_key = get_cookie_key(ip->saddr);
                                    /*  Generate New map_cookie and map_seed    */
                                    __u16 new_cookie = (bpf_get_prandom_u32() & 0xffff);
                                    __u32 new_seed = bpf_get_prandom_u32();

                                    set_map_cookie(ip->saddr,new_cookie);
                                    map_seeds[seed_key] = new_seed;


                                    ip->saddr ^= ip->daddr;
                                    ip->daddr ^= ip->saddr;
                                    ip->saddr ^= ip->daddr;

                                    /*  Store new info into some tcp header */
                                    tcp->source = cookie_key;
                                    tcp->dest = new_cookie;
                                    tcp->window = seed_key;
                                    tcp->seq = new_seed;
                                    tcp->ack_seq = *rtt_p;
                                    tcp->ece = 1;
                                    dropcnt = 0;

                                    /* Send to switch_agent*/
                                    return XDP_TX;
                                }
                            }
                            return XDP_DROP;
                        }
                    
                        /*   Get flow's info    */
                        if( bpf_probe_read_kernel(&val,sizeof(val),val_p) != 0){
                            DEBUG_PRINT ("SERVER_IN: Read map_val fail!\n");
                            return XDP_DROP;
                        }

                        /*  Store old info for csum computation */
                        __u32 rx_ack_seq = tcp->ack_seq;
                        __u32 rx_tsecr = ts->tsecr;
                        __u64 tcp_csum = tcp->check;
                        __u32 new_ack_seq;
                        int modify = 0; 

                        /*  Current flow's hash_seed not sync with global seed  */
                        if(val.cur_hash_seed != map_seeds[seed_key]){
                            __u32 hybrid_cookie = bpf_ntohl(val.hybrid_cookie);

                            /*  Hybrid cookie not init, it should be init by the first request ack packet*/
                            if(val.cur_hash_seed == 0){                                

                                /*  Hybrid cookie = 
                                Low(memory)                              HIGH
                                 ___________________________________________
                                |Ts counter | fold(syncookie) | hash_cookie |
                                |__2__bits__|____14 bits______|___16 bits___|   */

                                hybrid_cookie = get_hybrid_cookie(val.hash_cookie,ip->saddr,map_seeds[seed_key]);
                                hybrid_cookie &= 0x3fffffff; // mask out leftest 2 bits
                            }

                            /*  Hybrid cookie was outdated after change cookie  */
                            else{
                                uint32_t new_map_cookie = get_map_cookie(ip->saddr);
                                if((__s32)new_map_cookie < 0) return XDP_DROP;
                                hybrid_cookie = ((hybrid_cookie & 0xffff0000) | new_map_cookie);
                            }  

                            /*  Make the timestamp incremental   */
                            hybrid_cookie += 0x40000000; 
                            /*  Update cookie info  */
                            val.hybrid_cookie = bpf_htonl(hybrid_cookie);
                            val.cur_hash_seed = map_seeds[seed_key];
                            modify =1;
                        }

                        /*  TCP handover     */
                        new_ack_seq = bpf_htonl(bpf_ntohl(tcp->ack_seq) - val.delta);
                        tcp->ack_seq = new_ack_seq;
                        __u32 new_tsecr = val.ts_val_s;
                        ts->tsecr = new_tsecr; /*   convert ecr to server's ts_val */

                        if(modify)
                            bpf_map_update_elem(&conntrack_map,&key,&val,BPF_EXIST);
                        
                        DEBUG_PRINT("SERVER_IN: Packet (after ack -= delta) seq = %u, ack = %u\n",bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));
                        tcp_csum = bpf_csum_diff(&rx_ack_seq, 4, &new_ack_seq, 4, ~tcp_csum);
                        tcp_csum = bpf_csum_diff(&rx_tsecr, 4, &new_tsecr, 4, tcp_csum);
                        tcp->check = csum_fold_helper_64(tcp_csum);
                        
                    }
                }

                /*  server_en will redirect server's synack to server_in,
                    so convert synack to ack and send to server (only in SKB mode)*/
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
                /*  TODO: If disable timestamp*/
            }
        }
        /*  Else, not tcp packet just pass*/ 
    }
    return XDP_PASS;
}
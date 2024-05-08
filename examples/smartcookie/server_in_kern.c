#include "server.h"


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


const int key0 = 0x33323130;
const int key1 = 0x42413938;
const int c0 = 0x70736575;
const int c1 = 0x6e646f6d;
const int c2 = 0x6e657261;
const int c3 = 0x79746573;

static uint32_t get_hash(uint32_t src, uint32_t dst, uint16_t src_port, uint16_t dst_port){
	
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

	//second message 
	v3 = v3 ^ bpf_ntohl(dst);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ bpf_ntohl(dst); 

	//third message
	uint32_t ports = (uint32_t) dst_port << 16 | (uint32_t) src_port;  
	v3 = v3 ^ bpf_ntohl(ports);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ bpf_ntohl(ports); 

	// //fourth message 
	// v3 = v3 ^ ntohl(seq_no);
	// SIPROUND;
	// SIPROUND;
	// v0 = v0 ^ ntohl(seq_no); 
	
	//finalization
	v2 = v2 ^ 0xFF; 
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;

	uint32_t hash = (v0^v1)^(v2^v3);
        return hash; 	
}


uint8_t init = 0;
__u32 hash_num = 0;
__u16 map_cookies[65536];
__u32 map_seeds[65536];
__u32 dropcnt ;
__u32 hash_seed = 1234;
__u32 testcnt ;
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


static __always_inline __u32 fnv_32_buf(void *buf, size_t len, uint32_t seed)
{
    __u32 hval = seed;//FNV1_32_INIT;
    unsigned char *bp = (unsigned char *)buf;	/* start of buffer */
    unsigned char *be = bp + len;		/* beyond end of buffer */

    /*
     * FNV-1 hash each octet in the buffer
     */
    while (bp < be) {

	/* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
	hval *= FNV_32_PRIME;
#else
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif

	/* xor the bottom with the current octet */
	hval ^= (__u32)*bp++;
    }

    /* return our new hash value */
    return hval;
}



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
            map_seeds[i] = i;
        }
        init = 1;
    }
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

            // Use 
            if(DROPTEST){
                testcnt ++;
                //bpf_printk("%d\n",testcnt);
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
                    uint16_t seed_key = (ip->saddr) & 0xffff;            
                    __u16 cookie_key = fnv_32_buf(&ip->saddr,4,seed_key); 
                    __u16 new_cookie = (bpf_get_prandom_u32() & 0xffff);

                    /*  tricky way to pass varifier, ip should be big endian
                        if want to take ip's most significant 16 bits. 
                        we should mask with 0xffff  */

                    __u32 new_seed = bpf_get_prandom_u32();
                    map_cookies[cookie_key] = new_cookie;
                    map_seeds[seed_key] = new_seed;

                    //hash_seed = new_seed;
                    //DEBUG_PRINT ("SERVER_IN: New hash_seed = %u\n",hash_seed);

                    ip->saddr ^= ip->daddr;
                    ip->daddr ^= ip->saddr;
                    ip->saddr ^= ip->daddr;

                    tcp->source = cookie_key;
                    tcp->dest = new_cookie;
                    tcp->window = seed_key;
                    tcp->seq = new_seed;
                    tcp->ack_seq = *rtt_p;
                    tcp->ece = 1;

                    testcnt = 0;
                    return XDP_TX;
                }
            }

            // Packet with ts option
            
            struct tcp_opt_ts* ts = NULL;

            // if len > 32, parse timestamp to ts
            if(tcphdr_len >= 32){ 
                int opt_ts_offset = parse_timestamp(&cur,tcp,data_end,&ts);
                if(opt_ts_offset == -1) return XDP_DROP;
                
                void* tcp_header_end = (void*)tcp + (tcp->doff*4);
                if(tcp_header_end > data_end) return XDP_DROP;
            }
        
            // if(tcp->ack && (!tcp->syn)){

            //     // Packet have tag and no payload -> the last handshake ack of client
            //     if(tcp->ece && (void*)tcp + (tcp->doff*4) == data_end){
            //         struct map_key_t key = {
            //                 .src_ip = ip->saddr,
            //                 .dst_ip = ip->daddr,
            //                 .src_port = tcp->source,
            //                 .dst_port = tcp->dest
            //             };
            //         struct map_val_t val = {
            //                                 .delta = bpf_ntohl(tcp->ack_seq),
            //                                 //.ts_val_s = ts->tsval,
            //                                 //.hash_cookie = bpf_htonl(bpf_ntohl(tcp->ack_seq) - 1)
            //                                 };
            //         bpf_map_update_elem(&conntrack_map, &key, &val, BPF_ANY);
            //         __u32 old_tcp_seq = tcp->seq;
            //         __u32 old_tcp_ack = tcp->ack_seq;
            //         __u64 tcp_csum = tcp->check;
            //         __u32* flag_ptr ; 
            //         flag_ptr = ((void*)tcp) + 12;
            //         // if(((void*)tcp) + 12 > data_end) return XDP_DROP;
            //         // DEBUG_PRINT("ffffffff\n");

            //         if((void*)flag_ptr + 4 > data_end) return XDP_DROP;
            //         __u32 tcp_old_flag = *flag_ptr;
            //         tcp->ack = 0;tcp->syn = 1;
            //         __u32 tcp_new_flag = *flag_ptr;
            //         tcp->ece = 0;
            //         //tcp->seq -= bpf_htonl(1);
            //         tcp->seq = bpf_htonl(bpf_ntohl(tcp->seq)-1);
            //         tcp->ack_seq = 0;
                    
            //         //Compute TCP checksum
            //         tcp_csum = bpf_csum_diff(&tcp_old_flag, 4, &tcp_new_flag, 4, ~tcp_csum);
            //         tcp_csum = bpf_csum_diff(&old_tcp_seq, 4, &tcp->seq, 4, tcp_csum);
            //         tcp_csum = bpf_csum_diff(&old_tcp_ack, 4, 0, 0, tcp_csum);
            //         if(ts){ 
            //             __u32 old_tcp_tsecr = ts->tsecr;
            //             ts->tsecr = 0;
            //             tcp_csum = bpf_csum_diff(&old_tcp_tsecr, 4, 0, 0, tcp_csum);

            //         }
            //         tcp->check = csum_fold_helper_64(tcp_csum);
            //     }

            //     // The first ack after last handshake ack of client, and not insert bf yet.
            //     else if(tcp->ece && (tcp->doff*4) != data_end){
            //         // check if have connection, if no then create one.
            //     }
                
            //     // Packet pass through bf (might be malicious or benign).
            //     // Might have payload or no
            //     // check if connection, if no then do syncookie check, if pass then create connection.
            //     else{      
            //         struct map_key_t key = {
            //                 .src_ip = ip->saddr,
            //                 .dst_ip = ip->daddr,
            //                 .src_port = tcp->source,
            //                 .dst_port = tcp->dest
            //             };
            //         struct map_val_t val;
            //         struct map_val_t* val_p = bpf_map_lookup_elem(&conntrack_map,&key);
                    
            //         // Connection exist.
            //         if(val_p) {          
            //             // tcphandover
            //             if( bpf_probe_read_kernel(&val,sizeof(val),val_p) != 0){
            //                 DEBUG_PRINT ("SERVER_IN: Read map_val fail!\n");
            //                 return XDP_DROP;
            //             }
            //             __u32 rx_ack_seq = tcp->ack_seq;
            //             __u64 tcp_csum = tcp->check;
            //             __u32 new_ack_seq;
            //             __u32* flag_ptr ; 
            //             flag_ptr = ((void*)tcp) + 12;
            //             if((void*)flag_ptr + 4 > data_end) return XDP_DROP;
                        
                        
            //             new_ack_seq = bpf_htonl(bpf_ntohl(tcp->ack_seq) - val.delta);
            //             tcp->ack_seq = new_ack_seq; // Ack delta
            //             tcp->ece = 0; // won't modify cksum, since switch_agent didn't add it 
                    
            //             DEBUG_PRINT("SERVER_IN: Packet (after ack -= delta) seq = %u, ack = %u\n",bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));
            //             tcp_csum = bpf_csum_diff(&rx_ack_seq, 4, &new_ack_seq, 4, ~tcp_csum);
                
                        
            //             if(ts){
            //                 __u32 rx_tsecr = ts->tsecr;
            //                 __u32 new_tsecr = val.ts_val_s;
            //                 ts->tsecr = new_tsecr; // convert cookie to server's ts_val
            //                 tcp_csum = bpf_csum_diff(&rx_tsecr, 4, &new_tsecr, 4, tcp_csum);
            //             }
                        
            //             tcp->check = csum_fold_helper_64(tcp_csum);

            //         }

            //         // Packet has no connection               
            //         else {

            //             // check syncookie
            //             uint32_t syncookie = get_hash(ip->saddr,ip->daddr,tcp->source,tcp->dest);
            //             if(bpf_htonl(bpf_ntohl(tcp->ack_seq)-1) != syncookie)
            //                 return -1;
                        
            //             else{
            //                 // if no payload, create connection
            //                 if ((void*)tcp + (tcp->doff*4) == data_end){
            //                     struct map_key_t key = {
            //                         .src_ip = ip->saddr,
            //                         .dst_ip = ip->daddr,
            //                         .src_port = tcp->source,
            //                         .dst_port = tcp->dest
            //                     };
            //                     struct map_val_t val = {
            //                         .delta = bpf_ntohl(tcp->ack_seq),
            //                         //.ts_val_s = ts->tsval,
            //                         //.hash_cookie = bpf_htonl(bpf_ntohl(tcp->ack_seq) - 1)
            //                                             };
            //                     bpf_map_update_elem(&conntrack_map, &key, &val, BPF_ANY);
            //                     __u32 old_tcp_seq = tcp->seq;
            //                     __u32 old_tcp_ack = tcp->ack_seq;
            //                     __u64 tcp_csum = tcp->check;
            //                     __u32* flag_ptr ; 
            //                     flag_ptr = ((void*)tcp) + 12;
            //                     // if(((void*)tcp) + 12 > data_end) return XDP_DROP;
            //                     // DEBUG_PRINT("ffffffff\n");

            //                     if((void*)flag_ptr + 4 > data_end) return XDP_DROP;
            //                     __u32 tcp_old_flag = *flag_ptr;
            //                     tcp->ack = 0;tcp->syn = 1;
            //                     __u32 tcp_new_flag = *flag_ptr;
            //                     tcp->ece = 0;
            //                     //tcp->seq -= bpf_htonl(1);
            //                     tcp->seq = bpf_htonl(bpf_ntohl(tcp->seq)-1);
            //                     tcp->ack_seq = 0;
                                
            //                     //Compute TCP checksum
            //                     tcp_csum = bpf_csum_diff(&tcp_old_flag, 4, &tcp_new_flag, 4, ~tcp_csum);
            //                     tcp_csum = bpf_csum_diff(&old_tcp_seq, 4, &tcp->seq, 4, tcp_csum);
            //                     tcp_csum = bpf_csum_diff(&old_tcp_ack, 4, 0, 0, tcp_csum);
            //                     if(ts){ 
            //                         __u32 old_tcp_tsecr = ts->tsecr;
            //                         ts->tsecr = 0;
            //                         tcp_csum = bpf_csum_diff(&old_tcp_tsecr, 4, 0, 0, tcp_csum);

            //                     }
            //                     tcp->check = csum_fold_helper_64(tcp_csum);
            //                 }
                            
            //                 // if has payload, also create connection
            //                 else{
            //                     // todo;
            //                 }
            //             } 
            //         }
            
            //     }
            // }

            // /* server_en will redirect server's synack to server_in (only in skbmode),
            // so convert synack to ack and send to server */
            
            if (tcp->ack && (!tcp->syn)){
                struct map_key_t key = {
                    .src_ip = ip->saddr,
                    .dst_ip = ip->daddr,
                    .src_port = tcp->source,
                    .dst_port = tcp->dest
                };
                struct map_val_t val = {0};
                struct map_val_t* val_p = bpf_map_lookup_elem(&conntrack_map,&key);

                // Exist connection
                if(val_p){

                    //TCP handover
                    if(bpf_probe_read_kernel(&val,sizeof(val),val_p) != 0){
                            DEBUG_PRINT ("SERVER_IN: Read map_val fail!\n");
                            return XDP_DROP;
                        }
                    __u32 rx_ack_seq = tcp->ack_seq;
                    __u64 tcp_csum = tcp->check;
                    __u32 new_ack_seq;
                    __u32* flag_ptr ; 
                    flag_ptr = ((void*)tcp) + 12;
                    if((void*)flag_ptr + 4 > data_end) return XDP_DROP;
                    
                    
                    new_ack_seq = bpf_htonl(bpf_ntohl(tcp->ack_seq) - val.delta);
                    tcp->ack_seq = new_ack_seq; // Ack delta
                    tcp_csum = bpf_csum_diff(&rx_ack_seq, 4, &new_ack_seq, 4, ~tcp_csum);
                    tcp->ece = 0 ;
                    if(ts){
                        __u32 rx_tsecr = ts->tsecr;
                        __u32 new_tsecr = val.ts_val_s;
                        ts->tsecr = new_tsecr; // convert ecr to server's ts_val
                        tcp_csum = bpf_csum_diff(&rx_tsecr, 4, &new_tsecr, 4, tcp_csum);
                    }
                    
                    tcp->check = csum_fold_helper_64(tcp_csum);
                }
                
                // No connetion
                else{
                    if(!tcp->ece){
                        uint32_t syncookie = get_hash(ip->saddr,ip->daddr,tcp->source,tcp->dest);
                        bpf_printk("do hash: %u\n",++hash_num);
                        if(bpf_htonl(bpf_ntohl(tcp->ack_seq)-1) != syncookie){
                            return -1;
                        }
                        else{
                            if((void*)tcp + (tcp->doff*4) != data_end){
                                //TODO: remove all the data.
                                return -1;
                            }
                        }
                    }

                    else{
                        if((void*)tcp + (tcp->doff*4) != data_end){
                            //TODO: remove all the data
                            return -1;
                        }
                    }
                    // create connection and remove all the tag
                    val.delta = bpf_ntohl(tcp->ack_seq);
                    bpf_map_update_elem(&conntrack_map, &key, &val, BPF_ANY);

                    __u32 old_tcp_seq = tcp->seq;
                    __u32 old_tcp_ack = tcp->ack_seq;
                    __u64 tcp_csum = tcp->check;
                    __u32* flag_ptr ; 
                    flag_ptr = ((void*)tcp) + 12;
                    // if(((void*)tcp) + 12 > data_end) return XDP_DROP;
                    // DEBUG_PRINT("ffffffff\n");

                    if((void*)flag_ptr + 4 > data_end) return XDP_DROP;
                    __u32 tcp_old_flag = *flag_ptr;
                    tcp->ack = 0;tcp->syn = 1;
                    __u32 tcp_new_flag = *flag_ptr;
                    tcp->ece = 0;
                    //tcp->seq -= bpf_htonl(1);
                    tcp->seq = bpf_htonl(bpf_ntohl(tcp->seq)-1);
                    tcp->ack_seq = 0;
                    
                    //Compute TCP checksum
                    tcp_csum = bpf_csum_diff(&tcp_old_flag, 4, &tcp_new_flag, 4, ~tcp_csum);
                    tcp_csum = bpf_csum_diff(&old_tcp_seq, 4, &tcp->seq, 4, tcp_csum);
                    tcp_csum = bpf_csum_diff(&old_tcp_ack, 4, 0, 0, tcp_csum);
                    if(ts){ 
                        __u32 old_tcp_tsecr = ts->tsecr;
                        ts->tsecr = 0;
                        tcp_csum = bpf_csum_diff(&old_tcp_tsecr, 4, 0, 0, tcp_csum);

                    }
                    tcp->check = csum_fold_helper_64(tcp_csum);
                }
                
            }

            else if(tcp->ack && tcp->syn){
                __u64 tcp_csum = tcp->check;
                __u32* ptr ; 
                ptr = ((void*)tcp) + 12;
                if((void*)ptr + 4 > data_end) return XDP_DROP;    
                __u32 tcp_old_flag = *ptr;
                tcp->syn = 0;
                __u32 tcp_new_flag = *ptr;
                tcp_csum = bpf_csum_diff(&tcp_old_flag, 4, &tcp_new_flag, 4, ~tcp_csum);
                tcp->check = csum_fold_helper_64(tcp_csum);
            }
        
            else{
                // Other packet
            }
        } 
    }
    return XDP_PASS;
}
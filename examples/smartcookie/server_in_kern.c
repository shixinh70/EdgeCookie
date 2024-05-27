#include "server.h"

__u32 hash_num = 0;

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


char _license[] SEC("license") = "GPL";

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_CONNECTION);
        __type(key, struct map_key_t);
        __type(value, struct map_val_t);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack_map_sc SEC(".maps");


// main router logic
SEC("prog") int xdp_router(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor cur;
    struct ethhdr* eth;
    struct iphdr* ip;
    struct tcphdr* tcp;
   

   /*   Parser header */
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

         
            
            struct tcp_opt_ts* ts = NULL;
            
            if(tcphdr_len >= 32){ 
                int opt_ts_offset = parse_timestamp(&cur,tcp,data_end,&ts);
                DEBUG_PRINT("SERVER IN: Parse timestamp fail!\n");
                if(opt_ts_offset == -1) return XDP_DROP;
                
                void* tcp_header_end = (void*)tcp + (tcp->doff*4);
                DEBUG_PRINT("SERVER IN: Parse timestamp fail!\n");
                if(tcp_header_end > data_end) return XDP_DROP;
            }
        
            /*  For all the ack packet, include ack for create connection,
                client's first request, benign ack and malicious ack. */
            if (tcp->ack && (!tcp->syn)){
                struct map_key_t key = {
                    .src_ip = ip->saddr,
                    .dst_ip = ip->daddr,
                    .src_port = tcp->source,
                    .dst_port = tcp->dest
                };
                struct map_val_t val = {0};
                struct map_val_t* val_p = bpf_map_lookup_elem(&conntrack_map_sc,&key);
                //bpf_printk("SERVER IN: Do map_lookup_elem\n");

                /*  If the flow has already exist, just
                    do the tcp handover, must be benign traffic. */
                if(val_p && (!tcp->ece) && val.state != FIN){

                    if(bpf_probe_read_kernel(&val,sizeof(val),val_p) != 0){
                            DEBUG_PRINT ("SERVER_IN: Read map_val fail!\n");
                            return XDP_DROP;
                        }
                    if(val.state == ONGOING || val.state == ACK_SENT){
                        val.state == ONGOING;
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
                    else if(val.state == SYN_SENT){
                        ip->saddr ^= ip->daddr;
                        ip->daddr ^= ip->saddr;
                        ip->saddr ^= ip->daddr;

                        tcp->source ^= tcp->dest;
                        tcp->dest ^= tcp->source;
                        tcp->source ^= tcp->dest;

                        tcp->ack ^= tcp->ack_seq;
                        tcp->ack_seq ^= tcp->ack;
                        tcp->ack ^= tcp->ack_seq;

                        struct eth_mac_t mac_tmp;
                        __builtin_memcpy(&mac_tmp, eth->h_source, 6);
                        __builtin_memcpy(eth->h_source, eth->h_dest, 6);
                        __builtin_memcpy(eth->h_dest, &mac_tmp, 6);

                        __u32* flag_ptr ; 
                        flag_ptr = ((void*)tcp) + 12;
                   
                        if((void*)flag_ptr + 4 > data_end) return XDP_DROP;
                        __u32 tcp_old_flag = *flag_ptr;
                        tcp->psh = 0;
                        __u32 tcp_new_flag = *flag_ptr;
                        __u64 tcp_csum = tcp->check;
                        tcp_csum = bpf_csum_diff(&tcp_old_flag, 4, &tcp_new_flag, 4, ~tcp_csum);
                        tcp->check = csum_fold_helper_64(tcp_csum);
                        return XDP_TX;
                    }
                }
                
                /*  If no connection exist or has ece tag */
                else{

                    /*  If no tag (not passing switch_agent's syncookie)
                        1. Benign ack for create connection, but collision in bf (false positive)
                        2. Benign ack of the first request, but server_agent not finish the handshaking with server. 
                        3. Malicious ack, and collision in bf (false positive)  */
                    if(!tcp->ece){

                        /*  Check benign or malicious by syncookie  */
                        uint32_t syncookie = get_hash(ip->saddr,ip->daddr,tcp->source,tcp->dest);
                        //bpf_printk("SERVER IN: Do HSIPHASH\n");
                        /* Situation 1  */
                        if(bpf_htonl(bpf_ntohl(tcp->ack_seq)-1) != syncookie){
                            //bpf_printk("SERVER IN: Syncookie fail!\n");
                            return XDP_DROP;
                        }
                        else{

                            /*  Situation 2 */
                            if((void*)tcp + (tcp->doff*4) != data_end){
                                //TODO: remove all the data, current jsut drop.
                                //return XDP_DROP;
                            }
                        }
                    }

                    /*  If tag, means to need to create a new connection between server_agent and server*/
                    else{
                        if((void*)tcp + (tcp->doff*4) != data_end){
                            //TODO: remove all the data, current just drop.
                            //return XDP_DROP;
                        }
                    }

                    /* Create connection and remove the ECE tag */
                    val.delta = bpf_ntohl(tcp->ack_seq);
                    val.state = SYN_SENT;
                    bpf_map_update_elem(&conntrack_map_sc, &key, &val, BPF_ANY);

                    __u32 old_tcp_seq = tcp->seq;
                    __u32 old_tcp_ack = tcp->ack_seq;
                    __u64 tcp_csum = tcp->check;
                    __u32* flag_ptr ; 
                    flag_ptr = ((void*)tcp) + 12;
                   
                    if((void*)flag_ptr + 4 > data_end) return XDP_DROP;
                    __u32 tcp_old_flag = *flag_ptr;
                    tcp->ack = 0;tcp->syn = 1;
                    __u32 tcp_new_flag = *flag_ptr;

                    /*  Don't need to consider the ECE tag change, sicne we didn't
                        modify tcp csum at first time we changed it */
                    tcp->ece = 0;
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

            /*  This syn ack will only rediect by client in the XDP-SKB mode,
                because XDP-SKB will recive the packet redirect by server's TC,
                while the XDP-DRV won't. In XDP-DRV just convert syn-ack to ack
                then redirect to server. */
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
                // Other packets just forward to kernel.
            }
        } 
    }
    DEBUG_PRINT ("SERVER IN : PASS\n");
    return XDP_PASS;
}
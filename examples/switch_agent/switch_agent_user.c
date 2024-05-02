#include "switch_agent.h"

enum action {
	ACTION_REDIRECT,
	ACTION_DROP,
	ACTION_PASS
};

static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;
static enum action opt_action = ACTION_REDIRECT;
static int opt_double_macswap = 0;
struct bpf_object *obj;
struct xsknf_config config;

//uint32_t hash_seed = 1234;
uint32_t change_key_duration = 0;
uint16_t map_cookies[65536];
uint32_t map_seeds[65536];
__u64 client_mac_64 ; 
__u64 server_mac_64 ;
__u64 attacker_mac_64 ;
__u64 client_r_mac_64 ;
__u64 server_r_mac_64 ;
__u64 attacker_r_mac_64 ;

const int key0 = 0x33323130;
const int key1 = 0x42413938;
const int c0 = 0x70736575;
const int c1 = 0x6e646f6d;
const int c2 = 0x6e657261;
const int c3 = 0x79746573;

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

static uint32_t hsiphash(uint32_t src, uint32_t dst, uint16_t src_port, uint16_t dst_port){
	
	//initialization 
	int v0 = c0 ^ key0;
	int v1 = c1 ^ key1;
	int v2 = c2 ^ key0;
	int v3 = c3 ^ key1; 
	
	//first message 
	v3 = v3 ^ ntohl(src);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ ntohl(src); 

	//second message 
	v3 = v3 ^ ntohl(dst);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ ntohl(dst); 

	//third message
	uint32_t ports = (uint32_t) dst_port << 16 | (uint32_t) src_port;  
	v3 = v3 ^ ntohl(ports);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ ntohl(ports); 
	
	//finalization
	v2 = v2 ^ 0xFF; 
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;

	uint32_t hash = (v0^v1)^(v2^v3);
	hash = (hash >> 16) ^ (hash & 0xffff);
    return hash; 	
}



uint64_t MACstoi(unsigned char* str){
    int last = -1;
    unsigned char a[6];
    sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%n",
                    a + 0, a + 1, a + 2, a + 3, a + 4, a + 5,
                    &last);
    return
    (uint64_t)(a[5]) << 40 |
    (uint64_t)(a[4]) << 32 | ( 
        (uint32_t)(a[3]) << 24 | 
        (uint32_t)(a[2]) << 16 |
        (uint32_t)(a[1]) << 8 |
        (uint32_t)(a[0]));
    
}

static inline int forward(struct ethhdr* eth, struct iphdr* ip){

	if (ip->daddr == inet_addr(CLIENT_IP)){
		__builtin_memcpy(eth->h_source, &client_r_mac_64,6);
		__builtin_memcpy(eth->h_dest, &client_mac_64,6);
		

		return CLIENT_R_IF;
	}
	else if (ip->daddr == inet_addr(SERVER_IP)){
		__builtin_memcpy(eth->h_source, &server_r_mac_64,6);
		__builtin_memcpy(eth->h_dest, &server_mac_64,6);
		
		return SERVER_R_IF;
	}
	// TO attacker
	else if (ip->daddr == inet_addr (ATTACKER_IP)){
		__builtin_memcpy(eth->h_source, &attacker_r_mac_64,6);
		__builtin_memcpy(eth->h_dest, &attacker_mac_64,6);
		

		return ATTACKER_R_IF;
	}
	else return -1;
}


static __always_inline __u16 get_map_cookie(__u32 ipaddr){

	uint16_t seed_key = ipaddr & 0xffff;
	__u16 cookie_key = MurmurHash2(&ipaddr,4,map_seeds[seed_key]);
	return map_cookies[cookie_key];
}

// void init_sand(int sand_len){
// 	for(int i=0;i<sand_len/4;i++){
// 		global_salt[i] = rand();
// 	}
// }

void init_global_maps(){
	for(int i=0;i<65536;i++){
		map_cookies[i] = i;
		map_seeds[i] = i; 
	}
}


int xsknf_packet_processor(void *pkt, unsigned *len, unsigned ingress_ifindex)
{
	printf("hehe\n");
	// uint64_t timer = startTimer();
	//struct pkt_5tuple flow = {0};
	void *pkt_end = pkt + (*len);
	struct ethhdr *eth = pkt;
	struct iphdr* ip = (struct iphdr*)(eth +1);
	struct tcphdr* tcp = (struct tcphdr*)(ip +1);
	void* tcp_opt = (void*)(tcp + 1);

	return forward(eth,ip);
	// Back door for enable busy-polling
	if(tcp->syn && tcp->fin){
		return forward(eth,ip);
	}
	
	if(ingress_ifindex == 0){
		struct pkt_5tuple flow = {
			.src_ip = ip->saddr,
			.dst_ip = ip->daddr,
			.src_port = tcp->source,
			.dst_port = tcp->source,
			.sand = {0x728ea123,0x8874adee,0x129033ae,0xff12e561,0x17abc223}
		};

		if(tcp->syn && (!tcp->ack)) {

			// Find out timestamp offset
			struct tcp_opt_ts* ts;
			int opt_ts_offset = parse_timestamp(tcp); 
			if(opt_ts_offset < 0) return -1;
			ts = (tcp_opt + opt_ts_offset);
			if((void*)(ts + 1) > pkt_end){
				return -1;
			}

			// Store rx pkt's tsval, then pur to ts.ecr
			uint32_t rx_tsval = ts->tsval;

			// Remove old tcp option part and replace to common_syn_ack option.
			// Then adjust the packet length
			int delta = (int)(sizeof(struct tcphdr) + sizeof(struct common_synack_opt)) - (tcp->doff*4);
			__u16 old_ip_totlen = ip->tot_len;
			__u16 new_ip_totlen = bpf_htons(bpf_ntohs(ip->tot_len) + delta);
			struct common_synack_opt sa_opt = {
				.MSS = 0x18020402,
				.SackOK = 0x0204,
				.ts.tsval = TS_START,
				.ts.tsecr = rx_tsval,
				.ts.kind = 8,
				.ts.length = 10
			};
			__builtin_memcpy(tcp_opt,&sa_opt,sizeof(struct common_synack_opt));

			// Update length information 
			ip->tot_len = new_ip_totlen;
			tcp->doff += delta/4 ;
			(*len) += delta;

			// Modify iphdr
			ip->saddr ^= ip->daddr;
			ip->daddr ^= ip->saddr;
			ip->saddr ^= ip->daddr;
			
			// since we modify ip.totalen. We need to update ip_csum
			__u32 ip_csum = ~csum_unfold(ip->check);
			ip_csum = csum_add(ip_csum,~old_ip_totlen);
			ip_csum = csum_add(ip_csum,new_ip_totlen);
			ip->check = ~csum_fold(ip_csum);
			
			
			__u32 rx_seq = tcp->seq;

			// Get flow's syncookie (by haraka256)
			// Conver syn packet to synack, and put syncookie
			uint32_t hashcookie = 0;
			if(HARAKA)
				haraka256((uint8_t*)&hashcookie, (uint8_t*)&flow, 4 , 32);
			else
				hsiphash(ip->saddr,ip->daddr,tcp->source,tcp->dest);
			
			tcp->seq = hashcookie;
			tcp->ack_seq = bpf_htonl(bpf_ntohl(rx_seq) + 1);
			tcp->source ^= tcp->dest;
			tcp->dest ^= tcp->source;
			tcp->source ^= tcp->dest;

			tcp->syn = 1;
			tcp->ack = 1;
			tcp->check = cksumTcp(ip,tcp);
			return forward(eth,ip);
		}
		else if(tcp->ack && !(tcp->syn)){
			struct tcp_opt_ts* ts;
			int opt_ts_offset = parse_timestamp(tcp); 
			if(opt_ts_offset < 0) return -1;
			ts = (tcp_opt + opt_ts_offset);
			if((void*)(ts + 1) > pkt_end){
				return -1;
			}
			uint32_t hashcookie = 0;
			// printf("%u\n",map_seeds[(ip->saddr & 0xffff)]);
			// if ts.ecr =TS_START
			// Packet for three way handshake, and client's first request which not receive corresponding ack.
			// Can still use syncookie to validate packet  
			if (ts->tsecr == TS_START){
				if(HARAKA)
					haraka256((uint8_t*)&hashcookie, (uint8_t*)&flow, 4 , 32);
				
				else
					hashcookie = hsiphash(ip->saddr,ip->daddr,tcp->source,tcp->dest);

				if(bpf_htonl(bpf_ntohl(tcp->ack_seq) -1 ) != hashcookie){
					DEBUG_PRINT("Switch agent: Fail syncookie check!\n");
					return -1;
				}
			}
			// Other ack packet. Validate hybrid_cookie
			else{
				uint32_t hybrid_cookie = ntohl(ts->tsecr);
				if(((hybrid_cookie & 0xffff) == get_map_cookie(ip->saddr))){
					DEBUG_PRINT("Switch agent: Pass map_cookie, map cookie = %u, cal_map_cookie = %u\n"
																				,hybrid_cookie & 0xffff
																				,get_map_cookie(ip->saddr) );
				}
				else{
					DEBUG_PRINT("Switch agent: Fail map_cookie, map cookie = %u, cal_map_cookie = %u\n"
																				,hybrid_cookie & 0xffff
																				,get_map_cookie(ip->saddr) );
					if(change_key_duration){
						DEBUG_PRINT("Switch agent: Change seed for %u\n",change_key_duration);
						haraka256((uint8_t*)&hashcookie, (uint8_t*)&flow, 4 , 32);
						hashcookie = (hashcookie >> 16) ^ (hashcookie & 0xffff);
						if(((hybrid_cookie >> 16) & 0x3fff) == (hashcookie & 0x3fff)){
							DEBUG_PRINT("Switch agent: Pass hash_cookie\n");
							//printf("pass hash cookie %u %u %u %u\n",flow.src_ip,flow.dst_ip,flow.src_port,flow.dst_port);
						}
						else{
							//printf("fail hash cookie %u %u %u %u\n",flow.src_ip,flow.dst_ip,flow.src_port,flow.dst_port);
							DEBUG_PRINT("Switch agent: Fail hash_cookie, Drop packet\n");
							return -1;
						}
					}
					else{
						//DEBUG_PRINT("%u\n",change_key_duration);
						DEBUG_PRINT("Switch agent: Drop packet\n");
						return -1;
					}
				}
			}
			return forward(eth,ip);
			
		}
	}

	// Ingress from router eth2 (outbound)
	else{ 
		if(tcp->ece){
			DEBUG_PRINT("Receive change seed packet!\n");
			uint16_t cookie_key = tcp->source;
			uint16_t new_cookie = tcp->dest;
			uint16_t seed_key = tcp->window;
			uint32_t new_hash_seed = tcp->seq;
			map_seeds[seed_key] = new_hash_seed;
			//printf("hash_seed = %u\n",hash_seed);
			change_key_duration = tcp->ack_seq;
			map_cookies[cookie_key] = new_cookie;
			return -1;
		}
	}
	// Other Pass through Router
	return forward(eth,ip);
}


static struct option long_options[] = {
	{"action", required_argument, 0, 'c'},
	{"double-macswap", no_argument, 0, 'd'},
	{"quiet", no_argument, 0, 'q'},
	{"extra-stats", no_argument, 0, 'x'},
	{"app-stats", no_argument, 0, 'a'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [XSKNF_OPTIONS] -- [APP_OPTIONS]\n"
		"  App options:\n"
		"  -c, --action		REDIRECT, DROP packets or PASS to network stack (default REDIRECT).\n"
		"  -d, --double-macswap	Perform a double macswap on the packet.\n"
		"  -q, --quiet		Do not display any stats.\n"
		"  -x, --extra-stats	Display extra statistics.\n"
		"  -a, --app-stats	Display application (syscall) statistics.\n"
		"\n";
	fprintf(stderr, str, prog);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv, char *app_path)
{
	int option_index, c;

	for (;;) {
		c = getopt_long(argc, argv, "c:dqxa", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			if (!strcmp(optarg, "REDIRECT")) {
				opt_action = ACTION_REDIRECT;
			} else if (!strcmp(optarg, "DROP")) {
				opt_action = ACTION_DROP;
			} else if (!strcmp(optarg, "PASS")) {
				opt_action = ACTION_PASS;
			} else {
				fprintf(stderr, "ERROR: invalid action %s\n", optarg);
				usage(basename(app_path));
			}
			break;
		case 'd':
			opt_double_macswap = 1;
			break;
		case 'q':
			opt_quiet = 1;
			break;
		case 'x':
			opt_extra_stats = 1;
			break;
		case 'a':
			opt_app_stats = 1;
			break;
		default:
			usage(basename(app_path));
		}
	}
}

static void int_exit(int sig)
{
	benchmark_done = 1;
}

static void int_usr(int sig)
{
	print_stats(&config, obj);
}

int swich_agent (int argc, char **argv){
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);
	signal(SIGUSR1, int_usr);

	xsknf_parse_args(argc, argv, &config);
	strcpy(config.tc_progname, "handle_tc");
	xsknf_init(&config, &obj);

	parse_command_line(argc, argv, argv[0]);

	if (config.working_mode & MODE_XDP) {
		struct bpf_map *global_map = bpf_object__find_map_by_name(obj,
				"switch_a.bss");
		if (!global_map) {
			fprintf(stderr, "ERROR: unable to retrieve eBPF global data\n");
			exit(EXIT_FAILURE);
		}
		

		int global_fd = bpf_map__fd(global_map), zero = 0;
		if (global_fd < 0) {
			fprintf(stderr, "ERROR: unable to retrieve eBPF global data fd\n");
			exit(EXIT_FAILURE);
		}

		struct global_data global;
		switch (opt_action) {
		case ACTION_REDIRECT:
			global.action = XDP_TX;
			break;
		case ACTION_DROP:
			global.action = XDP_DROP;
			break;
		case ACTION_PASS:
			global.action = XDP_PASS;
			break;
		}
		global.double_macswap = opt_double_macswap;
		if (bpf_map_update_elem(global_fd, &zero, &global, 0)) {
			fprintf(stderr, "ERROR: unable to initialize eBPF global data\n");
			exit(EXIT_FAILURE);
		}
	}

	setlocale(LC_ALL, "");

	init_global_maps();

	//init_sand(20);
	
	client_mac_64 = MACstoi(CLIENT_MAC);
	server_mac_64 = MACstoi(SERVER_MAC);
	attacker_mac_64 = MACstoi(ATTACKER_MAC);
	
	client_r_mac_64 = MACstoi(CLIENT_R_MAC);
	server_r_mac_64 = MACstoi(SERVER_R_MAC);
	attacker_r_mac_64 = MACstoi(ATTACKER_R_MAC);

	//printf("%llx %llx %llx %llx\n ",u1_mac,u2_mac,reth1_mac,reth2_mac);
	load_constants();

	xsknf_start_workers();

	init_stats();
	while (!benchmark_done) {
		if(change_key_duration){
			//printf("Sleep %u ms....\n",change_key_duration);
			struct timespec sleep_time = {0};
			sleep_time.tv_nsec = (change_key_duration + 1) * MSTONS;
			//pthread_mutex_lock(&dutation_key);
			nanosleep(&sleep_time, NULL);
			//printf("wake up\n");
			change_key_duration = 0;
			//pthread_mutex_unlock(&dutation_key);
		}

		sleep(1);
		if (!opt_quiet) {
			dump_stats(config, obj, opt_extra_stats, opt_app_stats);
		}
	}

	xsknf_cleanup();

	return 0;
}

int main(int argc, char **argv){
	swich_agent(argc,argv);
}
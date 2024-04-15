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
struct pkt_5tuple flow ;

uint32_t hash_seed = 1234;
uint32_t change_key_duration = 0;
uint16_t map_cookies[65536];


static inline int redirect_if(int ingress_ifindex, int redirect_ifindex, struct ethhdr* eth){
	if(ingress_ifindex == RETH1){
		__builtin_memcpy(eth->h_source, &reth1_mac,6);
	}
	if(ingress_ifindex == RETH2){
		__builtin_memcpy(eth->h_source, &reth2_mac,6);
	}
	if(redirect_ifindex == RETH1){
		__builtin_memcpy(eth->h_dest, &u1_mac,6);
		return RETH1;
	}
	if(redirect_ifindex == RETH2){
		__builtin_memcpy(eth->h_dest, &u2_mac,6);
		return RETH2;
	}
}

static __always_inline __u16 get_map_cookie(__u32 ipaddr, __u32 salt){
	__u16 key = MurmurHash2(&ipaddr,4,salt);
	return map_cookies[key];
}

void init_sand(int sand_len){
	for(int i=0;i<sand_len;i++){
		flow.sand[i] = rand() & 0xff;
	}
}

void init_hash_cookies(){
	for(int i=0;i<65536;i++){
		map_cookies[i] = i;
	}
}


int xsknf_packet_processor(void *pkt, unsigned *len, unsigned ingress_ifindex)
{
	void *pkt_end = pkt + (*len);
	struct ethhdr *eth = pkt;
	struct iphdr* ip = (struct iphdr*)(eth +1);
	struct tcphdr* tcp = (struct tcphdr*)(ip +1);

	void* tcp_opt = (void*)(tcp + 1);

	if(ingress_ifindex == 0){
		if(tcp->syn && (!tcp->ack)) {
		
			// Store pkt's 5 turple
			flow.src_ip = ip->saddr;
			flow.dst_ip = ip->daddr;
			flow.src_port = tcp->source;
			flow.dst_port = tcp->dest;

			// Find out timestamp offset
			struct tcp_opt_ts* ts;
			int opt_ts_offset = parse_timestamp(tcp); 
			if(opt_ts_offset < 0) return -1;
			ts = (tcp_opt + opt_ts_offset);
			if((void*)(ts + 1) > pkt_end){
				return -1;
			}

			// Store rx pkt's tsval.
			uint32_t rx_tsval = ts->tsval;
			int delta = (int)(sizeof(struct tcphdr) + sizeof(struct common_synack_opt)) - (tcp->doff*4);
			__u16 old_ip_totlen = ip->tot_len;
			__u16 new_ip_totlen = bpf_htons(bpf_ntohs(ip->tot_len) + delta);
			// Replace old option to common syn ack packet's option
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
			
			// Update ip_csum
			
			__u32 ip_csum = ~csum_unfold(ip->check);
			ip_csum = csum_add(ip_csum,~old_ip_totlen);
			ip_csum = csum_add(ip_csum,new_ip_totlen);
			ip->check = ~csum_fold(ip_csum);
			
			
			// Modify tcphdr
			__u32 rx_seq = tcp->seq;

			// Get flow's hash cookie
		
			uint32_t hashcookie = 0;
			haraka256((uint8_t*)&hashcookie, (uint8_t*)&flow, 4 , 32); //Output 256, Input 256
			// hashcooke_32 = hashcookie_256[0] ^ hashcookie_256[1];
			// for(int i = 2; i < 8 ;i++){ 						  //fold to 32bit by xor
			// 	hashcooke_32 ^= hashcookie_256[i];
			// }
			tcp->seq = hashcookie;
			tcp->ack_seq = bpf_htonl(bpf_ntohl(rx_seq) + 1);
			tcp->source ^= tcp->dest;
			tcp->dest ^= tcp->source;
			tcp->source ^= tcp->dest;

			tcp->syn = 1;
			tcp->ack = 1;
			tcp->check = cksumTcp(ip,tcp);
			return redirect_if(ingress_ifindex,RETH1,eth);
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

			// If ts == TS_START  then validate syncookie
			if (ts->tsecr == TS_START){
				flow.src_ip = ip->saddr;
				flow.dst_ip = ip->daddr;
				flow.src_port = tcp->source;
				flow.dst_port = tcp->dest;
				haraka256((uint8_t*)&hashcookie, (uint8_t*)&flow, 4 , 32);
				//DEBUG_PRINT("%d %d\n",bpf_htonl(bpf_ntohl(tcp->ack_seq) -1), hashcookie);
				if(bpf_htonl(bpf_ntohl(tcp->ack_seq) -1 ) != hashcookie){
				DEBUG_PRINT("Switch agent: Fail syncookie check!\n");
					return -1;
				}
			}

			// Validate hybrid_cookie
			else{
				uint32_t hybrid_cookie = ntohl(ts->tsecr);
				if((hybrid_cookie & 0xffff) == get_map_cookie(ip->saddr,hash_seed)){
					DEBUG_PRINT("Switch agent: Pass map_cookie\n");
				}
				else{
					//DEBUG_PRINT("Switch agent: Fail map_cookie\n");
					if(change_key_duration){
						DEBUG_PRINT("Switch agent: Validate hash_cookie\n");
						haraka256((uint8_t*)&hashcookie, (uint8_t*)&flow, 4 , 32);
						hashcookie = (hashcookie >> 16) ^ (hashcookie & 0xffff);
						if(((hybrid_cookie >> 16) & 0x3fff) == (hashcookie & 0x3fff)){
							DEBUG_PRINT("Switch agent: Pass hash_cookie\n");
						}
						else{
							DEBUG_PRINT("Switch agent: Fail hash_cookie\n");
							return -1;
						}
					}
					
				}
				
				
			}
			redirect_if(ingress_ifindex,RETH2,eth);
			
		}
	}

	// Ingress from router eth2 (outbound)
	else{ 
		if(tcp->ece){
			//printf("Receive change seed packet!\n");
			uint16_t cookie_key = tcp->source;
			uint16_t new_cookie = tcp->dest;
			uint32_t new_hash_seed = tcp->seq;
			change_key_duration = tcp->ack_seq;
			
			return -1;
		}
	}
	// Other Pass through Router
	return opt_action == ACTION_DROP ?
		-1 : redirect_if(ingress_ifindex,(ingress_ifindex + 1) % config.num_interfaces,eth);
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

	init_hash_cookies();

	init_sand(20);
	
	load_constants();

	xsknf_start_workers();

	init_stats();

	while (!benchmark_done) {
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
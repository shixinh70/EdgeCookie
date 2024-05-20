#include "switch_agent.h"


static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;
static int opt_drop;
static int opt_pressure;
static int opt_forward;
static int opt_change_key;
static int opt_tcpoption ;
static int opt_add_connection ;

uint32_t drop_num;

struct bpf_object *obj;
struct xsknf_config config;
struct pkt_5tuple flows[16];
struct common_synack_opt sa_opts[16];

bloom_filter* bf_p;
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

uint32_t client_ip;
uint32_t server_ip;
uint32_t attacker_ip;

extern int global_workers_num;

static void init_saopts(){
	for(int i=0; i< global_workers_num;i++){
		sa_opts[i].MSS = 0x18020402;
		sa_opts[i].SackOK = 0x0204;
		sa_opts[i].ts.tsval = 1;
		sa_opts[i].ts.kind = 8;
		sa_opts[i].ts.length = 10;
	}
}
static void init_ip(){
	client_ip = inet_addr (CLIENT_IP);
	server_ip = inet_addr (SERVER_IP);
	attacker_ip = inet_addr (ATTACKER_IP);
}
static void add_bf(){
    int len = 12;
    uint8_t flow[len];
	for(int i =0;i<opt_add_connection;i++){
        for(int j =0 ;j <3; j++){
            int temp = rand();
            memcpy (flow + j*4, &temp, 4);
        }
        // if(i == 7){
        //     printf("%d\n", (flow[0] << 24) + (flow[1] << 16) + (flow[2] << 8) + flow[3]);
        // }
        bloom_filter_put(bf_p,&flow,len);
    }
}
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
    return hash; 	
}
static uint64_t MACstoi(unsigned char* str){
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
static void init_MAC(){
	
	client_mac_64 = MACstoi(CLIENT_MAC);
	server_mac_64 = MACstoi(SERVER_MAC);
	attacker_mac_64 = MACstoi(ATTACKER_MAC);
	
	client_r_mac_64 = MACstoi(CLIENT_R_MAC);
	server_r_mac_64 = MACstoi(SERVER_R_MAC);
	attacker_r_mac_64 = MACstoi(ATTACKER_R_MAC);
}
static __always_inline int forward(struct ethhdr* eth, struct iphdr* ip){
	
	if (ip->daddr == client_ip){
		__builtin_memcpy(eth->h_source, &client_r_mac_64,6);
		__builtin_memcpy(eth->h_dest, &client_mac_64,6);
		

		return CLIENT_R_IF_ORDER;
	}
	else if (ip->daddr == server_ip){
		__builtin_memcpy(eth->h_source, &server_r_mac_64,6);
		__builtin_memcpy(eth->h_dest, &server_mac_64,6);
		
		return SERVER_R_IF_ORDER;
	}
	// TO attacker
	else if (ip->daddr == attacker_ip){
		__builtin_memcpy(eth->h_source, &attacker_r_mac_64,6);
		__builtin_memcpy(eth->h_dest, &attacker_mac_64,6);
		

		return ATTACKER_R_IF_ORDER;
	}
	else return -1;
}



int xsknf_packet_processor(void *pkt, unsigned *len, unsigned ingress_ifindex, unsigned worker_id)
{
	
	if(opt_drop==1){
		return -1;
	}
	bool in_bf = false;
	void *pkt_end = pkt + (*len);
	struct ethhdr *eth = pkt;
    struct iphdr* ip = NULL;
    struct tcphdr* tcp = NULL;

    if(ntohs(eth->h_proto) == ETH_P_IP){
	    ip = (struct iphdr*)(eth +1);
        if (ip->protocol == IPPROTO_TCP){
            tcp = (struct tcphdr*)(ip +1);
        }
    }
    if(!tcp){
        return -1;
    }
   
    struct tcp_opt_ts* ts = NULL;
	void* tcp_opt = (void*)(tcp + 1);

	if(opt_forward){
		// ip->saddr ^= ip->daddr;
		// ip->daddr ^= ip->saddr;
		// ip->saddr ^= ip->daddr;
		return forward(eth,ip);
	}
    if(tcp->doff >=8){
        int opt_ts_offset = 0;
        opt_ts_offset = parse_timestamp(tcp); 
        if(opt_ts_offset < 0) return -1;
        ts = (tcp_opt + opt_ts_offset);
        if((void*)(ts + 1) > pkt_end){
            return -1;
        }
    }
	if(ingress_ifindex == 0){

		flows[worker_id].src_ip = ip->saddr;
	    flows[worker_id].dst_ip = ip->daddr;
		flows[worker_id].src_port = tcp->source;
		flows[worker_id].dst_port = tcp->source;

        
		if(tcp->syn && (!tcp->ack)) {
            __u16 old_ip_totlen = 0;
            __u16 new_ip_totlen = 0;
            int delta = 0;

            // Deal with option
            if(opt_tcpoption && ts){
                // Store rx pkt's tsval, then pur to ts.ecr
                uint32_t rx_tsval = ts->tsval;

                // Remove old tcp option part and replace to common_syn_ack option.
                // Then adjust the packet length
                delta = (int)(sizeof(struct tcphdr) + sizeof(struct common_synack_opt)) - (tcp->doff*4);
                old_ip_totlen = ip->tot_len;
                new_ip_totlen = bpf_htons(bpf_ntohs(ip->tot_len) + delta);


                sa_opts[worker_id].ts.tsecr = rx_tsval;
                /*  ts.tsval should be switch_agent's clock, but access clock will 
                    get very bad performance, so just give a contant*/

                sa_opts[worker_id].ts.tsval = 1; //htonl((uint32_t)clock());
                __builtin_memcpy(tcp_opt,&sa_opts[worker_id],sizeof(struct common_synack_opt));

                // Update length information 
            }

            // turn off all option
            else{
                delta = (int)(sizeof(struct tcphdr)) - (tcp->doff*4);
                old_ip_totlen = ip->tot_len;
                new_ip_totlen = bpf_htons(bpf_ntohs(ip->tot_len) + delta);
            }

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

            uint32_t hashcookie = hsiphash(ip->daddr,ip->saddr,tcp->source,tcp->dest);

            tcp->seq = hashcookie;
            tcp->ack_seq = bpf_htonl(bpf_ntohl(rx_seq) + 1);
            tcp->source ^= tcp->dest;
            tcp->dest ^= tcp->source;
            tcp->source ^= tcp->dest;

            tcp->syn = 1;
            tcp->ack = 1;
           
            tcp->check = cksumTcp(ip,tcp);
            if(opt_pressure == 1)
                return -1;

            return forward(eth,ip);
		}
        
        // if ack, check bf, if no, check syncookie, if pass tag, else drop.
		else if(tcp->ack && !(tcp->syn)){
            
            // If in bloomfilter
            in_bf = bloom_filter_test(bf_p, &flows[worker_id],12);
            if (in_bf)
                return forward(eth,ip);
            
            else{   
                // validate syncookie
                uint32_t syncookie = 0;
                syncookie = hsiphash(ip->saddr,ip->daddr,tcp->source,tcp->dest);
                if(bpf_htonl(bpf_ntohl(tcp->ack_seq) -1 ) != syncookie){
                    //printf("drop: %u\n",++drop_num);
                    return -1;
                }
                tcp->ece = 1; //tag the packet

                // This should be add after receive clone ack packet, but have some bugs.
                bloom_filter_put(bf_p,&flows[worker_id],12);
                return forward(eth,ip);   
            }
		}
	}

	// Ingress from router eth2 (outbound) 
	else{
        // clone Packet sent from server agent.(still fail)
		if(tcp->ece){
            // printf("%u\n",ingress_ifindex);
            // printf("receive ece\n");
            flows[worker_id].src_ip = ip->daddr;
            flows[worker_id].dst_ip = ip->saddr;
            flows[worker_id].src_port = tcp->dest;
            flows[worker_id].dst_port = tcp->source;
            bloom_filter_put(bf_p,&flows[worker_id],4);
            return -1;
        }
        else if (tcp->ack){
            if(ts){
                uint32_t old_ts_val = ts->tsval;
                /*  ts.tsval should be switch_agent's clock, but access clock will 
                    get very bad performance, so just give a contant*/
                ts->tsval =1; //htonl((uint32_t)clock());
                __u32 tcp_csum = ~csum_unfold(tcp->check);
                tcp_csum = csum_add(tcp_csum,~old_ts_val);
                tcp_csum = csum_add(tcp_csum,ts->tsval);
                tcp->check = ~csum_fold(tcp_csum);
            }
        }
	}
	// Other Pass through Router
	return forward(eth,ip);
}


static struct option long_options[] = {
	{"connection", required_argument, 0, 'c'},
    {"option-enable",no_argument, 0, 'o'},
	{"pressure", no_argument, 0, 'p'},
	{"drop", no_argument, 0, 'd'},
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
		"  -c, --connection       <N>, Generate N random flow into bloomfilter.\n"
        "  -o, --option-enable    Deal with all the tcp option.\n"
		"  -p, --pressure         Receive a SYN packet and caculate syncookie then DROP!\n"
		"  -f, --foward           Only foward packet in packet proccessor\n"
		"  -d, --drop             Only drop packet in packet proccessor.\n"
		"  -q, --quiet            Do not display any stats.\n"
		"  -x, --extra-stats      Display extra statistics.\n"
		"  -a, --app-stats        Display application (syscall) statistics.\n"
		"\n";
	fprintf(stderr, str, prog);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv, char *app_path)
{
	int option_index, c;

	for (;;) {
		c = getopt_long(argc, argv, "c:opdqxaf", long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'c':
			opt_add_connection = atoi(optarg);
			break;
        case 'o':
			opt_tcpoption = 1;
			break;	
		case 'p':
			opt_pressure = 1;
			break;		
		case 'd':
			opt_drop = 1;
			break;
		case 'f':
			opt_forward = 1;
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
    srand(SEED);
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
		global.workers_num = global_workers_num;
		global.client_r_if_order = CLIENT_R_IF_ORDER;
        global.server_r_if_order = SERVER_R_IF_ORDER;
        global.attacker_r_if_order = ATTACKER_R_IF_ORDER;
		
		if (bpf_map_update_elem(global_fd, &zero, &global, 0)) {
			fprintf(stderr, "ERROR: unable to initialize eBPF global data\n");
			exit(EXIT_FAILURE);
		}
	}

	setlocale(LC_ALL, "");

    bf_p = bloom_filter_new(3*1024*1024, 3, djb2,sdbm,mm2);
	init_saopts();
	init_MAC();
	init_ip();
	xsknf_start_workers();
    if(opt_add_connection){
        add_bf();
    }
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
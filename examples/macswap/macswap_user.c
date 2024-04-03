#include "macswap.h"
int compareDouble(const void *x, const void *y)
{
  double xx = *(double*)x, yy = *(double*)y;
  if (xx < yy) return -1;
  if (xx > yy) return  1;
  return 0;
}

unsigned long long int startTimer(void)
{
   unsigned a, d;

   __asm__ volatile("CPUID\n\t"
                    "RDTSC\n\t"
                    "mov %%edx, %0\n\t"
                    "mov %%eax, %1\n\t": "=r" (d),
                    "=r" (a):: "%rax", "%rbx", "%rcx", "%rdx");

   return ((unsigned long long)a) | (((unsigned long long)d) << 32);;
}

unsigned long long int endTimer(void)
{
   unsigned a, d;

   __asm__ volatile("RDTSCP\n\t"
                    "mov %%edx, %0\n\t"
                    "mov %%eax,%1\n\t"
                    "CPUID\n\t": "=r" (d), "=r" (a)::
                    "%rax", "%rbx", "%rcx", "%rdx");

   return ((unsigned long long)a) | (((unsigned long long)d) << 32);;
}




static inline __u32 rol(__u32 word, __u32 shift)
{
	return (word << shift) | (word >> (32 - shift));
}

// static uint32_t get_hash(uint32_t src, uint32_t dst, uint16_t src_port, uint16_t dst_port, uint32_t seq_no){
	
// 	//initialization 
// 	int v0 = c0 ^ key0;
// 	int v1 = c1 ^ key1;
// 	int v2 = c2 ^ key0;
// 	int v3 = c3 ^ key1; 
	
// 	//first message 
// 	v3 = v3 ^ ntohl(src);
// 	SIPROUND;
// 	SIPROUND;
// 	v0 = v0 ^ ntohl(src); 

// 	//second message 
// 	v3 = v3 ^ ntohl(dst);
// 	SIPROUND;
// 	SIPROUND;
// 	v0 = v0 ^ ntohl(dst); 

// 	//third message
// 	uint32_t ports = (uint32_t) dst_port << 16 | (uint32_t) src_port;  
// 	v3 = v3 ^ ntohl(ports);
// 	SIPROUND;
// 	SIPROUND;
// 	v0 = v0 ^ ntohl(ports); 

// 	//fourth message 
// 	v3 = v3 ^ ntohl(seq_no);
// 	SIPROUND;
// 	SIPROUND;
// 	v0 = v0 ^ ntohl(seq_no); 
	
// 	//finalization
// 	v2 = v2 ^ 0xFF; 
// 	SIPROUND;
// 	SIPROUND;
// 	SIPROUND;
// 	SIPROUND;

// 	uint32_t hash = (v0^v1)^(v2^v3);
//         return hash; 	
// }



static inline uint32_t CalSum(const uint8_t* buf, int len) {

  uint32_t sum = 0;
  const uint8_t* p = buf;
  
  for(; len > 1; len -= 2) {
    sum += (*p << 8)+ *(p + 1);
    p += 2;
  }
  if (len == 1)
    sum += *p << 8;  // 
    //sum += *p;  // 
  return sum;
}

uint32_t CalPseudoHeadSum(const struct iphdr* pIpHead, uint8_t type) {
  struct PseudoHead head;
  head.zero = 0;
  head.type = type; 
  head.len = bpf_htons((bpf_ntohs(pIpHead->tot_len) - pIpHead->ihl * 4));
  head.src_ip = pIpHead->saddr;
  head.dst_ip = pIpHead->daddr;
  return CalSum((uint8_t*)&head, sizeof(struct PseudoHead));
}

uint16_t cksumIp(struct iphdr* pIpHead){
  pIpHead->check = 0;
  uint32_t ckSum = CalSum((uint8_t*)pIpHead, pIpHead->ihl * 4);
  ckSum = (ckSum >> 16) + (ckSum & 0xffff);
  ckSum += ckSum >> 16;
  return htons((uint16_t)~ckSum);
}


uint16_t cksumTcp(struct iphdr* pIpHead, struct tcphdr* pTcpHead){
	
	pTcpHead->check = 0;
	uint32_t ckSum = CalPseudoHeadSum(pIpHead, 0x06);
	ckSum += CalSum((uint8_t*)pTcpHead, 
		ntohs(pIpHead->tot_len) - pIpHead->ihl * 4);
	ckSum = (ckSum >> 16) + (ckSum & 0xffff);
	ckSum += ckSum >> 16;
	
	return htons((uint16_t)~ckSum);
	
}


void load_constants() {
  rc[0] = _mm_set_epi32(0x0684704c,0xe620c00a,0xb2c5fef0,0x75817b9d);
  rc[1] = _mm_set_epi32(0x8b66b4e1,0x88f3a06b,0x640f6ba4,0x2f08f717);
  rc[2] = _mm_set_epi32(0x3402de2d,0x53f28498,0xcf029d60,0x9f029114);
  rc[3] = _mm_set_epi32(0x0ed6eae6,0x2e7b4f08,0xbbf3bcaf,0xfd5b4f79);
  rc[4] = _mm_set_epi32(0xcbcfb0cb,0x4872448b,0x79eecd1c,0xbe397044);
  rc[5] = _mm_set_epi32(0x7eeacdee,0x6e9032b7,0x8d5335ed,0x2b8a057b);
  rc[6] = _mm_set_epi32(0x67c28f43,0x5e2e7cd0,0xe2412761,0xda4fef1b);
  rc[7] = _mm_set_epi32(0x2924d9b0,0xafcacc07,0x675ffde2,0x1fc70b3b);
  rc[8] = _mm_set_epi32(0xab4d63f1,0xe6867fe9,0xecdb8fca,0xb9d465ee);
  rc[9] = _mm_set_epi32(0x1c30bf84,0xd4b7cd64,0x5b2a404f,0xad037e33);
  rc[10] = _mm_set_epi32(0xb2cc0bb9,0x941723bf,0x69028b2e,0x8df69800);
  rc[11] = _mm_set_epi32(0xfa0478a6,0xde6f5572,0x4aaa9ec8,0x5c9d2d8a);
  rc[12] = _mm_set_epi32(0xdfb49f2b,0x6b772a12,0x0efa4f2e,0x29129fd4);
  rc[13] = _mm_set_epi32(0x1ea10344,0xf449a236,0x32d611ae,0xbb6a12ee);
  rc[14] = _mm_set_epi32(0xaf044988,0x4b050084,0x5f9600c9,0x9ca8eca6);
  rc[15] = _mm_set_epi32(0x21025ed8,0x9d199c4f,0x78a2c7e3,0x27e593ec);
  rc[16] = _mm_set_epi32(0xbf3aaaf8,0xa759c9b7,0xb9282ecd,0x82d40173);
  rc[17] = _mm_set_epi32(0x6260700d,0x6186b017,0x37f2efd9,0x10307d6b);
  rc[18] = _mm_set_epi32(0x5aca45c2,0x21300443,0x81c29153,0xf6fc9ac6);
  rc[19] = _mm_set_epi32(0x9223973c,0x226b68bb,0x2caf92e8,0x36d1943a);
  rc[20] = _mm_set_epi32(0xd3bf9238,0x225886eb,0x6cbab958,0xe51071b4);
  rc[21] = _mm_set_epi32(0xdb863ce5,0xaef0c677,0x933dfddd,0x24e1128d);
  rc[22] = _mm_set_epi32(0xbb606268,0xffeba09c,0x83e48de3,0xcb2212b1);
  rc[23] = _mm_set_epi32(0x734bd3dc,0xe2e4d19c,0x2db91a4e,0xc72bf77d);
  rc[24] = _mm_set_epi32(0x43bb47c3,0x61301b43,0x4b1415c4,0x2cb3924e);
  rc[25] = _mm_set_epi32(0xdba775a8,0xe707eff6,0x03b231dd,0x16eb6899);
  rc[26] = _mm_set_epi32(0x6df3614b,0x3c755977,0x8e5e2302,0x7eca472c);
  rc[27] = _mm_set_epi32(0xcda75a17,0xd6de7d77,0x6d1be5b9,0xb88617f9);
  rc[28] = _mm_set_epi32(0xec6b43f0,0x6ba8e9aa,0x9d6c069d,0xa946ee5d);
  rc[29] = _mm_set_epi32(0xcb1e6950,0xf957332b,0xa2531159,0x3bf327c1);
  rc[30] = _mm_set_epi32(0x2cee0c75,0x00da619c,0xe4ed0353,0x600ed0d9);
  rc[31] = _mm_set_epi32(0xf0b1a5a1,0x96e90cab,0x80bbbabc,0x63a4a350);
  rc[32] = _mm_set_epi32(0xae3db102,0x5e962988,0xab0dde30,0x938dca39);
  rc[33] = _mm_set_epi32(0x17bb8f38,0xd554a40b,0x8814f3a8,0x2e75b442);
  rc[34] = _mm_set_epi32(0x34bb8a5b,0x5f427fd7,0xaeb6b779,0x360a16f6);
  rc[35] = _mm_set_epi32(0x26f65241,0xcbe55438,0x43ce5918,0xffbaafde);
  rc[36] = _mm_set_epi32(0x4ce99a54,0xb9f3026a,0xa2ca9cf7,0x839ec978);
  rc[37] = _mm_set_epi32(0xae51a51a,0x1bdff7be,0x40c06e28,0x22901235);
  rc[38] = _mm_set_epi32(0xa0c1613c,0xba7ed22b,0xc173bc0f,0x48a659cf);
  rc[39] = _mm_set_epi32(0x756acc03,0x02288288,0x4ad6bdfd,0xe9c59da1);
}

void haraka256(unsigned char *out, const unsigned char *in, int outlen, int inlen) {

	__m128i s[2], tmp;

	s[0] = LOAD(in);
	s[1] = LOAD(in + 16);

	AES2(s[0], s[1], 0);
	MIX2(s[0], s[1]);

	AES2(s[0], s[1], 4);
	MIX2(s[0], s[1]);

	AES2(s[0], s[1], 8);
	MIX2(s[0], s[1]);

	AES2(s[0], s[1], 12);
	MIX2(s[0], s[1]);

	AES2(s[0], s[1], 16);
	MIX2(s[0], s[1]);

	s[0] = _mm_xor_si128(s[0], LOAD(in));
	s[1] = _mm_xor_si128(s[1], LOAD(in + 16));
//   STORE(out, s[0]);
//   STORE(out + 16, s[1]);
	s[0] = _mm_xor_si128(s[0],s[1]); // xor 256 to 128;
	uint64_t tmp64 = _mm_extract_epi64(s[0], 0) ^ _mm_extract_epi64(s[0], 1);
	uint32_t tmp32 = (tmp64 >> 32) ^ (tmp64 & 0xffff); 
  
   //uint64_t second64 = _mm_extract_epi64(s[0], 1);
//   first64 ^= second64;
//   uint32_t first32 = (uint32_t)(first64 >> 32);
//   uint32_t second32 = (uint32_t)(first64 & 0x0000ffff);
//   first32 ^= second32;
	*((uint32_t*)out) = tmp32;
  // printf("%d\n", tmp32);
}

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


__u32 parse_timestamp(struct tcphdr *tcp)
{
	void* tcp_opt = (void*)(tcp + 1);
	int opt_ts_offset = -1;
	void *opt_end = (void *)tcp + (tcp->doff * 4);

	__u64 *tcp_opt_64 = (__u64 *)tcp_opt;
	if((void*)(tcp_opt_64 + 1) > opt_end){
		DEBUG_PRINT("tcp_opt_64 + 1 > opt_end\n");
		return -1;
	}
	if (tcp->syn && !tcp->ack){
		// Mask: MSS(4B), SackOK(2B), Timestamp(1B)
		if ((syn_1_mask & *tcp_opt_64) == syn_1_mask){
			DEBUG_PRINT("Match Mss, SackOK, Timestamp\n");
			return 6;
			
		}
		else
		{
			__u32 *tcp_opt_32 = (__u32*)(tcp_opt_64 + 1);
			if((void*)(tcp_opt_32 + 1) > opt_end){
				DEBUG_PRINT("tcp_opt_32 + 1 > opt_end\n");
				return -1;
			}
			if ((syn_2_mask_1 & *tcp_opt_64) == syn_2_mask_1){
				if ((syn_2_mask_2 & *tcp_opt_32) == syn_2_mask_2){	
					return 10;
				}
			}
			else if ((syn_3_mask_1 & *tcp_opt_64) == syn_3_mask_1){
				if ((syn_3_mask_2 & *tcp_opt_32) == syn_3_mask_2){
					return 10;
				}
			}
		}
	}
	else if (tcp->ack && !tcp->syn){
		if ((ack_1_mask & *tcp_opt_64) == ack_1_mask){
			return 2;
		}
	}

	else /*SYNACK*/{
		if ((synack_1_mask & *tcp_opt_64) == synack_1_mask){
			return 2;
		}
		else{
			__u32 *tcp_opt_32 = (__u32*)(tcp_opt_64 + 1);
			if((void*)(tcp_opt_32 + 1) > opt_end){
				DEBUG_PRINT("tcp_opt_32 + 1 > opt_end\n");
				return -1;
			}
			if ((synack_2_mask_1 & *tcp_opt_64) == synack_2_mask_1){
				if ((synack_2_mask_2 & *tcp_opt_32) == synack_2_mask_2){
					return 10;
				}
			}
			else if ((synack_3_mask & *tcp_opt_64) == synack_3_mask){
				if ((syn_3_mask_2 & *tcp_opt_32) == syn_3_mask_2){
					return 6;
				}
			}
			else if ((synack_4_mask_1 & *tcp_opt_64) == synack_4_mask_1){
				if ((synack_4_mask_2 & *tcp_opt_32) == synack_4_mask_2){
					return 10;
				}
			}
		}
	}

	
	DEBUG_PRINT("Slow path match timestamp\n");
	__u8 *opt = (__u8 *)tcp_opt;
	volatile __u8 opt_len;

	for (int i = 0; i < 40;  i++){
		if ((void*)(opt + 1) > opt_end){
			DEBUG_PRINT("No timestamp and reach opt_end or data_end\n");
			return -1;
		}
		if (*opt == 0){
			DEBUG_PRINT("No timestamp and reach end of list\n");
			return -1;
		}
		if (*opt == 1){
			// Find NOP(1B) continued;
			opt++;
			continue;
		}
		// option_type(1B) option length(1B) option
		if ((void*)(opt + 2) > opt_end){
			return -1;
		}

		opt_len = *(opt + 1);

		// option 2 ---> MSS(4B)
		if (*opt != 8){
			opt += opt_len;
		}
		else/*match timestamp*/{
			opt_ts_offset = (void *)opt - (void *)(tcp_opt);
			return opt_ts_offset;
		}
	}
	return opt_ts_offset;
}


static inline uint16_t csum_fold(uint32_t csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return csum;
}

static inline uint32_t csum_unfold(uint16_t n)
{
	return (uint32_t)n;
}

static inline uint32_t csum_add(uint32_t csum, uint32_t addend)
{
	csum += addend;
	return csum + (csum < addend);
}

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

void init_sand(int sand_len){
	for(int i=0;i<sand_len;i++){
		flow.sand[i] = rand() & 0xff;
	}
}

int xsknf_packet_processor(void *pkt, unsigned *len, unsigned ingress_ifindex)
{
	void *pkt_end = pkt + (*len);
	struct ethhdr *eth = pkt;
	struct iphdr* ip = (struct iphdr*)(eth +1);
	struct tcphdr* tcp = (struct tcphdr*)(ip +1);
	void* tcp_opt = (void*)(tcp + 1);
	if(tcp->syn && (!tcp->ack)) {

		// Store pkt's 5 turple
		flow.src_ip = ip->saddr;
		flow.dst_ip = ip->daddr;
		flow.seq = tcp->seq;
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
		uint32_t hashcookie_256[8] = {0};
		uint32_t hashcooke_32 = 0;

		
		haraka256((uint8_t*)hashcookie_256, (uint8_t*)&flow, 32 , 4); //Output 256, Input 256
		// hashcooke_32 = hashcookie_256[0] ^ hashcookie_256[1];
		// for(int i = 2; i < 8 ;i++){ 						  //fold to 32bit by xor
		// 	hashcooke_32 ^= hashcookie_256[i];
		// }
		
		tcp->seq = hashcooke_32;
		tcp->ack_seq = bpf_htonl(bpf_ntohl(rx_seq) + 1);
		tcp->source ^= tcp->dest;
		tcp->dest ^= tcp->source;
		tcp->source ^= tcp->dest;

		tcp->syn = 1;
		tcp->ack = 1;
		tcp->check = cksumTcp(ip,tcp);
		return redirect_if(ingress_ifindex,RETH1,eth);
	}
	
	return opt_action == ACTION_DROP ?
			-1 : (ingress_ifindex + 1) % config.num_interfaces;
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
				"macswap_.bss");
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
		// uint64_t timer = startTimer();
		// for(int i =0;i<1000;i++){
		// 	bpf_map_lookup_elem(global_fd,)
		// }
	}

	setlocale(LC_ALL, "");

	init_sand(16);
	
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


#define NUM_TIMINGS 1000
#define ITERATIONS 100000
uint32_t MurmurHash2 ( const void * key, int len, uint32_t seed )
{
  /* 'm' and 'r' are mixing constants generated offline.
     They're not really 'magic', they just happen to work well.  */

  const uint32_t m = 0x5bd1e995;
  const int r = 24;

  /* Initialize the hash to a 'random' value */

  uint32_t h = seed ^ len;

  /* Mix 4 bytes at a time into the hash */

  const unsigned char * data = (const unsigned char *)key;

  while(len >= 4)
  {
    uint32_t k = *(uint32_t*)data;

    k *= m;
    k ^= k >> r;
    k *= m;

    h *= m;
    h ^= k;

    data += 4;
    len -= 4;
  }

  /* Handle the last few bytes of the input array  */

  switch(len)
  {
  case 3: h ^= data[2] << 16;
  case 2: h ^= data[1] << 8;
  case 1: h ^= data[0];
      h *= m;
  };

  /* Do a few final mixes of the hash to ensure the last few
  // bytes are well-incorporated.  */

  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;

  return h;
}

void mm2_perf(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	uint32_t  h = MurmurHash2 (in, inlen, 0);
	*((uint32_t*)out) = h;
}

void tcp_cksum_perf(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	struct iphdr* ip = (struct iphdr*)in;
	struct tcphdr* tcp = (struct tcphdr*)(ip+1);
	uint16_t cksum = cksumTcp(ip,tcp);
	*((uint16_t*)out) = cksum;
	
}
void hsiphash_perf(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	
	const int key0 = in[0];
	const int key1 = in[1];
	const int c0 = 0x70736575;
	const int c1 = 0x6e646f6d;
	const int c2 = 0x6e657261;
	const int c3 = 0x79746573;

	uint32_t *ptr = (uint32_t *)in;
	//initialization 
	int v0 = c0 ^ key0;
	int v1 = c1 ^ key1;
	int v2 = c2 ^ key0;
	int v3 = c3 ^ key1; 
	
	//first message 
	v3 = v3 ^ ntohl(*ptr);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ ntohl(*ptr); 

	//second message 
	v3 = v3 ^ ntohl(*(ptr+1));
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ ntohl(*(ptr+1)); 

	//third message
	  
	v3 = v3 ^ ntohl(*(ptr+2));
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ ntohl(*(ptr+2)); 

	//fourth message 
	v3 = v3 ^ ntohl(*(ptr+3));
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ ntohl(*(ptr+3)); 
	
	//finalization
	v2 = v2 ^ 0xFF; 
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;

	uint32_t hash = (v0^v1)^(v2^v3);
	*((uint32_t*)out) = hash;
    //__builtin_memcpy(out,&hash,4);
}

typedef void (*hash_function)(unsigned char*, const unsigned char*, int outlen, int inlen);
double timeit(hash_function func, int inlen, int outlen) {
	unsigned char *in, *out;
	unsigned long long timer = 0;
	double timings[NUM_TIMINGS];

	int i, j;
	srand(0);

	in = malloc(inlen);
	out = malloc(outlen);

	struct iphdr* ip = (struct iphdr*)in;
	struct tcphdr* tcp = (struct tcphdr*)(ip+1);
	struct common_synack_opt* sa = (struct common_synack_opt*)(tcp+1);
	
	

	load_constants();

	for (i = -100; i < NUM_TIMINGS; i++) {
	//Get random input
		for (j = 0; j < inlen; j++) {
			in[j] = rand() & 0xff;
		}

		if(inlen>=56){
			ip->tot_len = ntohs((uint16_t)inlen);
			ip->ihl = 5;
			sa->ts.kind = 8;
		}
		
		timer = startTimer();
		for(j = 0; j < ITERATIONS; j++) {
			func(out, in, outlen, inlen);
		}
		timer = endTimer() - timer;

		if (i >= 0 && i < NUM_TIMINGS) {
			timings[i] = ((double)timer) / ITERATIONS;
		}
	}

	//Get Median
	qsort(timings, NUM_TIMINGS, sizeof(double), compareDouble);
	free(out);
	free(in);
	return timings[NUM_TIMINGS / 2];
}

void perf(){
	printf("Haraka-256: %f cycles \n", timeit(haraka256, 32, 4));
	printf("Hsiphash: %f cycles \n", timeit(hsiphash_perf,16 ,4));
	printf("tcp_cksum_perf: %f cycles \n", timeit(tcp_cksum_perf, 56, 2));
	printf("MurMur2: %f cycles \n", timeit(mm2_perf, 4, 4));
	  	
}
int main(int argc, char **argv){
	perf();
}
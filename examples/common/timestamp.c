#include "timestamp.h"


const uint64_t syn_1_mask = 0x0008000400000002;
const uint64_t syn_2_mask_1 = 0x0000070100000002;
const uint32_t syn_2_mask_2 = 0x08010100;
const uint64_t syn_3_mask_1 = 0x0000070100000002;
const uint32_t syn_3_mask_2 = 0x08000400;
const uint64_t ack_1_mask = 0x000000000080101;
const uint64_t synack_1_mask = ack_1_mask;
const uint64_t synack_2_mask_1 = syn_2_mask_1;
const uint32_t synack_2_mask_2 = syn_3_mask_2;
const uint64_t synack_3_mask = 0x0008010100000004;
const uint64_t synack_4_mask_1 = syn_2_mask_1;
const uint32_t synack_4_mask_2 = syn_2_mask_2;


__u32 parse_timestamp(struct tcphdr *tcp)
{
	
	void* tcp_opt = (void*)(tcp + 1);
	int opt_ts_offset = -1;
	void *opt_end = (void *)tcp + (tcp->doff * 4);

	__u64 *tcp_opt_64 = (__u64 *)tcp_opt;
	if((void*)(tcp_opt_64 + 1) > opt_end){
		//DEBUG_PRINT("tcp_opt_64 + 1 > opt_end\n");
		return -1;
	}
	if (tcp->syn && !tcp->ack){
		// Mask: MSS(4B), SackOK(2B), Timestamp(1B)
		if ((syn_1_mask & *tcp_opt_64) == syn_1_mask){
			//DEBUG_PRINT("Match Mss, SackOK, Timestamp\n");
			return 6;
			
		}
		else
		{
			__u32 *tcp_opt_32 = (__u32*)(tcp_opt_64 + 1);
			if((void*)(tcp_opt_32 + 1) > opt_end){
				//DEBUG_PRINT("tcp_opt_32 + 1 > opt_end\n");
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
				//DEBUG_PRINT("tcp_opt_32 + 1 > opt_end\n");
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

	
	//DEBUG_PRINT("Slow path match timestamp\n");
	__u8 *opt = (__u8 *)tcp_opt;
	volatile __u8 opt_len;

	for (int i = 0; i < 40;  i++){
		if ((void*)(opt + 1) > opt_end){
			//DEBUG_PRINT("No timestamp and reach opt_end or data_end\n");
			return -1;
		}
		if (*opt == 0){
			//DEBUG_PRINT("No timestamp and reach end of list\n");
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


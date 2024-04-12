#include "hsiphash.h"


static inline uint32_t rol(uint32_t word, uint32_t shift){
	return (word << shift) | (word >> (32 - shift));
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
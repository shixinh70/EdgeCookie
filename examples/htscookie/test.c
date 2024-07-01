#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <memory.h>
#include "fnv.h"
#include "haraka.h"
#include "murmur.h"
#include "crc32.h"

#define ROUND 1000
#define NUM_TIMINGS 10000
#define ITERATIONS 10000

enum modes {
    MSB16,
    LSB16,
    XOR,
    MODES_END
};
enum modes mode;

#include <stdint.h>

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
	__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define _le64toh(x) ((uint64_t)(x))
#elif defined(_WIN32)
/* Windows is always little endian, unless you're on xbox360
   http://msdn.microsoft.com/en-us/library/b0084kay(v=vs.80).aspx */
#  define _le64toh(x) ((uint64_t)(x))
#elif defined(__APPLE__)
#  include <libkern/OSByteOrder.h>
#  define _le64toh(x) OSSwapLittleToHostInt64(x)
#else

/* See: http://sourceforge.net/p/predef/wiki/Endianness/ */
#  if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#    include <sys/endian.h>
#  else
#    include <endian.h>
#  endif
#  if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && \
	__BYTE_ORDER == __LITTLE_ENDIAN
#    define _le64toh(x) ((uint64_t)(x))
#  else
#    define _le64toh(x) le64toh(x)
#  endif

#endif


#define ROTATE(x, b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define HALF_ROUND(a,b,c,d,s,t)			\
	a += b; c += d;				\
	b = ROTATE(b, s) ^ a;			\
	d = ROTATE(d, t) ^ c;			\
	a = ROTATE(a, 32);

#define DOUBLE_ROUND(v0,v1,v2,v3)		\
	HALF_ROUND(v0,v1,v2,v3,13,16);		\
	HALF_ROUND(v2,v1,v0,v3,17,21);		\
	HALF_ROUND(v0,v1,v2,v3,13,16);		\
	HALF_ROUND(v2,v1,v0,v3,17,21);


uint64_t siphash24(const void *src, unsigned long src_sz, uint32_t key) {
	
	uint64_t k0 = 0x77859091aff27184ULL;
	uint64_t k1 = 0x8192471092ffca12ULL;
	uint64_t b = (uint64_t)src_sz << 56;
	const uint64_t *in = (uint64_t*)src;

	uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
	uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
	uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
	uint64_t v3 = k1 ^ 0x7465646279746573ULL;

	while (src_sz >= 8) {
		uint64_t mi = _le64toh(*in);
		in += 1; src_sz -= 8;
		v3 ^= mi;
		DOUBLE_ROUND(v0,v1,v2,v3);
		v0 ^= mi;
	}

	uint64_t t = 0; uint8_t *pt = (uint8_t *)&t; uint8_t *m = (uint8_t *)in;
	switch (src_sz) {
	case 7: pt[6] = m[6];
	case 6: pt[5] = m[5];
	case 5: pt[4] = m[4];
	case 4: *((uint32_t*)&pt[0]) = *((uint32_t*)&m[0]); break;
	case 3: pt[2] = m[2];
	case 2: pt[1] = m[1];
	case 1: pt[0] = m[0];
	}
	b |= _le64toh(t);

	v3 ^= b;
	DOUBLE_ROUND(v0,v1,v2,v3);
	v0 ^= b; v2 ^= 0xff;
	DOUBLE_ROUND(v0,v1,v2,v3);
	DOUBLE_ROUND(v0,v1,v2,v3);
	return (v0 ^ v1) ^ (v2 ^ v3);
}


#define SIPROUND          \
	do                    \
	{                     \
		v0 += v1;         \
		v2 += v3;         \
		v1 = rol(v1, 5);  \
		v3 = rol(v3, 8);  \
		v1 ^= v0;         \
		v3 ^= v2;         \
		v0 = rol(v0, 16); \
		v2 += v1;         \
		v0 += v3;         \
		v1 = rol(v1, 13); \
		v3 = rol(v3, 7);  \
		v1 ^= v2;         \
		v3 ^= v0;         \
		v2 = rol(v2, 16); \
	} while (0)

static inline uint32_t rol(uint32_t word, uint32_t shift){
	return (word << shift) | (word >> (32 - shift));
}
int compareDouble(const void *x, const void *y){
  double xx = *(double*)x, yy = *(double*)y;
  if (xx < yy) return -1;
  if (xx > yy) return  1;
  return 0;
}
unsigned long long int startTimer(void){
   unsigned a, d;

   __asm__ volatile("CPUID\n\t"
                    "RDTSC\n\t"
                    "mov %%edx, %0\n\t"
                    "mov %%eax, %1\n\t": "=r" (d),
                    "=r" (a):: "%rax", "%rbx", "%rcx", "%rdx");

   return ((unsigned long long)a) | (((unsigned long long)d) << 32);;
}
unsigned long long int endTimer(void){
   unsigned a, d;

   __asm__ volatile("RDTSCP\n\t"
                    "mov %%edx, %0\n\t"
                    "mov %%eax,%1\n\t"
                    "CPUID\n\t": "=r" (d), "=r" (a)::
                    "%rax", "%rbx", "%rcx", "%rdx");

   return ((unsigned long long)a) | (((unsigned long long)d) << 32);;
}

typedef void (*hash_function_time)(unsigned char*, const unsigned char*, int outlen, int inlen);
double timeit(char* name, hash_function_time func, int inlen, int outlen) {
	unsigned char *in, *out;
	unsigned long long timer = 0;
	double timings[NUM_TIMINGS];

	int i, j;
	srand(0);

	in = malloc(inlen);
	out = malloc(outlen);

	load_constants();

	for (i = -100; i < NUM_TIMINGS; i++) {
	//Get random input
		for (j = 0; j < inlen; j++) {
			in[j] = rand() & 0xff;
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
    double midian = ((double)timer) / ITERATIONS;
    printf("%s : Need %lf cycles, median of %d times, each times %d iters\n",
            name, midian, NUM_TIMINGS, ITERATIONS );

	return timings[NUM_TIMINGS / 2];
}
unsigned long djb2(unsigned char *str, int len, uint32_t seed)
    {
        //5381
        unsigned long hash = seed;
        int c;

        while(len--){
            (c = *str++);
            hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
        }

        return hash;
    }
unsigned long djb2a(unsigned char *str, int len, uint32_t seed)
    {
        //5381
        unsigned long hash = seed;
        int c;

        while(len--){
            (c = *str++);
            hash = ((hash << 5) + hash) ^ c; /* hash * 33 + c */
        }

        return hash;
    }
long sdbm(unsigned char *str, int len, uint32_t seed) 
    {
        unsigned long hash = seed;
        int c;

        while(len--){
            (c = *str++);
            hash = c + (hash << 6) + (hash << 16) - hash;
        }
            

        return hash;
    }
long sdbma(unsigned char *str, int len, uint32_t seed) 
    {
        unsigned long hash = seed;
        int c;

        while(len--){
            (c = *str++);
            hash = c + (hash << 6) ^ (hash << 16) - hash;
        }
            

        return hash;
    }

typedef uint32_t (*hash_function)(const void* key,int len, uint32_t seed);
void hash_distribution(char* name,hash_function func){
    uint32_t array[65536] = {0};
    uint64_t cnt = 0 ;
    uint64_t cnt2 = 0;
    srand(time(NULL));
    uint32_t seeds[ROUND] = {0};
    uint32_t ms16b[ROUND] = {0};
    char text[][10] = {"MSB16","LSB16","XOR"};

    for(uint32_t i =0;i<ROUND;i++){
        seeds[i] = rand();
        ms16b[i] = rand() & 0xffff0000;
    }
    for(int m = MSB16; m<MODES_END; m++){
        for(uint32_t i=0;i<ROUND;i++){
            for(uint32_t j= 0;j<65536;j++){
                uint32_t k = ms16b[i]+j;
                uint32_t h = func((uint8_t*)&k,4,seeds[i]);
                if(m==XOR)
                    h = ((h>>16)^(h&0xffff)); // xor msb16 and lsb16
                else if(m==LSB16)    
                    h = (h&0xffff); // take lsb16
                else if(m==MSB16)
                    h = (h>>16); // take msb16
                else{
                    printf("Error: No define MSB16, LSB16, XOR\n");
                    exit(1);
                }
                if(array[h] == 0){
                    cnt++;
                }
                else{
                    cnt2++;
                }
                array[h] ++;
            }
            memset(array,0,sizeof(array));
        }
        printf("%s-%-10sdistribution: not col=%-10lu col=%-10lu, col_rate=%-10lf\n",\
                name, text[m], cnt, cnt2, (double)cnt2/(cnt+cnt2));
        cnt = 0; cnt2 =0;
    }
        
}

static __always_inline uint32_t djb2_perf ( const void * key, int len, uint32_t seed ){
    return djb2((uint8_t*)key,len,seed);
}
static __always_inline uint32_t djb2a_perf ( const void * key, int len, uint32_t seed ){
        return djb2a((uint8_t*)key, len,seed);
}
static __always_inline uint32_t sdbm_perf ( const void * key, int len, uint32_t seed ){
        
        return sdbm((uint8_t*)key,len,seed);

}
static __always_inline uint32_t sdbma_perf ( const void * key, int len, uint32_t seed ){
        return sdbma((uint8_t*)key,len,seed);

}
static __always_inline uint32_t fnv1_perf ( const void * key, int len, uint32_t seed ){
        return fnv_32_buf((uint8_t*)key,len,seed);

}
static __always_inline uint32_t fnv1a_perf ( const void * key, int len, uint32_t seed ){
        
        return fnv_32a_buf((uint8_t*)key,len, seed);
}

static __always_inline uint32_t crc_perf ( const void * key, int len, uint32_t seed ){
    return xcrc32(key,len,seed);
}
static __always_inline uint32_t siphash24_perf ( const void * key, int len, uint32_t seed ){
    return siphash24(key,len,seed);
}

void crc_perf_time ( unsigned char* out, const unsigned char* in, int outlen, int inlen ){
    (*(uint32_t*)out) = xcrc32((uint8_t*)&in,inlen,0xffff);
}
void mm2_perf_time(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	*((uint32_t*)out) = MurmurHash2 (in, inlen, 0);
	
}
void mm3_perf_time(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	*((uint32_t*)out) = murmurhash3 (in, inlen, 0);
	
}
void djb2_perf_time(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	*((uint32_t*)out) = djb2_perf(in, inlen, 0);
}
void djb2a_perf_time(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	*((uint32_t*)out) = djb2a_perf(in, inlen, 0);
}
void sdbm_perf_time(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	*((uint32_t*)out) = sdbm_perf(in, inlen, 0);
}
void sdbma_perf_time(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	*((uint32_t*)out) = sdbma_perf(in, inlen, 0);
}
void fnv1_perf_time(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	*((uint32_t*)out) = fnv1_perf(in, inlen, 0);
}
void fnv1a_perf_time(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	*((uint32_t*)out) = fnv1a_perf(in, inlen, 0);
}
void hsiphash_perf_time(unsigned char* out, const unsigned char* in, int outlen, int inlen){
	
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
	
    for(int i=0;i<(inlen/4);i++){
        v3 = v3 ^ (*(ptr+i));
        SIPROUND;
        SIPROUND;
        v0 = v0 ^ (*(ptr+i)); 
    }

	// //first message 
	// v3 = v3 ^ (*ptr);
	// SIPROUND;
	// SIPROUND;
	// v0 = v0 ^ (*ptr); 

	// //second message 
	// v3 = v3 ^ (*(ptr+1));
	// SIPROUND;
	// SIPROUND;
	// v0 = v0 ^ (*(ptr+1)); 

	// //third message
	  
	// v3 = v3 ^ (*(ptr+2));
	// SIPROUND;
	// SIPROUND;
	// v0 = v0 ^ (*(ptr+2)); 

	// //fourth message 
	// v3 = v3 ^ (*(ptr+3));
	// SIPROUND;
	// SIPROUND;
	// v0 = v0 ^ (*(ptr+3)); 
	
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
void siphash24_perf_time(unsigned char* out, const unsigned char* in, int outlen, int inlen){
    *((uint32_t*)out) = siphash24_perf(in, inlen, 0);
}
void graph(){
    srand(0x1234);
    uint32_t ms16bit = (rand()&0xffff0000);
    
    for(uint32_t i=0;i<65536;i++){
        uint32_t k = i | ms16bit;
        uint32_t h = crc_perf(&k,4,2);
        h = (h>>16);
        printf("%d ",h);
    }
}
#define N 10
void test(){
    uint64_t target = 0x1234;
    uint64_t ips[N] = {0};

    for(int i=0;i<N;i++){
        ips[i] = i;
    }

    uint64_t salt = rand() & 0xffffffff;
    uint8_t buffer[32] = {0};
    uint64_t target_and_salt = (target << 32) | salt;
    memcpy(&buffer,&target_and_salt,8);
    uint32_t ret;
    haraka256((uint8_t*)&ret,(uint8_t*)&buffer,4,4);
    ret = (ret>>16)^(ret&0xffff);
    

    for(uint64_t r_salt = 0; r_salt < UINT32_MAX;r_salt++){
        uint32_t tmp = 0;
        uint64_t target_and_salt_r = (target << 32) | r_salt;
        memcpy(&buffer,&target_and_salt_r,8);
        haraka256((uint8_t*)&tmp,(uint8_t*)&buffer,4,4);
        tmp = (tmp>>16)^(tmp&0xffff);
        if(tmp == ret){
            //printf("bingo!\n");
            
            int c = 0;
            for(int i = 0 ;i<N;i++){
                uint32_t tmp1 = 0;
                uint64_t new_target_and_salt = (ips[i] << 32) | r_salt;
                memcpy(&buffer,&new_target_and_salt,8);
                haraka256((uint8_t*)&tmp1,(uint8_t*)&buffer,4,4);
                tmp1 = (tmp1>>16)^(tmp1&0xffff);
                //printf("%d %d\n",tmp1,ret);
                if(tmp1==ret){
                    printf("bingo! c=%d i=%d salt = %ld salt_r = %ld\n",++c,i,salt,r_salt);
                }
            }
        }

    }
}
int main(){
	load_constants();
    test();
    // test();
    // hash_distribution("djb2",djb2_perf);
    // hash_distribution("djb2a",djb2a_perf);
    // hash_distribution("sdbm",sdbm_perf);
    // hash_distribution("sdbma",sdbma_perf);
    // hash_distribution("fnvla",fnv1a_perf);
    // hash_distribution("fnvl",fnv1_perf);
    // hash_distribution("murmur3",murmurhash3);
    // hash_distribution("murmur2",MurmurHash2);
    // hash_distribution("crc32",crc_perf);
    
    // timeit ("haraka256",haraka256,32,32);

    // timeit ("crc32",crc_perf_time,4,4);
    // timeit ("murmur2",mm2_perf_time,4,4);
    // timeit ("murmur3",mm3_perf_time,4,4);
    // timeit ("djb2",djb2_perf_time,4,4);
    // timeit ("djb2a",djb2a_perf_time,4,4);
    // timeit ("sdbm",sdbm_perf_time,4,4);
    // timeit ("sdbma",sdbma_perf_time,4,4);
    // timeit ("fnv1",fnv1_perf_time,4,4);
    // timeit ("fnv1a",fnv1a_perf_time,4,4);
    // timeit ("hsiphash",hsiphash_perf_time,12,4);
    // timeit ("siphash24",siphash24_perf_time,12,4);
    //graph();

}
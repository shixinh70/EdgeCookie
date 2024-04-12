#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define NUM_TIMINGS 10000
#define ITERATIONS 10000


unsigned long long int startTimer(void);
unsigned long long int endTimer(void);
typedef void (*hash_function)(unsigned char*, const unsigned char*, int outlen, int inlen);
double timeit(hash_function func, int inlen, int outlen);
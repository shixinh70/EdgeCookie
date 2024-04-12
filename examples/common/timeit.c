#include "timeit.h"




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

double timeit(hash_function func, int inlen, int outlen) {
	unsigned char *in, *out;
	unsigned long long timer = 0;
	double timings[NUM_TIMINGS];

	int i, j;
	srand(0);

	in = malloc(inlen);
	out = malloc(outlen);


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
	return timings[NUM_TIMINGS / 2];
}
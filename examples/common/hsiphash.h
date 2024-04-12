#pragma once
#include <stdint.h>
static inline uint32_t rol(uint32_t word, uint32_t shift);
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


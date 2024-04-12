/**
 * `murmurhash.h' - murmurhash
 *
 * copyright (c) 2014-2022 joseph werle <joseph.werle@gmail.com>
 */

#ifndef MURMURHASH_H
#define MURMURHASH_H

#include <stdint.h>

#define MURMURHASH_VERSION "0.1.0"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns a murmur hash of `key' based on `seed'
 * using the MurmurHash3 algorithm
 */

uint32_t murmurhash3 (const void * key, int len, uint32_t seed);
uint32_t MurmurHash2 ( const void * key, int len, uint32_t seed );

#ifdef __cplusplus
}
#endif

#endif
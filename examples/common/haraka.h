/*
Optimized Implementations for Haraka256 and Haraka512
*/
#ifndef HARAKA_H_
#define HARAKA_H_

#include "immintrin.h"
#include <stdio.h>
#include <stdint.h>


void load_constants();

// Return resault of haraka256 and fold 256 bit to 32 bit with xor
void haraka256(unsigned char *out, const unsigned char *in, int inlen, int outlen);



#endif
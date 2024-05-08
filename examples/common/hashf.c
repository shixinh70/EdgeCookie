#include "hashf.h"

uint32_t djb2(const void *buff, size_t length) {
    uint32_t hash = DJB2_INIT;
    const uint8_t *data = buff;
    for(size_t i = 0; i < length; i++) {
         hash = ((hash << 5) + hash) + data[i]; 
    }
    return hash;
}
uint32_t sdbm(const void *buff, size_t length) {
    uint32_t hash = 0;
    const uint8_t *data = buff;
    for(size_t i = 0; i < length; i++) {
        hash = data[i] + (hash << 6) + (hash << 16) - hash;
    }
    return hash;
}

uint32_t mm2 (const void * buff, size_t length){
    const uint32_t m = 0x5bd1e995;
    const int r = 24;
    uint32_t h = 0xffee;
    const unsigned char * data = (const unsigned char *)buff;
    while(length >= 4){
        uint32_t k = *(uint32_t*)data;
        k *= m;
        k ^= k >> r;
        k *= m;
        h *= m;
        h ^= k;
        data += 4;
        length -= 4;
    } 
    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;
    return h;
}
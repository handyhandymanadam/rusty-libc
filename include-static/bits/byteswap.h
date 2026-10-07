#ifndef _BITS_BYTESWAP_H
#define _BITS_BYTESWAP_H 1
#include <stdint.h>
#define __bswap_constant_16(x) ((uint16_t) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))
#define __bswap_constant_32(x) __builtin_bswap32 (x)
#define __bswap_constant_64(x) __builtin_bswap64 (x)
static __inline uint16_t __bswap_16 (uint16_t __bsx) { return __builtin_bswap16 (__bsx); }
static __inline uint32_t __bswap_32 (uint32_t __bsx) { return __builtin_bswap32 (__bsx); }
static __inline uint64_t __bswap_64 (uint64_t __bsx) { return __builtin_bswap64 (__bsx); }
#endif

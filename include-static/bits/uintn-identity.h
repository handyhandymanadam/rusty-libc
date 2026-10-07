#ifndef _BITS_UINTN_IDENTITY_H
#define _BITS_UINTN_IDENTITY_H 1
#include <stdint.h>
static __inline uint16_t __uint16_identity (uint16_t __x) { return __x; }
static __inline uint32_t __uint32_identity (uint32_t __x) { return __x; }
static __inline uint64_t __uint64_identity (uint64_t __x) { return __x; }
#endif

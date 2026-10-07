#ifndef _ALLOCA_H
#define _ALLOCA_H 1
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
extern void *alloca (size_t __size) __attribute__ ((__nothrow__));
#ifdef __cplusplus
}
#endif
#ifdef __GNUC__
# undef alloca
# define alloca(size) __builtin_alloca (size)
#endif
#endif

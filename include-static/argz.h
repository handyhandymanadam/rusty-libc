#ifndef _RLIBC_ARGZ_H
#define _RLIBC_ARGZ_H 1

#include <stddef.h>
#include <string.h>

#ifndef __error_t_defined
# define __error_t_defined 1
typedef int error_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-argzcalls.h>

extern size_t __argz_count (const char *__argz, size_t __len);
extern void __argz_stringify (char *__argz, size_t __len, int __sep);
extern char *__argz_next (const char *__argz, size_t __argz_len, const char *__entry);
#ifdef __cplusplus
}
#endif

#endif

#ifndef _SYS_PERM_H
#define _SYS_PERM_H 1
#include <features.h>
#ifdef __cplusplus
extern "C" {
#endif

extern int ioperm (unsigned long int __from, unsigned long int __num, int __turn_on) __attribute__ ((__nothrow__));
extern int iopl (int __level) __attribute__ ((__nothrow__));

#ifdef __cplusplus
}
#endif
#endif

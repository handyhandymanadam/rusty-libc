#ifndef _RLIBC_MCHECK_H
#define _RLIBC_MCHECK_H 1

#include <bits/rlibc-features.h>

#ifdef __cplusplus
extern "C" {
#endif

enum mcheck_status {
  MCHECK_DISABLED = -1,
  MCHECK_OK,
  MCHECK_FREE,
  MCHECK_HEAD,
  MCHECK_TAIL
};

extern int mcheck (void (*__abortfunc)(enum mcheck_status)) __attribute__ ((__nothrow__));
extern int mcheck_pedantic (void (*__abortfunc)(enum mcheck_status)) __attribute__ ((__nothrow__));
extern void mcheck_check_all (void);
extern enum mcheck_status mprobe (void *__ptr) __attribute__ ((__nothrow__));
extern void mtrace (void) __attribute__ ((__nothrow__));
extern void muntrace (void) __attribute__ ((__nothrow__));

#ifdef __cplusplus
}
#endif

#endif

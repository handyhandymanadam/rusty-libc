#ifndef _RLIBC_UCONTEXT_H
#define _RLIBC_UCONTEXT_H 1
#include <sys/ucontext.h>

extern int getcontext (ucontext_t *__ucp);
extern int setcontext (const ucontext_t *__ucp);
extern int swapcontext (ucontext_t *__restrict __oucp, const ucontext_t *__restrict __ucp);
extern void makecontext (ucontext_t *__ucp, void (*__func) (void), int __argc, ...);
#endif

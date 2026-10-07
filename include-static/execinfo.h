#ifndef _RLIBC_EXECINFO_H
#define _RLIBC_EXECINFO_H 1

#ifdef __cplusplus
extern "C" {
#endif

extern int backtrace (void **__array, int __size) __attribute__ ((__nonnull__ (1)));

extern char **backtrace_symbols (void *const *__array, int __size) __attribute__ ((__nothrow__, __nonnull__ (1)));

extern void backtrace_symbols_fd (void *const *__array, int __size, int __fd) __attribute__ ((__nothrow__, __nonnull__ (1)));

#ifdef __cplusplus
}
#endif

#endif

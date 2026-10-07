#ifndef _RLIBC_GNU_LIBC_VERSION_H
#define _RLIBC_GNU_LIBC_VERSION_H 1

#ifdef __cplusplus
extern "C" {
#endif
extern const char *gnu_get_libc_release (void) __attribute__ ((__nothrow__));
extern const char *gnu_get_libc_version (void) __attribute__ ((__nothrow__));
#ifdef __cplusplus
}
#endif

#endif

#ifndef _RLIBC_MONETARY_H
#define _RLIBC_MONETARY_H 1

#include <bits/rlibc-features.h>
#include <stddef.h>
#include <sys/types.h>
#include <bits/types/locale_t.h>

#ifdef __cplusplus
extern "C" {
#endif

extern ssize_t strfmon (char *__restrict __s, size_t __maxsize, const char *__restrict __format, ...)
  __attribute__ ((__nothrow__, __format__ (__strfmon__, 3, 4)));

extern ssize_t strfmon_l (char *__restrict __s, size_t __maxsize, locale_t __loc, const char *__restrict __format, ...)
  __attribute__ ((__nothrow__, __format__ (__strfmon__, 4, 5)));

#ifdef __cplusplus
}
#endif

#endif

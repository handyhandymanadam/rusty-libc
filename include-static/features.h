#ifndef _FEATURES_H
#define _FEATURES_H 1

#if defined _GNU_SOURCE
# undef _ISOC95_SOURCE
# define _ISOC95_SOURCE 1
# undef _ISOC99_SOURCE
# define _ISOC99_SOURCE 1
# undef _ISOC11_SOURCE
# define _ISOC11_SOURCE 1
# undef _ISOC23_SOURCE
# define _ISOC23_SOURCE 1
# undef _ISOC2Y_SOURCE
# define _ISOC2Y_SOURCE 1
# undef _POSIX_SOURCE
# define _POSIX_SOURCE 1
# undef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 202405L
# undef _XOPEN_SOURCE
# define _XOPEN_SOURCE 800
# undef _XOPEN_SOURCE_EXTENDED
# define _XOPEN_SOURCE_EXTENDED 1
# undef _LARGEFILE_SOURCE
# define _LARGEFILE_SOURCE 1
# undef _LARGEFILE64_SOURCE
# define _LARGEFILE64_SOURCE 1
# undef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE 1
# undef _ATFILE_SOURCE
# define _ATFILE_SOURCE 1
# undef _DYNAMIC_STACK_SIZE_SOURCE
# define _DYNAMIC_STACK_SIZE_SOURCE 1
#endif

#if (defined _DEFAULT_SOURCE || (!defined __STRICT_ANSI__ && !defined _ISOC99_SOURCE && !defined _ISOC11_SOURCE \
     && !defined _ISOC23_SOURCE && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE))
# undef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE 1
#endif

#if defined _DEFAULT_SOURCE && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 202405L
#endif

#if defined _XOPEN_SOURCE && !defined _POSIX_C_SOURCE
# if (_XOPEN_SOURCE - 0) >= 800
#  define _POSIX_C_SOURCE 202405L
# elif (_XOPEN_SOURCE - 0) >= 700
#  define _POSIX_C_SOURCE 200809L
# elif (_XOPEN_SOURCE - 0) >= 600
#  define _POSIX_C_SOURCE 200112L
# elif (_XOPEN_SOURCE - 0) >= 500
#  define _POSIX_C_SOURCE 199506L
# else
#  define _POSIX_C_SOURCE 2
# endif
#endif

#if defined _ISOC23_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ > 201710L)
# define __GLIBC_USE_ISOC23 1
#else
# define __GLIBC_USE_ISOC23 0
#endif
#if defined _ISOC2Y_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ > 202311L)
# define __GLIBC_USE_ISOC2Y 1
#else
# define __GLIBC_USE_ISOC2Y 0
#endif
#if __GLIBC_USE_ISOC23
# define __GLIBC_USE_C23_STRTOL 1
#else
# define __GLIBC_USE_C23_STRTOL 0
#endif
#if defined _ISOC11_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 201112L) \
    || (defined __cplusplus && __cplusplus >= 201103L) || __GLIBC_USE_ISOC23
# define __USE_ISOC11 1
#endif
#if defined _ISOC99_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L) \
    || (defined __cplusplus && __cplusplus >= 201103L) || defined __USE_ISOC11
# define __USE_ISOC99 1
#endif
#if defined _ISOC95_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199409L) || defined __USE_ISOC99
# define __USE_ISOC95 1
#endif

#if (defined _POSIX_SOURCE || defined _POSIX_C_SOURCE || defined _XOPEN_SOURCE || defined _DEFAULT_SOURCE) \
    && !(defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE \
         && !defined _DEFAULT_SOURCE)
# define __USE_POSIX 1
#endif
#if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 2 || defined _XOPEN_SOURCE
# define __USE_POSIX2 1
#endif
#if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 199309L
# define __USE_POSIX199309 1
#endif
#if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 199506L
# define __USE_POSIX199506 1
#endif
#if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200112L
# define __USE_XOPEN2K 1
# undef __USE_ISOC95
# define __USE_ISOC95 1
# undef __USE_ISOC99
# define __USE_ISOC99 1
#endif
#if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200809L
# define __USE_XOPEN2K8 1
# undef _ATFILE_SOURCE
# define _ATFILE_SOURCE 1
#endif
#if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 202405L
# define __USE_XOPEN2K24 1
#endif
#ifdef _XOPEN_SOURCE
# define __USE_XOPEN 1
# if (_XOPEN_SOURCE - 0) >= 500
#  define __USE_XOPEN_EXTENDED 1
#  define __USE_UNIX98 1
#  undef _LARGEFILE_SOURCE
#  define _LARGEFILE_SOURCE 1
#  if (_XOPEN_SOURCE - 0) >= 600
#   define __USE_XOPEN2K 1
#   define __USE_XOPEN2KXSI 1
#   undef __USE_ISOC99
#   define __USE_ISOC99 1
#   if (_XOPEN_SOURCE - 0) >= 700
#    define __USE_XOPEN2K8 1
#    define __USE_XOPEN2K8XSI 1
#    undef _ATFILE_SOURCE
#    define _ATFILE_SOURCE 1
#   endif
#   if (_XOPEN_SOURCE - 0) >= 800
#    define __USE_XOPEN2K24 1
#    define __USE_XOPEN2K24XSI 1
#   endif
#  endif
# elif defined _XOPEN_SOURCE_EXTENDED
#  define __USE_XOPEN_EXTENDED 1
# endif
#endif
#ifdef _XOPEN_SOURCE_EXTENDED
# define __USE_XOPEN_EXTENDED 1
#endif
#ifdef _DEFAULT_SOURCE
# define __USE_MISC 1
#endif
#if defined _LARGEFILE_SOURCE
# define __USE_LARGEFILE 1
#endif
#if defined _LARGEFILE64_SOURCE
# define __USE_LARGEFILE64 1
#endif
#ifdef _ATFILE_SOURCE
# define __USE_ATFILE 1
#endif
#ifdef _DYNAMIC_STACK_SIZE_SOURCE
# define __USE_DYNAMIC_STACK_SIZE 1
#endif
#ifdef _GNU_SOURCE
# define __USE_GNU 1
#endif
#define __USE_TIME_BITS64 1
#define __USE_FORTIFY_LEVEL 0

#define __GNU_LIBRARY__ 6
#define __GLIBC__ 2
#define __GLIBC_MINOR__ 43
#define __GLIBC_PREREQ(maj, min) ((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))

#if defined __cplusplus ? __cplusplus >= 201402L : defined __USE_ISOC11
# define __GLIBC_USE_DEPRECATED_GETS 0
#else
# define __GLIBC_USE_DEPRECATED_GETS 1
#endif
#if (defined __USE_GNU \
     && (defined __cplusplus ? (__cplusplus < 201103L && !defined __GXX_EXPERIMENTAL_CXX0X__) \
                             : (!defined __STDC_VERSION__ || __STDC_VERSION__ < 199901L)))
# define __GLIBC_USE_DEPRECATED_SCANF 1
#else
# define __GLIBC_USE_DEPRECATED_SCANF 0
#endif

#include <bits/rlibc-cdefs.h>
#include <bits/types.h>

#endif

#ifndef _RLIBC_FEATURES_H
#define _RLIBC_FEATURES_H 1

#if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)
# define __RLIBC_USE_MISC 1
#endif
#ifdef _GNU_SOURCE
# define __RLIBC_USE_GNU 1
#endif
#if defined _GNU_SOURCE || defined _XOPEN_SOURCE || defined __RLIBC_USE_MISC
# define __RLIBC_USE_XOPEN 1
#endif
#if defined __RLIBC_USE_MISC || (defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200809L) \
    || (defined _XOPEN_SOURCE && _XOPEN_SOURCE >= 700)
# define __RLIBC_USE_POSIX2008 1
#endif
#if defined _LARGEFILE64_SOURCE || defined _GNU_SOURCE
# define __RLIBC_USE_LF64 1
#endif

#endif

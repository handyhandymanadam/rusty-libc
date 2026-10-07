#ifndef _RLIBC_FTW_H
#define _RLIBC_FTW_H 1

#include <bits/rlibc-features.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  FTW_F,
#define FTW_F FTW_F
  FTW_D,
#define FTW_D FTW_D
  FTW_DNR,
#define FTW_DNR FTW_DNR
  FTW_NS,
#define FTW_NS FTW_NS
#if defined __RLIBC_USE_MISC || defined __RLIBC_USE_XOPEN
  FTW_SL,
# define FTW_SL FTW_SL
#endif
#ifdef __RLIBC_USE_XOPEN
  FTW_DP,
# define FTW_DP FTW_DP
  FTW_SLN
# define FTW_SLN FTW_SLN
#endif
};

#ifdef __RLIBC_USE_XOPEN
enum {
  FTW_PHYS = 1,
# define FTW_PHYS FTW_PHYS
  FTW_MOUNT = 2,
# define FTW_MOUNT FTW_MOUNT
  FTW_CHDIR = 4,
# define FTW_CHDIR FTW_CHDIR
  FTW_DEPTH = 8
# define FTW_DEPTH FTW_DEPTH
# ifdef __RLIBC_USE_GNU
  ,
  FTW_ACTIONRETVAL = 16
#  define FTW_ACTIONRETVAL FTW_ACTIONRETVAL
# endif
};

# ifdef __RLIBC_USE_GNU
enum {
  FTW_CONTINUE = 0,
# define FTW_CONTINUE FTW_CONTINUE
  FTW_STOP = 1,
# define FTW_STOP FTW_STOP
  FTW_SKIP_SUBTREE = 2,
# define FTW_SKIP_SUBTREE FTW_SKIP_SUBTREE
  FTW_SKIP_SIBLINGS = 3
# define FTW_SKIP_SIBLINGS FTW_SKIP_SIBLINGS
};
# endif

struct FTW {
  int base;
  int level;
};
#endif

typedef int (*__ftw_func_t) (const char *__filename, const struct stat *__status, int __flag);
#ifdef __RLIBC_USE_LF64
typedef int (*__ftw64_func_t) (const char *__filename, const struct stat64 *__status, int __flag);
#endif
#ifdef __RLIBC_USE_XOPEN
typedef int (*__nftw_func_t) (const char *__filename, const struct stat *__status, int __flag, struct FTW *__info);
# ifdef __RLIBC_USE_LF64
typedef int (*__nftw64_func_t) (const char *__filename, const struct stat64 *__status, int __flag, struct FTW *__info);
# endif
#endif

extern int ftw (const char *__dir, __ftw_func_t __func, int __descriptors);
#ifdef __RLIBC_USE_LF64
extern int ftw64 (const char *__dir, __ftw64_func_t __func, int __descriptors);
#endif
#ifdef __RLIBC_USE_XOPEN
extern int nftw (const char *__dir, __nftw_func_t __func, int __descriptors, int __flag);
# ifdef __RLIBC_USE_LF64
extern int nftw64 (const char *__dir, __nftw64_func_t __func, int __descriptors, int __flag);
# endif
#endif

#ifdef __cplusplus
}
#endif

#endif

#ifndef _RLIBC_WORDEXP_H
#define _RLIBC_WORDEXP_H 1

#include <bits/rlibc-features.h>
#define __need_size_t
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  WRDE_DOOFFS = (1 << 0),
  WRDE_APPEND = (1 << 1),
  WRDE_NOCMD = (1 << 2),
  WRDE_REUSE = (1 << 3),
  WRDE_SHOWERR = (1 << 4),
  WRDE_UNDEF = (1 << 5),
  __WRDE_FLAGS = (WRDE_DOOFFS | WRDE_APPEND | WRDE_NOCMD | WRDE_REUSE | WRDE_SHOWERR | WRDE_UNDEF)
};

typedef struct {
  size_t we_wordc;
  char **we_wordv;
  size_t we_offs;
} wordexp_t;

enum {
#ifdef __USE_XOPEN
  WRDE_NOSYS = -1,
#endif
  WRDE_NOSPACE = 1,
  WRDE_BADCHAR,
  WRDE_BADVAL,
  WRDE_CMDSUB,
  WRDE_SYNTAX
};

#include <bits/rlibc-wordexpcalls.h>

#ifdef __cplusplus
}
#endif

#endif

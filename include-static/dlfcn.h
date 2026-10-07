#ifndef _RLIBC_DLFCN_H
#define _RLIBC_DLFCN_H 1

#include <bits/rlibc-features.h>
#include <stddef.h>

#define RTLD_LAZY 0x00001
#define RTLD_NOW 0x00002
#define RTLD_BINDING_MASK 0x3
#define RTLD_NOLOAD 0x00004
#define RTLD_DEEPBIND 0x00008
#define RTLD_GLOBAL 0x00100
#define RTLD_LOCAL 0
#define RTLD_NODELETE 0x01000

#ifdef __RLIBC_USE_MISC
# define RTLD_NEXT ((void *) -1l)
# define RTLD_DEFAULT ((void *) 0)
typedef long int Lmid_t;
# define LM_ID_BASE 0
# define LM_ID_NEWLM -1
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern void *dlopen (const char *__file, int __mode);
extern int dlclose (void *__handle);
extern void *dlsym (void *__restrict __handle, const char *__restrict __name);
extern char *dlerror (void);

#ifdef __RLIBC_USE_GNU
extern void *dlmopen (Lmid_t __nsid, const char *__file, int __mode);
extern void *dlvsym (void *__restrict __handle, const char *__restrict __name, const char *__restrict __version);
#endif

#ifdef __RLIBC_USE_MISC
typedef struct {
  const char *dli_fname;
  void *dli_fbase;
  const char *dli_sname;
  void *dli_saddr;
} Dl_info;

extern int dladdr (const void *__address, Dl_info *__info);
extern int dladdr1 (const void *__address, Dl_info *__info, void **__extra_info, int __flags);

enum {
  RTLD_DL_SYMENT = 1,
  RTLD_DL_LINKMAP = 2
};

enum {
  RTLD_DI_LMID = 1,
  RTLD_DI_LINKMAP = 2,
  RTLD_DI_CONFIGADDR = 3,
  RTLD_DI_SERINFO = 4,
  RTLD_DI_SERINFOSIZE = 5,
  RTLD_DI_ORIGIN = 6,
  RTLD_DI_PROFILENAME = 7,
  RTLD_DI_PROFILEOUT = 8,
  RTLD_DI_TLS_MODID = 9,
  RTLD_DI_TLS_DATA = 10,
  RTLD_DI_MAX = 11
};

typedef struct {
  char *dls_name;
  unsigned int dls_flags;
} Dl_serpath;

typedef struct {
  size_t dls_size;
  unsigned int dls_cnt;
  Dl_serpath dls_serpath[1];
} Dl_serinfo;

extern int dlinfo (void *__restrict __handle, int __request, void *__restrict __arg);
#endif

#ifdef __cplusplus
}
#endif

#endif

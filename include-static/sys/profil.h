#ifndef _PROFIL_H
#define _PROFIL_H 1

#include <features.h>
#include <sys/time.h>
#include <sys/types.h>

struct prof
  {
    void *pr_base;
    size_t pr_size;
    size_t pr_off;
    unsigned long int pr_scale;
  };

enum
  {
    PROF_USHORT	= 0,
    PROF_UINT	= 1 << 0,
    PROF_FAST   = 1 << 1
  };

__BEGIN_DECLS

extern int sprofil (struct prof *__profp, int __profcnt,
		    struct timeval *__tvp, unsigned int __flags) __THROW;

__END_DECLS

#endif

#ifndef _SYS_GMON_H
#define _SYS_GMON_H 1

#include <features.h>
#include <sys/types.h>
#include <stdint.h>

#define GMON_PROF_ON	0
#define GMON_PROF_BUSY	1
#define GMON_PROF_ERROR	2
#define GMON_PROF_OFF	3
#define GMON_PROF_REDIRECT	4

#define HISTFRACTION	2
#define HASHFRACTION	2
#define ARCDENSITY	3
#define MINARCS		50
#define MAXARCS		((1 << 20))

struct tostruct
{
  unsigned long selfpc;
  long count;
  unsigned short link;
  unsigned short pad;
};

struct rawarc
{
  unsigned long raw_frompc;
  unsigned long raw_selfpc;
  long raw_count;
};

#define ROUNDDOWN(x,y)	(((x)/(y))*(y))
#define ROUNDUP(x,y)	((((x)+(y)-1)/(y))*(y))

struct gmonparam
{
  long int state;
  unsigned short *kcount;
  size_t kcountsize;
  unsigned long *froms;
  size_t fromssize;
  struct tostruct *tos;
  size_t tossize;
  long tolimit;
  unsigned long lowpc;
  unsigned long highpc;
  unsigned long textsize;
  unsigned long hashfraction;
  long int log_hashfraction;
};
extern struct gmonparam _gmonparam;

__BEGIN_DECLS

extern void __monstartup (unsigned long __lowpc, unsigned long __highpc) __THROW;
extern void monstartup (unsigned long __lowpc, unsigned long __highpc) __THROW;

extern void _mcleanup (void) __THROW;

__END_DECLS

#endif

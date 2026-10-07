#ifndef _SYS_PARAM_H
#define _SYS_PARAM_H 1
#include <features.h>
#include <limits.h>
#include <sys/types.h>
#define MAXSYMLINKS 20
#define NOFILE 256
#define NCARGS 131072
#define NGROUPS NGROUPS_MAX
#define NOGROUP (-1)
#define MAXHOSTNAMELEN 64
#define MAXPATHLEN PATH_MAX
#define CANBSIZ MAX_CANON
#define NBBY CHAR_BIT
#define HZ 100
#define EXEC_PAGESIZE 4096
#define DEV_BSIZE 512
#define NODEV ((dev_t) -1)
#define setbit(a,i) ((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define clrbit(a,i) ((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define isset(a,i) ((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define isclr(a,i) (((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)
#define howmany(x,y) (((x) + ((y) - 1)) / (y))
#define roundup(x,y) (__builtin_constant_p (y) && powerof2 (y) ? (((x) + (y) - 1) & ~((y) - 1)) : ((((x) + ((y) - 1)) / (y)) * (y)))
#define powerof2(x) ((((x) - 1) & (x)) == 0)
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

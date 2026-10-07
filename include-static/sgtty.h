#ifndef _SGTTY_H
#define _SGTTY_H 1

#include <features.h>
#include <sys/ioctl.h>

struct sgttyb;

__BEGIN_DECLS

extern int gtty (int __fd, struct sgttyb *__params) __THROW;
extern int stty (int __fd, const struct sgttyb *__params) __THROW;

__END_DECLS

#endif

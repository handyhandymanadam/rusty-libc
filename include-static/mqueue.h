#ifndef _MQUEUE_H
#define _MQUEUE_H 1

#include <stddef.h>
#include <sys/types.h>
#include <fcntl.h>
#include <bits/types/struct_sigevent.h>
#include <bits/types/struct_timespec.h>

#if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE) \
    || (defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200112L) || (defined _XOPEN_SOURCE && _XOPEN_SOURCE >= 600)
# define __RLIBC_MQ_XOPEN2K 1
#endif

typedef int mqd_t;

struct mq_attr {
  long int mq_flags;
  long int mq_maxmsg;
  long int mq_msgsize;
  long int mq_curmsgs;
  long int __pad[4];
};

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-mq-calls.h>
#ifdef __RLIBC_MQ_XOPEN2K
# include <bits/rlibc-mq-timed.h>
#endif
#ifdef __cplusplus
}
#endif

#endif

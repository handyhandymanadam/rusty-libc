#ifndef _SYS_MSG_H
#define _SYS_MSG_H 1

#include <stddef.h>
#include <sys/types.h>
#include <sys/ipc.h>

#if defined _GNU_SOURCE
# define __RLIBC_MSG_GNU 1
#endif
#if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)
# define __RLIBC_MSG_MISC 1
#endif

typedef unsigned long int msgqnum_t;
typedef unsigned long int msglen_t;

struct msqid_ds {
  struct ipc_perm msg_perm;
  time_t msg_stime;
  time_t msg_rtime;
  time_t msg_ctime;
  unsigned long int __msg_cbytes;
  msgqnum_t msg_qnum;
  msglen_t msg_qbytes;
  pid_t msg_lspid;
  pid_t msg_lrpid;
  unsigned long int __glibc_reserved4;
  unsigned long int __glibc_reserved5;
};

#define MSG_NOERROR 010000
#ifdef __RLIBC_MSG_GNU
# define MSG_EXCEPT 020000
# define MSG_COPY 040000
#endif

#ifdef __RLIBC_MSG_MISC
# define msg_cbytes __msg_cbytes
# define MSG_STAT 11
# define MSG_INFO 12
# define MSG_STAT_ANY 13
struct msginfo {
  int msgpool;
  int msgmap;
  int msgmax;
  int msgmnb;
  int msgmni;
  int msgssz;
  int msgtql;
  unsigned short int msgseg;
};
#endif

#ifdef __RLIBC_MSG_GNU
struct msgbuf {
  long int mtype;
  char mtext[1];
};
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-ipc-msg.h>
#ifdef __cplusplus
}
#endif

#endif

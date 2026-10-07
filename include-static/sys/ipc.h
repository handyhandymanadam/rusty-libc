#ifndef _SYS_IPC_H
#define _SYS_IPC_H 1

#include <stddef.h>
#include <sys/types.h>

#if defined _GNU_SOURCE
# define __RLIBC_IPC_GNU 1
#endif

#define IPC_CREAT 01000
#define IPC_EXCL 02000
#define IPC_NOWAIT 04000

#define IPC_RMID 0
#define IPC_SET 1
#define IPC_STAT 2
#ifdef __RLIBC_IPC_GNU
# define IPC_INFO 3
#endif

#define IPC_PRIVATE ((key_t) 0)

#ifndef __RLIBC_STRUCT_IPC_PERM
# define __RLIBC_STRUCT_IPC_PERM 1
struct ipc_perm {
  key_t __key;
  uid_t uid;
  gid_t gid;
  uid_t cuid;
  gid_t cgid;
  mode_t mode;
  unsigned short int __seq;
  unsigned short int __pad2;
  unsigned long int __glibc_reserved1;
  unsigned long int __glibc_reserved2;
};
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-ipc-ipc.h>
#ifdef __cplusplus
}
#endif

#endif

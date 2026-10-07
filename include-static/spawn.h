#ifndef _RLIBC_SPAWN_H
#define _RLIBC_SPAWN_H 1

#include <bits/rlibc-features.h>
#include <sched.h>
#include <sys/types.h>
#include <bits/types/sigset_t.h>

struct __spawn_action;

typedef struct {
  short int __flags;
  pid_t __pgrp;
  sigset_t __sd;
  sigset_t __ss;
  struct sched_param __sp;
  int __policy;
  int __cgroup;
  int __pad[15];
} posix_spawnattr_t;

typedef struct {
  int __allocated;
  int __used;
  struct __spawn_action *__actions;
  int __pad[16];
} posix_spawn_file_actions_t;

#define POSIX_SPAWN_RESETIDS 0x01
#define POSIX_SPAWN_SETPGROUP 0x02
#define POSIX_SPAWN_SETSIGDEF 0x04
#define POSIX_SPAWN_SETSIGMASK 0x08
#define POSIX_SPAWN_SETSCHEDPARAM 0x10
#define POSIX_SPAWN_SETSCHEDULER 0x20
#ifdef __RLIBC_USE_GNU
# define POSIX_SPAWN_USEVFORK 0x40
# define POSIX_SPAWN_SETSID 0x80
# define POSIX_SPAWN_SETCGROUP 0x100
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-spawncalls.h>
#ifdef __RLIBC_USE_MISC
# include <bits/rlibc-spawncalls-misc.h>
#endif
#ifdef __cplusplus
}
#endif

#endif

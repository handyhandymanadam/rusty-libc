#ifndef _RLIBC_FSTAB_H
#define _RLIBC_FSTAB_H 1

#include <bits/rlibc-features.h>

#define _PATH_FSTAB "/etc/fstab"
#define FSTAB "/etc/fstab"

#define FSTAB_RW "rw"
#define FSTAB_RQ "rq"
#define FSTAB_RO "ro"
#define FSTAB_SW "sw"
#define FSTAB_XX "xx"

struct fstab {
  char *fs_spec;
  char *fs_file;
  char *fs_vfstype;
  char *fs_mntops;
  const char *fs_type;
  int fs_freq;
  int fs_passno;
};

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-fstabcalls.h>
#ifdef __cplusplus
}
#endif

#endif

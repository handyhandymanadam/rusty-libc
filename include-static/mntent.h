#ifndef _RLIBC_MNTENT_H
#define _RLIBC_MNTENT_H 1

#include <bits/rlibc-features.h>
#include <stdio.h>
#include <paths.h>

#define MNTTAB _PATH_MNTTAB
#define MOUNTED _PATH_MOUNTED

#define MNTTYPE_IGNORE "ignore"
#define MNTTYPE_NFS "nfs"
#define MNTTYPE_SWAP "swap"

#define MNTOPT_DEFAULTS "defaults"
#define MNTOPT_RO "ro"
#define MNTOPT_RW "rw"
#define MNTOPT_SUID "suid"
#define MNTOPT_NOSUID "nosuid"
#define MNTOPT_NOAUTO "noauto"

struct mntent {
  char *mnt_fsname;
  char *mnt_dir;
  char *mnt_type;
  char *mnt_opts;
  int mnt_freq;
  int mnt_passno;
};

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-mntentcalls.h>
#ifdef __RLIBC_USE_MISC
# include <bits/rlibc-mntentcalls-misc.h>
#endif
#ifdef __cplusplus
}
#endif

#endif

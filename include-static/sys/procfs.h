#ifndef _SYS_PROCFS_H
#define _SYS_PROCFS_H 1

#include <features.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>

__extension__ typedef unsigned long long elf_greg_t;
#define ELF_NGREG (sizeof (struct user_regs_struct) / sizeof (elf_greg_t))
typedef elf_greg_t elf_gregset_t[ELF_NGREG];
typedef struct user_fpregs_struct elf_fpregset_t;

typedef unsigned int __pr_uid_t;
typedef unsigned int __pr_gid_t;

__BEGIN_DECLS

struct elf_siginfo
  {
    int si_signo;
    int si_code;
    int si_errno;
  };

struct elf_prstatus
  {
    struct elf_siginfo pr_info;
    short int pr_cursig;
    unsigned long int pr_sigpend;
    unsigned long int pr_sighold;
    pid_t pr_pid;
    pid_t pr_ppid;
    pid_t pr_pgrp;
    pid_t pr_sid;
    struct timeval pr_utime;
    struct timeval pr_stime;
    struct timeval pr_cutime;
    struct timeval pr_cstime;
    elf_gregset_t pr_reg;
    int pr_fpvalid;
  };

#define ELF_PRARGSZ (80)

struct elf_prpsinfo
  {
    char pr_state;
    char pr_sname;
    char pr_zomb;
    char pr_nice;
    unsigned long int pr_flag;
    __pr_uid_t pr_uid;
    __pr_gid_t pr_gid;
    int pr_pid, pr_ppid, pr_pgrp, pr_sid;
    char pr_fname[16];
    char pr_psargs[ELF_PRARGSZ];
  };

typedef void *psaddr_t;

typedef elf_gregset_t __prgregset_t;
typedef elf_fpregset_t __prfpregset_t;
typedef __prgregset_t prgregset_t;
typedef __prfpregset_t prfpregset_t;

typedef pid_t lwpid_t;

typedef struct elf_prstatus prstatus_t;
typedef struct elf_prpsinfo prpsinfo_t;

__END_DECLS

#endif

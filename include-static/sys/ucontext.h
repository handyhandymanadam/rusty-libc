#ifndef _RLIBC_SYS_UCONTEXT_H
#define _RLIBC_SYS_UCONTEXT_H 1
#include <bits/types/sigset_t.h>
#include <bits/types/stack_t.h>

#if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)
# define __RLIBC_UC_MISC 1
# define __ctx(fld) fld
#else
# define __ctx(fld) __ ## fld
#endif

__extension__ typedef long long int greg_t;
#define __NGREG 23
#ifdef __RLIBC_UC_MISC
# define NGREG __NGREG
#endif
typedef greg_t gregset_t[__NGREG];

#ifdef _GNU_SOURCE
enum {
  REG_R8 = 0,
# define REG_R8 REG_R8
  REG_R9,
# define REG_R9 REG_R9
  REG_R10,
# define REG_R10 REG_R10
  REG_R11,
# define REG_R11 REG_R11
  REG_R12,
# define REG_R12 REG_R12
  REG_R13,
# define REG_R13 REG_R13
  REG_R14,
# define REG_R14 REG_R14
  REG_R15,
# define REG_R15 REG_R15
  REG_RDI,
# define REG_RDI REG_RDI
  REG_RSI,
# define REG_RSI REG_RSI
  REG_RBP,
# define REG_RBP REG_RBP
  REG_RBX,
# define REG_RBX REG_RBX
  REG_RDX,
# define REG_RDX REG_RDX
  REG_RAX,
# define REG_RAX REG_RAX
  REG_RCX,
# define REG_RCX REG_RCX
  REG_RSP,
# define REG_RSP REG_RSP
  REG_RIP,
# define REG_RIP REG_RIP
  REG_EFL,
# define REG_EFL REG_EFL
  REG_CSGSFS,
# define REG_CSGSFS REG_CSGSFS
  REG_ERR,
# define REG_ERR REG_ERR
  REG_TRAPNO,
# define REG_TRAPNO REG_TRAPNO
  REG_OLDMASK,
# define REG_OLDMASK REG_OLDMASK
  REG_CR2
# define REG_CR2 REG_CR2
};
#endif

struct _libc_fpxreg {
  unsigned short int __ctx(significand)[4];
  unsigned short int __ctx(exponent);
  unsigned short int __glibc_reserved1[3];
};
struct _libc_xmmreg {
  unsigned int __ctx(element)[4];
};
struct _libc_fpstate {
  unsigned short __ctx(cwd);
  unsigned short __ctx(swd);
  unsigned short __ctx(ftw);
  unsigned short __ctx(fop);
  unsigned long __ctx(rip);
  unsigned long __ctx(rdp);
  unsigned int __ctx(mxcsr);
  unsigned int __ctx(mxcr_mask);
  struct _libc_fpxreg _st[8];
  struct _libc_xmmreg _xmm[16];
  unsigned int __glibc_reserved1[24];
};
typedef struct _libc_fpstate *fpregset_t;

typedef struct {
  gregset_t __ctx(gregs);
  fpregset_t __ctx(fpregs);
  __extension__ unsigned long long __reserved1[8];
} mcontext_t;

typedef struct ucontext_t {
  unsigned long int __ctx(uc_flags);
  struct ucontext_t *uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  sigset_t uc_sigmask;
  struct _libc_fpstate __fpregs_mem;
  __extension__ unsigned long long int __ssp[4];
} ucontext_t;

#undef __ctx
#endif

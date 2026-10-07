#ifndef _RLIBC_BITS_SIGCONTEXT_H
#define _RLIBC_BITS_SIGCONTEXT_H 1
#define FP_XSTATE_MAGIC1 0x46505853U
#define FP_XSTATE_MAGIC2 0x46505845U
#define FP_XSTATE_MAGIC2_SIZE sizeof (FP_XSTATE_MAGIC2)
struct _fpx_sw_bytes {
  unsigned int magic1;
  unsigned int extended_size;
  unsigned long xstate_bv;
  unsigned int xstate_size;
  unsigned int __glibc_reserved1[7];
};
struct _fpreg {
  unsigned short significand[4];
  unsigned short exponent;
};
struct _fpxreg {
  unsigned short significand[4];
  unsigned short exponent;
  unsigned short __glibc_reserved1[3];
};
struct _xmmreg {
  unsigned int element[4];
};
struct _fpstate {
  unsigned short cwd;
  unsigned short swd;
  unsigned short ftw;
  unsigned short fop;
  unsigned long rip;
  unsigned long rdp;
  unsigned int mxcsr;
  unsigned int mxcr_mask;
  struct _fpxreg _st[8];
  struct _xmmreg _xmm[16];
  unsigned int __glibc_reserved1[24];
};
struct sigcontext {
  unsigned long r8;
  unsigned long r9;
  unsigned long r10;
  unsigned long r11;
  unsigned long r12;
  unsigned long r13;
  unsigned long r14;
  unsigned long r15;
  unsigned long rdi;
  unsigned long rsi;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long rdx;
  unsigned long rax;
  unsigned long rcx;
  unsigned long rsp;
  unsigned long rip;
  unsigned long eflags;
  unsigned short cs;
  unsigned short gs;
  unsigned short fs;
  unsigned short __pad0;
  unsigned long err;
  unsigned long trapno;
  unsigned long oldmask;
  unsigned long cr2;
  __extension__ union {
    struct _fpstate *fpstate;
    unsigned long __fpstate_word;
  };
  unsigned long __reserved1[8];
};
struct _xsave_hdr {
  unsigned long xstate_bv;
  unsigned long __glibc_reserved1[2];
  unsigned long __glibc_reserved2[5];
};
struct _ymmh_state {
  unsigned int ymmh_space[64];
};
struct _xstate {
  struct _fpstate fpstate;
  struct _xsave_hdr xstate_hdr;
  struct _ymmh_state ymmh;
};
#endif

use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/ucontext.h",
    items: &[
        Item::Guard { name: "_RLIBC_SYS_UCONTEXT_H", value: "1", end: "", items: &[
            Item::Include("<bits/types/sigset_t.h>"),
            Item::Include("<bits/types/stack_t.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: r#"if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)"#, items: &[
                    Item::Consts(&[
                        ("__RLIBC_UC_MISC", V::Dec(1)),
                    ]),
                    Item::Raw(Reason::GlibcMacro, "# define __ctx(fld) fld"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::GlibcMacro, "# define __ctx(fld) __ ## fld"),
                ] },
            ], ""),
            Item::Blank,
            Item::Decl("__extension__ typedef long long int greg_t;"),
            Item::Consts(&[
                ("__NGREG", V::Dec(23)),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_UC_MISC", items: &[
                    Item::Consts(&[
                        ("NGREG", V::Txt("__NGREG")),
                    ]),
                ] },
            ], ""),
            Item::Decl("typedef greg_t gregset_t[__NGREG];"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef _GNU_SOURCE", items: &[
                    Item::Block { head: "enum ", body: &["", "  REG_R8 = 0,", "# define REG_R8 REG_R8", "  REG_R9,", "# define REG_R9 REG_R9", "  REG_R10,", "# define REG_R10 REG_R10", "  REG_R11,", "# define REG_R11 REG_R11", "  REG_R12,", "# define REG_R12 REG_R12", "  REG_R13,", "# define REG_R13 REG_R13", "  REG_R14,", "# define REG_R14 REG_R14", "  REG_R15,", "# define REG_R15 REG_R15", "  REG_RDI,", "# define REG_RDI REG_RDI", "  REG_RSI,", "# define REG_RSI REG_RSI", "  REG_RBP,", "# define REG_RBP REG_RBP", "  REG_RBX,", "# define REG_RBX REG_RBX", "  REG_RDX,", "# define REG_RDX REG_RDX", "  REG_RAX,", "# define REG_RAX REG_RAX", "  REG_RCX,", "# define REG_RCX REG_RCX", "  REG_RSP,", "# define REG_RSP REG_RSP", "  REG_RIP,", "# define REG_RIP REG_RIP", "  REG_EFL,", "# define REG_EFL REG_EFL", "  REG_CSGSFS,", "# define REG_CSGSFS REG_CSGSFS", "  REG_ERR,", "# define REG_ERR REG_ERR", "  REG_TRAPNO,", "# define REG_TRAPNO REG_TRAPNO", "  REG_OLDMASK,", "# define REG_OLDMASK REG_OLDMASK", "  REG_CR2", "# define REG_CR2 REG_CR2", ""], tail: "" },
                ] },
            ], ""),
            Item::Blank,
            Item::Block { head: "struct _libc_fpxreg ", body: &["", "  unsigned short int __ctx(significand)[4];", "  unsigned short int __ctx(exponent);", "  unsigned short int __glibc_reserved1[3];", ""], tail: "" },
            Item::Block { head: "struct _libc_xmmreg ", body: &["", "  unsigned int __ctx(element)[4];", ""], tail: "" },
            Item::Block { head: "struct _libc_fpstate ", body: &["", "  unsigned short __ctx(cwd);", "  unsigned short __ctx(swd);", "  unsigned short __ctx(ftw);", "  unsigned short __ctx(fop);", "  unsigned long __ctx(rip);", "  unsigned long __ctx(rdp);", "  unsigned int __ctx(mxcsr);", "  unsigned int __ctx(mxcr_mask);", "  struct _libc_fpxreg _st[8];", "  struct _libc_xmmreg _xmm[16];", "  unsigned int __glibc_reserved1[24];", ""], tail: "" },
            Item::Typedef("struct _libc_fpstate *", "fpregset_t"),
            Item::Blank,
            Item::Block { head: "typedef struct ", body: &["", "  gregset_t __ctx(gregs);", "  fpregset_t __ctx(fpregs);", "  __extension__ unsigned long long __reserved1[8];", ""], tail: " mcontext_t" },
            Item::Blank,
            Item::Block { head: "typedef struct ucontext_t ", body: &["", "  unsigned long int __ctx(uc_flags);", "  struct ucontext_t *uc_link;", "  stack_t uc_stack;", "  mcontext_t uc_mcontext;", "  sigset_t uc_sigmask;", "  struct _libc_fpstate __fpregs_mem;", "  __extension__ unsigned long long int __ssp[4];", ""], tail: " ucontext_t" },
            Item::Blank,
            Item::Undef("__ctx"),
        ]},
    ],
};

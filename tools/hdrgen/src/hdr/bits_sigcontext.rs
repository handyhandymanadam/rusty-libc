use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/sigcontext.h",
    items: &[
        Item::Guard { name: "_RLIBC_BITS_SIGCONTEXT_H", value: "1", end: "", items: &[
            Item::Consts(&[
                ("FP_XSTATE_MAGIC1", V::Txt("0x46505853U")),
                ("FP_XSTATE_MAGIC2", V::Txt("0x46505845U")),
                ("FP_XSTATE_MAGIC2_SIZE", V::Txt("sizeof (FP_XSTATE_MAGIC2)")),
            ]),
            Item::Block { head: "struct _fpx_sw_bytes ", body: &["", "  unsigned int magic1;", "  unsigned int extended_size;", "  unsigned long xstate_bv;", "  unsigned int xstate_size;", "  unsigned int __glibc_reserved1[7];", ""], tail: "" },
            Item::Block { head: "struct _fpreg ", body: &["", "  unsigned short significand[4];", "  unsigned short exponent;", ""], tail: "" },
            Item::Block { head: "struct _fpxreg ", body: &["", "  unsigned short significand[4];", "  unsigned short exponent;", "  unsigned short __glibc_reserved1[3];", ""], tail: "" },
            Item::Block { head: "struct _xmmreg ", body: &["", "  unsigned int element[4];", ""], tail: "" },
            Item::Block { head: "struct _fpstate ", body: &["", "  unsigned short cwd;", "  unsigned short swd;", "  unsigned short ftw;", "  unsigned short fop;", "  unsigned long rip;", "  unsigned long rdp;", "  unsigned int mxcsr;", "  unsigned int mxcr_mask;", "  struct _fpxreg _st[8];", "  struct _xmmreg _xmm[16];", "  unsigned int __glibc_reserved1[24];", ""], tail: "" },
            Item::Block { head: "struct sigcontext ", body: &["", "  unsigned long r8;", "  unsigned long r9;", "  unsigned long r10;", "  unsigned long r11;", "  unsigned long r12;", "  unsigned long r13;", "  unsigned long r14;", "  unsigned long r15;", "  unsigned long rdi;", "  unsigned long rsi;", "  unsigned long rbp;", "  unsigned long rbx;", "  unsigned long rdx;", "  unsigned long rax;", "  unsigned long rcx;", "  unsigned long rsp;", "  unsigned long rip;", "  unsigned long eflags;", "  unsigned short cs;", "  unsigned short gs;", "  unsigned short fs;", "  unsigned short __pad0;", "  unsigned long err;", "  unsigned long trapno;", "  unsigned long oldmask;", "  unsigned long cr2;", "  __extension__ union {", "    struct _fpstate *fpstate;", "    unsigned long __fpstate_word;", "  };", "  unsigned long __reserved1[8];", ""], tail: "" },
            Item::Block { head: "struct _xsave_hdr ", body: &["", "  unsigned long xstate_bv;", "  unsigned long __glibc_reserved1[2];", "  unsigned long __glibc_reserved2[5];", ""], tail: "" },
            Item::Block { head: "struct _ymmh_state ", body: &["", "  unsigned int ymmh_space[64];", ""], tail: "" },
            Item::Block { head: "struct _xstate ", body: &["", "  struct _fpstate fpstate;", "  struct _xsave_hdr xstate_hdr;", "  struct _ymmh_state ymmh;", ""], tail: "" },
        ]},
    ],
};

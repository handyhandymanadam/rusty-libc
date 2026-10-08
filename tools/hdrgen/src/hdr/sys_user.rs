use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/user.h",
    items: &[
        Item::Guard { name: "_SYS_USER_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Block { head: r#"struct user_fpregs_struct
"#, body: &["", "  unsigned short int cwd;", "  unsigned short int swd;", "  unsigned short int ftw;", "  unsigned short int fop;", "  __extension__ unsigned long long int rip;", "  __extension__ unsigned long long int rdp;", "  unsigned int mxcsr;", "  unsigned int mxcr_mask;", r#"  unsigned int st_space[32];"#, r#"  unsigned int xmm_space[64];"#, "  unsigned int padding[24];", ""], tail: "" },
            Item::Blank,
            Item::Block { head: r#"struct user_regs_struct
"#, body: &["", "  __extension__ unsigned long long int r15;", "  __extension__ unsigned long long int r14;", "  __extension__ unsigned long long int r13;", "  __extension__ unsigned long long int r12;", "  __extension__ unsigned long long int rbp;", "  __extension__ unsigned long long int rbx;", "  __extension__ unsigned long long int r11;", "  __extension__ unsigned long long int r10;", "  __extension__ unsigned long long int r9;", "  __extension__ unsigned long long int r8;", "  __extension__ unsigned long long int rax;", "  __extension__ unsigned long long int rcx;", "  __extension__ unsigned long long int rdx;", "  __extension__ unsigned long long int rsi;", "  __extension__ unsigned long long int rdi;", "  __extension__ unsigned long long int orig_rax;", "  __extension__ unsigned long long int rip;", "  __extension__ unsigned long long int cs;", "  __extension__ unsigned long long int eflags;", "  __extension__ unsigned long long int rsp;", "  __extension__ unsigned long long int ss;", "  __extension__ unsigned long long int fs_base;", "  __extension__ unsigned long long int gs_base;", "  __extension__ unsigned long long int ds;", "  __extension__ unsigned long long int es;", "  __extension__ unsigned long long int fs;", "  __extension__ unsigned long long int gs;", ""], tail: "" },
            Item::Blank,
            Item::Block { head: r#"struct user
"#, body: &["", "  struct user_regs_struct regs;", "  int u_fpvalid;", "  struct user_fpregs_struct i387;", "  __extension__ unsigned long long int u_tsize;", "  __extension__ unsigned long long int u_dsize;", "  __extension__ unsigned long long int u_ssize;", "  __extension__ unsigned long long int start_code;", "  __extension__ unsigned long long int start_stack;", "  __extension__ long long int signal;", "  int reserved;", "  __extension__ union", "    {", "      struct user_regs_struct *u_ar0;", "      __extension__ unsigned long long int __u_ar0_word;", "    };", "  __extension__ union", "    {", "      struct user_fpregs_struct *u_fpstate;", "      __extension__ unsigned long long int __u_fpstate_word;", "    };", "  __extension__ unsigned long long int magic;", "  char u_comm[32];", "  __extension__ unsigned long long int u_debugreg[8];", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("PAGE_SHIFT", V::Dec(12)),
                ("PAGE_SIZE", V::Txt("(1UL << PAGE_SHIFT)")),
                ("PAGE_MASK", V::Txt("(~(PAGE_SIZE - 1))")),
                ("NBPG", V::Txt("PAGE_SIZE")),
                ("UPAGES", V::Dec(1)),
                ("HOST_TEXT_START_ADDR", V::Txt("(u.start_code)")),
                ("HOST_STACK_END_ADDR", V::Txt("(u.start_stack + u.u_ssize * NBPG)")),
            ]),
            Item::Blank,
        ]},
    ],
};

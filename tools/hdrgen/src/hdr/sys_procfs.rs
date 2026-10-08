use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/procfs.h",
    items: &[
        Item::Guard { name: "_SYS_PROCFS_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<features.h>"),
            Item::Include("<sys/time.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<sys/user.h>"),
            Item::Blank,
            Item::Decl("__extension__ typedef unsigned long long elf_greg_t;"),
            Item::Consts(&[
                ("ELF_NGREG", V::Txt("(sizeof (struct user_regs_struct) / sizeof (elf_greg_t))")),
            ]),
            Item::Decl("typedef elf_greg_t elf_gregset_t[ELF_NGREG];"),
            Item::Typedef("struct user_fpregs_struct", "elf_fpregset_t"),
            Item::Blank,
            Item::Typedef("unsigned int", "__pr_uid_t"),
            Item::Typedef("unsigned int", "__pr_gid_t"),
            Item::Blank,
            Item::Decl("__BEGIN_DECLS"),
            Item::Blank,
            Item::Block { head: r#"struct elf_siginfo
  "#, body: &["", r#"    int si_signo;"#, r#"    int si_code;"#, r#"    int si_errno;"#, "  "], tail: "" },
            Item::Blank,
            Item::Block { head: r#"struct elf_prstatus
  "#, body: &["", r#"    struct elf_siginfo pr_info;"#, r#"    short int pr_cursig;"#, r#"    unsigned long int pr_sigpend;"#, r#"    unsigned long int pr_sighold;"#, "    pid_t pr_pid;", "    pid_t pr_ppid;", "    pid_t pr_pgrp;", "    pid_t pr_sid;", r#"    struct timeval pr_utime;"#, r#"    struct timeval pr_stime;"#, r#"    struct timeval pr_cutime;"#, r#"    struct timeval pr_cstime;"#, r#"    elf_gregset_t pr_reg;"#, r#"    int pr_fpvalid;"#, "  "], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("ELF_PRARGSZ", V::Txt(r#"(80)"#)),
            ]),
            Item::Blank,
            Item::Block { head: r#"struct elf_prpsinfo
  "#, body: &["", r#"    char pr_state;"#, r#"    char pr_sname;"#, r#"    char pr_zomb;"#, r#"    char pr_nice;"#, r#"    unsigned long int pr_flag;"#, "    __pr_uid_t pr_uid;", "    __pr_gid_t pr_gid;", "    int pr_pid, pr_ppid, pr_pgrp, pr_sid;", r#"    char pr_fname[16];"#, r#"    char pr_psargs[ELF_PRARGSZ];"#, "  "], tail: "" },
            Item::Blank,
            Item::Typedef("void *", "psaddr_t"),
            Item::Blank,
            Item::Typedef("elf_gregset_t", "__prgregset_t"),
            Item::Typedef("elf_fpregset_t", "__prfpregset_t"),
            Item::Typedef("__prgregset_t", "prgregset_t"),
            Item::Typedef("__prfpregset_t", "prfpregset_t"),
            Item::Blank,
            Item::Typedef("pid_t", "lwpid_t"),
            Item::Blank,
            Item::Typedef("struct elf_prstatus", "prstatus_t"),
            Item::Typedef("struct elf_prpsinfo", "prpsinfo_t"),
            Item::Blank,
            Item::Decl("__END_DECLS"),
            Item::Blank,
        ]},
    ],
};

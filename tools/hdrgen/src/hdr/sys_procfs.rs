use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/procfs.h",
    items: &[
        Item::Comment(r#"/* sys/procfs.h for the Rust libc (x86_64 only): the structures of an ELF core file (elf_prstatus, elf_prpsinfo) and the
   Solaris proc_service types libthread_db users expect. With glibc's bits/procfs*.h folded in. Layouts equal glibc 2.43's
   (tests/c/user_procfs.c; Rust definitions in crates/rusty-libc-sys/src/user.rs). */"#),
        Item::Guard { name: "_SYS_PROCFS_H", value: "1", end: " /* sys/procfs.h */", items: &[
            Item::Blank,
            Item::Include("<features.h>"),
            Item::Include("<sys/time.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<sys/user.h>"),
            Item::Blank,
            Item::Comment("/* a general-purpose register, and the whole set as an array */"),
            Item::Decl("__extension__ typedef unsigned long long elf_greg_t;"),
            Item::Consts(&[
                ("ELF_NGREG", V::Txt("(sizeof (struct user_regs_struct) / sizeof (elf_greg_t))")),
            ]),
            Item::Decl("typedef elf_greg_t elf_gregset_t[ELF_NGREG];"),
            Item::Typedef("struct user_fpregs_struct", "elf_fpregset_t"),
            Item::Blank,
            Item::Comment("/* the types of pr_uid and pr_gid */"),
            Item::Typedef("unsigned int", "__pr_uid_t"),
            Item::Typedef("unsigned int", "__pr_gid_t"),
            Item::Blank,
            Item::Decl("__BEGIN_DECLS"),
            Item::Blank,
            Item::Block { head: r#"struct elf_siginfo
  "#, body: &["", r#"    int si_signo;			/* Signal number.  */"#, r#"    int si_code;			/* Extra code.  */"#, r#"    int si_errno;			/* Errno.  */"#, "  "], tail: "" },
            Item::Blank,
            Item::Block { head: r#"struct elf_prstatus
  "#, body: &["", r#"    struct elf_siginfo pr_info;		/* Info associated with signal.  */"#, r#"    short int pr_cursig;		/* Current signal.  */"#, r#"    unsigned long int pr_sigpend;	/* Set of pending signals.  */"#, r#"    unsigned long int pr_sighold;	/* Set of held signals.  */"#, "    pid_t pr_pid;", "    pid_t pr_ppid;", "    pid_t pr_pgrp;", "    pid_t pr_sid;", r#"    struct timeval pr_utime;		/* User time.  */"#, r#"    struct timeval pr_stime;		/* System time.  */"#, r#"    struct timeval pr_cutime;		/* Cumulative user time.  */"#, r#"    struct timeval pr_cstime;		/* Cumulative system time.  */"#, r#"    elf_gregset_t pr_reg;		/* GP registers.  */"#, r#"    int pr_fpvalid;			/* True if math copro being used.  */"#, "  "], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("ELF_PRARGSZ", V::Txt(r#"(80)		/* Number of chars for args.  */"#)),
            ]),
            Item::Blank,
            Item::Block { head: r#"struct elf_prpsinfo
  "#, body: &["", r#"    char pr_state;			/* Numeric process state.  */"#, r#"    char pr_sname;			/* Char for pr_state.  */"#, r#"    char pr_zomb;			/* Zombie.  */"#, r#"    char pr_nice;			/* Nice val.  */"#, r#"    unsigned long int pr_flag;		/* Flags.  */"#, "    __pr_uid_t pr_uid;", "    __pr_gid_t pr_gid;", "    int pr_pid, pr_ppid, pr_pgrp, pr_sid;", r#"    char pr_fname[16];			/* Filename of executable.  */"#, r#"    char pr_psargs[ELF_PRARGSZ];	/* Initial part of arg list.  */"#, "  "], tail: "" },
            Item::Blank,
            Item::Comment("/* Solaris <proc_service.h> emulation for libthread_db users */"),
            Item::Typedef("void *", "psaddr_t"),
            Item::Blank,
            Item::Typedef("elf_gregset_t", "__prgregset_t"),
            Item::Typedef("elf_fpregset_t", "__prfpregset_t"),
            Item::Typedef("__prgregset_t", "prgregset_t"),
            Item::Typedef("__prfpregset_t", "prfpregset_t"),
            Item::Blank,
            Item::Comment("/* one PID type: Linux makes no difference between processes and threads */"),
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

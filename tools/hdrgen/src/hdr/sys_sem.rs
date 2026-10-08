use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/sem.h",
    items: &[
        Item::Guard { name: "_SYS_SEM_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<sys/ipc.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined _GNU_SOURCE", items: &[
                    Item::Consts(&[
                        ("__RLIBC_SEM_GNU", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: r#"if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)"#, items: &[
                    Item::Consts(&[
                        ("__RLIBC_SEM_MISC", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_SEM_GNU", items: &[
                    Item::Include("<bits/types/struct_timespec.h>"),
                ] },
            ], ""),
            Item::Blank,
            Item::Block { head: "struct semid_ds ", body: &["", "  struct ipc_perm sem_perm;", "  time_t sem_otime;", "  unsigned long int __sem_otime_high;", "  time_t sem_ctime;", "  unsigned long int __sem_ctime_high;", "  unsigned long int sem_nsems;", "  unsigned long int __glibc_reserved3;", "  unsigned long int __glibc_reserved4;", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("SEM_UNDO", V::Hex(0x1000)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("GETPID", V::Dec(11)),
                ("GETVAL", V::Dec(12)),
                ("GETALL", V::Dec(13)),
                ("GETNCNT", V::Dec(14)),
                ("GETZCNT", V::Dec(15)),
                ("SETVAL", V::Dec(16)),
                ("SETALL", V::Dec(17)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("_SEM_SEMUN_UNDEFINED", V::Dec(1)),
            ]),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_SEM_MISC", items: &[
                    Item::Consts(&[
                        ("SEM_STAT", V::Dec(18)),
                        ("SEM_INFO", V::Dec(19)),
                        ("SEM_STAT_ANY", V::Dec(20)),
                    ]),
                    Item::Block { head: "struct seminfo ", body: &["", "  int semmap;", "  int semmni;", "  int semmns;", "  int semmnu;", "  int semmsl;", "  int semopm;", "  int semume;", "  int semusz;", "  int semvmx;", "  int semaem;", ""], tail: "" },
                ] },
            ], ""),
            Item::Blank,
            Item::Block { head: "struct sembuf ", body: &["", "  unsigned short int sem_num;", "  short int sem_op;", "  short int sem_flg;", ""], tail: "" },
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-ipc-sem.h>"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_SEM_GNU", items: &[
                    Item::Include("<bits/rlibc-ipc-semgnu.h>"),
                ] },
            ], ""),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};

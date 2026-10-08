use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/shm.h",
    items: &[
        Item::Guard { name: "_SYS_SHM_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<sys/ipc.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: r#"if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)"#, items: &[
                    Item::Consts(&[
                        ("__RLIBC_SHM_MISC", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Decl("extern int __getpagesize (void) __attribute__ ((__const__));"),
            Item::ExternEnd,
            Item::Consts(&[
                ("SHMLBA", V::Txt("(__getpagesize ())")),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("SHM_R", V::Txt("0400")),
                ("SHM_W", V::Txt("0200")),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("SHM_RDONLY", V::Txt("010000")),
                ("SHM_RND", V::Txt("020000")),
                ("SHM_REMAP", V::Txt("040000")),
                ("SHM_EXEC", V::Txt("0100000")),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("SHM_LOCK", V::Dec(11)),
                ("SHM_UNLOCK", V::Dec(12)),
            ]),
            Item::Blank,
            Item::Typedef("unsigned long int", "shmatt_t"),
            Item::Blank,
            Item::Block { head: "struct shmid_ds ", body: &["", "  struct ipc_perm shm_perm;", "  size_t shm_segsz;", "  time_t shm_atime;", "  time_t shm_dtime;", "  time_t shm_ctime;", "  pid_t shm_cpid;", "  pid_t shm_lpid;", "  shmatt_t shm_nattch;", "  unsigned long int __glibc_reserved5;", "  unsigned long int __glibc_reserved6;", ""], tail: "" },
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_SHM_MISC", items: &[
                    Item::Consts(&[
                        ("SHM_STAT", V::Dec(13)),
                        ("SHM_INFO", V::Dec(14)),
                        ("SHM_STAT_ANY", V::Dec(15)),
                    ]),
                    Item::Blank,
                    Item::Consts(&[
                        ("SHM_DEST", V::Txt("01000")),
                        ("SHM_LOCKED", V::Txt("02000")),
                        ("SHM_HUGETLB", V::Txt("04000")),
                        ("SHM_NORESERVE", V::Txt("010000")),
                    ]),
                    Item::Blank,
                    Item::Consts(&[
                        ("SHM_HUGE_SHIFT", V::Dec(26)),
                        ("SHM_HUGE_MASK", V::Hex(0x3f)),
                        ("SHM_HUGE_16KB", V::Txt("(14 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_64KB", V::Txt("(16 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_512KB", V::Txt("(19 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_1MB", V::Txt("(20 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_2MB", V::Txt("(21 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_8MB", V::Txt("(23 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_16MB", V::Txt("(24 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_32MB", V::Txt("(25 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_256MB", V::Txt("(28 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_512MB", V::Txt("(29 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_1GB", V::Txt("(30 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_2GB", V::Txt("(31 << SHM_HUGE_SHIFT)")),
                        ("SHM_HUGE_16GB", V::Txt("(34U << SHM_HUGE_SHIFT)")),
                    ]),
                    Item::Blank,
                    Item::Block { head: "struct shminfo ", body: &["", "  unsigned long int shmmax;", "  unsigned long int shmmin;", "  unsigned long int shmmni;", "  unsigned long int shmseg;", "  unsigned long int shmall;", "  unsigned long int __glibc_reserved1;", "  unsigned long int __glibc_reserved2;", "  unsigned long int __glibc_reserved3;", "  unsigned long int __glibc_reserved4;", ""], tail: "" },
                    Item::Blank,
                    Item::Block { head: "struct shm_info ", body: &["", "  int used_ids;", "  unsigned long int shm_tot;", "  unsigned long int shm_rss;", "  unsigned long int shm_swp;", "  unsigned long int swap_attempts;", "  unsigned long int swap_successes;", ""], tail: "" },
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-ipc-shm.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};

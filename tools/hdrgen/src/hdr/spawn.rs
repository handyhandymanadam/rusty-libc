use crate::model::*;

pub static HDR: Header = Header {
    path: "spawn.h",
    items: &[
        Item::Guard { name: "_RLIBC_SPAWN_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<sched.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<bits/types/sigset_t.h>"),
            Item::Blank,
            Item::Decl("struct __spawn_action;"),
            Item::Blank,
            Item::Block { head: "typedef struct ", body: &["", "  short int __flags;", "  pid_t __pgrp;", "  sigset_t __sd;", "  sigset_t __ss;", "  struct sched_param __sp;", "  int __policy;", "  int __cgroup;", "  int __pad[15];", ""], tail: " posix_spawnattr_t" },
            Item::Blank,
            Item::Block { head: "typedef struct ", body: &["", "  int __allocated;", "  int __used;", "  struct __spawn_action *__actions;", "  int __pad[16];", ""], tail: " posix_spawn_file_actions_t" },
            Item::Blank,
            Item::Consts(&[
                ("POSIX_SPAWN_RESETIDS", V::Txt("0x01")),
                ("POSIX_SPAWN_SETPGROUP", V::Txt("0x02")),
                ("POSIX_SPAWN_SETSIGDEF", V::Txt("0x04")),
                ("POSIX_SPAWN_SETSIGMASK", V::Txt("0x08")),
                ("POSIX_SPAWN_SETSCHEDPARAM", V::Hex(0x10)),
                ("POSIX_SPAWN_SETSCHEDULER", V::Hex(0x20)),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_GNU", items: &[
                    Item::Consts(&[
                        ("POSIX_SPAWN_USEVFORK", V::Hex(0x40)),
                        ("POSIX_SPAWN_SETSID", V::Hex(0x80)),
                        ("POSIX_SPAWN_SETCGROUP", V::Hex(0x100)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-spawncalls.h>"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_MISC", items: &[
                    Item::Include("<bits/rlibc-spawncalls-misc.h>"),
                ] },
            ], ""),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};

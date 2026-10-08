use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/ipc.h",
    items: &[
        Item::Guard { name: "_SYS_IPC_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Include("<sys/types.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined _GNU_SOURCE", items: &[
                    Item::Consts(&[
                        ("__RLIBC_IPC_GNU", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Consts(&[
                ("IPC_CREAT", V::Txt("01000")),
                ("IPC_EXCL", V::Txt("02000")),
                ("IPC_NOWAIT", V::Txt("04000")),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("IPC_RMID", V::Dec(0)),
                ("IPC_SET", V::Dec(1)),
                ("IPC_STAT", V::Dec(2)),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_IPC_GNU", items: &[
                    Item::Consts(&[
                        ("IPC_INFO", V::Dec(3)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Consts(&[
                ("IPC_PRIVATE", V::Txt("((key_t) 0)")),
            ]),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef __RLIBC_STRUCT_IPC_PERM", items: &[
                    Item::Consts(&[
                        ("__RLIBC_STRUCT_IPC_PERM", V::Dec(1)),
                    ]),
                    Item::Block { head: "struct ipc_perm ", body: &["", "  key_t __key;", "  uid_t uid;", "  gid_t gid;", "  uid_t cuid;", "  gid_t cgid;", "  mode_t mode;", "  unsigned short int __seq;", "  unsigned short int __pad2;", "  unsigned long int __glibc_reserved1;", "  unsigned long int __glibc_reserved2;", ""], tail: "" },
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-ipc-ipc.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};

use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/perm.h",
    items: &[
        Item::Guard { name: "_SYS_PERM_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::ExternBegin,
            Item::Blank,
            Item::Decl("extern int ioperm (unsigned long int __from, unsigned long int __num, int __turn_on) __attribute__ ((__nothrow__));"),
            Item::Decl("extern int iopl (int __level) __attribute__ ((__nothrow__));"),
            Item::Blank,
            Item::ExternEnd,
        ]},
    ],
};

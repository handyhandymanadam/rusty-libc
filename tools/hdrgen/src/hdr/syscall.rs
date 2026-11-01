use crate::model::*;

pub static HDR: Header = Header {
    path: "syscall.h",
    items: &[
        Item::Comment("/* syscall.h: the older name of sys/syscall.h */"),
        Item::Include("<sys/syscall.h>"),
    ],
};

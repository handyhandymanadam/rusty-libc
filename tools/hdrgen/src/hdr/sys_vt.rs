use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/vt.h",
    items: &[
        Item::Comment("/* sys/vt.h: virtual terminal ioctls, as in glibc a thin wrapper of the kernel header */"),
        Item::Include("<linux/vt.h>"),
    ],
};

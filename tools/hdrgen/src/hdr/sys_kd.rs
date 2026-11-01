use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/kd.h",
    items: &[
        Item::Comment("/* sys/kd.h: console keyboard and display ioctls, as in glibc a thin wrapper of the kernel header */"),
        Item::Include("<linux/kd.h>"),
    ],
};

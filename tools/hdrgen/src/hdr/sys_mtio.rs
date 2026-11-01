use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/mtio.h",
    items: &[
        Item::Comment("/* sys/mtio.h: magnetic tape ioctls (the kernel's header, with sys/ioctl.h as glibc includes) */"),
        Item::Include("<sys/ioctl.h>"),
        Item::Include("<linux/mtio.h>"),
    ],
};

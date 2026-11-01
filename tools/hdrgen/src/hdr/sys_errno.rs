use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/errno.h",
    items: &[
        Item::Comment("/* sys/errno.h: the BSD name of errno.h */"),
        Item::Include("<errno.h>"),
    ],
};

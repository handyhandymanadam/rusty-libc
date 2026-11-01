use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/unistd.h",
    items: &[
        Item::Comment("/* sys/unistd.h: the BSD name of unistd.h */"),
        Item::Include("<unistd.h>"),
    ],
};

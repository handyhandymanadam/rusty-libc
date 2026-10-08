use crate::model::*;

pub static HDR: Header = Header {
    path: "syscall.h",
    items: &[
        Item::Include("<sys/syscall.h>"),
    ],
};

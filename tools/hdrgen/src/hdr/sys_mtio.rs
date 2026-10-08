use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/mtio.h",
    items: &[
        Item::Include("<sys/ioctl.h>"),
        Item::Include("<linux/mtio.h>"),
    ],
};

use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/termios.h",
    items: &[
        Item::Include("<termios.h>"),
    ],
};

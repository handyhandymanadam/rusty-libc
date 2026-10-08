use crate::model::*;

pub static HDR: Header = Header {
    path: "wait.h",
    items: &[
        Item::Include("<sys/wait.h>"),
    ],
};

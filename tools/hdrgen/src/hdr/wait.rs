use crate::model::*;

pub static HDR: Header = Header {
    path: "wait.h",
    items: &[
        Item::Comment("/* wait.h: the older name of sys/wait.h */"),
        Item::Include("<sys/wait.h>"),
    ],
};

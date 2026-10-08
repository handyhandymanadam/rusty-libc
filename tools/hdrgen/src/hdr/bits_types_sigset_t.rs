use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/sigset_t.h",
    items: &[
        Item::Guard { name: "__sigset_t_defined", value: "1", end: "", items: &[
            Item::Include("<bits/types/__sigset_t.h>"),
            Item::Typedef("__sigset_t", "sigset_t"),
        ]},
    ],
};

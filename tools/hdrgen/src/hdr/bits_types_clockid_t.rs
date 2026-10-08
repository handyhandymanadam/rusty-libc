use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/clockid_t.h",
    items: &[
        Item::Guard { name: "__clockid_t_defined", value: "1", end: "", items: &[
            Item::Typedef("int", "clockid_t"),
        ]},
    ],
};

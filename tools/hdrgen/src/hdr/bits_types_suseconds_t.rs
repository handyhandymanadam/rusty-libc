use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/suseconds_t.h",
    items: &[
        Item::Guard { name: "__suseconds_t_defined", value: "1", end: "", items: &[
            Item::Typedef("long", "suseconds_t"),
        ]},
    ],
};

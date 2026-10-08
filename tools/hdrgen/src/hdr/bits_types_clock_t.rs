use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/clock_t.h",
    items: &[
        Item::Guard { name: "__clock_t_defined", value: "1", end: "", items: &[
            Item::Typedef("long", "clock_t"),
        ]},
    ],
};

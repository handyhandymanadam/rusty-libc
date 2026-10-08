use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/time_t.h",
    items: &[
        Item::Guard { name: "__time_t_defined", value: "1", end: "", items: &[
            Item::Typedef("long", "time_t"),
        ]},
    ],
};

use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/timer_t.h",
    items: &[
        Item::Guard { name: "__timer_t_defined", value: "1", end: "", items: &[
            Item::Typedef("void *", "timer_t"),
        ]},
    ],
};

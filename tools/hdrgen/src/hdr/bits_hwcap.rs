use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/hwcap.h",
    items: &[
        Item::Guard { name: "_RLIBC_BITS_HWCAP_H", value: "1", end: "", items: &[
        ]},
    ],
};

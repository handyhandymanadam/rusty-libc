use crate::model::*;

pub static HDR: Header = Header {
    path: "gnu-versions.h",
    items: &[
        Item::Guard { name: "_GNU_VERSIONS_H", value: "1", end: "", items: &[
            Item::Consts(&[
                ("_GNU_OBSTACK_INTERFACE_VERSION", V::Dec(1)),
                ("_GNU_REGEX_INTERFACE_VERSION", V::Dec(1)),
                ("_GNU_GLOB_INTERFACE_VERSION", V::Dec(2)),
                ("_GNU_GETOPT_INTERFACE_VERSION", V::Dec(2)),
            ]),
        ]},
    ],
};

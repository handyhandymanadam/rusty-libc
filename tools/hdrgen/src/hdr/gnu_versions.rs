use crate::model::*;

pub static HDR: Header = Header {
    path: "gnu-versions.h",
    items: &[
        Item::Comment("/* gnu-versions.h for the Rust libc: interface versions of the GNU pieces glibc carries (same numbers as glibc 2.43). */"),
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

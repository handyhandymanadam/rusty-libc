use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/wordsize.h",
    items: &[
        Item::Comment("/* Word size of the target: x86-64 with 64-bit longs and pointers (the x32 ABI is not supported). */"),
        Item::Guard { name: "_RLIBC_BITS_WORDSIZE_H", value: "1", end: "", items: &[
            Item::Gate(&[
                Branch { head: "ifndef __WORDSIZE", items: &[
                    Item::Consts(&[
                        ("__WORDSIZE", V::Dec(64)),
                    ]),
                ] },
            ], ""),
            Item::Consts(&[
                ("__WORDSIZE_TIME64_COMPAT32", V::Dec(1)),
                ("__SYSCALL_WORDSIZE", V::Dec(64)),
            ]),
        ]},
    ],
};

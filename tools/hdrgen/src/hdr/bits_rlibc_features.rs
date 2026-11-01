use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/rlibc-features.h",
    items: &[
        Item::Comment(r#"/* Feature-test tiers for the hand-written headers of rusty-libc-extra (our stand-in for glibc's features.h):
     __RLIBC_USE_MISC   _DEFAULT_SOURCE (the default mode), _GNU_SOURCE, _BSD_SOURCE, _SVID_SOURCE
     __RLIBC_USE_GNU    _GNU_SOURCE
     __RLIBC_USE_XOPEN  _XOPEN_SOURCE or _GNU_SOURCE or MISC (glibc: __USE_XOPEN_EXTENDED or MISC)
     __RLIBC_USE_POSIX2008  POSIX.1-2008 or later, or MISC
     __RLIBC_USE_LF64   _LARGEFILE64_SOURCE or _GNU_SOURCE (the *64 names) */"#),
        Item::Guard { name: "_RLIBC_FEATURES_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Gate(&[
                Branch { head: r#"if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)"#, items: &[
                    Item::Consts(&[
                        ("__RLIBC_USE_MISC", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef _GNU_SOURCE", items: &[
                    Item::Consts(&[
                        ("__RLIBC_USE_GNU", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _GNU_SOURCE || defined _XOPEN_SOURCE || defined __RLIBC_USE_MISC", items: &[
                    Item::Consts(&[
                        ("__RLIBC_USE_XOPEN", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: r#"if defined __RLIBC_USE_MISC || (defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200809L) \
    || (defined _XOPEN_SOURCE && _XOPEN_SOURCE >= 700)"#, items: &[
                    Item::Consts(&[
                        ("__RLIBC_USE_POSIX2008", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _LARGEFILE64_SOURCE || defined _GNU_SOURCE", items: &[
                    Item::Consts(&[
                        ("__RLIBC_USE_LF64", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
        ]},
    ],
};

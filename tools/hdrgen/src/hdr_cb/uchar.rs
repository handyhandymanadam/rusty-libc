use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("__need_wint_t", V::Txt("")),
    ]),
    Item::Include("<stddef.h>"),
    Item::Undef("__need_wint_t"),
    Item::Gate(&[
        Branch { head: "ifndef ____mbstate_t_defined", items: &[
            Item::ConstsFlat(&[
                ("____mbstate_t_defined", V::Dec(1)),
            ]),
            Item::Block { head: "typedef struct ", body: &[" int __count; union { wint_t __wch; char __wchb[4]; } __value; "], tail: " __mbstate_t" },
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "ifndef __mbstate_t_defined", items: &[
            Item::ConstsFlat(&[
                ("__mbstate_t_defined", V::Dec(1)),
            ]),
            Item::Typedef("__mbstate_t", "mbstate_t"),
        ] },
    ], ""),
    Item::Include("<bits/types/locale_t.h>"),
    Item::Blank,
    Item::Gate(&[
        Branch { head: "ifndef __cplusplus", items: &[
            Item::Typedef("__UINT_LEAST16_TYPE__", "char16_t"),
            Item::Typedef("__UINT_LEAST32_TYPE__", "char32_t"),
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "if !defined __cpp_char8_t && (defined _GNU_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ > 201710L))", items: &[
            Item::Typedef("unsigned char", "char8_t"),
        ] },
    ], ""),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;


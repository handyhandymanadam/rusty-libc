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
    Item::Gate(&[
        Branch { head: "if !defined _BITS_TYPES_LOCALE_T_H && !defined _RLIBC_LOCALE_T", items: &[
            Item::ConstsFlat(&[
                ("_BITS_TYPES_LOCALE_T_H", V::Dec(1)),
                ("_RLIBC_LOCALE_T", V::Txt("")),
            ]),
            Item::Typedef("struct __locale_struct *", "__locale_t"),
            Item::Typedef("__locale_t", "locale_t"),
        ] },
    ], ""),
    Item::Blank,
    Item::Consts(&[
        ("WEOF", V::Txt("(0xffffffffu)")),
    ]),
    Item::Typedef("unsigned long", "wctype_t"),
    Item::Typedef("const __INT32_TYPE__ *", "wctrans_t"),
    Item::Blank,
    Item::Decl("int iswalnum(wint_t);"),
    Item::Decl("int iswalpha(wint_t);"),
    Item::Decl("int iswblank(wint_t);"),
    Item::Decl("int iswcntrl(wint_t);"),
    Item::Decl("int iswdigit(wint_t);"),
    Item::Decl("int iswgraph(wint_t);"),
    Item::Decl("int iswlower(wint_t);"),
    Item::Decl("int iswprint(wint_t);"),
    Item::Decl("int iswpunct(wint_t);"),
    Item::Decl("int iswspace(wint_t);"),
    Item::Decl("int iswupper(wint_t);"),
    Item::Decl("int iswxdigit(wint_t);"),
    Item::Decl("int iswalnum_l(wint_t, locale_t);"),
    Item::Decl("int iswalpha_l(wint_t, locale_t);"),
    Item::Decl("int iswblank_l(wint_t, locale_t);"),
    Item::Decl("int iswcntrl_l(wint_t, locale_t);"),
    Item::Decl("int iswdigit_l(wint_t, locale_t);"),
    Item::Decl("int iswgraph_l(wint_t, locale_t);"),
    Item::Decl("int iswlower_l(wint_t, locale_t);"),
    Item::Decl("int iswprint_l(wint_t, locale_t);"),
    Item::Decl("int iswpunct_l(wint_t, locale_t);"),
    Item::Decl("int iswspace_l(wint_t, locale_t);"),
    Item::Decl("int iswupper_l(wint_t, locale_t);"),
    Item::Decl("int iswxdigit_l(wint_t, locale_t);"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;


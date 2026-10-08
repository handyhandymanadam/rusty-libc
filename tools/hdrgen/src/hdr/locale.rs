use crate::model::*;

pub static HDR: Header = Header {
    path: "locale.h",
    items: &[
        Item::Guard { name: "_RLIBC_LOCALE_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Consts(&[
                ("LC_CTYPE", V::Dec(0)),
                ("LC_NUMERIC", V::Dec(1)),
                ("LC_TIME", V::Dec(2)),
                ("LC_COLLATE", V::Dec(3)),
                ("LC_MONETARY", V::Dec(4)),
                ("LC_MESSAGES", V::Dec(5)),
                ("LC_ALL", V::Dec(6)),
                ("LC_PAPER", V::Dec(7)),
                ("LC_NAME", V::Dec(8)),
                ("LC_ADDRESS", V::Dec(9)),
                ("LC_TELEPHONE", V::Dec(10)),
                ("LC_MEASUREMENT", V::Dec(11)),
                ("LC_IDENTIFICATION", V::Dec(12)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("LC_CTYPE_MASK", V::Txt("(1 << LC_CTYPE)")),
                ("LC_NUMERIC_MASK", V::Txt("(1 << LC_NUMERIC)")),
                ("LC_TIME_MASK", V::Txt("(1 << LC_TIME)")),
                ("LC_COLLATE_MASK", V::Txt("(1 << LC_COLLATE)")),
                ("LC_MONETARY_MASK", V::Txt("(1 << LC_MONETARY)")),
                ("LC_MESSAGES_MASK", V::Txt("(1 << LC_MESSAGES)")),
                ("LC_PAPER_MASK", V::Txt("(1 << LC_PAPER)")),
                ("LC_NAME_MASK", V::Txt("(1 << LC_NAME)")),
                ("LC_ADDRESS_MASK", V::Txt("(1 << LC_ADDRESS)")),
                ("LC_TELEPHONE_MASK", V::Txt("(1 << LC_TELEPHONE)")),
                ("LC_MEASUREMENT_MASK", V::Txt("(1 << LC_MEASUREMENT)")),
                ("LC_IDENTIFICATION_MASK", V::Txt("(1 << LC_IDENTIFICATION)")),
                ("LC_ALL_MASK", V::Txt(r#"(LC_CTYPE_MASK | LC_NUMERIC_MASK | LC_TIME_MASK | LC_COLLATE_MASK | LC_MONETARY_MASK | LC_MESSAGES_MASK \
                     | LC_PAPER_MASK | LC_NAME_MASK | LC_ADDRESS_MASK | LC_TELEPHONE_MASK | LC_MEASUREMENT_MASK | LC_IDENTIFICATION_MASK)"#)),
            ]),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef NULL", items: &[
                    Item::Consts(&[
                        ("NULL", V::Txt("((void *) 0)")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Block { head: r#"struct lconv
"#, body: &["", "  char *decimal_point;", "  char *thousands_sep;", "  char *grouping;", "  char *int_curr_symbol;", "  char *currency_symbol;", "  char *mon_decimal_point;", "  char *mon_thousands_sep;", "  char *mon_grouping;", "  char *positive_sign;", "  char *negative_sign;", "  char int_frac_digits;", "  char frac_digits;", "  char p_cs_precedes;", "  char p_sep_by_space;", "  char n_cs_precedes;", "  char n_sep_by_space;", "  char p_sign_posn;", "  char n_sign_posn;", "  char int_p_cs_precedes;", "  char int_p_sep_by_space;", "  char int_n_cs_precedes;", "  char int_n_sep_by_space;", "  char int_p_sign_posn;", "  char int_n_sign_posn;", ""], tail: "" },
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef _RLIBC_LOCALE_STRUCT", items: &[
                    Item::Consts(&[
                        ("_RLIBC_LOCALE_STRUCT", V::Dec(1)),
                    ]),
                    Item::Decl("struct __locale_data;"),
                    Item::Block { head: r#"struct __locale_struct
"#, body: &["", "  struct __locale_data *__locales[13];", "  const unsigned short int *__ctype_b;", "  const int *__ctype_tolower;", "  const int *__ctype_toupper;", "  const char *__names[13];", ""], tail: "" },
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if !defined _BITS_TYPES_LOCALE_T_H && !defined _RLIBC_LOCALE_T", items: &[
                    Item::Consts(&[
                        ("_BITS_TYPES_LOCALE_T_H", V::Dec(1)),
                        ("_RLIBC_LOCALE_T", V::Txt("")),
                    ]),
                    Item::Typedef("struct __locale_struct *", "__locale_t"),
                    Item::Typedef("__locale_t", "locale_t"),
                ] },
            ], ""),
            Item::Blank,
            Item::Consts(&[
                ("LC_GLOBAL_LOCALE", V::Txt("((locale_t) -1L)")),
            ]),
            Item::Blank,
            Item::Decl("extern char *setlocale (int __category, const char *__locale) __attribute__ ((__nothrow__));"),
            Item::Decl("extern struct lconv *localeconv (void) __attribute__ ((__nothrow__));"),
            Item::Decl("extern locale_t newlocale (int __category_mask, const char *__locale, locale_t __base) __attribute__ ((__nothrow__));"),
            Item::Decl("extern locale_t duplocale (locale_t __dataset) __attribute__ ((__nothrow__));"),
            Item::Decl("extern void freelocale (locale_t __dataset) __attribute__ ((__nothrow__));"),
            Item::Decl("extern locale_t uselocale (locale_t __dataset) __attribute__ ((__nothrow__));"),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};

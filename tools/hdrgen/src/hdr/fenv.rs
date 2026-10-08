use crate::model::*;

pub static HDR: Header = Header {
    path: "fenv.h",
    items: &[
        Item::Guard { name: "_RLIBC_FENV_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef _GNU_SOURCE", items: &[
                    Item::Gate(&[
                        Branch { head: "ifndef __RLIBC_MATH_GNU", items: &[
                            Item::Consts(&[
                                ("__RLIBC_MATH_GNU", V::Dec(1)),
                            ]),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: r#"if defined _GNU_SOURCE || defined __STDC_WANT_IEC_60559_BFP_EXT__ || defined __STDC_WANT_IEC_60559_FUNCS_EXT__ \
    || defined __STDC_WANT_IEC_60559_EXT__ || (defined __STDC_VERSION__ && __STDC_VERSION__ > 201710L)"#, items: &[
                    Item::Gate(&[
                        Branch { head: "ifndef __RLIBC_MATH_EXT", items: &[
                            Item::Consts(&[
                                ("__RLIBC_MATH_EXT", V::Dec(1)),
                            ]),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Blank,
            Item::Consts(&[
                ("FE_INVALID", V::Txt("0x01")),
                ("__FE_DENORM", V::Txt("0x02")),
                ("FE_DIVBYZERO", V::Txt("0x04")),
                ("FE_OVERFLOW", V::Txt("0x08")),
                ("FE_UNDERFLOW", V::Hex(0x10)),
                ("FE_INEXACT", V::Hex(0x20)),
                ("FE_ALL_EXCEPT", V::Txt("(FE_INEXACT | FE_DIVBYZERO | FE_UNDERFLOW | FE_OVERFLOW | FE_INVALID)")),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("FE_TONEAREST", V::Dec(0)),
                ("FE_DOWNWARD", V::Hex(0x400)),
                ("FE_UPWARD", V::Hex(0x800)),
                ("FE_TOWARDZERO", V::Hex(0xc00)),
            ]),
            Item::Blank,
            Item::Typedef("unsigned short int", "fexcept_t"),
            Item::Blank,
            Item::Block { head: "typedef struct ", body: &["", "  unsigned short int __control_word;", "  unsigned short int __glibc_reserved1;", "  unsigned short int __status_word;", "  unsigned short int __glibc_reserved2;", "  unsigned short int __tags;", "  unsigned short int __glibc_reserved3;", "  unsigned int __eip;", "  unsigned short int __cs_selector;", "  unsigned int __opcode:11;", "  unsigned int __glibc_reserved4:5;", "  unsigned int __data_offset;", "  unsigned short int __data_selector;", "  unsigned short int __glibc_reserved5;", "  unsigned int __mxcsr;", ""], tail: " fenv_t" },
            Item::Blank,
            Item::Consts(&[
                ("FE_DFL_ENV", V::Txt("((const fenv_t *) -1)")),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MATH_GNU", items: &[
                    Item::Consts(&[
                        ("FE_NOMASK_ENV", V::Txt("((const fenv_t *) -2)")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MATH_EXT", items: &[
                    Item::Block { head: "typedef struct ", body: &["", "  unsigned short int __control_word;", "  unsigned short int __glibc_reserved;", "  unsigned int __mxcsr;", ""], tail: " femode_t" },
                    Item::Consts(&[
                        ("FE_DFL_MODE", V::Txt("((const femode_t *) -1L)")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Include("<bits/rlibc-fenvcalls.h>"),
            Item::Blank,
        ]},
    ],
};

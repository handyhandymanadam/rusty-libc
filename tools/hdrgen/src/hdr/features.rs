use crate::model::*;

pub static HDR: Header = Header {
    path: "features.h",
    items: &[
        Item::Guard { name: "_FEATURES_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined _GNU_SOURCE", items: &[
                    Item::Undef("_ISOC95_SOURCE"),
                    Item::Consts(&[
                        ("_ISOC95_SOURCE", V::Dec(1)),
                    ]),
                    Item::Undef("_ISOC99_SOURCE"),
                    Item::Consts(&[
                        ("_ISOC99_SOURCE", V::Dec(1)),
                    ]),
                    Item::Undef("_ISOC11_SOURCE"),
                    Item::Consts(&[
                        ("_ISOC11_SOURCE", V::Dec(1)),
                    ]),
                    Item::Undef("_ISOC23_SOURCE"),
                    Item::Consts(&[
                        ("_ISOC23_SOURCE", V::Dec(1)),
                    ]),
                    Item::Undef("_ISOC2Y_SOURCE"),
                    Item::Consts(&[
                        ("_ISOC2Y_SOURCE", V::Dec(1)),
                    ]),
                    Item::Undef("_POSIX_SOURCE"),
                    Item::Consts(&[
                        ("_POSIX_SOURCE", V::Dec(1)),
                    ]),
                    Item::Undef("_POSIX_C_SOURCE"),
                    Item::Consts(&[
                        ("_POSIX_C_SOURCE", V::Txt("202405L")),
                    ]),
                    Item::Undef("_XOPEN_SOURCE"),
                    Item::Consts(&[
                        ("_XOPEN_SOURCE", V::Dec(800)),
                    ]),
                    Item::Undef("_XOPEN_SOURCE_EXTENDED"),
                    Item::Consts(&[
                        ("_XOPEN_SOURCE_EXTENDED", V::Dec(1)),
                    ]),
                    Item::Undef("_LARGEFILE_SOURCE"),
                    Item::Consts(&[
                        ("_LARGEFILE_SOURCE", V::Dec(1)),
                    ]),
                    Item::Undef("_LARGEFILE64_SOURCE"),
                    Item::Consts(&[
                        ("_LARGEFILE64_SOURCE", V::Dec(1)),
                    ]),
                    Item::Undef("_DEFAULT_SOURCE"),
                    Item::Consts(&[
                        ("_DEFAULT_SOURCE", V::Dec(1)),
                    ]),
                    Item::Undef("_ATFILE_SOURCE"),
                    Item::Consts(&[
                        ("_ATFILE_SOURCE", V::Dec(1)),
                    ]),
                    Item::Undef("_DYNAMIC_STACK_SIZE_SOURCE"),
                    Item::Consts(&[
                        ("_DYNAMIC_STACK_SIZE_SOURCE", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: r#"if (defined _DEFAULT_SOURCE || (!defined __STRICT_ANSI__ && !defined _ISOC99_SOURCE && !defined _ISOC11_SOURCE \
     && !defined _ISOC23_SOURCE && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE))"#, items: &[
                    Item::Undef("_DEFAULT_SOURCE"),
                    Item::Consts(&[
                        ("_DEFAULT_SOURCE", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined _DEFAULT_SOURCE && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE", items: &[
                    Item::Consts(&[
                        ("_POSIX_C_SOURCE", V::Txt("202405L")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined _XOPEN_SOURCE && !defined _POSIX_C_SOURCE", items: &[
                    Item::Gate(&[
                        Branch { head: "if (_XOPEN_SOURCE - 0) >= 800", items: &[
                            Item::Consts(&[
                                ("_POSIX_C_SOURCE", V::Txt("202405L")),
                            ]),
                        ] },
                        Branch { head: "elif (_XOPEN_SOURCE - 0) >= 700", items: &[
                            Item::Consts(&[
                                ("_POSIX_C_SOURCE", V::Txt("200809L")),
                            ]),
                        ] },
                        Branch { head: "elif (_XOPEN_SOURCE - 0) >= 600", items: &[
                            Item::Consts(&[
                                ("_POSIX_C_SOURCE", V::Txt("200112L")),
                            ]),
                        ] },
                        Branch { head: "elif (_XOPEN_SOURCE - 0) >= 500", items: &[
                            Item::Consts(&[
                                ("_POSIX_C_SOURCE", V::Txt("199506L")),
                            ]),
                        ] },
                        Branch { head: "else", items: &[
                            Item::Consts(&[
                                ("_POSIX_C_SOURCE", V::Dec(2)),
                            ]),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined _ISOC23_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ > 201710L)", items: &[
                    Item::Consts(&[
                        ("__GLIBC_USE_ISOC23", V::Dec(1)),
                    ]),
                ] },
                Branch { head: "else", items: &[
                    Item::Consts(&[
                        ("__GLIBC_USE_ISOC23", V::Dec(0)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _ISOC2Y_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ > 202311L)", items: &[
                    Item::Consts(&[
                        ("__GLIBC_USE_ISOC2Y", V::Dec(1)),
                    ]),
                ] },
                Branch { head: "else", items: &[
                    Item::Consts(&[
                        ("__GLIBC_USE_ISOC2Y", V::Dec(0)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if __GLIBC_USE_ISOC23", items: &[
                    Item::Consts(&[
                        ("__GLIBC_USE_C23_STRTOL", V::Dec(1)),
                    ]),
                ] },
                Branch { head: "else", items: &[
                    Item::Consts(&[
                        ("__GLIBC_USE_C23_STRTOL", V::Dec(0)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: r#"if defined _ISOC11_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 201112L) \
    || (defined __cplusplus && __cplusplus >= 201103L) || __GLIBC_USE_ISOC23"#, items: &[
                    Item::Consts(&[
                        ("__USE_ISOC11", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: r#"if defined _ISOC99_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L) \
    || (defined __cplusplus && __cplusplus >= 201103L) || defined __USE_ISOC11"#, items: &[
                    Item::Consts(&[
                        ("__USE_ISOC99", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _ISOC95_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199409L) || defined __USE_ISOC99", items: &[
                    Item::Consts(&[
                        ("__USE_ISOC95", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: r#"if (defined _POSIX_SOURCE || defined _POSIX_C_SOURCE || defined _XOPEN_SOURCE || defined _DEFAULT_SOURCE) \
    && !(defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE \
         && !defined _DEFAULT_SOURCE)"#, items: &[
                    Item::Consts(&[
                        ("__USE_POSIX", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 2 || defined _XOPEN_SOURCE", items: &[
                    Item::Consts(&[
                        ("__USE_POSIX2", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 199309L", items: &[
                    Item::Consts(&[
                        ("__USE_POSIX199309", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 199506L", items: &[
                    Item::Consts(&[
                        ("__USE_POSIX199506", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200112L", items: &[
                    Item::Consts(&[
                        ("__USE_XOPEN2K", V::Dec(1)),
                    ]),
                    Item::Undef("__USE_ISOC95"),
                    Item::Consts(&[
                        ("__USE_ISOC95", V::Dec(1)),
                    ]),
                    Item::Undef("__USE_ISOC99"),
                    Item::Consts(&[
                        ("__USE_ISOC99", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200809L", items: &[
                    Item::Consts(&[
                        ("__USE_XOPEN2K8", V::Dec(1)),
                    ]),
                    Item::Undef("_ATFILE_SOURCE"),
                    Item::Consts(&[
                        ("_ATFILE_SOURCE", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 202405L", items: &[
                    Item::Consts(&[
                        ("__USE_XOPEN2K24", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef _XOPEN_SOURCE", items: &[
                    Item::Consts(&[
                        ("__USE_XOPEN", V::Dec(1)),
                    ]),
                    Item::Gate(&[
                        Branch { head: "if (_XOPEN_SOURCE - 0) >= 500", items: &[
                            Item::Consts(&[
                                ("__USE_XOPEN_EXTENDED", V::Dec(1)),
                                ("__USE_UNIX98", V::Dec(1)),
                            ]),
                            Item::Undef("_LARGEFILE_SOURCE"),
                            Item::Consts(&[
                                ("_LARGEFILE_SOURCE", V::Dec(1)),
                            ]),
                            Item::Gate(&[
                                Branch { head: "if (_XOPEN_SOURCE - 0) >= 600", items: &[
                                    Item::Consts(&[
                                        ("__USE_XOPEN2K", V::Dec(1)),
                                        ("__USE_XOPEN2KXSI", V::Dec(1)),
                                    ]),
                                    Item::Undef("__USE_ISOC99"),
                                    Item::Consts(&[
                                        ("__USE_ISOC99", V::Dec(1)),
                                    ]),
                                    Item::Gate(&[
                                        Branch { head: "if (_XOPEN_SOURCE - 0) >= 700", items: &[
                                            Item::Consts(&[
                                                ("__USE_XOPEN2K8", V::Dec(1)),
                                                ("__USE_XOPEN2K8XSI", V::Dec(1)),
                                            ]),
                                            Item::Undef("_ATFILE_SOURCE"),
                                            Item::Consts(&[
                                                ("_ATFILE_SOURCE", V::Dec(1)),
                                            ]),
                                        ] },
                                    ], ""),
                                    Item::Gate(&[
                                        Branch { head: "if (_XOPEN_SOURCE - 0) >= 800", items: &[
                                            Item::Consts(&[
                                                ("__USE_XOPEN2K24", V::Dec(1)),
                                                ("__USE_XOPEN2K24XSI", V::Dec(1)),
                                            ]),
                                        ] },
                                    ], ""),
                                ] },
                            ], ""),
                        ] },
                        Branch { head: "elif defined _XOPEN_SOURCE_EXTENDED", items: &[
                            Item::Consts(&[
                                ("__USE_XOPEN_EXTENDED", V::Dec(1)),
                            ]),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef _XOPEN_SOURCE_EXTENDED", items: &[
                    Item::Consts(&[
                        ("__USE_XOPEN_EXTENDED", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef _DEFAULT_SOURCE", items: &[
                    Item::Consts(&[
                        ("__USE_MISC", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _LARGEFILE_SOURCE", items: &[
                    Item::Consts(&[
                        ("__USE_LARGEFILE", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _LARGEFILE64_SOURCE", items: &[
                    Item::Consts(&[
                        ("__USE_LARGEFILE64", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef _ATFILE_SOURCE", items: &[
                    Item::Consts(&[
                        ("__USE_ATFILE", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef _DYNAMIC_STACK_SIZE_SOURCE", items: &[
                    Item::Consts(&[
                        ("__USE_DYNAMIC_STACK_SIZE", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef _GNU_SOURCE", items: &[
                    Item::Consts(&[
                        ("__USE_GNU", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Consts(&[
                ("__USE_TIME_BITS64", V::Dec(1)),
                ("__USE_FORTIFY_LEVEL", V::Dec(0)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("__GNU_LIBRARY__", V::Dec(6)),
                ("__GLIBC__", V::Dec(2)),
                ("__GLIBC_MINOR__", V::Dec(43)),
            ]),
            Item::Raw(Reason::GlibcMacro, "#define __GLIBC_PREREQ(maj, min) ((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined __cplusplus ? __cplusplus >= 201402L : defined __USE_ISOC11", items: &[
                    Item::Consts(&[
                        ("__GLIBC_USE_DEPRECATED_GETS", V::Dec(0)),
                    ]),
                ] },
                Branch { head: "else", items: &[
                    Item::Consts(&[
                        ("__GLIBC_USE_DEPRECATED_GETS", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: r#"if (defined __USE_GNU \
     && (defined __cplusplus ? (__cplusplus < 201103L && !defined __GXX_EXPERIMENTAL_CXX0X__) \
                             : (!defined __STDC_VERSION__ || __STDC_VERSION__ < 199901L)))"#, items: &[
                    Item::Consts(&[
                        ("__GLIBC_USE_DEPRECATED_SCANF", V::Dec(1)),
                    ]),
                ] },
                Branch { head: "else", items: &[
                    Item::Consts(&[
                        ("__GLIBC_USE_DEPRECATED_SCANF", V::Dec(0)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Include("<bits/rlibc-cdefs.h>"),
            Item::Include("<bits/types.h>"),
            Item::Blank,
        ]},
    ],
};

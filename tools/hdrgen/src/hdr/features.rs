use crate::model::*;

pub static HDR: Header = Header {
    path: "features.h",
    items: &[
        Item::Comment(r#"/* features.h for the Rust libc: the glibc identity macros and the feature-test logic, written from
   glibc's documented rules (feature_test_macros(7)); the _ISOC2X_SOURCE remap and the POSIX-level block follow glibc 2.43's
   include/features.h conditions (LGPL-2.1-or-later, see LICENSES.md). Every public header includes it, so
   __GLIBC__ and the __USE_* macros are visible after any standard include, as programs expect. The
   compiler-helper macros (__THROW, __BEGIN_DECLS, __nonnull, ...) are in bits/rlibc-cdefs.h. */"#),
        Item::Guard { name: "_FEATURES_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Comment("/* what the program asked for (_ISOC2X_SOURCE is the old name of _ISOC23_SOURCE) */"),
            Item::Gate(&[
                Branch { head: "ifdef _ISOC2X_SOURCE", items: &[
                    Item::Undef("_ISOC2X_SOURCE"),
                    Item::Undef("_ISOC23_SOURCE"),
                    Item::Consts(&[
                        ("_ISOC23_SOURCE", V::Dec(1)),
                    ]),
                ] },
            ], ""),
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
            Item::Comment("/* no feature macro at all: the default mode */"),
            Item::Gate(&[
                Branch { head: r#"if (defined _DEFAULT_SOURCE || (!defined __STRICT_ANSI__ && !defined _ISOC99_SOURCE && !defined _ISOC11_SOURCE \
     && !defined _ISOC23_SOURCE && !defined _ISOC2Y_SOURCE && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE))"#, items: &[
                    Item::Undef("_DEFAULT_SOURCE"),
                    Item::Consts(&[
                        ("_DEFAULT_SOURCE", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Comment(r#"/* the POSIX level (as glibc 2.43): _DEFAULT_SOURCE selects POSIX.1-2024; a program that names no POSIX level
   gets one implicitly unless it is strict ISO C (then only from _XOPEN_SOURCE 500 or later), matching _XOPEN_SOURCE;
   _REENTRANT and _THREAD_SAFE raise it to 199506L */"#),
            Item::Raw(Reason::FeatureTest, r#"#ifdef _DEFAULT_SOURCE
# if !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE
#  define __USE_POSIX_IMPLICITLY 1
# endif
# undef _POSIX_SOURCE
# define _POSIX_SOURCE 1
# undef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 202405L
#endif
#if ((!defined __STRICT_ANSI__ || (defined _XOPEN_SOURCE && (_XOPEN_SOURCE - 0) >= 500)) \
     && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE)
# define _POSIX_SOURCE 1
# if defined _XOPEN_SOURCE && (_XOPEN_SOURCE - 0) < 500
#  define _POSIX_C_SOURCE 2
# elif defined _XOPEN_SOURCE && (_XOPEN_SOURCE - 0) < 600
#  define _POSIX_C_SOURCE 199506L
# elif defined _XOPEN_SOURCE && (_XOPEN_SOURCE - 0) < 700
#  define _POSIX_C_SOURCE 200112L
# elif defined _XOPEN_SOURCE && (_XOPEN_SOURCE - 0) < 800
#  define _POSIX_C_SOURCE 200809L
# else
#  define _POSIX_C_SOURCE 202405L
# endif
# define __USE_POSIX_IMPLICITLY 1
#endif
#if ((!defined _POSIX_C_SOURCE || (_POSIX_C_SOURCE - 0) < 199506L) && (defined _REENTRANT || defined _THREAD_SAFE))
# define _POSIX_SOURCE 1
# undef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 199506L
#endif"#),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined _ISOC23_SOURCE || defined _ISOC2Y_SOURCE || (defined __STDC_VERSION__ && __STDC_VERSION__ > 201710L)", items: &[
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
            Item::Comment("/* C23 added a 0b prefix to the strtol family; glibc's headers select the C23 entry points with this */"),
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
            Item::Comment("/* POSIX and X/Open levels */"),
            Item::Gate(&[
                Branch { head: "if defined _POSIX_SOURCE || (defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 1) || defined _XOPEN_SOURCE", items: &[
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
            Item::Comment("/* x86-64: time_t is 64 bits, no 32-bit variants */"),
            Item::Consts(&[
                ("__USE_TIME_BITS64", V::Dec(1)),
            ]),
            Item::Comment("/* _FORTIFY_SOURCE: level 1, 2 or 3 (3 needs gcc 12 or clang 9 for __builtin_dynamic_object_size); the wrappers need optimization */"),
            Item::Gate(&[
                Branch { head: "if defined _FORTIFY_SOURCE && _FORTIFY_SOURCE > 0", items: &[
                    Item::Gate(&[
                        Branch { head: "if !defined __OPTIMIZE__ || __OPTIMIZE__ <= 0", items: &[
                            Item::Raw(Reason::Other, "#  warning _FORTIFY_SOURCE requires compiling with optimization (-O)"),
                        ] },
                        Branch { head: "elif _FORTIFY_SOURCE > 2 && ((defined __clang__ && __clang_major__ >= 9) || (defined __GNUC__ && __GNUC__ >= 12))", items: &[
                            Item::Gate(&[
                                Branch { head: "if _FORTIFY_SOURCE > 3", items: &[
                                    Item::Raw(Reason::Other, "#   warning _FORTIFY_SOURCE > 3 is treated like 3 on this platform"),
                                ] },
                            ], ""),
                            Item::Consts(&[
                                ("__USE_FORTIFY_LEVEL", V::Dec(3)),
                            ]),
                        ] },
                        Branch { head: "elif _FORTIFY_SOURCE > 1", items: &[
                            Item::Gate(&[
                                Branch { head: "if _FORTIFY_SOURCE > 2", items: &[
                                    Item::Raw(Reason::Other, "#   warning _FORTIFY_SOURCE > 2 is treated like 2 on this platform"),
                                ] },
                            ], ""),
                            Item::Consts(&[
                                ("__USE_FORTIFY_LEVEL", V::Dec(2)),
                            ]),
                        ] },
                        Branch { head: "else", items: &[
                            Item::Consts(&[
                                ("__USE_FORTIFY_LEVEL", V::Dec(1)),
                            ]),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifndef __USE_FORTIFY_LEVEL", items: &[
                    Item::Consts(&[
                        ("__USE_FORTIFY_LEVEL", V::Dec(0)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Comment("/* which glibc this library follows */"),
            Item::Consts(&[
                ("__GNU_LIBRARY__", V::Dec(6)),
                ("__GLIBC__", V::Dec(2)),
                ("__GLIBC_MINOR__", V::Dec(43)),
            ]),
            Item::Raw(Reason::GlibcMacro, "#define __GLIBC_PREREQ(maj, min) ((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))"),
            Item::Blank,
            Item::Comment("/* gets is gone from C11 (and C++14); scanf's old %a (allocate a string) extension is what -std=c89/gnu89 with _GNU_SOURCE selects */"),
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
            Item::Comment(r#"/* Headers may define `extern inline' functions (stdio.h's getc_unlocked, ...) when the code is optimized for speed and
   inlining is on, as glibc decides it. */"#),
            Item::Gate(&[
                Branch { head: "if defined __GNUC__ && defined __OPTIMIZE__ && !defined __OPTIMIZE_SIZE__ && !defined __NO_INLINE__ && defined __extern_inline", items: &[
                    Item::Consts(&[
                        ("__USE_EXTERN_INLINES", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
        ]},
    ],
};

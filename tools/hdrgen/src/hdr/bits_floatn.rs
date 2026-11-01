use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/floatn.h",
    items: &[
        Item::Comment(r#"/* bits/floatn.h: which TS 18661-3 floating types exist on x86-64 and how to spell their literals and complex types
   (the same macro names and values as glibc's header of that name; GCC 7 or later, and clang). */"#),
        Item::Guard { name: "_BITS_FLOATN_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::Consts(&[
                ("__HAVE_FLOAT128", V::Dec(1)),
                ("__HAVE_DISTINCT_FLOAT128", V::Dec(1)),
                ("__HAVE_FLOAT64X", V::Dec(1)),
                ("__HAVE_FLOAT64X_LONG_DOUBLE", V::Dec(1)),
            ]),
            // clang (C) has no _Float128 keyword, f128 literal suffix or _Complex _Float128: glibc's header spells them with
            // __float128, the q suffix and a TC-mode complex type there (its branch for compilers other than GCC 7 or later)
            Item::Gate(&[
                Branch { head: "ifndef __ASSEMBLER__", items: &[
                    Item::Gate(&[
                        Branch { head: "if defined __clang__", items: &[
                            Item::Raw(Reason::GlibcMacro, "#  define __f128(x) x##q"),
                            Item::Raw(Reason::Other, "typedef _Complex float __cfloat128 __attribute__ ((__mode__ (__TC__)));"),
                            Item::Raw(Reason::Other, "#  define __CFLOAT128 __cfloat128"),
                            Item::Raw(Reason::Other, "typedef __float128 _Float128;"),
                            // glibc defines it for every compiler before GCC 6 (clang says it is GCC 4.2): there is no
                            // __builtin_signbitf128, so a call of it goes to the library's __signbitf128
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_signbitf128 __signbitf128"),
                        ] },
                        Branch { head: "else", items: &[
                            Item::Raw(Reason::GlibcMacro, "#  define __f128(x) x##f128"),
                            Item::Raw(Reason::Other, "#  define __CFLOAT128 _Complex _Float128"),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Include("<bits/floatn-common.h>"),
        ]},
    ],
};

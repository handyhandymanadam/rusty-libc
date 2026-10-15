use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/floatn.h",
    items: &[
        Item::Guard { name: "_BITS_FLOATN_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::Consts(&[
                ("__HAVE_FLOAT128", V::Dec(1)),
                ("__HAVE_DISTINCT_FLOAT128", V::Dec(1)),
                ("__HAVE_FLOAT64X", V::Dec(1)),
                ("__HAVE_FLOAT64X_LONG_DOUBLE", V::Dec(1)),
            ]),
            Item::Gate(&[
                Branch { head: "ifndef __ASSEMBLER__", items: &[
                    Item::Gate(&[
                        Branch { head: "if defined __clang__", items: &[
                            Item::Raw(Reason::GlibcMacro, "#  define __f128(x) x##q"),
                            Item::Raw(Reason::Other, "typedef _Complex float __cfloat128 __attribute__ ((__mode__ (__TC__)));"),
                            Item::Raw(Reason::Other, "#  define __CFLOAT128 __cfloat128"),
                            Item::Raw(Reason::Other, "typedef __float128 _Float128;"),
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

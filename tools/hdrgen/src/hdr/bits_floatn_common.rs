use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/floatn-common.h",
    items: &[
        Item::Guard { name: "_BITS_FLOATN_COMMON_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::Consts(&[
                ("__HAVE_FLOAT16", V::Dec(0)),
                ("__HAVE_FLOAT32", V::Dec(1)),
                ("__HAVE_FLOAT64", V::Dec(1)),
                ("__HAVE_FLOAT32X", V::Dec(1)),
                ("__HAVE_FLOAT128X", V::Dec(0)),
                ("__HAVE_DISTINCT_FLOAT16", V::Txt("__HAVE_FLOAT16")),
                ("__HAVE_DISTINCT_FLOAT32", V::Dec(0)),
                ("__HAVE_DISTINCT_FLOAT64", V::Dec(0)),
                ("__HAVE_DISTINCT_FLOAT32X", V::Dec(0)),
                ("__HAVE_DISTINCT_FLOAT64X", V::Dec(0)),
                ("__HAVE_DISTINCT_FLOAT128X", V::Txt("__HAVE_FLOAT128X")),
                ("__HAVE_FLOAT128_UNLIKE_LDBL", V::Txt("(__HAVE_DISTINCT_FLOAT128 && __LDBL_MANT_DIG__ != 113)")),
            ]),
            Item::Gate(&[
                Branch { head: "if !defined __cplusplus", items: &[
                    Item::Consts(&[
                        ("__HAVE_FLOATN_NOT_TYPEDEF", V::Dec(1)),
                    ]),
                ] },
                Branch { head: "else", items: &[
                    Item::Consts(&[
                        ("__HAVE_FLOATN_NOT_TYPEDEF", V::Dec(0)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifndef __ASSEMBLER__", items: &[
                    Item::Raw(Reason::GlibcMacro, "# define __f32(x) x##f32"),
                    Item::Raw(Reason::GlibcMacro, "# define __f64(x) x##f64"),
                    Item::Raw(Reason::GlibcMacro, "# define __f32x(x) x##f32x"),
                    Item::Raw(Reason::GlibcMacro, "# define __f64x(x) x##f64x"),
                    Item::Consts(&[
                        ("__CFLOAT32", V::Txt("_Complex _Float32")),
                        ("__CFLOAT64", V::Txt("_Complex _Float64")),
                        ("__CFLOAT32X", V::Txt("_Complex _Float32x")),
                        ("__CFLOAT64X", V::Txt("_Complex _Float64x")),
                    ]),
                ] },
            ], ""),
        ]},
    ],
};

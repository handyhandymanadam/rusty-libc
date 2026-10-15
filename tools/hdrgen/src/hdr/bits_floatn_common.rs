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
                Branch { head: "if !defined __cplusplus && !defined __clang__", items: &[
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
                    Item::Gate(&[
                        Branch { head: "if defined __clang__", items: &[
                            Item::Raw(Reason::GlibcMacro, "#  define __f32(x) x##f"),
                            Item::Raw(Reason::GlibcMacro, "#  define __f64(x) x"),
                            Item::Raw(Reason::GlibcMacro, "#  define __f32x(x) x"),
                            Item::Raw(Reason::GlibcMacro, "#  define __f64x(x) x##l"),
                            Item::Raw(Reason::Other, "typedef float _Float32;"),
                            Item::Raw(Reason::Other, "typedef double _Float64;"),
                            Item::Raw(Reason::Other, "typedef double _Float32x;"),
                            Item::Raw(Reason::Other, "typedef long double _Float64x;"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_huge_valf32() (__builtin_huge_valf ())"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_inff32() (__builtin_inff ())"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_nanf32(x) (__builtin_nanf (x))"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_nansf32(x) (__builtin_nansf (x))"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_huge_valf64() (__builtin_huge_val ())"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_inff64() (__builtin_inf ())"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_nanf64(x) (__builtin_nan (x))"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_nansf64(x) (__builtin_nans (x))"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_huge_valf32x() (__builtin_huge_val ())"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_inff32x() (__builtin_inf ())"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_nanf32x(x) (__builtin_nan (x))"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_nansf32x(x) (__builtin_nans (x))"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_huge_valf64x() (__builtin_huge_vall ())"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_inff64x() (__builtin_infl ())"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_nanf64x(x) (__builtin_nanl (x))"),
                            Item::Raw(Reason::GlibcMacro, "#  define __builtin_nansf64x(x) (__builtin_nansl (x))"),
                            Item::Raw(Reason::Other, "#  define __CFLOAT32 _Complex float"),
                            Item::Raw(Reason::Other, "#  define __CFLOAT64 _Complex double"),
                            Item::Raw(Reason::Other, "#  define __CFLOAT32X _Complex double"),
                            Item::Raw(Reason::Other, "#  define __CFLOAT64X _Complex long double"),
                        ] },
                        Branch { head: "else", items: &[
                            Item::Raw(Reason::GlibcMacro, "#  define __f32(x) x##f32"),
                            Item::Raw(Reason::GlibcMacro, "#  define __f64(x) x##f64"),
                            Item::Raw(Reason::GlibcMacro, "#  define __f32x(x) x##f32x"),
                            Item::Raw(Reason::GlibcMacro, "#  define __f64x(x) x##f64x"),
                            Item::Raw(Reason::Other, "#  define __CFLOAT32 _Complex _Float32"),
                            Item::Raw(Reason::Other, "#  define __CFLOAT64 _Complex _Float64"),
                            Item::Raw(Reason::Other, "#  define __CFLOAT32X _Complex _Float32x"),
                            Item::Raw(Reason::Other, "#  define __CFLOAT64X _Complex _Float64x"),
                        ] },
                    ], ""),
                ] },
            ], ""),
        ]},
    ],
};

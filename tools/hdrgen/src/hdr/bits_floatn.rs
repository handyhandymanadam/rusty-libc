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
                    Item::Raw(Reason::GlibcMacro, "# define __f128(x) x##f128"),
                    Item::Consts(&[
                        ("__CFLOAT128", V::Txt("_Complex _Float128")),
                    ]),
                ] },
            ], ""),
            Item::Include("<bits/floatn-common.h>"),
        ]},
    ],
};

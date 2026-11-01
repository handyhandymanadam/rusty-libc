use crate::model::*;

pub static HDR: Header = Header {
    path: "stdc-predef.h",
    items: &[
        Item::Comment("/* stdc-predef.h for the Rust libc (gcc includes it implicitly): what the C library promises, same as glibc 2.43. */"),
        Item::Guard { name: "_STDC_PREDEF_H", value: "1", end: "", items: &[
            Item::Consts(&[
                ("__STDC_IEC_559__", V::Dec(1)),
                ("__STDC_IEC_60559_BFP__", V::Txt("201404L")),
                ("__STDC_IEC_559_COMPLEX__", V::Dec(1)),
                ("__STDC_IEC_60559_COMPLEX__", V::Txt("201404L")),
                ("__STDC_ISO_10646__", V::Txt("201706L")),
            ]),
        ]},
    ],
};

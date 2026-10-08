use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/endian.h",
    items: &[
        Item::Guard { name: "_BITS_ENDIAN_H", value: "1", end: "", items: &[
            Item::Consts(&[
                ("__LITTLE_ENDIAN", V::Dec(1234)),
                ("__BIG_ENDIAN", V::Dec(4321)),
                ("__PDP_ENDIAN", V::Dec(3412)),
                ("__BYTE_ORDER", V::Txt("__LITTLE_ENDIAN")),
                ("__FLOAT_WORD_ORDER", V::Txt("__BYTE_ORDER")),
            ]),
        ]},
    ],
};

use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/waitflags.h",
    items: &[
        Item::Guard { name: "_BITS_WAITFLAGS_H", value: "1", end: "", items: &[
            Item::Consts(&[
                ("WNOHANG", V::Dec(1)),
                ("WUNTRACED", V::Dec(2)),
                ("WSTOPPED", V::Dec(2)),
                ("WEXITED", V::Dec(4)),
                ("WCONTINUED", V::Dec(8)),
                ("WNOWAIT", V::Txt("0x01000000")),
                ("__WNOTHREAD", V::Hex(0x20000000)),
                ("__WALL", V::Hex(0x40000000)),
                ("__WCLONE", V::Hex(0x80000000)),
            ]),
        ]},
    ],
};

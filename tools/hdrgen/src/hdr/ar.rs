use crate::model::*;

pub static HDR: Header = Header {
    path: "ar.h",
    items: &[
        Item::Guard { name: "_AR_H", value: "1", end: "", items: &[
            Item::Include("<sys/types.h>"),
            Item::Consts(&[
                ("ARMAG", V::Txt(r#""!<arch>\n""#)),
                ("SARMAG", V::Dec(8)),
                ("ARFMAG", V::Txt(r#""`\n""#)),
            ]),
            Item::Block { head: r#"struct ar_hdr
  "#, body: &["", "    char ar_name[16];", "    char ar_date[12];", "    char ar_uid[6], ar_gid[6];", "    char ar_mode[8];", "    char ar_size[10];", "    char ar_fmag[2];", "  "], tail: "" },
        ]},
    ],
};

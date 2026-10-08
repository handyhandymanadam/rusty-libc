use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/dir.h",
    items: &[
        Item::Include("<dirent.h>"),
        Item::Consts(&[
            ("direct", V::Txt("dirent")),
        ]),
    ],
};

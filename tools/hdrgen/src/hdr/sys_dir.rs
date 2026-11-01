use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/dir.h",
    items: &[
        Item::Comment("/* sys/dir.h: the BSD name; struct direct is struct dirent */"),
        Item::Include("<dirent.h>"),
        Item::Consts(&[
            ("direct", V::Txt("dirent")),
        ]),
    ],
};

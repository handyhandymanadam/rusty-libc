use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/locale_t.h",
    items: &[
        Item::Gate(&[
            Branch { head: "ifndef ____locale_t_defined", items: &[
                Item::ConstsFlat(&[
                    ("____locale_t_defined", V::Dec(1)),
                ]),
                Item::Decl("struct __locale_struct;"),
                Item::Typedef("struct __locale_struct *", "__locale_t"),
            ] },
        ], ""),
        Item::Gate(&[
            Branch { head: "ifndef __locale_t_defined", items: &[
                Item::ConstsFlat(&[
                    ("__locale_t_defined", V::Dec(1)),
                ]),
                Item::Typedef("__locale_t", "locale_t"),
            ] },
        ], ""),
    ],
};

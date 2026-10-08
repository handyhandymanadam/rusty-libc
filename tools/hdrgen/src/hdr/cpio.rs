use crate::model::*;

pub static HDR: Header = Header {
    path: "cpio.h",
    items: &[
        Item::Guard { name: "_CPIO_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::ExternBegin,
            Item::Consts(&[
                ("C_IRGRP", V::Txt("000040")),
                ("C_IROTH", V::Txt("000004")),
                ("C_IRUSR", V::Txt("000400")),
                ("C_ISBLK", V::Txt("060000")),
                ("C_ISCHR", V::Txt("020000")),
                ("C_ISCTG", V::Txt("0110000")),
                ("C_ISDIR", V::Txt("040000")),
                ("C_ISFIFO", V::Txt("010000")),
                ("C_ISGID", V::Txt("002000")),
                ("C_ISLNK", V::Txt("0120000")),
                ("C_ISREG", V::Txt("0100000")),
                ("C_ISSOCK", V::Txt("0140000")),
                ("C_ISUID", V::Txt("004000")),
                ("C_ISVTX", V::Txt("001000")),
                ("C_IWGRP", V::Txt("000020")),
                ("C_IWOTH", V::Txt("000002")),
                ("C_IWUSR", V::Txt("000200")),
                ("C_IXGRP", V::Txt("000010")),
                ("C_IXOTH", V::Txt("000001")),
                ("C_IXUSR", V::Txt("000100")),
                ("MAGIC", V::Txt(r#""070707""#)),
            ]),
            Item::ExternEnd,
        ]},
    ],
};

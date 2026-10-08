use crate::model::*;

pub static HDR: Header = Header {
    path: "sgtty.h",
    items: &[
        Item::Guard { name: "_SGTTY_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<features.h>"),
            Item::Include("<sys/ioctl.h>"),
            Item::Blank,
            Item::Decl("struct sgttyb;"),
            Item::Blank,
            Item::Decl("__BEGIN_DECLS"),
            Item::Blank,
            Item::Decl("extern int gtty (int __fd, struct sgttyb *__params) __THROW;"),
            Item::Decl("extern int stty (int __fd, const struct sgttyb *__params) __THROW;"),
            Item::Blank,
            Item::Decl("__END_DECLS"),
            Item::Blank,
        ]},
    ],
};

use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("FD_SETSIZE", V::Dec(1024)),
        ("NFDBITS", V::Dec(64)),
    ]),
    Item::Blank,
    Item::Typedef("long int", "__fd_mask"),
    Item::Consts(&[
        ("__NFDBITS", V::Txt("(8 * (int)sizeof(__fd_mask))")),
    ]),
    Item::Block { head: "typedef struct ", body: &["", "  __fd_mask fds_bits[1024 / (8 * (int)sizeof(__fd_mask))];", ""], tail: " fd_set" },
    Item::Typedef("__fd_mask", "fd_mask"),
    Item::Raw(Reason::GlibcMacro, "#define __FD_MASK(d) ((__fd_mask)(1UL << ((d) % __NFDBITS)))"),
    Item::Raw(Reason::StdMacro, "#define FD_SET(fd, set) ((void)(((set)->fds_bits)[(fd) / __NFDBITS] |= __FD_MASK(fd)))"),
    Item::Raw(Reason::StdMacro, "#define FD_CLR(fd, set) ((void)(((set)->fds_bits)[(fd) / __NFDBITS] &= ~__FD_MASK(fd)))"),
    Item::Raw(Reason::StdMacro, "#define FD_ISSET(fd, set) ((((set)->fds_bits)[(fd) / __NFDBITS] & __FD_MASK(fd)) != 0)"),
    Item::Raw(Reason::StdMacro, r#"#define FD_ZERO(set) \
  do { unsigned int __i; fd_set *__arr = (set); \
       for (__i = 0; __i < sizeof(fd_set) / sizeof(__fd_mask); ++__i) __arr->fds_bits[__i] = 0; } while (0)"#),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;


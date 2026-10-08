use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("_DIRENT_MATCHES_DIRENT64", V::Dec(1)),
        ("DT_UNKNOWN", V::Dec(0)),
        ("DT_FIFO", V::Dec(1)),
        ("DT_CHR", V::Dec(2)),
        ("DT_DIR", V::Dec(4)),
        ("DT_BLK", V::Dec(6)),
        ("DT_REG", V::Dec(8)),
        ("DT_LNK", V::Dec(10)),
        ("DT_SOCK", V::Dec(12)),
        ("DT_WHT", V::Dec(14)),
        ("MAXNAMLEN", V::Dec(255)),
    ]),
    Item::Gate(&[
        Branch { head: "ifdef __USE_MISC", items: &[
            Item::Include("<limits.h>"),
        ] },
    ], ""),
    Item::Blank,
    Item::Typedef("struct __dirstream", "DIR"),
    Item::Block { head: "struct dirent64 ", body: &["", "  uint64_t d_ino;", "  int64_t d_off;", "  unsigned short d_reclen;", "  unsigned char d_type;", "  char d_name[256];", ""], tail: "" },
    Item::Consts(&[
        ("d_fileno", V::Txt("d_ino")),
        ("_DIRENT_HAVE_D_RECLEN", V::Dec(1)),
        ("_DIRENT_HAVE_D_OFF", V::Dec(1)),
        ("_DIRENT_HAVE_D_TYPE", V::Dec(1)),
    ]),
    Item::Gate(&[
        Branch { head: "ifdef __USE_MISC", items: &[
            Item::Raw(Reason::GlibcMacro, "# define _D_EXACT_NAMLEN(d) (strlen ((d)->d_name))"),
            Item::Raw(Reason::GlibcMacro, "# define _D_ALLOC_NAMLEN(d) (((char *) (d) + (d)->d_reclen) - &(d)->d_name[0])"),
        ] },
    ], ""),
    Item::Raw(Reason::GlibcMacro, "#define IFTODT(mode) (((mode) & 0170000) >> 12)"),
    Item::Raw(Reason::GlibcMacro, "#define DTTOIF(dirtype) ((dirtype) << 12)"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;


use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Include("<bits/types/locale_t.h>"),
    Item::Blank,
    Item::Include("<bits/endian.h>"),
    Item::Gate(&[
        Branch { head: "ifndef _ISbit", items: &[
            Item::Gate(&[
                Branch { head: "if __BYTE_ORDER == __BIG_ENDIAN", items: &[
                    Item::Raw(Reason::GlibcMacro, "# define _ISbit(bit) (1 << (bit))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::GlibcMacro, "# define _ISbit(bit) ((bit) < 8 ? ((1 << (bit)) << 8) : ((1 << (bit)) >> 8))"),
                ] },
            ], ""),
            Item::Block { head: "enum\n", body: &["", "  _ISupper = _ISbit (0),", "  _ISlower = _ISbit (1),", "  _ISalpha = _ISbit (2),", "  _ISdigit = _ISbit (3),", "  _ISxdigit = _ISbit (4),", "  _ISspace = _ISbit (5),", "  _ISprint = _ISbit (6),", "  _ISgraph = _ISbit (7),", "  _ISblank = _ISbit (8),", "  _IScntrl = _ISbit (9),", "  _ISpunct = _ISbit (10),", "  _ISalnum = _ISbit (11)", ""], tail: "" },
        ] },
    ], ""),
    Item::Blank,
    Item::Decl("int isalnum(int);"),
    Item::Decl("int isalpha(int);"),
    Item::Decl("int isblank(int);"),
    Item::Decl("int iscntrl(int);"),
    Item::Decl("int isdigit(int);"),
    Item::Decl("int isgraph(int);"),
    Item::Decl("int islower(int);"),
    Item::Decl("int isprint(int);"),
    Item::Decl("int ispunct(int);"),
    Item::Decl("int isspace(int);"),
    Item::Decl("int isupper(int);"),
    Item::Decl("int isxdigit(int);"),
    Item::Decl("int isalnum_l(int, locale_t);"),
    Item::Decl("int isalpha_l(int, locale_t);"),
    Item::Decl("int isblank_l(int, locale_t);"),
    Item::Decl("int iscntrl_l(int, locale_t);"),
    Item::Decl("int isdigit_l(int, locale_t);"),
    Item::Decl("int isgraph_l(int, locale_t);"),
    Item::Decl("int islower_l(int, locale_t);"),
    Item::Decl("int isprint_l(int, locale_t);"),
    Item::Decl("int ispunct_l(int, locale_t);"),
    Item::Decl("int isspace_l(int, locale_t);"),
    Item::Decl("int isupper_l(int, locale_t);"),
    Item::Decl("int isxdigit_l(int, locale_t);"),
    Item::Decl("int tolower_l(int, locale_t);"),
    Item::Decl("int toupper_l(int, locale_t);"),
    Item::Gate(&[
        Branch { head: "if !defined __STRICT_ANSI__ || defined _GNU_SOURCE || defined _DEFAULT_SOURCE", items: &[
            Item::Raw(Reason::GlibcMacro, "# define isascii_l(c, l) __isascii_l ((c), (l))"),
            Item::Raw(Reason::GlibcMacro, "# define toascii_l(c, l) __toascii_l ((c), (l))"),
        ] },
    ], ""),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;


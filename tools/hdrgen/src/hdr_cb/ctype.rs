use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Gate(&[
        Branch { head: "ifndef _RLIBC_LOCALE_T", items: &[
            Item::ConstsFlat(&[
                ("_RLIBC_LOCALE_T", V::Txt("")),
            ]),
            Item::Typedef("struct __locale_struct *", "locale_t"),
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


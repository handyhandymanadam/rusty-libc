use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Decl("struct dirent;"),
    Item::Decl("struct stat;"),
    Item::Decl("struct dirent64;"),
    Item::Decl("struct stat64;"),
    Item::Blank,
    Item::Consts(&[
        ("GLOB_ERR", V::Txt("(1 << 0)")),
        ("GLOB_MARK", V::Txt("(1 << 1)")),
        ("GLOB_NOSORT", V::Txt("(1 << 2)")),
        ("GLOB_DOOFFS", V::Txt("(1 << 3)")),
        ("GLOB_NOCHECK", V::Txt("(1 << 4)")),
        ("GLOB_APPEND", V::Txt("(1 << 5)")),
        ("GLOB_NOESCAPE", V::Txt("(1 << 6)")),
        ("GLOB_PERIOD", V::Txt("(1 << 7)")),
        ("GLOB_MAGCHAR", V::Txt("(1 << 8)")),
        ("GLOB_ALTDIRFUNC", V::Txt("(1 << 9)")),
        ("GLOB_BRACE", V::Txt("(1 << 10)")),
        ("GLOB_NOMAGIC", V::Txt("(1 << 11)")),
        ("GLOB_TILDE", V::Txt("(1 << 12)")),
        ("GLOB_ONLYDIR", V::Txt("(1 << 13)")),
        ("GLOB_TILDE_CHECK", V::Txt("(1 << 14)")),
        ("GLOB_NOSPACE", V::Dec(1)),
        ("GLOB_ABORTED", V::Dec(2)),
        ("GLOB_NOMATCH", V::Dec(3)),
        ("GLOB_NOSYS", V::Dec(4)),
    ]),
    Item::Blank,
    Item::Block { head: "typedef struct ", body: &["", "  size_t gl_pathc;", "  char **gl_pathv;", "  size_t gl_offs;", "  int gl_flags;", "  void (*gl_closedir)(void *);", "  struct dirent *(*gl_readdir)(void *);", "  void *(*gl_opendir)(const char *);", "  int (*gl_lstat)(const char *__restrict, struct stat *__restrict);", "  int (*gl_stat)(const char *__restrict, struct stat *__restrict);", ""], tail: " glob_t" },
    Item::Blank,
    Item::Block { head: "typedef struct ", body: &["", "  size_t gl_pathc;", "  char **gl_pathv;", "  size_t gl_offs;", "  int gl_flags;", "  void (*gl_closedir)(void *);", "  struct dirent64 *(*gl_readdir)(void *);", "  void *(*gl_opendir)(const char *);", "  int (*gl_lstat)(const char *__restrict, struct stat64 *__restrict);", "  int (*gl_stat)(const char *__restrict, struct stat64 *__restrict);", ""], tail: " glob64_t" },
    Item::Blank,
    Item::Decl("int glob64(const char *__pattern, int __flags, int (*__errfunc)(const char *, int), glob64_t *__pglob);"),
    Item::Decl("void globfree64(glob64_t *__pglob);"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;


use crate::model::*;

pub static HDR: Header = Header {
    path: "wordexp.h",
    items: &[
        Item::Comment(r#"/* wordexp.h for the Rust libc (crates/rusty-libc-util/src/wordexp.rs): POSIX.2 word expansion. The types and
   constants are written here with glibc's values; the prototypes are generated
   (bits/rlibc-wordexpcalls.h). */"#),
        Item::Guard { name: "_RLIBC_WORDEXP_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Consts(&[
                ("__need_size_t", V::Txt("")),
            ]),
            Item::Include("<stddef.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Comment("/* Bits set in the FLAGS argument to `wordexp'.  */"),
            Item::Block { head: "enum ", body: &["", "  WRDE_DOOFFS = (1 << 0),   /* Insert PWORDEXP->we_offs NULLs.  */", "  WRDE_APPEND = (1 << 1),   /* Append to results of a previous call.  */", "  WRDE_NOCMD = (1 << 2),    /* Don't do command substitution.  */", "  WRDE_REUSE = (1 << 3),    /* Reuse storage in PWORDEXP.  */", "  WRDE_SHOWERR = (1 << 4),  /* Don't redirect stderr to /dev/null.  */", "  WRDE_UNDEF = (1 << 5),    /* Error for expanding undefined variables.  */", "  __WRDE_FLAGS = (WRDE_DOOFFS | WRDE_APPEND | WRDE_NOCMD | WRDE_REUSE | WRDE_SHOWERR | WRDE_UNDEF)", ""], tail: "" },
            Item::Blank,
            Item::Comment("/* Structure describing a word-expansion run.  */"),
            Item::Block { head: "typedef struct ", body: &["", "  size_t we_wordc;   /* Count of words matched.  */", "  char **we_wordv;   /* List of expanded words.  */", "  size_t we_offs;    /* Slots to reserve in `we_wordv'.  */", ""], tail: " wordexp_t" },
            Item::Blank,
            Item::Comment("/* Possible nonzero return values from `wordexp'.  */"),
            Item::Block { head: "enum ", body: &["", "#ifdef __USE_XOPEN", "  WRDE_NOSYS = -1,   /* Never used since we support `wordexp'.  */", "#endif", "  WRDE_NOSPACE = 1,  /* Ran out of memory.  */", "  WRDE_BADCHAR,      /* A metachar appears in the wrong place.  */", "  WRDE_BADVAL,       /* Undefined var reference with WRDE_UNDEF.  */", "  WRDE_CMDSUB,       /* Command substitution with WRDE_NOCMD.  */", "  WRDE_SYNTAX        /* Shell syntax error.  */", ""], tail: "" },
            Item::Blank,
            Item::Include("<bits/rlibc-wordexpcalls.h>"),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};

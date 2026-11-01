use crate::model::*;

pub static HDR: Header = Header {
    path: "dlfcn.h",
    items: &[
        Item::Comment(r#"/* dlfcn.h for the Rust libc (crates/rusty-libc-extra/src/dlfcn.rs). The runtime's programs are static: dlopen
   hands out a handle for the program itself (NULL or "" as the name) and nothing else can be loaded;
   see the crate for the exact behaviour. Written by hand (constants, structures, and a handful of
   prototypes with void pointers). */"#),
        Item::Guard { name: "_RLIBC_DLFCN_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<stddef.h>"),
            Item::Blank,
            Item::Comment("/* Flags of dlopen. */"),
            Item::Consts(&[
                ("RTLD_LAZY", V::Txt("0x00001")),
                ("RTLD_NOW", V::Txt("0x00002")),
                ("RTLD_BINDING_MASK", V::Hex(0x3)),
                ("RTLD_NOLOAD", V::Txt("0x00004")),
                ("RTLD_DEEPBIND", V::Txt("0x00008")),
                ("RTLD_GLOBAL", V::Txt("0x00100")),
                ("RTLD_LOCAL", V::Dec(0)),
                ("RTLD_NODELETE", V::Txt("0x01000")),
            ]),
            Item::Blank,
            Item::Comment("/* Pseudo handles of dlsym. */"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_MISC", items: &[
                    Item::Consts(&[
                        ("RTLD_NEXT", V::Txt("((void *) -1l)")),
                        ("RTLD_DEFAULT", V::Txt("((void *) 0)")),
                    ]),
                    Item::Typedef("long int", "Lmid_t"),
                    Item::Consts(&[
                        ("LM_ID_BASE", V::Dec(0)),
                        ("LM_ID_NEWLM", V::Dec(-1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Decl("extern void *dlopen (const char *__file, int __mode);"),
            Item::Decl("extern int dlclose (void *__handle);"),
            Item::Decl("extern void *dlsym (void *__restrict __handle, const char *__restrict __name);"),
            Item::Decl("extern char *dlerror (void);"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_GNU", items: &[
                    Item::Decl("extern void *dlmopen (Lmid_t __nsid, const char *__file, int __mode);"),
                    Item::Decl("extern void *dlvsym (void *__restrict __handle, const char *__restrict __name, const char *__restrict __version);"),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_MISC", items: &[
                    Item::Comment("/* Information about an address (dladdr). */"),
                    Item::Block { head: "typedef struct ", body: &["", "  const char *dli_fname;        /* file name of the object */", "  void *dli_fbase;              /* load address of the object */", "  const char *dli_sname;        /* name of the symbol (NULL: none known) */", "  void *dli_saddr;              /* address of that symbol */", ""], tail: " Dl_info" },
                    Item::Blank,
                    Item::Decl("extern int dladdr (const void *__address, Dl_info *__info);"),
                    Item::Decl("extern int dladdr1 (const void *__address, Dl_info *__info, void **__extra_info, int __flags);"),
                    Item::Blank,
                    Item::Comment("/* Values of the flags of dladdr1. */"),
                    Item::Block { head: "enum ", body: &["", "  RTLD_DL_SYMENT = 1,           /* the symbol table entry in *EXTRA_INFO */", "  RTLD_DL_LINKMAP = 2           /* the link map in *EXTRA_INFO */", ""], tail: "" },
                    Item::Blank,
                    Item::Comment("/* Requests of dlinfo. */"),
                    Item::Block { head: "enum ", body: &["", "  RTLD_DI_LMID = 1,", "  RTLD_DI_LINKMAP = 2,", "  RTLD_DI_CONFIGADDR = 3,", "  RTLD_DI_SERINFO = 4,", "  RTLD_DI_SERINFOSIZE = 5,", "  RTLD_DI_ORIGIN = 6,", "  RTLD_DI_PROFILENAME = 7,", "  RTLD_DI_PROFILEOUT = 8,", "  RTLD_DI_TLS_MODID = 9,", "  RTLD_DI_TLS_DATA = 10,", "  RTLD_DI_MAX = 11", ""], tail: "" },
                    Item::Blank,
                    Item::Comment("/* The search path entries of RTLD_DI_SERINFO. */"),
                    Item::Block { head: "typedef struct ", body: &["", "  char *dls_name;", "  unsigned int dls_flags;", ""], tail: " Dl_serpath" },
                    Item::Blank,
                    Item::Block { head: "typedef struct ", body: &["", "  size_t dls_size;", "  unsigned int dls_cnt;", "  Dl_serpath dls_serpath[1];", ""], tail: " Dl_serinfo" },
                    Item::Blank,
                    Item::Decl("extern int dlinfo (void *__restrict __handle, int __request, void *__restrict __arg);"),
                ] },
            ], ""),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};

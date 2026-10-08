use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/profil.h",
    items: &[
        Item::Guard { name: "_PROFIL_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<features.h>"),
            Item::Include("<sys/time.h>"),
            Item::Include("<sys/types.h>"),
            Item::Blank,
            Item::Block { head: r#"struct prof
  "#, body: &["", r#"    void *pr_base;"#, r#"    size_t pr_size;"#, r#"    size_t pr_off;"#, r#"    unsigned long int pr_scale;"#, "  "], tail: "" },
            Item::Blank,
            Item::Block { head: r#"enum
  "#, body: &["", r#"    PROF_USHORT	= 0,"#, r#"    PROF_UINT	= 1 << 0,"#, r#"    PROF_FAST   = 1 << 1"#, "  "], tail: "" },
            Item::Blank,
            Item::Decl("__BEGIN_DECLS"),
            Item::Blank,
            Item::Decl(r#"extern int sprofil (struct prof *__profp, int __profcnt,
		    struct timeval *__tvp, unsigned int __flags) __THROW;"#),
            Item::Blank,
            Item::Decl("__END_DECLS"),
            Item::Blank,
        ]},
    ],
};

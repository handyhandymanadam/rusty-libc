use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/profil.h",
    items: &[
        Item::Comment(r#"/* sys/profil.h for the Rust libc: sprofil, the multi-region program counter profiler (described by the
   sprofil(2) page of Irix 6.5, with unsigned long scale, size_t size and offset). */"#),
        Item::Guard { name: "_PROFIL_H", value: "1", end: " /* profil.h */", items: &[
            Item::Blank,
            Item::Include("<features.h>"),
            Item::Include("<sys/time.h>"),
            Item::Include("<sys/types.h>"),
            Item::Blank,
            Item::Block { head: r#"struct prof
  "#, body: &["", r#"    void *pr_base;		/* buffer base */"#, r#"    size_t pr_size;		/* buffer size */"#, r#"    size_t pr_off;		/* pc offset */"#, r#"    unsigned long int pr_scale;	/* pc scaling (fixed-point number) */"#, "  "], tail: "" },
            Item::Blank,
            Item::Block { head: r#"enum
  "#, body: &["", r#"    PROF_USHORT	= 0,		/* use 16-bit counters (default) */"#, r#"    PROF_UINT	= 1 << 0,	/* use 32-bit counters */"#, r#"    PROF_FAST   = 1 << 1	/* profile faster than usual */"#, "  "], tail: "" },
            Item::Blank,
            Item::Decl("__BEGIN_DECLS"),
            Item::Blank,
            Item::Comment(r#"/* Sample the program counter into the counters of the regions in PROFP (an overflow bin has pr_off 0
   and pr_scale 2); with PROFCNT 0 stop. TVP receives the clock tick. */"#),
            Item::Decl(r#"extern int sprofil (struct prof *__profp, int __profcnt,
		    struct timeval *__tvp, unsigned int __flags) __THROW;"#),
            Item::Blank,
            Item::Decl("__END_DECLS"),
            Item::Blank,
        ]},
    ],
};

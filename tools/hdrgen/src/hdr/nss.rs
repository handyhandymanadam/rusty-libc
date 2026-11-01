use crate::model::*;

pub static HDR: Header = Header {
    path: "nss.h",
    items: &[
        Item::Comment(r#"/* nss.h for the Rust libc: the status codes of name service modules and the call that overrides the
   service list of a database (the module-side prototypes of glibc's header are not provided: this
   library has the `files` and `dns` sources built in and loads no modules). */"#),
        Item::Guard { name: "_NSS_H", value: "1", end: " /* nss.h */", items: &[
            Item::Blank,
            Item::Include("<features.h>"),
            Item::Blank,
            Item::Decl("__BEGIN_DECLS"),
            Item::Blank,
            Item::Comment("/* Possible results of lookup using a nss_* function. */"),
            Item::Block { head: r#"enum nss_status
"#, body: &["", "  NSS_STATUS_TRYAGAIN = -2,", "  NSS_STATUS_UNAVAIL,", "  NSS_STATUS_NOTFOUND,", "  NSS_STATUS_SUCCESS,", "  NSS_STATUS_RETURN", ""], tail: "" },
            Item::Blank,
            Item::Comment(r#"/* Overwrite the service selection for database DBNAME with the specification in STRING (an
   nsswitch.conf line). Returns 0, or -1 (EINVAL for a malformed STRING; an unknown database leaves
   errno alone). */"#),
            Item::Decl(r#"extern int __nss_configure_lookup (const char *__dbname,
                                   const char *__string) __THROW;"#),
            Item::Blank,
            Item::Decl("__END_DECLS"),
            Item::Blank,
        ]},
    ],
};

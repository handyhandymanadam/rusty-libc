use crate::model::*;

pub static HDR: Header = Header {
    path: "nss.h",
    items: &[
        Item::Guard { name: "_NSS_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<features.h>"),
            Item::Blank,
            Item::Decl("__BEGIN_DECLS"),
            Item::Blank,
            Item::Block { head: r#"enum nss_status
"#, body: &["", "  NSS_STATUS_TRYAGAIN = -2,", "  NSS_STATUS_UNAVAIL,", "  NSS_STATUS_NOTFOUND,", "  NSS_STATUS_SUCCESS,", "  NSS_STATUS_RETURN", ""], tail: "" },
            Item::Blank,
            Item::Decl(r#"extern int __nss_configure_lookup (const char *__dbname,
                                   const char *__string) __THROW;"#),
            Item::Blank,
            Item::Decl("__END_DECLS"),
            Item::Blank,
        ]},
    ],
};

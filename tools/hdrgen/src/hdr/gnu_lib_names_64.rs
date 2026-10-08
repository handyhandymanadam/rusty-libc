use crate::model::*;

pub static HDR: Header = Header {
    path: "gnu/lib-names-64.h",
    items: &[
        Item::Consts(&[
            ("LD_LINUX_X86_64_SO", V::Sp(r#"             "ld-linux-x86-64.so.2""#)),
            ("LD_SO", V::Sp(r#"                          "ld-linux-x86-64.so.2""#)),
            ("LIBANL_SO", V::Sp(r#"                      "libanl.so.1""#)),
            ("LIBBROKENLOCALE_SO", V::Sp(r#"             "libBrokenLocale.so.1""#)),
            ("LIBC_MALLOC_DEBUG_SO", V::Sp(r#"           "libc_malloc_debug.so.0""#)),
            ("LIBC_SO", V::Sp(r#"                        "libc.so.6""#)),
            ("LIBDL_SO", V::Sp(r#"                       "libdl.so.2""#)),
            ("LIBGCC_S_SO", V::Sp(r#"                    "libgcc_s.so.1""#)),
            ("LIBMVEC_SO", V::Sp(r#"                     "libmvec.so.1""#)),
            ("LIBM_SO", V::Sp(r#"                        "libm.so.6""#)),
            ("LIBNSL_SO", V::Sp(r#"                      "libnsl.so.1""#)),
            ("LIBNSS_COMPAT_SO", V::Sp(r#"               "libnss_compat.so.2""#)),
            ("LIBNSS_DB_SO", V::Sp(r#"                   "libnss_db.so.2""#)),
            ("LIBNSS_DNS_SO", V::Sp(r#"                  "libnss_dns.so.2""#)),
            ("LIBNSS_FILES_SO", V::Sp(r#"                "libnss_files.so.2""#)),
            ("LIBNSS_HESIOD_SO", V::Sp(r#"               "libnss_hesiod.so.2""#)),
            ("LIBNSS_LDAP_SO", V::Sp(r#"                 "libnss_ldap.so.2""#)),
            ("LIBPTHREAD_SO", V::Sp(r#"                  "libpthread.so.0""#)),
            ("LIBRESOLV_SO", V::Sp(r#"                   "libresolv.so.2""#)),
            ("LIBRT_SO", V::Sp(r#"                       "librt.so.1""#)),
            ("LIBTHREAD_DB_SO", V::Sp(r#"                "libthread_db.so.1""#)),
            ("LIBUTIL_SO", V::Sp(r#"                     "libutil.so.1""#)),
        ]),
    ],
};

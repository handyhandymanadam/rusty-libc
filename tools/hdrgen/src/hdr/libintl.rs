use crate::model::*;

pub static HDR: Header = Header {
    path: "libintl.h",
    items: &[
        Item::Guard { name: "_RLIBC_LIBINTL_H", value: "1", end: "", items: &[
            Item::Include("<locale.h>"),
            Item::ExternBegin,
            Item::Decl("extern char *gettext (const char *__msgid);"),
            Item::Decl("extern char *dgettext (const char *__domainname, const char *__msgid);"),
            Item::Decl("extern char *dcgettext (const char *__domainname, const char *__msgid, int __category);"),
            Item::Decl("extern char *ngettext (const char *__msgid1, const char *__msgid2, unsigned long int __n);"),
            Item::Decl("extern char *dngettext (const char *__domainname, const char *__msgid1, const char *__msgid2, unsigned long int __n);"),
            Item::Decl("extern char *dcngettext (const char *__domainname, const char *__msgid1, const char *__msgid2, unsigned long int __n, int __category);"),
            Item::Decl("extern char *textdomain (const char *__domainname);"),
            Item::Decl("extern char *bindtextdomain (const char *__domainname, const char *__dirname);"),
            Item::Decl("extern char *bind_textdomain_codeset (const char *__domainname, const char *__codeset);"),
            Item::ExternEnd,
        ]},
    ],
};

#ifndef _RLIBC_LIBINTL_H
#define _RLIBC_LIBINTL_H 1
#include <locale.h>
#ifdef __cplusplus
extern "C" {
#endif
extern char *gettext (const char *__msgid);
extern char *dgettext (const char *__domainname, const char *__msgid);
extern char *dcgettext (const char *__domainname, const char *__msgid, int __category);
extern char *ngettext (const char *__msgid1, const char *__msgid2, unsigned long int __n);
extern char *dngettext (const char *__domainname, const char *__msgid1, const char *__msgid2, unsigned long int __n);
extern char *dcngettext (const char *__domainname, const char *__msgid1, const char *__msgid2, unsigned long int __n, int __category);
extern char *textdomain (const char *__domainname);
extern char *bindtextdomain (const char *__domainname, const char *__dirname);
extern char *bind_textdomain_codeset (const char *__domainname, const char *__codeset);
#ifdef __cplusplus
}
#endif
#endif

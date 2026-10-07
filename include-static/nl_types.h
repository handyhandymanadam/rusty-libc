#ifndef _RLIBC_NL_TYPES_H
#define _RLIBC_NL_TYPES_H 1
#ifdef __cplusplus
extern "C" {
#endif
#define NL_SETD 1
#define NL_CAT_LOCALE 1
typedef void *nl_catd;
typedef int nl_item;
extern nl_catd catopen (const char *__cat_name, int __flag);
extern char *catgets (nl_catd __catalog, int __set, int __number, const char *__string);
extern int catclose (nl_catd __catalog);
#ifdef __cplusplus
}
#endif
#endif

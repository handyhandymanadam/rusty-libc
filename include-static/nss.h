#ifndef _NSS_H
#define _NSS_H 1

#include <features.h>

__BEGIN_DECLS

enum nss_status
{
  NSS_STATUS_TRYAGAIN = -2,
  NSS_STATUS_UNAVAIL,
  NSS_STATUS_NOTFOUND,
  NSS_STATUS_SUCCESS,
  NSS_STATUS_RETURN
};

extern int __nss_configure_lookup (const char *__dbname,
                                   const char *__string) __THROW;

__END_DECLS

#endif

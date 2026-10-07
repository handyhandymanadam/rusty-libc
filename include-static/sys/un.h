#ifndef _SYS_UN_H
#define _SYS_UN_H 1
#include <stddef.h>
#include <string.h>
#ifndef __sa_family_t_defined
#define __sa_family_t_defined 1
typedef unsigned short int sa_family_t;
#endif

struct sockaddr_un {
  sa_family_t sun_family;
  char sun_path[108];
};

#define SUN_LEN(ptr) ((size_t) offsetof (struct sockaddr_un, sun_path) + strlen ((ptr)->sun_path))
#endif

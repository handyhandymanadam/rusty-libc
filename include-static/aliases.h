#ifndef _ALIASES_H
#define _ALIASES_H 1
#include <stddef.h>

struct aliasent {
  char *alias_name;
  size_t alias_members_len;
  char **alias_members;
  int alias_local;
};

#include <bits/rlibc-net-aliases.h>
#endif

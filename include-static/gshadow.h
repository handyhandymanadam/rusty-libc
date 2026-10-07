#ifndef _RLIBC_GSHADOW_H
#define _RLIBC_GSHADOW_H 1

#include <bits/rlibc-features.h>
#include <paths.h>
#include <stdio.h>
#include <stddef.h>

#define GSHADOW _PATH_GSHADOW

struct sgrp {
  char *sg_namp;
  char *sg_passwd;
  char **sg_adm;
  char **sg_mem;
};

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-gshadowcalls.h>
#ifdef __cplusplus
}
#endif

#endif

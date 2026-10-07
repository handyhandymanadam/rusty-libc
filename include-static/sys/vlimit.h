#ifndef _SYS_VLIMIT_H
#define _SYS_VLIMIT_H 1
#include <features.h>
#ifdef __cplusplus
extern "C" {
#endif

enum __vlimit_resource
{
  LIM_NORAISE,
  LIM_CPU,
  LIM_FSIZE,
  LIM_DATA,
  LIM_STACK,
  LIM_CORE,
  LIM_MAXRSS
};
#define INFINITY 0x7fffffff
extern int vlimit (enum __vlimit_resource __resource, int __value) __attribute__ ((__nothrow__));

#ifdef __cplusplus
}
#endif
#endif

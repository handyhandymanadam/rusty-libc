#ifndef __stack_t_defined
#define __stack_t_defined 1
#include <stddef.h>
typedef struct {
  void *ss_sp;
  int ss_flags;
  size_t ss_size;
} stack_t;
#endif

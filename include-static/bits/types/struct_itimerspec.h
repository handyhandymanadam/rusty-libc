#ifndef __itimerspec_defined
#define __itimerspec_defined 1
#include <bits/types/struct_timespec.h>
struct itimerspec {
  struct timespec it_interval;
  struct timespec it_value;
};
#endif

#ifndef __have_sigevent_t
#define __have_sigevent_t 1
#include <bits/types/__sigval_t.h>
#ifndef SIGEV_SIGNAL
# define SIGEV_SIGNAL 0
# define SIGEV_NONE 1
# define SIGEV_THREAD 2
# define SIGEV_THREAD_ID 4
#endif
#define __SIGEV_MAX_SIZE 64
#define __SIGEV_PAD_SIZE ((__SIGEV_MAX_SIZE / sizeof (int)) - 4)
union pthread_attr_t;
typedef struct sigevent {
  __sigval_t sigev_value;
  int sigev_signo;
  int sigev_notify;
  union {
    int _pad[__SIGEV_PAD_SIZE];
    int _tid;
    struct {
      void (*_function)(__sigval_t);
      union pthread_attr_t *_attribute;
    } _sigev_thread;
  } _sigev_un;
} sigevent_t;
#define sigev_notify_function _sigev_un._sigev_thread._function
#define sigev_notify_attributes _sigev_un._sigev_thread._attribute
#endif

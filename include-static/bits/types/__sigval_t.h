#ifndef __sigval_t_defined
#define __sigval_t_defined 1
union sigval {
  int sival_int;
  void *sival_ptr;
};
typedef union sigval __sigval_t;
#endif

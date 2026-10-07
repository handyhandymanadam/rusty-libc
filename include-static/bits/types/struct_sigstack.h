#ifndef __sigstack_defined
#define __sigstack_defined 1
struct sigstack {
  void *ss_sp;
  int ss_onstack;
};
#endif

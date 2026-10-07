#ifndef _SYS_TTYCHARS_H
#define _SYS_TTYCHARS_H 1
#include <features.h>
#ifdef __cplusplus
extern "C" {
#endif

struct ttychars {
  char tc_erase;
  char tc_kill;
  char tc_intrc;
  char tc_quitc;
  char tc_startc;
  char tc_stopc;
  char tc_eofc;
  char tc_brkc;
  char tc_suspc;
  char tc_dsuspc;
  char tc_rprntc;
  char tc_flushc;
  char tc_werasc;
  char tc_lnextc;
};

#ifdef __cplusplus
}
#endif
#endif

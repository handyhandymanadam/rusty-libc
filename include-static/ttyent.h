#ifndef _RLIBC_TTYENT_H
#define _RLIBC_TTYENT_H 1

#include <bits/rlibc-features.h>

#define _PATH_TTYS "/etc/ttys"

#define _TTYS_OFF "off"
#define _TTYS_ON "on"
#define _TTYS_SECURE "secure"
#define _TTYS_WINDOW "window"

struct ttyent {
  char *ty_name;
  char *ty_getty;
  char *ty_type;
#define TTY_ON 0x01
#define TTY_SECURE 0x02
  int ty_status;
  char *ty_window;
  char *ty_comment;
};

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-ttyentcalls.h>
#ifdef __cplusplus
}
#endif

#endif

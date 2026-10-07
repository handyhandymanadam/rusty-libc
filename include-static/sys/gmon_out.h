#ifndef _SYS_GMON_OUT_H
#define _SYS_GMON_OUT_H 1

#include <features.h>

#define GMON_MAGIC	"gmon"
#define GMON_VERSION	1

struct gmon_hdr
{
  char cookie[4];
  char version[4];
  char spare[3 * 4];
};

#define GMON_TAG_TIME_HIST	0
#define GMON_TAG_CG_ARC		1
#define GMON_TAG_BB_COUNT	2

struct gmon_hist_hdr
{
  char low_pc[sizeof (char *)];
  char high_pc[sizeof (char *)];
  char hist_size[4];
  char prof_rate[4];
  char dimen[15];
  char dimen_abbrev;
};

struct gmon_cg_arc_record
{
  char from_pc[sizeof (char *)];
  char self_pc[sizeof (char *)];
  char count[4];
};

#endif

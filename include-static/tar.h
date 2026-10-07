#ifndef _TAR_H
#define _TAR_H 1
#include <features.h>
#ifdef __cplusplus
extern "C" {
#endif
#define AREGTYPE '\0'
#define BLKTYPE '4'
#define CHRTYPE '3'
#define CONTTYPE '7'
#define DIRTYPE '5'
#define FIFOTYPE '6'
#define LNKTYPE '1'
#define REGTYPE '0'
#define SYMTYPE '2'
#define TGEXEC 00010
#define TGREAD 00040
#define TGWRITE 00020
#define TMAGIC "ustar"
#define TMAGLEN 6
#define TOEXEC 00001
#define TOREAD 00004
#define TOWRITE 00002
#define TSGID 02000
#define TSUID 04000
#define TSVTX 01000
#define TUEXEC 00100
#define TUREAD 00400
#define TUWRITE 00200
#define TVERSION "00"
#define TVERSLEN 2
#define _ATFILE_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _DYNAMIC_STACK_SIZE_SOURCE 1
#define _ISOC11_SOURCE 1
#define _ISOC23_SOURCE 1
#define _ISOC2Y_SOURCE 1
#define _ISOC95_SOURCE 1
#define _ISOC99_SOURCE 1
#define _LARGEFILE64_SOURCE 1
#define _LARGEFILE_SOURCE 1
#define _POSIX_C_SOURCE 202405L
#define _POSIX_SOURCE 1
#define _XOPEN_SOURCE 800
#define _XOPEN_SOURCE_EXTENDED 1
#ifdef __cplusplus
}
#endif
#endif

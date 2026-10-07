#ifndef _RLIBC_LINK_H
#define _RLIBC_LINK_H 1

#include <stddef.h>
#include <stdint.h>

#include <elf.h>

#define ElfW(type) _ElfW (Elf, 64, type)
#define _ElfW(e, w, t) _ElfW_1 (e, w, _##t)
#define _ElfW_1(e, w, t) e##w##t

struct link_map {
  Elf64_Addr l_addr;
  char *l_name;
  Elf64_Dyn *l_ld;
  struct link_map *l_next, *l_prev;
};

#ifdef __cplusplus
extern "C" {
#endif

struct dl_phdr_info {
  Elf64_Addr dlpi_addr;
  const char *dlpi_name;
  const Elf64_Phdr *dlpi_phdr;
  Elf64_Half dlpi_phnum;
  unsigned long long int dlpi_adds;
  unsigned long long int dlpi_subs;
  size_t dlpi_tls_modid;
  void *dlpi_tls_data;
};

#ifdef _GNU_SOURCE
struct dl_find_object {
  unsigned long long int dlfo_flags;
  void *dlfo_map_start;
  void *dlfo_map_end;
  struct link_map *dlfo_link_map;
  void *dlfo_eh_frame;
  unsigned long long int __dflo_reserved[7];
};
extern int _dl_find_object (void *__address, struct dl_find_object *__result);
#endif

extern int dl_iterate_phdr (int (*__callback) (struct dl_phdr_info *, size_t, void *), void *__data);

struct r_debug {
  int r_version;
  struct link_map *r_map;
  Elf64_Addr r_brk;
  enum { RT_CONSISTENT, RT_ADD, RT_DELETE } r_state;
  Elf64_Addr r_ldbase;
};
struct r_debug_extended {
  int r_version;
  struct link_map *r_map;
  Elf64_Addr r_brk;
  enum { RTX_CONSISTENT, RTX_ADD, RTX_DELETE } r_state;
  Elf64_Addr r_ldbase;
  struct r_debug_extended *r_next;
};
extern struct r_debug _r_debug;

extern Elf64_Dyn _DYNAMIC[];

#define LAV_CURRENT 2
#define LA_ACT_CONSISTENT 0
#define LA_ACT_ADD 1
#define LA_ACT_DELETE 2
#define LA_SER_ORIG 0x01
#define LA_SER_LIBPATH 0x02
#define LA_SER_RUNPATH 0x04
#define LA_SER_CONFIG 0x08
#define LA_SER_DEFAULT 0x40
#define LA_SER_SECURE 0x80
#define LA_FLG_BINDTO 0x01
#define LA_FLG_BINDFROM 0x02
#define LA_SYMB_NOPLTENTER 0x01
#define LA_SYMB_NOPLTEXIT 0x02
#define LA_SYMB_STRUCTCALL 0x04
#define LA_SYMB_DLSYM 0x08
#define LA_SYMB_ALTVALUE 0x10

#ifdef __cplusplus
}
#endif

#endif

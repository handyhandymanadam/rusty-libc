#!/usr/bin/env python3
import os, re, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def macros(extra):
    out = subprocess.run(["gcc", "-E", "-dM", "-x", "c", "-"] + extra, input="", capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        m = re.match(r"#define (\w+(?:\([^)]*\))?) ?(.*)", line)
        if m:
            d[m.group(1)] = m.group(2)
    return d

base = macros(["-D_GNU_SOURCE"])
full = macros(["-D_GNU_SOURCE", "-include", "regex.h"])
names = [n for n in sorted(full) if re.match(r"(_?RE_|REG_|REGS_)", n) and n not in base]
gnu = [n for n in names if re.match(r"(_?RE_|REGS_)", n)]
posix = [n for n in names if n.startswith("REG_")]

def fmt(ns):
    return "\n".join("#define %s %s" % (n, full[n]) for n in ns)

text = '''/* regex.h for the Rust libc (written by tools/gen_regex_h.py; constants are the system header's values,
   structs and prototypes are written by hand). The GNU interface (re_*, RE_* bits) needs _GNU_SOURCE. */
#ifndef _RLIBC_REGEX_H
#define _RLIBC_REGEX_H 1

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int regoff_t;
typedef unsigned long int reg_syntax_t;

/* the error codes: REG_xxx above are macros for these enumerators (programs use both spellings) */
typedef enum
{
  _REG_ENOSYS = -1,
  _REG_NOERROR = 0,
  _REG_NOMATCH,
  _REG_BADPAT,
  _REG_ECOLLATE,
  _REG_ECTYPE,
  _REG_EESCAPE,
  _REG_ESUBREG,
  _REG_EBRACK,
  _REG_EPAREN,
  _REG_EBRACE,
  _REG_BADBR,
  _REG_ERANGE,
  _REG_ESPACE,
  _REG_BADRPT,
  _REG_EEND,
  _REG_ESIZE,
  _REG_ERPAREN
} reg_errcode_t;

''' + fmt(posix) + '''

#ifdef _GNU_SOURCE
''' + fmt(gnu) + '''
#endif

#ifdef _GNU_SOURCE
# define __REPB_PREFIX(name) name
#else
# define __REPB_PREFIX(name) __##name
#endif

struct re_pattern_buffer
{
  struct re_dfa_t *__REPB_PREFIX(buffer);
  unsigned long int __REPB_PREFIX(allocated);
  unsigned long int __REPB_PREFIX(used);
  reg_syntax_t __REPB_PREFIX(syntax);
  char *__REPB_PREFIX(fastmap);
  unsigned char *__REPB_PREFIX(translate);
  size_t re_nsub;
  unsigned __REPB_PREFIX(can_be_null) : 1;
  unsigned __REPB_PREFIX(regs_allocated) : 2;
  unsigned __REPB_PREFIX(fastmap_accurate) : 1;
  unsigned __REPB_PREFIX(no_sub) : 1;
  unsigned __REPB_PREFIX(not_bol) : 1;
  unsigned __REPB_PREFIX(not_eol) : 1;
  unsigned __REPB_PREFIX(newline_anchor) : 1;
};
typedef struct re_pattern_buffer regex_t;

typedef struct
{
  regoff_t rm_so;
  regoff_t rm_eo;
} regmatch_t;

#ifdef _GNU_SOURCE
struct re_registers
{
  unsigned num_regs;
  regoff_t *start;
  regoff_t *end;
};
extern reg_syntax_t re_syntax_options;
extern reg_syntax_t re_set_syntax (reg_syntax_t __syntax);
extern const char *re_compile_pattern (const char *__pattern, size_t __length, struct re_pattern_buffer *__buffer);
extern int re_compile_fastmap (struct re_pattern_buffer *__buffer);
extern regoff_t re_search (struct re_pattern_buffer *__buffer, const char *__String, regoff_t __length,
                           regoff_t __start, regoff_t __range, struct re_registers *__regs);
extern regoff_t re_search_2 (struct re_pattern_buffer *__buffer, const char *__string1, regoff_t __length1,
                             const char *__string2, regoff_t __length2, regoff_t __start, regoff_t __range,
                             struct re_registers *__regs, regoff_t __stop);
extern regoff_t re_match (struct re_pattern_buffer *__buffer, const char *__String, regoff_t __length,
                          regoff_t __start, struct re_registers *__regs);
extern regoff_t re_match_2 (struct re_pattern_buffer *__buffer, const char *__string1, regoff_t __length1,
                            const char *__string2, regoff_t __length2, regoff_t __start,
                            struct re_registers *__regs, regoff_t __stop);
extern void re_set_registers (struct re_pattern_buffer *__buffer, struct re_registers *__regs,
                              unsigned __num_regs, regoff_t *__starts, regoff_t *__ends);
#endif

#if defined _REGEX_RE_COMP || (defined _GNU_SOURCE && !defined _POSIX_C_SOURCE) || defined _DEFAULT_SOURCE
extern char *re_comp (const char *);
extern int re_exec (const char *);
#endif

extern int regcomp (regex_t *__restrict __preg, const char *__restrict __pattern, int __cflags);
extern int regexec (const regex_t *__restrict __preg, const char *__restrict __String, size_t __nmatch,
                    regmatch_t __pmatch[__restrict], int __eflags);
extern size_t regerror (int __errcode, const regex_t *__restrict __preg, char *__restrict __errbuf, size_t __errbuf_size);
extern void regfree (regex_t *__preg);

#ifdef __cplusplus
}
#endif

#endif
'''
with open(os.path.join(ROOT, "include-static", "regex.h"), "w") as f:
    f.write(text)
print(len(names), "macros")

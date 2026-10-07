import re


def _td(guard, text, needs=()):
    return ([guard] if isinstance(guard, str) else list(guard), text, list(needs))


TYPES = {
    "ssize_t": _td("__ssize_t_defined", "typedef long ssize_t;"),
    "off_t": _td("__off_t_defined", "typedef long off_t;"),
    "off64_t": _td("__off64_t_defined", "typedef long off64_t;"),
    "loff_t": _td("__loff_t_defined", "typedef long loff_t;"),
    "pid_t": _td("__pid_t_defined", "typedef int pid_t;"),
    "uid_t": _td("__uid_t_defined", "typedef unsigned int uid_t;"),
    "gid_t": _td("__gid_t_defined", "typedef unsigned int gid_t;"),
    "mode_t": _td("__mode_t_defined", "typedef unsigned int mode_t;"),
    "dev_t": _td("__dev_t_defined", "typedef unsigned long dev_t;"),
    "ino_t": _td("__ino_t_defined", "typedef unsigned long ino_t;"),
    "ino64_t": _td("__ino64_t_defined", "typedef unsigned long ino64_t;"),
    "nlink_t": _td("__nlink_t_defined", "typedef unsigned long nlink_t;"),
    "blksize_t": _td("__blksize_t_defined", "typedef long blksize_t;"),
    "blkcnt_t": _td("__blkcnt_t_defined", "typedef long blkcnt_t;"),
    "blkcnt64_t": _td("__blkcnt64_t_defined", "typedef long blkcnt64_t;"),
    "fsblkcnt_t": _td("__fsblkcnt_t_defined", "typedef unsigned long fsblkcnt_t;"),
    "fsblkcnt64_t": _td("__fsblkcnt64_t_defined", "typedef unsigned long fsblkcnt64_t;"),
    "fsfilcnt_t": _td("__fsfilcnt_t_defined", "typedef unsigned long fsfilcnt_t;"),
    "fsfilcnt64_t": _td("__fsfilcnt64_t_defined", "typedef unsigned long fsfilcnt64_t;"),
    "id_t": _td("__id_t_defined", "typedef unsigned int id_t;"),
    "key_t": _td("__key_t_defined", "typedef int key_t;"),
    "useconds_t": _td("__useconds_t_defined", "typedef unsigned int useconds_t;"),
    "suseconds_t": _td("__suseconds_t_defined", "typedef long suseconds_t;"),
    "time_t": _td("__time_t_defined", "typedef long time_t;"),
    "clock_t": _td("__clock_t_defined", "typedef long clock_t;"),
    "clockid_t": _td("__clockid_t_defined", "typedef int clockid_t;"),
    "socklen_t": _td("__socklen_t_defined", "typedef unsigned int socklen_t;"),
    "caddr_t": _td("__caddr_t_defined", "typedef char *caddr_t;"),
    "rlim_t": _td("__rlim_t_defined", "typedef unsigned long rlim_t;"),
    "rlim64_t": _td("__rlim64_t_defined", "typedef unsigned long rlim64_t;"),
    "struct timespec": _td(["_STRUCT_TIMESPEC", "__timespec_defined"],
        "struct timespec {\n  long tv_sec;\n  long tv_nsec;\n};", ["time_t"]),
    "struct timeval": _td("__timeval_defined",
        "struct timeval {\n  long tv_sec;\n  long tv_usec;\n};", ["time_t", "suseconds_t"]),
    "struct itimerspec": _td("__itimerspec_defined",
        "struct itimerspec {\n  struct timespec it_interval;\n  struct timespec it_value;\n};", ["struct timespec"]),
    "struct iovec": _td("__iovec_defined",
        "struct iovec {\n  void *iov_base;\n  size_t iov_len;\n};"),
    "sigset_t": _td("__sigset_t_defined",
        "#ifndef ____sigset_t_defined\n#define ____sigset_t_defined\ntypedef struct {\n  unsigned long __val[16];\n} __sigset_t;\n#endif\ntypedef __sigset_t sigset_t;"),
    "struct rusage": _td("__rusage_defined",
        "struct rusage {\n  struct timeval ru_utime;\n  struct timeval ru_stime;\n  long ru_maxrss;\n  long ru_ixrss;\n  long ru_idrss;\n  long ru_isrss;\n"
        "  long ru_minflt;\n  long ru_majflt;\n  long ru_nswap;\n  long ru_inblock;\n  long ru_oublock;\n  long ru_msgsnd;\n  long ru_msgrcv;\n"
        "  long ru_nsignals;\n  long ru_nvcsw;\n  long ru_nivcsw;\n};", ["struct timeval"]),
    "struct sched_param": _td("_BITS_TYPES_STRUCT_SCHED_PARAM",
        "struct sched_param {\n  int sched_priority;\n};"),
    "siginfo_t": _td("__siginfo_t_defined", "#include <bits/types/siginfo_t.h>", ["pid_t", "uid_t", "clock_t"]),
}


FORCE = {"sys/types": ["ssize_t", "off_t", "off64_t", "loff_t", "pid_t", "uid_t", "gid_t", "mode_t", "dev_t", "ino_t",
                       "ino64_t", "nlink_t", "blksize_t", "blkcnt_t", "blkcnt64_t", "fsblkcnt_t", "fsblkcnt64_t",
                       "fsfilcnt_t", "fsfilcnt64_t", "id_t", "key_t", "useconds_t", "suseconds_t", "time_t", "clock_t",
                       "clockid_t", "caddr_t"],
         "sys/resource": ["rlim_t", "rlim64_t"]}


def types_block(body, force=()):
    wanted, order = set(), []

    def want(name):
        if name in wanted:
            return
        wanted.add(name)
        for dep in TYPES[name][2]:
            want(dep)
        order.append(name)

    for name in force:
        want(name)
    for name in TYPES:
        if " " in name:
            pat = r"\bstruct\s+" + name.split()[1] + r"\b"
        else:
            pat = r"\b" + name + r"\b"
        if re.search(pat, body):
            want(name)
    out = []
    for name in order:
        guards, text, _ = TYPES[name]
        cond = " && ".join(f"!defined {g}" for g in guards)
        defs = "\n".join(f"#define {g} 1" for g in guards)
        out.append(f"#if {cond}\n{defs}\n{text}\n#endif")
    return "\n".join(out)


def finish(text, hdr=""):
    text = re.sub(r"\bstruct_(\w+)\b", r"struct \1", text)
    block = types_block(text, FORCE.get(hdr, ()))
    if block:
        m = None
        for m in re.finditer(r"^#include <[^>]+>\n", text, re.M):
            pass
        pos = m.end() if m else text.index("\n", text.index("#define")) + 1
        text = text[:pos] + "\n" + block + "\n" + text[pos:]
    return text

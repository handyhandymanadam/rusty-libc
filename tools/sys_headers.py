import os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_SRC = os.path.join(ROOT, "crates/rusty-libc-sys/src")

SYS_FNS = {
    "unistd": """
        access acct alarm brk chdir chown chroot close close_range closefrom confstr copy_file_range
        daemon dup dup2 dup3 eaccess euidaccess execl execle execlp execv execve execveat execvp execvpe
        faccessat fchdir fchown fchownat fdatasync fexecve fork fpathconf fsync ftruncate ftruncate64
        get_current_dir_name getcwd getdomainname getdtablesize getegid getentropy geteuid getgid getgroups
        gethostid gethostname getpagesize getpgid getpgrp getpid getppid getresgid getresuid getsid getuid
        getwd group_member isatty lchown link linkat lseek lseek64 nice pathconf pause pipe pipe2
        pread pread64 pwrite pwrite64 read readlink readlinkat revoke rmdir sbrk setdomainname setegid seteuid
        setgid setgroups sethostid sethostname setlogin setpgid setpgrp setregid setresgid setresuid setreuid
        setsid setuid symlink symlinkat sync syncfs sysconf syscall tcgetpgrp
        tcsetpgrp truncate truncate64 ttyname ttyname_r unlink unlinkat vfork vhangup __getpgid gettid _Fork ualarm getpass""".split(),
    "fcntl": """
        creat fcntl fcntl64 open open64 openat openat64 openat2 posix_fadvise posix_fallocate fallocate
        fallocate64 posix_fadvise64 posix_fallocate64 creat64 lockf lockf64 name_to_handle_at open_by_handle_at
        readahead splice sync_file_range tee vmsplice""".split(),
    "dirent": """
        alphasort alphasort64 closedir dirfd fdopendir getdents64 getdirentries getdirentries64 opendir readdir
        readdir64 readdir64_r readdir_r rewinddir scandir scandir64 scandirat scandirat64 seekdir telldir
        versionsort versionsort64""".split(),
    "poll": "poll ppoll".split(),
    "pty": "forkpty openpty login_tty".split(),
    "sched": """
        __sched_cpualloc __sched_cpucount __sched_cpufree sched_get_priority_max sched_get_priority_min
        sched_getaffinity sched_getattr sched_getcpu sched_getparam sched_getscheduler sched_rr_get_interval
        sched_setaffinity sched_setattr sched_setparam sched_setscheduler sched_yield setns unshare getcpu clone""".split(),
    "sys/acct": ["acct"],
    "sys/epoll": "epoll_create epoll_create1 epoll_ctl epoll_pwait epoll_pwait2 epoll_wait".split(),
    "sys/eventfd": "eventfd eventfd_read eventfd_write".split(),
    "sys/fanotify": "fanotify_init fanotify_mark".split(),
    "sys/fsuid": "setfsgid setfsuid".split(),
    "sys/inotify": "inotify_add_watch inotify_init inotify_init1 inotify_rm_watch".split(),
    "sys/ioctl": ["ioctl"],
    "sys/klog": ["klogctl"],
    "sys/mman": """
        madvise memfd_create mincore mlock mlock2 mlockall mmap mmap64 mprotect mremap msync munlock munlockall
        munmap pkey_alloc pkey_free pkey_get pkey_mprotect pkey_set posix_madvise process_madvise process_mrelease
        remap_file_pages shm_open shm_unlink mseal""".split(),
    "sys/mount": """
        fsconfig fsmount fsopen fspick mount mount_setattr move_mount open_tree pivot_root umount umount2""".split(),
    "sys/personality": ["personality"],
    "sys/pidfd": "pidfd_getfd pidfd_getpid pidfd_open pidfd_send_signal".split(),
    "sys/prctl": ["prctl"],
    "sys/ptrace": ["ptrace"],
    "sys/quota": ["quotactl"],
    "sys/random": "getentropy getrandom".split(),
    "sys/reboot": ["reboot"],
    "sys/resource": "getpriority getrlimit getrlimit64 getrusage prlimit prlimit64 setpriority setrlimit setrlimit64".split(),
    "sys/select": "pselect select".split(),
    "sys/sendfile": "sendfile sendfile64".split(),
    "sys/signalfd": ["signalfd"],
    "sys/stat": """
        chmod fchmod fchmodat fstat fstat64 fstatat fstatat64 futimens lchmod lstat lstat64 mkdir mkdirat mkfifo
        mkfifoat mknod mknodat stat stat64 statx umask utimensat getumask""".split(),
    "sys/statfs": "fstatfs fstatfs64 statfs statfs64".split(),
    "sys/statvfs": "fstatvfs fstatvfs64 statvfs statvfs64".split(),
    "sys/swap": "swapoff swapon".split(),
    "sys/sysinfo": "get_avphys_pages get_nprocs get_nprocs_conf get_phys_pages sysinfo".split(),
    "sys/sysmacros": "gnu_dev_major gnu_dev_makedev gnu_dev_minor".split(),
    "sys/timerfd": "timerfd_create timerfd_gettime timerfd_settime".split(),
    "sys/times": ["times"],
    "sys/timex": "adjtimex clock_adjtime ntp_adjtime ntp_gettime ntp_gettimex".split(),
    "sys/uio": """
        preadv preadv2 preadv64 preadv64v2 process_vm_readv process_vm_writev pwritev pwritev2 pwritev64
        pwritev64v2 readv writev""".split(),
    "sys/utsname": ["uname"],
    "sys/wait": "wait wait3 wait4 waitid waitpid".split(),
    "sys/xattr": """
        fgetxattr flistxattr fremovexattr fsetxattr getxattr lgetxattr listxattr llistxattr lremovexattr
        lsetxattr removexattr setxattr""".split(),
    "termios": """
        cfgetibaud cfgetispeed cfgetobaud cfgetospeed cfmakeraw cfsetbaud cfsetibaud cfsetispeed cfsetobaud
        cfsetospeed cfsetspeed tcdrain tcflow tcflush tcgetattr tcgetsid tcsendbreak tcsetattr""".split(),
    "ulimit": ["ulimit"],
    "sys/file": ["flock"],
}

SYS_STRUCTS = {
    "sys/stat": [("stat", "Stat", "stat")],
    "sched": [("misc", "sched_attr", "sched_attr")],
    "sys/utsname": [("utsname", "Utsname", "utsname")],
    "sys/resource": [("resource", "Rlimit", "rlimit")],
    "fcntl": [("fcntl", "Flock", "flock")],
    "termios": [("termios", "termios", "termios")],
    "sys/ioctl": [("termios", "winsize", "winsize")],
    "poll": [("poll", "pollfd", "pollfd")],
    "dirent": [("dirent", "dirent", "dirent")],
    "sys/sysinfo": [("misc", "sysinfo", "sysinfo")],
    "sys/times": [("misc", "tms", "tms")],
    "sys/timex": [("misc", "timex", "timex"), ("misc", "ntptimeval", "ntptimeval")],
    "sys/statfs": [("misc", "statfs", "statfs")],
    "sys/statvfs": [("misc", "statvfs", "statvfs")],
}

OPAQUE = {
    "DIR": "DIR", "fd_set": "fd_set",
    "timespec": "struct_timespec", "Timespec": "struct_timespec", "timeval": "struct_timeval",
    "Timeval": "struct_timeval", "itimerspec": "struct_itimerspec", "iovec": "struct_iovec",
    "sched_param": "struct_sched_param", "epoll_event": "struct_epoll_event",
    "termios": "struct_termios", "winsize": "struct_winsize",
}

CONST_ONLY = ["sys/syscall", "sys/ttydefaults"]

_U = "u32"
RULES = [
    (r".", r"mode", "u32", "mode_t"), (r".", r"dev", "u64", "dev_t"),
    (r"^(umask|getumask)$", r"->|mask", "u32", "mode_t"),
    (r"^(lseek|lseek64)$", r"->", "i64", "off_t"),
    (r".", r"(off|offset|len|nbytes)", "i64", "off_t"),
    (r"^(truncate|ftruncate|truncate64|ftruncate64)$", r"len", "i64", "off_t"),
    (r".", r"(off_in|off_out)", "*mut i64", "*mut loff_t"),
    (r"^(sendfile|sendfile64)$", r"offset", "*mut i64", "*mut off_t"),
    (r"^getdirentries", r"basep", "*mut i64", "*mut off_t"),
    (r"^(getuid|geteuid)$", r"->", "u32", "uid_t"), (r"^(getgid|getegid)$", r"->", "u32", "gid_t"),
    (r".*uid.*|^(chown|lchown|fchown|fchownat)$", r"uid|r|e|s", "u32", "uid_t"),
    (r".*gid.*|^group_member$|^(chown|lchown|fchown|fchownat)$", r"gid|r|e|s", "u32", "gid_t"),
    (r"^(setuid|seteuid)$", r"uid", "u32", "uid_t"), (r"^(setgid|setegid)$", r"gid", "u32", "gid_t"),
    (r"^setfsuid$", r"uid", "c_uint", "uid_t"), (r"^setfsgid$", r"gid", "c_uint", "gid_t"),
    (r"^getresuid$|^setresuid$|^setreuid$", r"r|e|s", "u32", "uid_t"),
    (r"^getresgid$|^setresgid$|^setregid$", r"r|e|s", "u32", "gid_t"),
    (r"^getresuid$", r"r|e|s", "*mut u32", "*mut uid_t"), (r"^getresgid$", r"r|e|s", "*mut u32", "*mut gid_t"),
    (r"^getgroups$", r"list", "*mut u32", "*mut gid_t"), (r"^setgroups$", r"list", "*const u32", "*const gid_t"),
    (r"^(getpriority|setpriority)$", r"who", "u32", "id_t"), (r"^waitid$", r"id", "u32", "id_t"),
    (r"^waitid$", r"idtype", "c_int", "idtype_t"),
    (r".", r"pid|pgid|pgrp", "c_int", "pid_t"),
    (r"^(getpid|getppid|getpgrp|getpgid|__getpgid|getsid|setsid|fork|vfork|wait|waitpid|wait3|wait4|tcgetpgrp|tcgetsid|forkpty)$", r"->", "c_int", "pid_t"),
    (r"^(ppoll|pselect|epoll_pwait|epoll_pwait2)$", r"sigmask", "*const c_void", "*const sigset_t"),
    (r"^signalfd$", r"mask", "*const c_void", "*const sigset_t"),
    (r"^(wait3|wait4|getrusage)$", r"rusage|usage", "*mut c_void", "*mut struct_rusage"),
    (r"^(waitid|pidfd_send_signal)$", r"infop|info", "*mut c_void", "*mut siginfo_t"),
    (r"^(name_to_handle_at|open_by_handle_at)$", r"handle", "*mut c_void", "*mut struct_file_handle"),
    (r"^statx$", r"buf", "*mut c_void", "*mut struct_statx"),
    (r"^mount_setattr$", r"attr", "*mut c_void", "*mut struct_mount_attr"),
    (r"^sched_getaffinity$", r"mask", "*mut c_void", "*mut cpu_set_t"),
    (r"^sched_setaffinity$", r"mask", "*const c_void", "*const cpu_set_t"),
    (r"^vmsplice$", r"iov", "*const c_void", "*const struct_iovec"),
    (r"^(exec\w*|fexecve)$", r"argv|envp", "*const *const c_char", "*const *mut c_char"),
    (r"^cf\w*baud$", r"speed", "u32", "baud_t"),
    (r"^cfget\w*baud$", r"->", "u32", "baud_t"),
    (r"^(cfset\w*|cfget\w*)$", r"speed", "u32", "speed_t"),
    (r"^cfget\w*$", r"->", "u32", "speed_t"),
    (r"^__sched_cpualloc$", r"->", "*mut c_void", "*mut cpu_set_t"),
    (r"^__sched_cpucount$", r"set", "*const u8", "*const cpu_set_t"),
    (r"^__sched_cpufree$", r"set", "*mut c_void", "*mut cpu_set_t"),
    (r"^openat2$", r"how", "*mut c_void", "*const struct_open_how"),
    (r"^quotactl$", r"addr", "*mut c_char", "caddr_t"),
    (r"^sbrk$", r"increment", "isize", "intptr_t"),
    (r"^(clock_adjtime|timerfd_create)$", r"clock", "c_int", "clockid_t"),
    (r"^times$", r"->", "c_long", "clock_t"),
    (r"^poll$|^ppoll$", r"nfds", "c_ulong", "nfds_t"),
    (r"^gnu_dev_makedev$", r"->", "u64", "dev_t"),
]
STRUCT64 = {"Stat": "struct_stat64", "stat": "struct_stat64", "statfs": "struct_statfs64", "statvfs": "struct_statvfs64",
            "dirent": "struct_dirent64", "Rlimit": "struct_rlimit64"}
NO64 = {"preadv64", "pwritev64", "preadv64v2", "pwritev64v2", "pread64", "pwrite64", "lseek64", "ftruncate64",
        "truncate64", "mmap64", "sendfile64", "openat64", "open64", "creat64", "lockf64", "fcntl64",
        "posix_fadvise64", "posix_fallocate64", "fallocate64", "getdirentries64", "getdents64", "scandirat64_"}


def _read(name):
    with open(os.path.join(SYS_SRC, name + ".rs")) as f:
        return f.read()


_FN_RE = re.compile(r'cfg_attr\(feature = "export", unsafe\(no_mangle\)\)\]\n(?:#\[[^\n]*\n)*pub (unsafe )?extern "C" fn (\w+)\((.*?)\)(?: -> ([^{]+?))? \{', re.S)
_ALIAS_RE = re.compile(r'^(?:crate::\w+::)?alias!\(\s*(?:(?:///|#\[)[^\n]*\n\s*)*(\w+) => (\w+)\s*\((.*?)\) -> ([^)]+?)\s*\)', re.S | re.M)
_GETTER_RE = re.compile(r'^getter!\(\s*(?:(?:///|#\[)[^\n]*\n\s*)*(\w+), [^,]+, ([^)]+?)\s*\)', re.S | re.M)


def _clean_params(p):
    p = re.sub(r"\s+", " ", p).strip().rstrip(",").strip()
    p = re.sub(r"\bmut args: \.\.\.", "...", p)
    p = re.sub(r"crate::\w+::", "", p)
    return p


def fn_signatures():
    sigs = {}
    for name in sorted(os.listdir(SYS_SRC)):
        if not name.endswith(".rs") or name == "lib.rs":
            continue
        text = open(os.path.join(SYS_SRC, name)).read()
        for m in _FN_RE.finditer(text):
            sigs[m.group(2)] = (_clean_params(m.group(3)), (m.group(4) or "").strip())
        for m in _ALIAS_RE.finditer(text):
            sigs[m.group(1)] = (_clean_params(m.group(3)), m.group(4).strip())
        for m in _GETTER_RE.finditer(text):
            sigs[m.group(1)] = ("", m.group(2).strip())
    return sigs


def struct_text(mod, rust_name):
    text = _read(mod)
    m = re.search(r'((?:///[^\n]*\n|#\[[^\n]*\n)*)pub (struct|union) ' + rust_name + r' \{.*?\n\}\n', text, re.S)
    if not m:
        raise KeyError(f"{mod}.{rust_name}")
    return m.group(0)


def const_text(mod, name):
    text = _read(mod)
    m = re.search(r'pub const ' + name + r': [^\n]*;\n', text)
    return m.group(0)


def split_params(p):
    out, depth, cur = [], 0, ""
    for ch in p:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def fix_type(fn, pname, ty):
    if ty == "Select":
        ty = "Option<unsafe extern \"C\" fn(*const dirent) -> c_int>"
    if ty == "Cmp":
        ty = "Option<unsafe extern \"C\" fn(*mut *const dirent, *mut *const dirent) -> c_int>"
    for fre, pre, frm, to in RULES:
        if ty == frm and re.fullmatch(pre, pname) and re.search(fre, fn):
            ty = to
            break
    ty = re.sub(r"\bisize\b", "ssize_t", ty)
    if re.search(r"64(_r)?$", fn) and fn not in NO64:
        for k, v in STRUCT64.items():
            ty = re.sub(r"\b" + k + r"\b", v, ty)
    return ty


def stub(name, sigs):
    params, ret = sigs[name]
    ps = []
    for p in split_params(params):
        if p == "...":
            ps.append("...")
            continue
        pn, ty = [x.strip() for x in p.split(":", 1)]
        ps.append(f"{pn}: {fix_type(name, pn, ty)}")
    ret = fix_type(name, "->", ret) if ret else ret
    r = f" -> {ret}" if ret and ret != "()" else ""
    return f'#[unsafe(no_mangle)]\npub unsafe extern "C" fn {name}({", ".join(ps)}){r} {{}}\n'


def header_source(hdr, extra_fns=()):
    sigs = fn_signatures()
    parts, ren = [], {}
    for mod, rname, cname in SYS_STRUCTS.get(hdr, []):
        parts.append(re.sub(r"^///.*\n", "", struct_text(mod, rname), flags=re.M))
        ren[rname] = cname
    for name in SYS_FNS.get(hdr, []) + list(extra_fns):
        parts.append(stub(name, sigs))
    src = "\n".join(parts)
    src = src.replace("; NCCS]", "; 32]")
    src = re.sub(r"f_fsid: \[c_int; 2\]", "f_fsid: fsid_t", src)
    for k, v in ren.items():
        if k != v:
            src = re.sub(r"\b" + k + r"\b(?!\()", v, src)
    for k, v in OPAQUE.items():
        if k not in ren:
            src = re.sub(r"\b" + k + r"\b", v, src)
    src = re.sub(r"\bmut\s+args\b", "args", src)
    return src

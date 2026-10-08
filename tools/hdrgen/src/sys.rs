use crate::text::{contains_word, replace_word, word_positions};
use regex_lite::Regex;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

fn w(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

pub fn sys_fns() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("unistd", w("access acct alarm brk chdir chown chroot close close_range closefrom confstr copy_file_range
        daemon dup dup2 dup3 eaccess euidaccess execl execle execlp execv execve execveat execvp execvpe
        faccessat fchdir fchown fchownat fdatasync fexecve fork fpathconf fsync ftruncate ftruncate64
        get_current_dir_name getcwd getdomainname getdtablesize getegid getentropy geteuid getgid getgroups
        gethostid gethostname getpagesize getpgid getpgrp getpid getppid getresgid getresuid getsid getuid
        getwd group_member isatty lchown link linkat lseek lseek64 nice pathconf pause pipe pipe2
        pread pread64 pwrite pwrite64 read readlink readlinkat revoke rmdir sbrk setdomainname setegid seteuid
        setgid setgroups sethostid sethostname setlogin setpgid setpgrp setregid setresgid setresuid setreuid
        setsid setuid symlink symlinkat sync syncfs sysconf syscall tcgetpgrp
        tcsetpgrp truncate truncate64 ttyname ttyname_r unlink unlinkat vfork vhangup __getpgid gettid _Fork ualarm getpass")),
        ("fcntl", w("creat fcntl fcntl64 open open64 openat openat64 openat2 posix_fadvise posix_fallocate fallocate
        fallocate64 posix_fadvise64 posix_fallocate64 creat64 lockf lockf64 name_to_handle_at open_by_handle_at
        readahead splice sync_file_range tee vmsplice")),
        ("dirent", w("alphasort alphasort64 closedir dirfd fdopendir getdents64 getdirentries getdirentries64 opendir readdir
        readdir64 readdir64_r readdir_r rewinddir scandir scandir64 scandirat scandirat64 seekdir telldir
        versionsort versionsort64")),
        ("poll", w("poll ppoll")),
        ("pty", w("forkpty openpty login_tty")),
        ("sched", w("__sched_cpualloc __sched_cpucount __sched_cpufree sched_get_priority_max sched_get_priority_min
        sched_getaffinity sched_getattr sched_getcpu sched_getparam sched_getscheduler sched_rr_get_interval
        sched_setaffinity sched_setattr sched_setparam sched_setscheduler sched_yield setns unshare getcpu clone")),
        ("sys/acct", w("acct")),
        ("sys/epoll", w("epoll_create epoll_create1 epoll_ctl epoll_pwait epoll_pwait2 epoll_wait")),
        ("sys/eventfd", w("eventfd eventfd_read eventfd_write")),
        ("sys/fanotify", w("fanotify_init fanotify_mark")),
        ("sys/fsuid", w("setfsgid setfsuid")),
        ("sys/inotify", w("inotify_add_watch inotify_init inotify_init1 inotify_rm_watch")),
        ("sys/ioctl", w("ioctl")),
        ("sys/klog", w("klogctl")),
        ("sys/mman", w("madvise memfd_create mincore mlock mlock2 mlockall mmap mmap64 mprotect mremap msync munlock munlockall
        munmap pkey_alloc pkey_free pkey_get pkey_mprotect pkey_set posix_madvise process_madvise process_mrelease
        remap_file_pages shm_open shm_unlink mseal")),
        ("sys/mount", w("fsconfig fsmount fsopen fspick mount mount_setattr move_mount open_tree pivot_root umount umount2")),
        ("sys/personality", w("personality")),
        ("sys/pidfd", w("pidfd_getfd pidfd_getpid pidfd_open pidfd_send_signal")),
        ("sys/prctl", w("prctl")),
        ("sys/ptrace", w("ptrace")),
        ("sys/quota", w("quotactl")),
        ("sys/random", w("getentropy getrandom")),
        ("sys/reboot", w("reboot")),
        ("sys/resource", w("getpriority getrlimit getrlimit64 getrusage prlimit prlimit64 setpriority setrlimit setrlimit64")),
        ("sys/select", w("pselect select")),
        ("sys/sendfile", w("sendfile sendfile64")),
        ("sys/signalfd", w("signalfd")),
        ("sys/stat", w("chmod fchmod fchmodat fstat fstat64 fstatat fstatat64 futimens lchmod lstat lstat64 mkdir mkdirat mkfifo
        mkfifoat mknod mknodat stat stat64 statx umask utimensat getumask")),
        ("sys/statfs", w("fstatfs fstatfs64 statfs statfs64")),
        ("sys/statvfs", w("fstatvfs fstatvfs64 statvfs statvfs64")),
        ("sys/swap", w("swapoff swapon")),
        ("sys/sysinfo", w("get_avphys_pages get_nprocs get_nprocs_conf get_phys_pages sysinfo")),
        ("sys/sysmacros", w("gnu_dev_major gnu_dev_makedev gnu_dev_minor")),
        ("sys/timerfd", w("timerfd_create timerfd_gettime timerfd_settime")),
        ("sys/times", w("times")),
        ("sys/timex", w("adjtimex clock_adjtime ntp_adjtime ntp_gettime ntp_gettimex")),
        ("sys/uio", w("preadv preadv2 preadv64 preadv64v2 process_vm_readv process_vm_writev pwritev pwritev2 pwritev64
        pwritev64v2 readv writev")),
        ("sys/utsname", w("uname")),
        ("sys/wait", w("wait wait3 wait4 waitid waitpid")),
        ("sys/xattr", w("fgetxattr flistxattr fremovexattr fsetxattr getxattr lgetxattr listxattr llistxattr lremovexattr
        lsetxattr removexattr setxattr")),
        ("termios", w("cfgetibaud cfgetispeed cfgetobaud cfgetospeed cfmakeraw cfsetbaud cfsetibaud cfsetispeed cfsetobaud
        cfsetospeed cfsetspeed tcdrain tcflow tcflush tcgetattr tcgetsid tcsendbreak tcsetattr")),
        ("ulimit", w("ulimit")),
        ("sys/file", w("flock")),
    ]
}

pub const CONST_ONLY: [&str; 2] = ["sys/syscall", "sys/ttydefaults"];

fn sys_structs(hdr: &str) -> Vec<(&'static str, &'static str, &'static str)> {
    match hdr {
        "sys/stat" => vec![("stat", "Stat", "stat")],
        "sched" => vec![("misc", "sched_attr", "sched_attr")],
        "sys/utsname" => vec![("utsname", "Utsname", "utsname")],
        "sys/resource" => vec![("resource", "Rlimit", "rlimit")],
        "fcntl" => vec![("fcntl", "Flock", "flock")],
        "termios" => vec![("termios", "termios", "termios")],
        "sys/ioctl" => vec![("termios", "winsize", "winsize")],
        "poll" => vec![("poll", "pollfd", "pollfd")],
        "dirent" => vec![("dirent", "dirent", "dirent")],
        "sys/sysinfo" => vec![("misc", "sysinfo", "sysinfo")],
        "sys/times" => vec![("misc", "tms", "tms")],
        "sys/timex" => vec![("misc", "timex", "timex"), ("misc", "ntptimeval", "ntptimeval")],
        "sys/statfs" => vec![("misc", "statfs", "statfs")],
        "sys/statvfs" => vec![("misc", "statvfs", "statvfs")],
        _ => vec![],
    }
}

const OPAQUE: [(&str, &str); 12] = [
    ("DIR", "DIR"), ("fd_set", "fd_set"),
    ("timespec", "struct_timespec"), ("Timespec", "struct_timespec"), ("timeval", "struct_timeval"),
    ("Timeval", "struct_timeval"), ("itimerspec", "struct_itimerspec"), ("iovec", "struct_iovec"),
    ("sched_param", "struct_sched_param"), ("epoll_event", "struct_epoll_event"),
    ("termios", "struct_termios"), ("winsize", "struct_winsize"),
];

const RULES: &[(&str, &str, &str, &str)] = &[
    (".", "mode", "u32", "mode_t"), (".", "dev", "u64", "dev_t"),
    ("^(umask|getumask)$", "->|mask", "u32", "mode_t"),
    ("^(lseek|lseek64)$", "->", "i64", "off_t"),
    (".", "(off|offset|len|nbytes)", "i64", "off_t"),
    ("^(truncate|ftruncate|truncate64|ftruncate64)$", "len", "i64", "off_t"),
    (".", "(off_in|off_out)", "*mut i64", "*mut loff_t"),
    ("^(sendfile|sendfile64)$", "offset", "*mut i64", "*mut off_t"),
    ("^getdirentries", "basep", "*mut i64", "*mut off_t"),
    ("^(getuid|geteuid)$", "->", "u32", "uid_t"), ("^(getgid|getegid)$", "->", "u32", "gid_t"),
    (".*uid.*|^(chown|lchown|fchown|fchownat)$", "uid|r|e|s", "u32", "uid_t"),
    (".*gid.*|^group_member$|^(chown|lchown|fchown|fchownat)$", "gid|r|e|s", "u32", "gid_t"),
    ("^(setuid|seteuid)$", "uid", "u32", "uid_t"), ("^(setgid|setegid)$", "gid", "u32", "gid_t"),
    ("^setfsuid$", "uid", "c_uint", "uid_t"), ("^setfsgid$", "gid", "c_uint", "gid_t"),
    ("^getresuid$|^setresuid$|^setreuid$", "r|e|s", "u32", "uid_t"),
    ("^getresgid$|^setresgid$|^setregid$", "r|e|s", "u32", "gid_t"),
    ("^getresuid$", "r|e|s", "*mut u32", "*mut uid_t"), ("^getresgid$", "r|e|s", "*mut u32", "*mut gid_t"),
    ("^getgroups$", "list", "*mut u32", "*mut gid_t"), ("^setgroups$", "list", "*const u32", "*const gid_t"),
    ("^(getpriority|setpriority)$", "who", "u32", "id_t"), ("^waitid$", "id", "u32", "id_t"),
    ("^waitid$", "idtype", "c_int", "idtype_t"),
    (".", "pid|pgid|pgrp", "c_int", "pid_t"),
    ("^(getpid|getppid|getpgrp|getpgid|__getpgid|getsid|setsid|fork|vfork|wait|waitpid|wait3|wait4|tcgetpgrp|tcgetsid|forkpty)$", "->", "c_int", "pid_t"),
    ("^(ppoll|pselect|epoll_pwait|epoll_pwait2)$", "sigmask", "*const c_void", "*const sigset_t"),
    ("^signalfd$", "mask", "*const c_void", "*const sigset_t"),
    ("^(wait3|wait4|getrusage)$", "rusage|usage", "*mut c_void", "*mut struct_rusage"),
    ("^(waitid|pidfd_send_signal)$", "infop|info", "*mut c_void", "*mut siginfo_t"),
    ("^(name_to_handle_at|open_by_handle_at)$", "handle", "*mut c_void", "*mut struct_file_handle"),
    ("^statx$", "buf", "*mut c_void", "*mut struct_statx"),
    ("^mount_setattr$", "attr", "*mut c_void", "*mut struct_mount_attr"),
    ("^sched_getaffinity$", "mask", "*mut c_void", "*mut cpu_set_t"),
    ("^sched_setaffinity$", "mask", "*const c_void", "*const cpu_set_t"),
    ("^vmsplice$", "iov", "*const c_void", "*const struct_iovec"),
    ("^(exec\\w*|fexecve)$", "argv|envp", "*const *const c_char", "*const *mut c_char"),
    ("^cf\\w*baud$", "speed", "u32", "baud_t"),
    ("^cfget\\w*baud$", "->", "u32", "baud_t"),
    ("^(cfset\\w*|cfget\\w*)$", "speed", "u32", "speed_t"),
    ("^cfget\\w*$", "->", "u32", "speed_t"),
    ("^__sched_cpualloc$", "->", "*mut c_void", "*mut cpu_set_t"),
    ("^__sched_cpucount$", "set", "*const u8", "*const cpu_set_t"),
    ("^__sched_cpufree$", "set", "*mut c_void", "*mut cpu_set_t"),
    ("^openat2$", "how", "*mut c_void", "*const struct_open_how"),
    ("^quotactl$", "addr", "*mut c_char", "caddr_t"),
    ("^sbrk$", "increment", "isize", "intptr_t"),
    ("^(clock_adjtime|timerfd_create)$", "clock", "c_int", "clockid_t"),
    ("^times$", "->", "c_long", "clock_t"),
    ("^poll$|^ppoll$", "nfds", "c_ulong", "nfds_t"),
    ("^gnu_dev_makedev$", "->", "u64", "dev_t"),
];

const STRUCT64: [(&str, &str); 6] = [
    ("Stat", "struct_stat64"), ("stat", "struct_stat64"), ("statfs", "struct_statfs64"), ("statvfs", "struct_statvfs64"),
    ("dirent", "struct_dirent64"), ("Rlimit", "struct_rlimit64"),
];
const NO64: [&str; 14] = [
    "preadv64", "pwritev64", "preadv64v2", "pwritev64v2", "pread64", "pwrite64", "lseek64", "ftruncate64",
    "truncate64", "mmap64", "sendfile64", "openat64", "open64", "creat64",
];
const NO64_MORE: [&str; 6] = ["lockf64", "fcntl64", "posix_fadvise64", "posix_fallocate64", "fallocate64", "getdirentries64"];

struct Rule {
    f: Regex,
    p: Regex,
    from: &'static str,
    to: &'static str,
}

pub struct Sys {
    root: std::path::PathBuf,
    rules: Vec<Rule>,
    sigs: BTreeMap<String, (String, String)>,
}

fn clean_params(p: &str) -> String {
    let ws = Regex::new(r"\s+").unwrap();
    let mut p = ws.replace_all(p, " ").trim().to_string();
    p = p.trim_end_matches(',').trim().to_string();
    p = Regex::new(r"\bmut args: \.\.\.").unwrap().replace_all(&p, "...").to_string();
    p = Regex::new(r"crate::\w+::").unwrap().replace_all(&p, "").to_string();
    p
}

fn split_params(p: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in p.chars() {
        match ch {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            _ => {}
        }
        if ch == ',' && depth == 0 {
            out.push(cur.trim().to_string());
            cur.clear();
        } else {
            cur.push(ch);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

impl Sys {
    pub fn new(root: &Path) -> Sys {
        let rules = RULES
            .iter()
            .map(|(f, p, from, to)| Rule {
                f: Regex::new(f).unwrap(),
                p: Regex::new(&format!("^(?:{p})$")).unwrap(),
                from,
                to,
            })
            .collect();
        let mut s = Sys { root: root.join("crates/rusty-libc-sys/src"), rules, sigs: BTreeMap::new() };
        s.sigs = s.fn_signatures();
        s
    }

    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(format!("{name}.rs"))).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    fn fn_signatures(&self) -> BTreeMap<String, (String, String)> {
        let fn_re = Regex::new(r#"(?s)cfg_attr\(feature = "export", unsafe\(no_mangle\)\)\]\n(?:#\[[^\n]*\n)*pub (unsafe )?extern "C" fn (\w+)\((.*?)\)(?: -> ([^{]+?))? \{"#).unwrap();
        let alias_re = Regex::new(r"(?ms)^(?:crate::\w+::)?alias!\(\s*(?:(?:///|#\[)[^\n]*\n\s*)*(\w+) => (\w+)\s*\((.*?)\) -> ([^)]+?)\s*\)").unwrap();
        let getter_re = Regex::new(r"(?ms)^getter!\(\s*(?:(?:///|#\[)[^\n]*\n\s*)*(\w+), [^,]+, ([^)]+?)\s*\)").unwrap();
        let mut sigs = BTreeMap::new();
        let mut names: Vec<String> = fs::read_dir(&self.root).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
        names.sort();
        for name in names {
            if !name.ends_with(".rs") || name == "lib.rs" {
                continue;
            }
            let text = fs::read_to_string(self.root.join(&name)).unwrap();
            for m in fn_re.captures_iter(&text) {
                sigs.insert(m[2].to_string(), (clean_params(&m[3]), m.get(4).map(|x| x.as_str().trim().to_string()).unwrap_or_default()));
            }
            for m in alias_re.captures_iter(&text) {
                sigs.insert(m[1].to_string(), (clean_params(&m[3]), m[4].trim().to_string()));
            }
            for m in getter_re.captures_iter(&text) {
                sigs.insert(m[1].to_string(), (String::new(), m[2].trim().to_string()));
            }
        }
        sigs
    }

    fn struct_text(&self, module: &str, rust_name: &str) -> String {
        let text = self.read(module);
        let re = Regex::new(&format!(r"(?s)(?:///[^\n]*\n|#\[[^\n]*\n)*pub (?:struct|union) {rust_name} \{{.*?\n\}}\n")).unwrap();
        re.find(&text).unwrap_or_else(|| panic!("{module}.{rust_name}")).as_str().to_string()
    }

    fn fix_type(&self, func: &str, pname: &str, ty: &str) -> String {
        let mut ty = ty.to_string();
        if ty == "Select" {
            ty = "Option<unsafe extern \"C\" fn(*const dirent) -> c_int>".into();
        }
        if ty == "Cmp" {
            ty = "Option<unsafe extern \"C\" fn(*mut *const dirent, *mut *const dirent) -> c_int>".into();
        }
        for r in &self.rules {
            if ty == r.from && r.p.is_match(pname) && r.f.is_match(func) {
                ty = r.to.to_string();
                break;
            }
        }
        ty = replace_word(&ty, "isize", "ssize_t", false);
        let is64 = func.ends_with("64") || func.ends_with("64_r");
        let no64 = NO64.contains(&func) || NO64_MORE.contains(&func) || func == "scandirat64_";
        if is64 && !no64 {
            for (k, v) in STRUCT64 {
                ty = replace_word(&ty, k, v, false);
            }
        }
        ty
    }

    fn stub(&self, name: &str) -> String {
        let (params, ret) = self.sigs.get(name).unwrap_or_else(|| panic!("no signature: {name}"));
        let mut ps = Vec::new();
        for p in split_params(params) {
            if p == "..." {
                ps.push("...".to_string());
                continue;
            }
            let (pn, ty) = p.split_once(':').unwrap();
            ps.push(format!("{}: {}", pn.trim(), self.fix_type(name, pn.trim(), ty.trim())));
        }
        let ret = if ret.is_empty() { ret.clone() } else { self.fix_type(name, "->", ret) };
        let r = if !ret.is_empty() && ret != "()" { format!(" -> {ret}") } else { String::new() };
        format!("#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn {name}({}){r} {{}}\n", ps.join(", "))
    }

    pub fn header_source(&self, hdr: &str) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut ren: Vec<(&str, &str)> = Vec::new();
        let doc = Regex::new(r"(?m)^///.*\n").unwrap();
        for (module, rname, cname) in sys_structs(hdr) {
            parts.push(doc.replace_all(&self.struct_text(module, rname), "").to_string());
            ren.push((rname, cname));
        }
        for (h, names) in sys_fns() {
            if h == hdr {
                for n in names {
                    parts.push(self.stub(n));
                }
            }
        }
        let mut src = parts.join("\n");
        src = src.replace("; NCCS]", "; 32]");
        src = Regex::new(r"f_fsid: \[c_int; 2\]").unwrap().replace_all(&src, "f_fsid: fsid_t").to_string();
        for (k, v) in &ren {
            if k != v {
                src = replace_word(&src, k, v, true);
            }
        }
        for (k, v) in OPAQUE.iter() {
            if !ren.iter().any(|(rk, _)| rk == k) {
                src = replace_word(&src, k, v, false);
            }
        }
        Regex::new(r"\bmut\s+args\b").unwrap().replace_all(&src, "args").to_string()
    }
}

struct Ty {
    name: &'static str,
    guards: Vec<&'static str>,
    text: &'static str,
    needs: Vec<&'static str>,
}

fn td(name: &'static str, guard: &'static str, text: &'static str) -> Ty {
    Ty { name, guards: vec![guard], text, needs: vec![] }
}

fn types() -> Vec<Ty> {
    let mut v = vec![
        td("ssize_t", "__ssize_t_defined", "typedef long ssize_t;"),
        td("off_t", "__off_t_defined", "typedef long off_t;"),
        td("off64_t", "__off64_t_defined", "typedef long off64_t;"),
        td("loff_t", "__loff_t_defined", "typedef long loff_t;"),
        td("pid_t", "__pid_t_defined", "typedef int pid_t;"),
        td("uid_t", "__uid_t_defined", "typedef unsigned int uid_t;"),
        td("gid_t", "__gid_t_defined", "typedef unsigned int gid_t;"),
        td("mode_t", "__mode_t_defined", "typedef unsigned int mode_t;"),
        td("dev_t", "__dev_t_defined", "typedef unsigned long dev_t;"),
        td("ino_t", "__ino_t_defined", "typedef unsigned long ino_t;"),
        td("ino64_t", "__ino64_t_defined", "typedef unsigned long ino64_t;"),
        td("nlink_t", "__nlink_t_defined", "typedef unsigned long nlink_t;"),
        td("blksize_t", "__blksize_t_defined", "typedef long blksize_t;"),
        td("blkcnt_t", "__blkcnt_t_defined", "typedef long blkcnt_t;"),
        td("blkcnt64_t", "__blkcnt64_t_defined", "typedef long blkcnt64_t;"),
        td("fsblkcnt_t", "__fsblkcnt_t_defined", "typedef unsigned long fsblkcnt_t;"),
        td("fsblkcnt64_t", "__fsblkcnt64_t_defined", "typedef unsigned long fsblkcnt64_t;"),
        td("fsfilcnt_t", "__fsfilcnt_t_defined", "typedef unsigned long fsfilcnt_t;"),
        td("fsfilcnt64_t", "__fsfilcnt64_t_defined", "typedef unsigned long fsfilcnt64_t;"),
        td("id_t", "__id_t_defined", "typedef unsigned int id_t;"),
        td("key_t", "__key_t_defined", "typedef int key_t;"),
        td("useconds_t", "__useconds_t_defined", "typedef unsigned int useconds_t;"),
        td("suseconds_t", "__suseconds_t_defined", "typedef long suseconds_t;"),
        td("time_t", "__time_t_defined", "typedef long time_t;"),
        td("clock_t", "__clock_t_defined", "typedef long clock_t;"),
        td("clockid_t", "__clockid_t_defined", "typedef int clockid_t;"),
        td("socklen_t", "__socklen_t_defined", "typedef unsigned int socklen_t;"),
        td("caddr_t", "__caddr_t_defined", "typedef char *caddr_t;"),
        td("rlim_t", "__rlim_t_defined", "typedef unsigned long rlim_t;"),
        td("rlim64_t", "__rlim64_t_defined", "typedef unsigned long rlim64_t;"),
    ];
    v.push(Ty { name: "struct timespec", guards: vec!["_STRUCT_TIMESPEC", "__timespec_defined"], text: "struct timespec {\n  long tv_sec;\n  long tv_nsec;\n};", needs: vec!["time_t"] });
    v.push(Ty { name: "struct timeval", guards: vec!["__timeval_defined"], text: "struct timeval {\n  long tv_sec;\n  long tv_usec;\n};", needs: vec!["time_t", "suseconds_t"] });
    v.push(Ty { name: "struct itimerspec", guards: vec!["__itimerspec_defined"], text: "struct itimerspec {\n  struct timespec it_interval;\n  struct timespec it_value;\n};", needs: vec!["struct timespec"] });
    v.push(td("struct iovec", "__iovec_defined", "struct iovec {\n  void *iov_base;\n  size_t iov_len;\n};"));
    v.push(td("sigset_t", "__sigset_t_defined", "#ifndef ____sigset_t_defined\n#define ____sigset_t_defined\ntypedef struct {\n  unsigned long __val[16];\n} __sigset_t;\n#endif\ntypedef __sigset_t sigset_t;"));
    v.push(Ty { name: "struct rusage", guards: vec!["__rusage_defined"], text: "struct rusage {\n  struct timeval ru_utime;\n  struct timeval ru_stime;\n  long ru_maxrss;\n  long ru_ixrss;\n  long ru_idrss;\n  long ru_isrss;\n  long ru_minflt;\n  long ru_majflt;\n  long ru_nswap;\n  long ru_inblock;\n  long ru_oublock;\n  long ru_msgsnd;\n  long ru_msgrcv;\n  long ru_nsignals;\n  long ru_nvcsw;\n  long ru_nivcsw;\n};", needs: vec!["struct timeval"] });
    v.push(td("struct sched_param", "_BITS_TYPES_STRUCT_SCHED_PARAM", "struct sched_param {\n  int sched_priority;\n};"));
    v.push(Ty { name: "siginfo_t", guards: vec!["__siginfo_t_defined"], text: "#include <bits/types/siginfo_t.h>", needs: vec!["pid_t", "uid_t", "clock_t"] });
    v
}

fn force(hdr: &str) -> Vec<&'static str> {
    match hdr {
        "sys/types" => vec!["ssize_t", "off_t", "off64_t", "loff_t", "pid_t", "uid_t", "gid_t", "mode_t", "dev_t", "ino_t",
            "ino64_t", "nlink_t", "blksize_t", "blkcnt_t", "blkcnt64_t", "fsblkcnt_t", "fsblkcnt64_t",
            "fsfilcnt_t", "fsfilcnt64_t", "id_t", "key_t", "useconds_t", "suseconds_t", "time_t", "clock_t",
            "clockid_t", "caddr_t"],
        "sys/resource" => vec!["rlim_t", "rlim64_t"],
        _ => vec![],
    }
}

fn types_block(body: &str, force: &[&str]) -> String {
    let all = types();
    let mut order: Vec<usize> = Vec::new();
    fn want(all: &[Ty], name: &str, order: &mut Vec<usize>) {
        let i = all.iter().position(|t| t.name == name).unwrap();
        if order.contains(&i) {
            return;
        }
        for dep in &all[i].needs {
            want(all, dep, order);
        }
        if !order.contains(&i) {
            order.push(i);
        }
    }
    for n in force {
        want(&all, n, &mut order);
    }
    for t in &all {
        let found = if let Some(rest) = t.name.strip_prefix("struct ") {
            let mut f = false;
            for p in word_positions(body, "struct") {
                let after = &body[p + 6..];
                let trimmed = after.trim_start();
                if trimmed.len() < after.len() && trimmed.starts_with(rest) {
                    let e = &trimmed[rest.len()..];
                    if e.bytes().next().map_or(true, |c| !(c.is_ascii_alphanumeric() || c == b'_')) {
                        f = true;
                        break;
                    }
                }
            }
            f
        } else {
            contains_word(body, t.name)
        };
        if found {
            want(&all, t.name, &mut order);
        }
    }
    let mut out = Vec::new();
    for i in order {
        let t = &all[i];
        let cond: Vec<String> = t.guards.iter().map(|g| format!("!defined {g}")).collect();
        let defs: Vec<String> = t.guards.iter().map(|g| format!("#define {g} 1")).collect();
        out.push(format!("#if {}\n{}\n{}\n#endif", cond.join(" && "), defs.join("\n"), t.text));
    }
    out.join("\n")
}

pub fn finish(text: &str, hdr: &str) -> String {
    let text = Regex::new(r"\bstruct_(\w+)\b").unwrap().replace_all(text, "struct $1").to_string();
    let block = types_block(&text, &force(hdr));
    if block.is_empty() {
        return text;
    }
    let inc = Regex::new(r"(?m)^#include <[^>]+>\n").unwrap();
    let pos = match inc.find_iter(&text).last() {
        Some(m) => m.end(),
        None => {
            let d = text.find("#define").unwrap();
            d + text[d..].find('\n').unwrap() + 1
        }
    };
    format!("{}\n{}\n{}", &text[..pos], block, &text[pos..])
}

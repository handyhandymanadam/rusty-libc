use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use rusty_libc_core::syscall::{check, syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};
use rusty_libc_core::{Errno, errno};

#[inline]
pub(crate) fn sc(ret: usize) -> isize {
    if ret > usize::MAX - 4095 {
        errno::set((ret as isize).wrapping_neg() as i32);
        -1
    } else {
        ret as isize
    }
}

#[inline]
pub(crate) fn sci(ret: usize) -> c_int {
    sc(ret) as c_int
}

const SYS_READ: usize = 0;
const SYS_OPEN: usize = 2;
const SYS_CLOSE: usize = 3;
const SYS_SCHED_YIELD: usize = 24;
const SYS_SYSINFO: usize = 99;
const SYS_TIMES: usize = 100;
const SYS_PTRACE: usize = 101;
const SYS_SYSLOG: usize = 103;
const SYS_PERSONALITY: usize = 135;
const SYS_STATFS: usize = 137;
const SYS_FSTATFS: usize = 138;
const SYS_SCHED_SETPARAM: usize = 142;
const SYS_SCHED_GETPARAM: usize = 143;
const SYS_SCHED_SETSCHEDULER: usize = 144;
const SYS_SCHED_GETSCHEDULER: usize = 145;
const SYS_SCHED_GET_PRIORITY_MAX: usize = 146;
const SYS_SCHED_GET_PRIORITY_MIN: usize = 147;
const SYS_SCHED_RR_GET_INTERVAL: usize = 148;
const SYS_PIVOT_ROOT: usize = 155;
const SYS_PRCTL: usize = 157;
const SYS_ACCT: usize = 163;
const SYS_MOUNT: usize = 165;
const SYS_UMOUNT2: usize = 166;
const SYS_SWAPON: usize = 167;
const SYS_SWAPOFF: usize = 168;
const SYS_REBOOT: usize = 169;
const SYS_QUOTACTL: usize = 179;
const SYS_SETXATTR: usize = 188;
const SYS_LSETXATTR: usize = 189;
const SYS_FSETXATTR: usize = 190;
const SYS_GETXATTR: usize = 191;
const SYS_LGETXATTR: usize = 192;
const SYS_FGETXATTR: usize = 193;
const SYS_LISTXATTR: usize = 194;
const SYS_LLISTXATTR: usize = 195;
const SYS_FLISTXATTR: usize = 196;
const SYS_REMOVEXATTR: usize = 197;
const SYS_LREMOVEXATTR: usize = 198;
const SYS_FREMOVEXATTR: usize = 199;
const SYS_SETFSUID: usize = 122;
const SYS_SETFSGID: usize = 123;
const SYS_SCHED_SETAFFINITY: usize = 203;
const SYS_SCHED_GETAFFINITY: usize = 204;
const SYS_UNSHARE: usize = 272;
const SYS_SETNS: usize = 308;
const SYS_CAPGET: usize = 125;
const SYS_CAPSET: usize = 126;
const SYS_GETCPU: usize = 309;
const SYS_CLOCK_ADJTIME: usize = 305;
const SYS_SCHED_SETATTR: usize = 314;
const SYS_SCHED_GETATTR: usize = 315;
const SYS_PIDFD_SEND_SIGNAL: usize = 424;
const SYS_OPEN_TREE: usize = 428;
const SYS_MOVE_MOUNT: usize = 429;
const SYS_FSOPEN: usize = 430;
const SYS_FSCONFIG: usize = 431;
const SYS_FSMOUNT: usize = 432;
const SYS_FSPICK: usize = 433;
const SYS_PIDFD_OPEN: usize = 434;
const SYS_PIDFD_GETFD: usize = 438;
const SYS_MOUNT_SETATTR: usize = 442;

const EIO: i32 = 5;
const EINTR: i32 = 4;
const EFAULT: i32 = 14;
const O_RDONLY_CLOEXEC: usize = 0o2000000;
const CLOCK_REALTIME: c_int = 0;
const ST_VALID: c_ulong = 0x20;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn prctl(option: c_int, mut args: ...) -> c_int {
    unsafe {
        let a2 = args.next_arg::<c_ulong>();
        let a3 = args.next_arg::<c_ulong>();
        let a4 = args.next_arg::<c_ulong>();
        let a5 = args.next_arg::<c_ulong>();
        sci(syscall5(SYS_PRCTL, option as usize, a2 as usize, a3 as usize, a4 as usize, a5 as usize))
    }
}

pub fn getrandom_r(buf: &mut [u8], flags: u32) -> Result<usize, Errno> {
    unsafe { check(syscall3(rusty_libc_core::syscall::SYS_GETRANDOM, buf.as_mut_ptr() as usize, buf.len(), flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrandom(buf: *mut c_void, len: usize, flags: c_uint) -> isize {
    unsafe { sc(syscall3(rusty_libc_core::syscall::SYS_GETRANDOM, buf as usize, len, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getentropy(buf: *mut c_void, len: usize) -> c_int {
    unsafe {
        if len > 256 {
            errno::set(EIO);
            return -1;
        }
        let mut p = buf as usize;
        let end = p + len;
        while p < end {
            let n = sc(syscall3(rusty_libc_core::syscall::SYS_GETRANDOM, p, end - p, 0));
            if n < 0 {
                if errno::get() == EINTR {
                    continue;
                }
                return -1;
            }
            if n == 0 {
                errno::set(EIO);
                return -1;
            }
            p += n as usize;
        }
        0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sysinfo {
    pub uptime: c_long,
    pub loads: [c_ulong; 3],
    pub totalram: c_ulong,
    pub freeram: c_ulong,
    pub sharedram: c_ulong,
    pub bufferram: c_ulong,
    pub totalswap: c_ulong,
    pub freeswap: c_ulong,
    pub procs: u16,
    pub pad: u16,
    pub totalhigh: c_ulong,
    pub freehigh: c_ulong,
    pub mem_unit: c_uint,
}

pub fn sysinfo_r() -> Result<sysinfo, Errno> {
    let mut s = sysinfo::default();
    unsafe { check(syscall1(SYS_SYSINFO, &mut s as *mut sysinfo as usize))? };
    Ok(s)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sysinfo(info: *mut sysinfo) -> c_int {
    unsafe { sci(syscall1(SYS_SYSINFO, info as usize)) }
}

unsafe fn slurp(path: *const u8, buf: &mut [u8]) -> usize {
    unsafe {
        let fd = syscall3(SYS_OPEN, path as usize, O_RDONLY_CLOEXEC, 0);
        if fd > usize::MAX - 4095 {
            return 0;
        }
        let n = syscall3(SYS_READ, fd, buf.as_mut_ptr() as usize, buf.len());
        syscall1(SYS_CLOSE, fd);
        if n > usize::MAX - 4095 { 0 } else { n }
    }
}

fn count_cpu_list(text: &[u8]) -> c_int {
    let mut i = 0;
    let mut total: u64 = 0;
    let num = |i: &mut usize| -> Option<u64> {
        let s = *i;
        let mut v: u64 = 0;
        while *i < text.len() && text[*i].is_ascii_digit() {
            v = v.saturating_mul(10).saturating_add((text[*i] - b'0') as u64);
            *i += 1;
        }
        if *i == s { None } else { Some(v) }
    };
    if text.is_empty() || text[0] == b'\n' {
        return 0;
    }
    loop {
        let n = match num(&mut i) {
            Some(v) => v,
            None => return 0,
        };
        let mut m = n;
        if i < text.len() && text[i] == b'-' {
            i += 1;
            m = match num(&mut i) {
                Some(v) => v,
                None => return 0,
            };
        }
        if m >= n {
            total += m - n + 1;
        }
        if i < text.len() && text[i] == b',' {
            i += 1;
        }
        if !(i < text.len() && text[i] != b'\n') {
            break;
        }
    }
    total as c_int
}

fn nprocs_stat() -> c_int {
    unsafe {
        let fd = syscall3(SYS_OPEN, c"/proc/stat".as_ptr() as usize, O_RDONLY_CLOEXEC, 0);
        if fd > usize::MAX - 4095 {
            return 0;
        }
        let mut buf = [0u8; 1024];
        let mut line = [0u8; 4];
        let mut pos = 0usize;
        let mut count = 0;
        'outer: loop {
            let n = syscall3(SYS_READ, fd, buf.as_mut_ptr() as usize, buf.len());
            if n > usize::MAX - 4095 || n == 0 {
                break;
            }
            for &b in &buf[..n] {
                if b == b'\n' {
                    if pos >= 3 && &line[..3] == b"cpu" {
                        if pos >= 4 && line[3].is_ascii_digit() {
                            count += 1;
                        }
                    } else {
                        break 'outer;
                    }
                    pos = 0;
                } else {
                    if pos < 4 {
                        line[pos] = b;
                    }
                    pos += 1;
                }
            }
        }
        syscall1(SYS_CLOSE, fd);
        count
    }
}

fn nprocs_sched() -> c_int {
    unsafe {
        let mut bits = [0u64; 512];
        let r = syscall3(SYS_SCHED_GETAFFINITY, 0, 4096, bits.as_mut_ptr() as usize);
        if r != 0 && r <= usize::MAX - 4095 {
            let bytes = r.min(4096);
            let mut c = 0u32;
            for (i, w) in bits.iter().enumerate() {
                if i * 8 < bytes {
                    c += w.count_ones();
                }
            }
            return c as c_int;
        }
        if r == (-22isize) as usize {
            return 32768;
        }
        0
    }
}

fn nprocs_fallback() -> c_int {
    let r = nprocs_stat();
    if r != 0 {
        return r;
    }
    let r = nprocs_sched();
    if r != 0 {
        return r;
    }
    2
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn get_nprocs() -> c_int {
    let mut buf = [0u8; 1024];
    let n = unsafe { slurp(c"/sys/devices/system/cpu/online".as_ptr().cast(), &mut buf) };
    let r = count_cpu_list(&buf[..n]);
    if r != 0 { r } else { nprocs_fallback() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn get_nprocs_conf() -> c_int {
    let mut buf = [0u8; 1024];
    let n = unsafe { slurp(c"/sys/devices/system/cpu/possible".as_ptr().cast(), &mut buf) };
    let r = count_cpu_list(&buf[..n]);
    if r != 0 { r } else { nprocs_fallback() }
}

fn mempages(num: c_ulong, mut mem_unit: c_uint) -> c_long {
    let mut ps: c_ulong = 4096;
    while mem_unit > 1 && ps > 1 {
        mem_unit >>= 1;
        ps >>= 1;
    }
    let mut num = num.wrapping_mul(mem_unit as c_ulong);
    while ps > 1 {
        ps >>= 1;
        num >>= 1;
    }
    num as c_long
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn get_phys_pages() -> c_long {
    let mut s = sysinfo::default();
    unsafe { syscall1(SYS_SYSINFO, &mut s as *mut sysinfo as usize) };
    mempages(s.totalram, s.mem_unit)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn get_avphys_pages() -> c_long {
    let mut s = sysinfo::default();
    unsafe { syscall1(SYS_SYSINFO, &mut s as *mut sysinfo as usize) };
    mempages(s.freeram, s.mem_unit)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct sched_param {
    pub sched_priority: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sched_attr {
    pub size: u32,
    pub sched_policy: u32,
    pub sched_flags: u64,
    pub sched_nice: i32,
    pub sched_priority: u32,
    pub sched_runtime: u64,
    pub sched_deadline: u64,
    pub sched_period: u64,
    pub sched_util_min: u32,
    pub sched_util_max: u32,
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getcpu(cpu: *mut c_uint, node: *mut c_uint) -> c_int {
    unsafe { sci(syscall3(309, cpu as usize, node as usize, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sched_yield() -> c_int {
    unsafe { sci(syscall0(SYS_SCHED_YIELD)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getaffinity(pid: c_int, size: usize, mask: *mut c_void) -> c_int {
    unsafe {
        let r = sc(syscall3(SYS_SCHED_GETAFFINITY, pid as usize, size.min(i32::MAX as usize), mask as usize));
        if r != -1 {
            let w = r as usize;
            if size > w {
                core::ptr::write_bytes((mask as *mut u8).add(w), 0, size - w);
            }
            return 0;
        }
        -1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setaffinity(pid: c_int, size: usize, mask: *const c_void) -> c_int {
    unsafe { sci(syscall3(SYS_SCHED_SETAFFINITY, pid as usize, size, mask as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sched_getscheduler(pid: c_int) -> c_int {
    unsafe { sci(syscall1(SYS_SCHED_GETSCHEDULER, pid as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setscheduler(pid: c_int, policy: c_int, param: *const sched_param) -> c_int {
    unsafe { sci(syscall3(SYS_SCHED_SETSCHEDULER, pid as usize, policy as usize, param as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getparam(pid: c_int, param: *mut sched_param) -> c_int {
    unsafe { sci(syscall2(SYS_SCHED_GETPARAM, pid as usize, param as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setparam(pid: c_int, param: *const sched_param) -> c_int {
    unsafe { sci(syscall2(SYS_SCHED_SETPARAM, pid as usize, param as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sched_get_priority_max(policy: c_int) -> c_int {
    unsafe { sci(syscall1(SYS_SCHED_GET_PRIORITY_MAX, policy as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sched_get_priority_min(policy: c_int) -> c_int {
    unsafe { sci(syscall1(SYS_SCHED_GET_PRIORITY_MIN, policy as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_rr_get_interval(pid: c_int, tp: *mut crate::poll::timespec) -> c_int {
    unsafe { sci(syscall2(SYS_SCHED_RR_GET_INTERVAL, pid as usize, tp as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getattr(pid: c_int, attr: *mut sched_attr, size: c_uint, flags: c_uint) -> c_int {
    unsafe { sci(syscall4(SYS_SCHED_GETATTR, pid as usize, attr as usize, size as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setattr(pid: c_int, attr: *mut sched_attr, flags: c_uint) -> c_int {
    unsafe { sci(syscall3(SYS_SCHED_SETATTR, pid as usize, attr as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sched_getcpu() -> c_int {
    let mut cpu: c_uint = 0;
    unsafe {
        let r = sci(syscall3(SYS_GETCPU, &mut cpu as *mut c_uint as usize, 0, 0));
        if r == -1 { -1 } else { cpu as c_int }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __sched_cpualloc(count: usize) -> *mut c_void {
    unsafe { rusty_libc_malloc::malloc(count.div_ceil(64) * 8) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_cpufree(set: *mut c_void) {
    unsafe { rusty_libc_malloc::free(set) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_cpucount(setsize: usize, set: *const u8) -> c_int {
    unsafe {
        let mut c = 0u32;
        for i in 0..setsize {
            c += (*set.add(i)).count_ones();
        }
        c as c_int
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn unshare(flags: c_int) -> c_int {
    unsafe { sci(syscall1(SYS_UNSHARE, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn capget(header: *mut c_void, data: *mut c_void) -> c_int {
    unsafe { sci(syscall2(SYS_CAPGET, header as usize, data as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn capset(header: *mut c_void, data: *mut c_void) -> c_int {
    unsafe { sci(syscall2(SYS_CAPSET, header as usize, data as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setns(fd: c_int, nstype: c_int) -> c_int {
    unsafe { sci(syscall2(SYS_SETNS, fd as usize, nstype as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn reboot(howto: c_int) -> c_int {
    unsafe { sci(syscall3(SYS_REBOOT, 0xfee1_dead, 672274793, howto as isize as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mount(source: *const c_char, target: *const c_char, fstype: *const c_char, flags: c_ulong, data: *const c_void) -> c_int {
    unsafe { sci(syscall5(SYS_MOUNT, source as usize, target as usize, fstype as usize, flags as usize, data as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn umount(target: *const c_char) -> c_int {
    unsafe { sci(syscall2(SYS_UMOUNT2, target as usize, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn umount2(target: *const c_char, flags: c_int) -> c_int {
    unsafe { sci(syscall2(SYS_UMOUNT2, target as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pivot_root(new_root: *const c_char, put_old: *const c_char) -> c_int {
    unsafe { sci(syscall2(SYS_PIVOT_ROOT, new_root as usize, put_old as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open_tree(dfd: c_int, path: *const c_char, flags: c_uint) -> c_int {
    unsafe { sci(syscall3(SYS_OPEN_TREE, dfd as isize as usize, path as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn move_mount(from_dfd: c_int, from_path: *const c_char, to_dfd: c_int, to_path: *const c_char, flags: c_uint) -> c_int {
    unsafe {
        sci(syscall5(SYS_MOVE_MOUNT, from_dfd as isize as usize, from_path as usize, to_dfd as isize as usize, to_path as usize, flags as usize))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fsopen(fsname: *const c_char, flags: c_uint) -> c_int {
    unsafe { sci(syscall2(SYS_FSOPEN, fsname as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fsconfig(fd: c_int, cmd: c_uint, key: *const c_char, value: *const c_void, aux: c_int) -> c_int {
    unsafe { sci(syscall5(SYS_FSCONFIG, fd as usize, cmd as usize, key as usize, value as usize, aux as isize as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fsmount(fd: c_int, flags: c_uint, attr_flags: c_uint) -> c_int {
    unsafe { sci(syscall3(SYS_FSMOUNT, fd as usize, flags as usize, attr_flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fspick(dfd: c_int, path: *const c_char, flags: c_uint) -> c_int {
    unsafe { sci(syscall3(SYS_FSPICK, dfd as isize as usize, path as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mount_setattr(dfd: c_int, path: *const c_char, flags: c_uint, attr: *mut c_void, size: usize) -> c_int {
    unsafe { sci(syscall5(SYS_MOUNT_SETATTR, dfd as isize as usize, path as usize, flags as usize, attr as usize, size)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn swapon(path: *const c_char, flags: c_int) -> c_int {
    unsafe { sci(syscall2(SYS_SWAPON, path as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn swapoff(path: *const c_char) -> c_int {
    unsafe { sci(syscall1(SYS_SWAPOFF, path as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ptrace(request: c_int, mut args: ...) -> c_long {
    unsafe {
        let pid = args.next_arg::<c_int>();
        let addr = args.next_arg::<*mut c_void>();
        let mut data = args.next_arg::<*mut c_void>();
        let mut word: c_long = 0;
        let peek = request > 0 && request < 4;
        if peek {
            data = &mut word as *mut c_long as *mut c_void;
        }
        let res = sc(syscall4(SYS_PTRACE, request as isize as usize, pid as isize as usize, addr as usize, data as usize)) as c_long;
        if res >= 0 && peek {
            errno::set(0);
            return word;
        }
        res
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn personality(persona: c_ulong) -> c_int {
    unsafe { syscall1(SYS_PERSONALITY, persona as u32 as usize) as isize as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn klogctl(kind: c_int, buf: *mut c_char, len: c_int) -> c_int {
    unsafe { sci(syscall3(SYS_SYSLOG, kind as usize, buf as usize, len as isize as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn acct(file: *const c_char) -> c_int {
    unsafe { sci(syscall1(SYS_ACCT, file as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn quotactl(cmd: c_int, special: *const c_char, id: c_int, addr: *mut c_char) -> c_int {
    unsafe { sci(syscall4(SYS_QUOTACTL, cmd as usize, special as usize, id as isize as usize, addr as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pidfd_open(pid: c_int, flags: c_uint) -> c_int {
    unsafe { sci(syscall2(SYS_PIDFD_OPEN, pid as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pidfd_getfd(pidfd: c_int, targetfd: c_int, flags: c_uint) -> c_int {
    unsafe { sci(syscall3(SYS_PIDFD_GETFD, pidfd as usize, targetfd as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_send_signal(pidfd: c_int, sig: c_int, info: *mut c_void, flags: c_uint) -> c_int {
    unsafe { sci(syscall4(SYS_PIDFD_SEND_SIGNAL, pidfd as usize, sig as usize, info as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn syscall(number: c_long, mut args: ...) -> c_long {
    unsafe {
        let a0 = args.next_arg::<c_long>();
        let a1 = args.next_arg::<c_long>();
        let a2 = args.next_arg::<c_long>();
        let a3 = args.next_arg::<c_long>();
        let a4 = args.next_arg::<c_long>();
        let a5 = args.next_arg::<c_long>();
        sc(syscall6(number as usize, a0 as usize, a1 as usize, a2 as usize, a3 as usize, a4 as usize, a5 as usize)) as c_long
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct timex {
    pub modes: c_uint,
    pub offset: c_long,
    pub freq: c_long,
    pub maxerror: c_long,
    pub esterror: c_long,
    pub status: c_int,
    pub constant: c_long,
    pub precision: c_long,
    pub tolerance: c_long,
    pub time: crate::poll::timeval,
    pub tick: c_long,
    pub ppsfreq: c_long,
    pub jitter: c_long,
    pub shift: c_int,
    pub stabil: c_long,
    pub jitcnt: c_long,
    pub calcnt: c_long,
    pub errcnt: c_long,
    pub stbcnt: c_long,
    pub tai: c_int,
    pub _pad: [c_int; 11],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ntptimeval {
    pub time: crate::poll::timeval,
    pub maxerror: c_long,
    pub esterror: c_long,
    pub tai: c_long,
    pub reserved: [c_long; 4],
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_adjtime(clock: c_int, tx: *mut timex) -> c_int {
    unsafe { sci(syscall2(SYS_CLOCK_ADJTIME, clock as usize, tx as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn adjtimex(tx: *mut timex) -> c_int {
    unsafe { clock_adjtime(CLOCK_REALTIME, tx) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ntp_adjtime(tx: *mut timex) -> c_int {
    unsafe { clock_adjtime(CLOCK_REALTIME, tx) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ntp_gettime(ntv: *mut ntptimeval) -> c_int {
    unsafe {
        let mut t = timex::default();
        let r = clock_adjtime(CLOCK_REALTIME, &mut t);
        (*ntv).time = t.time;
        (*ntv).maxerror = t.maxerror;
        (*ntv).esterror = t.esterror;
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ntp_gettimex(ntv: *mut ntptimeval) -> c_int {
    unsafe {
        let mut t = timex::default();
        let r = clock_adjtime(CLOCK_REALTIME, &mut t);
        (*ntv).time = t.time;
        (*ntv).maxerror = t.maxerror;
        (*ntv).esterror = t.esterror;
        (*ntv).tai = t.tai as c_long;
        (*ntv).reserved = [0; 4];
        r
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tms {
    pub tms_utime: c_long,
    pub tms_stime: c_long,
    pub tms_cutime: c_long,
    pub tms_cstime: c_long,
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn times(buf: *mut tms) -> c_long {
    unsafe {
        let ret = syscall1(SYS_TIMES, buf as usize);
        if ret > usize::MAX - 4095 && (ret as isize).wrapping_neg() as i32 == EFAULT && !buf.is_null() {
            let _ = core::ptr::read_volatile(&(*buf).tms_utime);
        }
        if ret as isize == -1 { 0 } else { ret as c_long }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct statfs {
    pub f_type: c_long,
    pub f_bsize: c_long,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: [c_int; 2],
    pub f_namelen: c_long,
    pub f_frsize: c_long,
    pub f_flags: c_long,
    pub f_spare: [c_long; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct statvfs {
    pub f_bsize: c_ulong,
    pub f_frsize: c_ulong,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_favail: u64,
    pub f_fsid: c_ulong,
    pub f_flag: c_ulong,
    pub f_namemax: c_ulong,
    pub f_type: c_uint,
    pub __f_spare: [c_int; 5],
}

pub fn statfs_to_statvfs(fs: &statfs) -> statvfs {
    statvfs {
        f_bsize: fs.f_bsize as c_ulong,
        f_frsize: if fs.f_frsize != 0 { fs.f_frsize } else { fs.f_bsize } as c_ulong,
        f_blocks: fs.f_blocks,
        f_bfree: fs.f_bfree,
        f_bavail: fs.f_bavail,
        f_files: fs.f_files,
        f_ffree: fs.f_ffree,
        f_favail: fs.f_ffree,
        f_fsid: (fs.f_fsid[0] as u32 as c_ulong) | ((fs.f_fsid[1] as u32 as c_ulong) << 32),
        f_flag: (fs.f_flags as c_ulong) ^ ST_VALID,
        f_namemax: fs.f_namelen as c_ulong,
        f_type: fs.f_type as c_uint,
        __f_spare: [0; 5],
    }
}

pub unsafe fn statfs_r(path: *const c_char) -> Result<statfs, Errno> {
    unsafe {
        let mut s = statfs::default();
        check(syscall2(SYS_STATFS, path as usize, &mut s as *mut statfs as usize))?;
        Ok(s)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn statfs(path: *const c_char, buf: *mut statfs) -> c_int {
    unsafe { sci(syscall2(SYS_STATFS, path as usize, buf as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn statfs64(path: *const c_char, buf: *mut statfs) -> c_int {
    unsafe { statfs(path, buf) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fstatfs(fd: c_int, buf: *mut statfs) -> c_int {
    unsafe { sci(syscall2(SYS_FSTATFS, fd as usize, buf as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fstatfs64(fd: c_int, buf: *mut statfs) -> c_int {
    unsafe { fstatfs(fd, buf) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn statvfs(path: *const c_char, buf: *mut statvfs) -> c_int {
    unsafe {
        let mut fs = statfs::default();
        if statfs(path, &mut fs) < 0 {
            return -1;
        }
        *buf = statfs_to_statvfs(&fs);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn statvfs64(path: *const c_char, buf: *mut statvfs) -> c_int {
    unsafe { statvfs(path, buf) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fstatvfs(fd: c_int, buf: *mut statvfs) -> c_int {
    unsafe {
        let mut fs = statfs::default();
        if fstatfs(fd, &mut fs) < 0 {
            return -1;
        }
        *buf = statfs_to_statvfs(&fs);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fstatvfs64(fd: c_int, buf: *mut statvfs) -> c_int {
    unsafe { fstatvfs(fd, buf) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getxattr(path: *const c_char, name: *const c_char, value: *mut c_void, size: usize) -> isize {
    unsafe { sc(syscall4(SYS_GETXATTR, path as usize, name as usize, value as usize, size)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lgetxattr(path: *const c_char, name: *const c_char, value: *mut c_void, size: usize) -> isize {
    unsafe { sc(syscall4(SYS_LGETXATTR, path as usize, name as usize, value as usize, size)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetxattr(fd: c_int, name: *const c_char, value: *mut c_void, size: usize) -> isize {
    unsafe { sc(syscall4(SYS_FGETXATTR, fd as usize, name as usize, value as usize, size)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setxattr(path: *const c_char, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
    unsafe { sci(syscall5(SYS_SETXATTR, path as usize, name as usize, value as usize, size, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lsetxattr(path: *const c_char, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
    unsafe { sci(syscall5(SYS_LSETXATTR, path as usize, name as usize, value as usize, size, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fsetxattr(fd: c_int, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
    unsafe { sci(syscall5(SYS_FSETXATTR, fd as usize, name as usize, value as usize, size, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn listxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    unsafe { sc(syscall3(SYS_LISTXATTR, path as usize, list as usize, size)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    unsafe { sc(syscall3(SYS_LLISTXATTR, path as usize, list as usize, size)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn flistxattr(fd: c_int, list: *mut c_char, size: usize) -> isize {
    unsafe { sc(syscall3(SYS_FLISTXATTR, fd as usize, list as usize, size)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn removexattr(path: *const c_char, name: *const c_char) -> c_int {
    unsafe { sci(syscall2(SYS_REMOVEXATTR, path as usize, name as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int {
    unsafe { sci(syscall2(SYS_LREMOVEXATTR, path as usize, name as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fremovexattr(fd: c_int, name: *const c_char) -> c_int {
    unsafe { sci(syscall2(SYS_FREMOVEXATTR, fd as usize, name as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setfsuid(uid: c_uint) -> c_int {
    unsafe { sci(syscall1(SYS_SETFSUID, uid as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setfsgid(gid: c_uint) -> c_int {
    unsafe { sci(syscall1(SYS_SETFSGID, gid as usize)) }
}


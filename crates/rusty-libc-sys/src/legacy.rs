use crate::resource::{Rlimit, getrlimit, setrlimit};
use crate::unistd::rc;
use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use rusty_libc_core::syscall::{self, syscall1, syscall2, syscall3, syscall4, syscall5};
use rusty_libc_core::errno;

const ENOSYS: c_int = 38;
const EINVAL: c_int = 22;
const EBADF: c_int = 9;
const ESRCH: c_int = 3;
const ENOENT: c_int = 2;

mod nr {
    pub const ARCH_PRCTL: usize = 158;
    pub const SYSCTL: usize = 156;
    pub const MODIFY_LDT: usize = 154;
    pub const IOPL: usize = 172;
    pub const IOPERM: usize = 173;
    pub const CREATE_MODULE: usize = 174;
    pub const INIT_MODULE: usize = 175;
    pub const DELETE_MODULE: usize = 176;
    pub const GET_KERNEL_SYMS: usize = 177;
    pub const QUERY_MODULE: usize = 178;
    pub const NFSSERVCTL: usize = 180;
    pub const USTAT: usize = 136;
    pub const USELIB: usize = 134;
    pub const OPENAT: usize = 257;
    pub const READ: usize = 0;
    pub const CLOSE: usize = 3;
}

fn fail(e: c_int) -> c_int {
    errno::set(e);
    -1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gtty(_fd: c_int, params: *mut c_void) -> c_int {
    fail(if params.is_null() { EINVAL } else { ENOSYS })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn stty(_fd: c_int, params: *const c_void) -> c_int {
    fail(if params.is_null() { EINVAL } else { ENOSYS })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn chflags(_file: *const c_char, _flags: c_ulong) -> c_int {
    fail(ENOSYS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fchflags(_fd: c_int, _flags: c_ulong) -> c_int {
    fail(ENOSYS)
}

#[repr(C)]
struct SysctlArgs {
    name: *mut c_int,
    nlen: c_int,
    oldval: *mut c_void,
    oldlenp: *mut usize,
    newval: *mut c_void,
    newlen: usize,
    unused: [c_ulong; 4],
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sysctl(name: *mut c_int, nlen: c_int, oldval: *mut c_void, oldlenp: *mut usize, newval: *mut c_void, newlen: usize) -> c_int {
    let args = SysctlArgs { name, nlen, oldval, oldlenp, newval, newlen, unused: [0; 4] };
    rc(unsafe { syscall1(nr::SYSCTL, &args as *const SysctlArgs as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ioperm(from: c_ulong, num: c_ulong, turn_on: c_int) -> c_int {
    rc(unsafe { syscall3(nr::IOPERM, from as usize, num as usize, turn_on as isize as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn iopl(level: c_int) -> c_int {
    rc(unsafe { syscall1(nr::IOPL, level as isize as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn modify_ldt(func: c_int, ptr: *mut c_void, bytecount: c_ulong) -> c_int {
    rc(unsafe { syscall3(nr::MODIFY_LDT, func as isize as usize, ptr as usize, bytecount as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn init_module(image: *mut c_void, len: c_ulong, params: *const c_char) -> c_int {
    rc(unsafe { syscall3(nr::INIT_MODULE, image as usize, len as usize, params as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn delete_module(name: *const c_char, flags: c_uint) -> c_int {
    rc(unsafe { syscall2(nr::DELETE_MODULE, name as usize, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn create_module(name: *const c_char, size: usize) -> c_long {
    let r = rc(unsafe { syscall2(nr::CREATE_MODULE, name as usize, size) });
    r as c_long
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn query_module(name: *const c_char, which: c_int, buf: *mut c_void, bufsize: usize, ret: *mut usize) -> c_int {
    rc(unsafe { syscall5(nr::QUERY_MODULE, name as usize, which as isize as usize, buf as usize, bufsize, ret as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn get_kernel_syms(table: *mut c_void) -> c_int {
    rc(unsafe { syscall1(nr::GET_KERNEL_SYMS, table as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nfsservctl(cmd: c_int, argp: *mut c_void, resp: *mut c_void) -> c_long {
    rc(unsafe { syscall3(nr::NFSSERVCTL, cmd as isize as usize, argp as usize, resp as usize) }) as c_long
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn uselib(library: *const c_char) -> c_int {
    rc(unsafe { syscall1(nr::USELIB, library as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ustat(dev: c_ulong, ubuf: *mut c_void) -> c_int {
    rc(unsafe { syscall2(nr::USTAT, dev as usize, ubuf as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn bdflush(_func: c_int, _data: c_long) -> c_int {
    fail(ENOSYS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sysctl(name: *mut c_int, nlen: c_int, oldval: *mut c_void, oldlenp: *mut usize, newval: *mut c_void, newlen: usize) -> c_int {
    unsafe { sysctl(name, nlen, oldval, oldlenp, newval, newlen) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isastream(fildes: c_int) -> c_int {
    let r = unsafe { syscall3(72, fildes as isize as usize, 1, 0) };
    match syscall::check(r) {
        Ok(_) => 0,
        Err(e) => fail(e.0),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getmsg(_fildes: c_int, _ctlptr: *mut c_void, _dataptr: *mut c_void, _flagsp: *mut c_int) -> c_int {
    fail(ENOSYS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpmsg(_fildes: c_int, _ctlptr: *mut c_void, _dataptr: *mut c_void, _bandp: *mut c_int, _flagsp: *mut c_int) -> c_int {
    fail(ENOSYS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putmsg(_fildes: c_int, _ctlptr: *const c_void, _dataptr: *const c_void, _flags: c_int) -> c_int {
    fail(ENOSYS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putpmsg(_fildes: c_int, _ctlptr: *const c_void, _dataptr: *const c_void, _band: c_int, _flags: c_int) -> c_int {
    fail(ENOSYS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fattach(_fildes: c_int, _path: *const c_char) -> c_int {
    fail(ENOSYS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fdetach(_path: *const c_char) -> c_int {
    fail(ENOSYS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sstk(_increment: c_int) -> *mut c_void {
    errno::set(ENOSYS);
    -1isize as *mut c_void
}

#[repr(C)]
pub struct Vtimes {
    pub vm_utime: c_int,
    pub vm_stime: c_int,
    pub vm_idsrss: c_uint,
    pub vm_ixrss: c_uint,
    pub vm_maxrss: c_int,
    pub vm_majflt: c_int,
    pub vm_minflt: c_int,
    pub vm_nswap: c_int,
    pub vm_inblk: c_int,
    pub vm_oublk: c_int,
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vtimes(current: *mut Vtimes, child: *mut Vtimes) -> c_int {
    unsafe {
        const HZ: i64 = 60;
        fn from_usage(v: &mut Vtimes, r: &crate::resource::Rusage) {
            let ticks = |t: &crate::resource::Timeval| (t.tv_sec * HZ + t.tv_usec * HZ / 1_000_000) as c_int;
            v.vm_utime = ticks(&r.ru_utime);
            v.vm_stime = ticks(&r.ru_stime);
            v.vm_idsrss = (r.ru_idrss as u64).wrapping_add(r.ru_isrss as u64) as c_uint;
            v.vm_majflt = r.ru_majflt as c_int;
            v.vm_minflt = r.ru_minflt as c_int;
            v.vm_nswap = r.ru_nswap as c_int;
            v.vm_inblk = r.ru_inblock as c_int;
            v.vm_oublk = r.ru_oublock as c_int;
        }
        let mut usage = crate::resource::Rusage::default();
        if !current.is_null() {
            if crate::resource::getrusage(crate::resource::RUSAGE_SELF, (&mut usage as *mut crate::resource::Rusage).cast()) < 0 {
                return -1;
            }
            from_usage(&mut *current, &usage);
        }
        if !child.is_null() {
            if crate::resource::getrusage(crate::resource::RUSAGE_CHILDREN, (&mut usage as *mut crate::resource::Rusage).cast()) < 0 {
                return -1;
            }
            from_usage(&mut *child, &usage);
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn vlimit(resource: c_int, value: c_int) -> c_int {
    use crate::resource::{RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA, RLIMIT_FSIZE, RLIMIT_RSS, RLIMIT_STACK};
    let res = match resource {
        1 => RLIMIT_CPU,
        2 => RLIMIT_FSIZE,
        3 => RLIMIT_DATA,
        4 => RLIMIT_STACK,
        5 => RLIMIT_CORE,
        6 => RLIMIT_RSS,
        _ => return fail(EINVAL),
    };
    let mut lim = Rlimit::default();
    unsafe {
        if getrlimit(res, &mut lim) < 0 {
            return -1;
        }
        lim.rlim_cur = value as i64 as u64;
        setrlimit(res, &lim)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn llseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    unsafe { crate::unistd::lseek64(fd, offset, whence) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn arch_prctl(code: c_int, addr: c_ulong) -> c_int {
    rc(unsafe { syscall2(nr::ARCH_PRCTL, code as isize as usize, addr as usize) })
}

core::arch::global_asm!(
    ".text",
    ".globl rl_clone_raw",
    ".type rl_clone_raw, @function",
    "rl_clone_raw:",
    "mov rax, -22",
    "test rdi, rdi",
    "jz 2f",
    "test rsi, rsi",
    "jz 2f",
    "and rsi, -16",
    "sub rsi, 16",
    "mov qword ptr [rsi + 8], rcx",
    "mov qword ptr [rsi], rdi",
    "mov rdi, rdx",
    "mov rdx, r8",
    "mov r8, r9",
    "mov r10, qword ptr [rsp + 8]",
    "mov eax, 56",
    "syscall",
    "test rax, rax",
    "jz 3f",
    "2:",
    "ret",
    "3:",
    "xor ebp, ebp",
    "pop rax",
    "pop rdi",
    "call rax",
    "mov rdi, rax",
    "mov eax, 60",
    "syscall",
    "ud2",
    ".size rl_clone_raw, . - rl_clone_raw",
);

unsafe extern "C" {
    fn rl_clone_raw(f: unsafe extern "C" fn(*mut c_void) -> c_int, stack: *mut c_void, flags: c_int, arg: *mut c_void, ptid: *mut c_int, tls: *mut c_void, ctid: *mut c_int) -> isize;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clone(f: Option<unsafe extern "C" fn(*mut c_void) -> c_int>, stack: *mut c_void, flags: c_int, arg: *mut c_void, mut args: ...) -> c_int {
    unsafe {
        let ptid: *mut c_int = args.next_arg();
        let tls: *mut c_void = args.next_arg();
        let ctid: *mut c_int = args.next_arg();
        let Some(f) = f else { return fail(EINVAL) };
        rc(rl_clone_raw(f, stack, flags, arg, ptid, tls, ctid) as usize)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pidfd_getpid(fd: c_int) -> c_int {
    if fd < 0 {
        return fail(EBADF);
    }
    let mut path = [0u8; 40];
    let prefix = b"/proc/self/fdinfo/";
    path[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0u8; 12];
    let mut n = fd as u32;
    let mut k = digits.len();
    loop {
        k -= 1;
        digits[k] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let dl = digits.len() - k;
    path[prefix.len()..prefix.len() + dl].copy_from_slice(&digits[k..]);
    const AT_FDCWD: usize = -100isize as usize;
    const O_RDONLY_CLOEXEC: usize = 0o2000000;
    let f = unsafe { syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as usize, O_RDONLY_CLOEXEC, 0) };
    let f = match syscall::check(f) {
        Ok(v) => v as c_int,
        Err(e) => {
            errno::set(if e.0 == ENOENT { EBADF } else { e.0 });
            return -1;
        }
    };
    let mut buf = [0u8; 1024];
    let mut len = 0usize;
    loop {
        let r = unsafe { syscall3(nr::READ, f as usize, buf.as_mut_ptr().add(len) as usize, buf.len() - len) };
        match syscall::check(r) {
            Ok(0) => break,
            Ok(m) => {
                len += m;
                if len == buf.len() {
                    break;
                }
            }
            Err(e) => {
                unsafe { syscall1(nr::CLOSE, f as usize) };
                errno::set(e.0);
                return -1;
            }
        }
    }
    unsafe { syscall1(nr::CLOSE, f as usize) };
    let text = &buf[..len];
    let mut pid: Option<i32> = None;
    for line in text.split(|&c| c == b'\n') {
        if let Some(rest) = line.strip_prefix(b"Pid:") {
            let rest = rest.trim_ascii_start();
            let (neg, rest) = match rest.first() {
                Some(b'-') => (true, &rest[1..]),
                Some(b'+') => (false, &rest[1..]),
                _ => (false, rest),
            };
            let mut v: i64 = 0;
            let mut any = false;
            for &c in rest {
                if !c.is_ascii_digit() {
                    break;
                }
                any = true;
                v = (v * 10 + (c - b'0') as i64).min(i32::MAX as i64 + 1);
            }
            if any {
                pid = Some(if neg { -(v as i32) } else { v as i32 });
                break;
            }
        }
    }
    match pid {
        None => fail(EBADF),
        Some(-1) => fail(ESRCH),
        Some(p) => p,
    }
}


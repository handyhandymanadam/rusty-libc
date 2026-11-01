//! Functions and data that glibc 2.43 exports only under an old symbol version (no new program can link them): the BSD
//! `sigvec`, `vtimes`, `sstk`, the removed system calls (`ustat`, `uselib`, `create_module`, ...), the STREAMS stubs, the
//! regexp.h `step` / `advance`, the inline string helpers of old string.h, the `__nss_*` stubs, `__ivaliduser`, ...
//! They are exported by compat_symver.rs under their old version names (`sigvec@GLIBC_2.2.5`) so a static program that asks
//! for one with `.symver` (or an old object file) links; this file has the code, under private names (`__rl_old_*`).
//! The behaviour follows glibc 2.43's compat sources (signal/sigvec.c, resource/vtimes.c, misc/regexp.c,
//! string/string-inlines.c, nss/compat-lookup.c, posix/streams-compat.c, ...), read as reference; the code is Rust.
use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{errno, ffi, syscall};

const ENOSYS: i32 = 38;
const EINVAL: i32 = 22;

fn fail<T>(e: i32, v: T) -> T {
    errno::set(e);
    v
}

/// A raw system call with C's convention: -1 and errno on failure.
///
/// # Safety
/// The arguments are valid for system call `nr` (pointers the kernel reads or writes point to what the call expects).
unsafe fn sys(nr: usize, a: usize, b: usize, c: usize, d: usize, e: usize) -> isize {
    // SAFETY: the arguments are valid for `nr` (forwarded contract).
    let r = unsafe { syscall::syscall5(nr, a, b, c, d, e) };
    match syscall::check(r) {
        Ok(v) => v as isize,
        Err(e) => fail(e.0, -1),
    }
}

// ---------------------------------------------------------------------------------------- sigvec

/// BSD `struct sigvec`.
#[repr(C)]
pub struct SigVec {
    sv_handler: usize,
    sv_mask: c_int,
    sv_flags: c_int,
}

const SV_ONSTACK: c_int = 1;
const SV_INTERRUPT: c_int = 2;
const SV_RESETHAND: c_int = 4;
const SA_ONSTACK: i32 = 0x0800_0000;
const SA_RESTART: i32 = 0x1000_0000;
const SA_RESETHAND: i32 = 0x8000_0000u32 as i32;

/// `sigvec(sig, vec, ovec)`: `sigaction` with the old BSD mask (an int: signals 1 to 31) and flags.
///
/// # Safety
/// `vec` and `ovec` are NULL or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_sigvec(sig: c_int, vec: *const SigVec, ovec: *mut SigVec) -> c_int {
    // SAFETY: `vec` is NULL or a readable `struct sigvec` (the contract); the borrow ends in this statement, before `ovec` is
    // written, so the two may be the same structure.
    let new = unsafe { vec.as_ref() }.map(sigvec_action);
    let old = match rusty_libc_signal::action::sigaction_rs(sig, new.as_ref()) {
        Ok(old) => old,
        Err(e) => return fail(e.0, -1),
    };
    // SAFETY: `ovec` is NULL or a writable `struct sigvec` (the contract); nothing else refers to it now.
    if let Some(o) = unsafe { ffi::out(ovec) } {
        *o = action_sigvec(&old);
    }
    0
}

/// The `sigaction` form of a BSD `struct sigvec`.
fn sigvec_action(v: &SigVec) -> rusty_libc_signal::types::Sigaction {
    let mut new = rusty_libc_signal::types::Sigaction::ZERO;
    let mut sa_flags = 0;
    if v.sv_flags & SV_ONSTACK != 0 {
        sa_flags |= SA_ONSTACK;
    }
    if v.sv_flags & SV_INTERRUPT == 0 {
        sa_flags |= SA_RESTART;
    }
    if v.sv_flags & SV_RESETHAND != 0 {
        sa_flags |= SA_RESETHAND;
    }
    new.sa_handler = v.sv_handler;
    new.sa_mask.val[0] = u64::from(v.sv_mask as u32);
    new.sa_flags = sa_flags;
    new
}

/// The BSD `struct sigvec` form of an action.
fn action_sigvec(old: &rusty_libc_signal::types::Sigaction) -> SigVec {
    let mut sv_flags = 0;
    if old.sa_flags & SA_RESETHAND != 0 {
        sv_flags |= SV_RESETHAND;
    }
    if old.sa_flags & SA_ONSTACK != 0 {
        sv_flags |= SV_ONSTACK;
    }
    if old.sa_flags & SA_RESTART == 0 {
        sv_flags |= SV_INTERRUPT;
    }
    SigVec { sv_handler: old.sa_handler, sv_mask: old.sa_mask.val[0] as u32 as c_int, sv_flags }
}

// ---------------------------------------------------------------------------------------- vtimes

/// BSD `struct vtimes` (40 bytes).
#[repr(C)]
pub struct Vtimes {
    vm_utime: c_int,
    vm_stime: c_int,
    vm_idsrss: u32,
    vm_ixrss: u32,
    vm_maxrss: c_int,
    vm_majflt: c_int,
    vm_minflt: c_int,
    vm_nswap: c_int,
    vm_inblk: c_int,
    vm_oublk: c_int,
}

const VTIMES_UNITS_PER_SECOND: i64 = 60;

fn vtimes_one(vt: Option<&mut Vtimes>, who: c_int) -> c_int {
    let Some(vt) = vt else {
        return 0;
    };
    let u = match rusty_libc_sys::resource::rs::getrusage(who) {
        Ok(u) => u,
        Err(e) => return fail(e.0, -1),
    };
    let t = |tv: &rusty_libc_sys::resource::Timeval| (tv.tv_sec * VTIMES_UNITS_PER_SECOND + tv.tv_usec * VTIMES_UNITS_PER_SECOND / 1_000_000) as c_int;
    // (as in glibc, vm_ixrss and vm_maxrss are left alone)
    vt.vm_utime = t(&u.ru_utime);
    vt.vm_stime = t(&u.ru_stime);
    vt.vm_idsrss = (u.ru_idrss + u.ru_isrss) as u32;
    vt.vm_majflt = u.ru_majflt as c_int;
    vt.vm_minflt = u.ru_minflt as c_int;
    vt.vm_nswap = u.ru_nswap as c_int;
    vt.vm_inblk = u.ru_inblock as c_int;
    vt.vm_oublk = u.ru_oublock as c_int;
    0
}

/// `vtimes(current, child)`: resource usage of this process and of its waited-for children, in 1/60 s.
///
/// # Safety
/// The pointers are NULL or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_vtimes(current: *mut Vtimes, child: *mut Vtimes) -> c_int {
    // SAFETY: NULL or a writable `struct vtimes` (the contract); the borrow ends with this call, so `child` may be the same.
    if vtimes_one(unsafe { ffi::out(current) }, 0) < 0 {
        return -1;
    }
    // SAFETY: as above.
    if vtimes_one(unsafe { ffi::out(child) }, -1) < 0 {
        return -1;
    }
    0
}

// ---------------------------------------------------------------------------------------- removed system calls

/// `sstk`: always ENOSYS.
#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_sstk(_increment: c_int) -> *mut c_void {
    fail(ENOSYS, usize::MAX as *mut c_void)
}

/// `sysctl`, `__sysctl`: always ENOSYS.
#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_sysctl(_name: *mut c_int, _nlen: c_int, _oldval: *mut c_void, _oldlenp: *mut usize, _newval: *mut c_void, _newlen: usize) -> c_int {
    fail(ENOSYS, -1)
}

/// `ustat(dev, ubuf)`: the system call; a device number that does not fit 32 bits is EINVAL.
///
/// # Safety
/// `ubuf` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_ustat(dev: c_ulong, ubuf: *mut c_void) -> c_int {
    let k = dev & 0xffff_ffff;
    if k != dev {
        return fail(EINVAL, -1);
    }
    // SAFETY: ustat(2) writes a `struct ustat` to `ubuf`, which is writable (the contract); the kernel checks it (EFAULT).
    unsafe { sys(136, k as usize, ubuf as usize, 0, 0, 0) as c_int }
}

/// `uselib(library)`: the system call.
///
/// # Safety
/// `library` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_uselib(library: *const c_char) -> c_int {
    // SAFETY: uselib(2) reads the C string `library` (the contract).
    unsafe { sys(134, library as usize, 0, 0, 0, 0) as c_int }
}

/// `bdflush(func, data)`: this architecture has no such system call.
#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_bdflush(_func: c_int, _data: c_long) -> c_int {
    fail(ENOSYS, -1)
}

/// `create_module(name, size)`: the system call.
///
/// # Safety
/// `name` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_create_module(name: *const c_char, size: usize) -> *mut c_void {
    // SAFETY: create_module(2) reads the C string `name` (the contract).
    unsafe { sys(174, name as usize, size, 0, 0, 0) as *mut c_void }
}

/// `get_kernel_syms(table)`: the system call.
///
/// # Safety
/// `table` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_get_kernel_syms(table: *mut c_void) -> c_int {
    // SAFETY: get_kernel_syms(2) writes to `table`, NULL or writable (the contract).
    unsafe { sys(177, table as usize, 0, 0, 0, 0) as c_int }
}

/// `query_module(name, which, buf, bufsize, ret)`: the system call.
///
/// # Safety
/// The pointers are valid for the request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_query_module(name: *const c_char, which: c_int, buf: *mut c_void, bufsize: usize, ret: *mut usize) -> c_int {
    // SAFETY: query_module(2) reads `name` and writes `buf` and `ret`, valid for the request (the contract).
    unsafe { sys(178, name as usize, which as usize, buf as usize, bufsize, ret as usize) as c_int }
}

/// `nfsservctl(cmd, argp, resp)`: the system call.
///
/// # Safety
/// The pointers are valid for the request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_nfsservctl(cmd: c_int, argp: *mut c_void, resp: *mut c_void) -> c_long {
    // SAFETY: nfsservctl(2) uses `argp` and `resp`, valid for the request (the contract).
    unsafe { sys(180, cmd as usize, argp as usize, resp as usize, 0, 0) as c_long }
}

// ---------------------------------------------------------------------------------------- STREAMS

/// `fattach`, `fdetach`, `getmsg`, `getpmsg`, `putmsg`, `putpmsg`: no STREAMS, ENOSYS.
#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_streams_enosys() -> c_int {
    fail(ENOSYS, -1)
}

/// `matherr(struct exception *)` of GLIBC_2.2.5: the default handler (the SVID hook a program could override; glibc 2.27 and later
/// never call it), returns 0 for "not handled".
#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_matherr(_exc: *mut core::ffi::c_void) -> c_int {
    0
}

/// `isastream(fd)`: -1 for an invalid descriptor, else 0 (nothing is a STREAM).
#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_isastream(fd: c_int) -> c_int {
    // fcntl(fd, F_GETFD)
    match rusty_libc_core::unistd::fcntl_int(fd, 1, 0) {
        Ok(_) => 0,
        Err(e) => fail(e.0, -1),
    }
}

// ---------------------------------------------------------------------------------------- regexp.h step / advance

// loc1, loc2, locs: the data of the old regexp.h interface, defined in rusty-libc-regex (the shared build exports them as
// loc1@@GLIBC_2.2.5 so that a program's copy relocation and this code use one object); `step` and `advance` are its code.

/// `step(string, expbuf)`: the next match in `string` (`loc1`, `loc2` set to its ends).
///
/// # Safety
/// `string` is a C string, `expbuf` holds a compiled expression.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_step(string: *const c_char, expbuf: *const c_char) -> c_int {
    // SAFETY: the contract is regexp.h's `step`.
    unsafe { rusty_libc_regex::cabi::step(string, expbuf) }
}

/// `advance(string, expbuf)`: a match at the start of `string` (`loc2` set to its end).
///
/// # Safety
/// As `step`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_advance(string: *const c_char, expbuf: *const c_char) -> c_int {
    // SAFETY: the contract is regexp.h's `advance`.
    unsafe { rusty_libc_regex::cabi::advance(string, expbuf) }
}

// ---------------------------------------------------------------------------------------- small ones

/// `tr_break`: the empty function a debugger sets a breakpoint on (mtrace).
#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_tr_break() {}

/// `_dl_mcount_wrapper(selfpc)`: profiling hook, nothing to do here.
#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_dl_mcount_wrapper(_selfpc: *mut c_void) {}

/// `pthread_kill_other_threads_np()`: does nothing.
#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_pthread_kill_other_threads_np() {}

/// `__default_morecore(increment)`: `sbrk`, with NULL for the failure.
///
/// # Safety
/// As `sbrk`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_default_morecore(increment: isize) -> *mut c_void {
    let r = rusty_libc_sys::unistd::sbrk(increment);
    if r as usize == usize::MAX { null_mut() } else { r }
}

/// `__nss_passwd_lookup`, `__nss_group_lookup`, `__nss_hosts_lookup`: ENOSYS (the service list type is gone).
#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_nss_lookup(_ni: *mut c_void, _fct_name: *const c_char, _fctp: *mut *mut c_void) -> c_int {
    fail(ENOSYS, -1)
}

/// `__nss_next`: -1.
#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_nss_next(_ni: *mut c_void, _fct_name: *const c_char, _fctp: *mut *mut c_void, _status: c_int, _all_values: c_int) -> c_int {
    -1
}

/// `__nss_database_lookup`: `*ni = NULL` and -1.
///
/// # Safety
/// `ni` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_nss_database_lookup(_database: *const c_char, _alternate: *const c_char, _defconfig: *const c_char, ni: *mut *mut c_void) -> c_int {
    // SAFETY: `ni` is writable (the contract; glibc writes it unconditionally too).
    unsafe { *ni = null_mut() };
    -1
}

/// `_IO_vfscanf(fp, format, ap, errp)`: `vfscanf`; `*errp` is set to whether it failed with EOF.
///
/// # Safety
/// As `vfscanf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_io_vfscanf(fp: *mut rusty_libc_stdio::file::File, format: *const c_char, ap: core::ffi::VaList, errp: *mut c_int) -> c_int {
    // SAFETY: the contract is `vfscanf`'s.
    let rv = unsafe { rusty_libc_stdio::vfscanf(fp, format, ap) };
    // SAFETY: `errp` is NULL or writable (the contract).
    if let Some(e) = unsafe { ffi::out(errp) } {
        *e = c_int::from(rv == -1);
    }
    rv
}

/// `__ivaliduser(hostf, raddr, luser, ruser)`: is `ruser` at the IPv4 address `raddr` allowed to log in as `luser`
/// according to the hosts.equiv-style file `hostf`. (This version reads the rest of the stream; glibc's stops after
/// the line that decided.)
///
/// # Safety
/// `hostf` is an open stream; the names are C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_ivaliduser(hostf: *mut rusty_libc_stdio::file::File, raddr: u32, luser: *const c_char, ruser: *const c_char) -> c_int {
    // sockaddr_in: family AF_INET, port 0, address
    let mut ra = [0u8; 16];
    ra[..2].copy_from_slice(&2u16.to_ne_bytes());
    ra[4..8].copy_from_slice(&raddr.to_ne_bytes());
    // SAFETY: `hostf` is an open stream this thread may use (the contract); no other reference to it is made here.
    let f = unsafe { rusty_libc_stdio::file::stream(hostf) };
    let mut data: *mut u8 = null_mut();
    let (mut len, mut cap) = (0usize, 0usize);
    loop {
        if len == cap {
            let ncap = if cap == 0 { 4096 } else { cap * 2 };
            // SAFETY: `data` is NULL or the block this loop allocated.
            let np = unsafe { rusty_libc_malloc::realloc(data.cast(), ncap) } as *mut u8;
            if np.is_null() {
                // SAFETY: as above (realloc failed and left it alone).
                unsafe { rusty_libc_malloc::free(data.cast()) };
                return -1;
            }
            data = np;
            cap = ncap;
        }
        // SAFETY: bytes `len..cap` of the block are ours and not otherwise referenced.
        let n = rusty_libc_stdio::file::read_bytes(f, unsafe { ffi::bytes_mut(data.wrapping_add(len), cap - len) });
        if n == 0 {
            break;
        }
        len += n;
    }
    // SAFETY: the first `len` bytes of the block were filled above.
    let text = unsafe { ffi::bytes(data, len) };
    // SAFETY: `luser` is a C string (the contract).
    let luser = unsafe { ffi::cstr_bytes(luser) };
    // SAFETY: `ruser` is a C string (the contract).
    let ruser = unsafe { ffi::cstr_bytes(ruser) };
    let r = rusty_libc_net::rcmd::validuser_text(text, &ra, luser, ruser, b"-");
    // SAFETY: the block this loop allocated; `text` is not used after this.
    unsafe { rusty_libc_malloc::free(data.cast()) };
    if r.is_ok() { 0 } else { -1 }
}

// ---- the signal set helpers that used to be inline in old <signal.h> ----

/// `__sigismember(set, sig)`.
///
/// # Safety
/// `set` points to a signal set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_sigismember(set: *const [c_ulong; 16], sig: c_int) -> c_int {
    // SAFETY: `set` points to a readable signal set (the contract).
    let set = unsafe { &*set };
    let s = (sig as i64) - 1;
    c_int::from(set[(s / 64) as usize] & (1u64 << (s % 64)) != 0)
}

/// `__sigaddset(set, sig)`.
///
/// # Safety
/// `set` points to a signal set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_sigaddset(set: *mut [c_ulong; 16], sig: c_int) -> c_int {
    // SAFETY: `set` points to a writable signal set (the contract).
    let set = unsafe { &mut *set };
    let s = (sig as i64) - 1;
    set[(s / 64) as usize] |= 1u64 << (s % 64);
    0
}

/// `__sigdelset(set, sig)`.
///
/// # Safety
/// `set` points to a signal set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_sigdelset(set: *mut [c_ulong; 16], sig: c_int) -> c_int {
    // SAFETY: `set` points to a writable signal set (the contract).
    let set = unsafe { &mut *set };
    let s = (sig as i64) - 1;
    set[(s / 64) as usize] &= !(1u64 << (s % 64));
    0
}

// ---------------------------------------------------------------------------------------- old string.h inlines
// The tokenizers keep glibc's pointer loops (a NUL separator or accept character walks on exactly as glibc's inline code
// did); each read or write is its own block.

macro_rules! cset {
    ($c:expr, $set:expr) => {
        $set.iter().any(|&x| x == $c)
    };
}

/// Length of the prefix of the C string `s` without a byte for which `stop` holds.
///
/// # Safety
/// `s` is a C string.
unsafe fn strlen_until(s: *const c_char, stop: impl Fn(u8) -> bool) -> usize {
    // SAFETY: `s` is a C string (forwarded contract).
    let b = unsafe { ffi::cstr_bytes(s) };
    b.iter().position(|&c| stop(c)).unwrap_or(b.len())
}

/// `__strtok_r_1c(s, sep, nextp)`.
///
/// # Safety
/// As `strtok_r`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strtok_r_1c(mut s: *mut c_char, sep: c_char, nextp: *mut *mut c_char) -> *mut c_char {
    if s.is_null() {
        // SAFETY: `nextp` holds the position a previous call saved (strtok_r's contract).
        s = unsafe { *nextp };
    }
    // SAFETY: `s` points into a writable C string (strtok_r's contract).
    while unsafe { *s } == sep {
        s = s.wrapping_add(1);
    }
    let mut result = null_mut();
    // SAFETY: as above.
    if unsafe { *s } != 0 {
        result = s;
        s = s.wrapping_add(1);
        loop {
            // SAFETY: `s` is inside the string: the loop stops at its NUL.
            let c = unsafe { *s };
            if c == 0 {
                break;
            }
            s = s.wrapping_add(1);
            if c == sep {
                // SAFETY: the separator just read, inside the writable string.
                unsafe { *s.wrapping_sub(1) = 0 };
                break;
            }
        }
    }
    // SAFETY: `nextp` is writable (strtok_r's contract).
    unsafe { *nextp = s };
    result
}

/// `__strsep_1c(sp, reject)`.
///
/// # Safety
/// As `strsep`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strsep_1c(sp: *mut *mut c_char, reject: c_char) -> *mut c_char {
    // SAFETY: `sp` points to the string pointer (strsep's contract).
    let retval = unsafe { *sp };
    if !retval.is_null() {
        let mut p = retval;
        let c = loop {
            // SAFETY: `p` is inside the writable C string `retval`: the loop stops at its NUL.
            let c = unsafe { *p };
            if c == 0 || c == reject {
                break c;
            }
            p = p.wrapping_add(1);
        };
        if c == reject {
            // SAFETY: `p` is the separator found above.
            unsafe { *p = 0 };
            // SAFETY: `sp` is writable (strsep's contract).
            unsafe { *sp = p.wrapping_add(1) };
        } else {
            // SAFETY: as above.
            unsafe { *sp = null_mut() };
        }
    }
    retval
}

/// `strsep` with the separators `rej`.
///
/// # Safety
/// As `strsep`.
unsafe fn strsep_n(sp: *mut *mut c_char, rej: &[c_char]) -> *mut c_char {
    // SAFETY: `sp` points to the string pointer (strsep's contract).
    let retval = unsafe { *sp };
    if !retval.is_null() {
        let mut cp = retval;
        loop {
            // SAFETY: `cp` is inside the writable C string `retval`: the loop stops at its NUL.
            let c = unsafe { *cp };
            if c == 0 {
                cp = null_mut();
                break;
            }
            if cset!(c, rej) {
                // SAFETY: the separator just read.
                unsafe { *cp = 0 };
                cp = cp.wrapping_add(1);
                break;
            }
            cp = cp.wrapping_add(1);
        }
        // SAFETY: `sp` is writable (strsep's contract).
        unsafe { *sp = cp };
    }
    retval
}

/// `__strsep_2c(sp, r1, r2)`.
///
/// # Safety
/// As `strsep`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strsep_2c(sp: *mut *mut c_char, r1: c_char, r2: c_char) -> *mut c_char {
    // SAFETY: forwarded contract.
    unsafe { strsep_n(sp, &[r1, r2]) }
}

/// `__strsep_3c(sp, r1, r2, r3)`.
///
/// # Safety
/// As `strsep`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strsep_3c(sp: *mut *mut c_char, r1: c_char, r2: c_char, r3: c_char) -> *mut c_char {
    // SAFETY: forwarded contract.
    unsafe { strsep_n(sp, &[r1, r2, r3]) }
}

/// `__strcspn_c1(s, reject)`.
///
/// # Safety
/// `s` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strcspn_c1(s: *const c_char, r1: c_int) -> usize {
    // SAFETY: forwarded contract.
    unsafe { strlen_until(s, |c| i32::from(c as c_char) == r1) }
}

/// `__strcspn_c2`.
///
/// # Safety
/// `s` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strcspn_c2(s: *const c_char, r1: c_int, r2: c_int) -> usize {
    // SAFETY: forwarded contract.
    unsafe { strlen_until(s, |c| i32::from(c as c_char) == r1 || i32::from(c as c_char) == r2) }
}

/// `__strcspn_c3`.
///
/// # Safety
/// `s` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strcspn_c3(s: *const c_char, r1: c_int, r2: c_int, r3: c_int) -> usize {
    // SAFETY: forwarded contract.
    unsafe { strlen_until(s, |c| [r1, r2, r3].contains(&i32::from(c as c_char))) }
}

/// Length of the prefix of `s` made of characters in `acc` (as glibc's inline code: an accept character 0 walks on past the NUL).
///
/// # Safety
/// `s` is a C string, and if `acc` holds 0 the bytes after it up to the first byte not in `acc` are readable.
unsafe fn span_of(s: *const c_char, acc: &[c_int]) -> usize {
    let mut n = 0;
    // SAFETY: byte `n` is in the string (the loop stops at the NUL unless the caller's `acc` holds 0, see the contract).
    while acc.contains(&i32::from(unsafe { *s.wrapping_add(n) })) {
        n += 1;
    }
    n
}

/// `__strspn_c1(s, accept)`.
///
/// # Safety
/// `s` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strspn_c1(s: *const c_char, a1: c_int) -> usize {
    // SAFETY: forwarded contract.
    unsafe { span_of(s, &[a1]) }
}

/// `__strspn_c2`.
///
/// # Safety
/// `s` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strspn_c2(s: *const c_char, a1: c_int, a2: c_int) -> usize {
    // SAFETY: forwarded contract.
    unsafe { span_of(s, &[a1, a2]) }
}

/// `__strspn_c3`.
///
/// # Safety
/// `s` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strspn_c3(s: *const c_char, a1: c_int, a2: c_int, a3: c_int) -> usize {
    // SAFETY: forwarded contract.
    unsafe { span_of(s, &[a1, a2, a3]) }
}

/// The first character of `s` in `acc`, or NULL.
///
/// # Safety
/// `s` is a C string.
unsafe fn pbrk_of(s: *const c_char, acc: &[c_int]) -> *mut c_char {
    // SAFETY: `s` is a C string (forwarded contract).
    let b = unsafe { ffi::cstr_bytes(s) };
    match b.iter().position(|&c| acc.contains(&i32::from(c as c_char))) {
        Some(i) => s.wrapping_add(i).cast_mut(),
        None => null_mut(),
    }
}

/// `__strpbrk_c2(s, a1, a2)`.
///
/// # Safety
/// `s` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strpbrk_c2(s: *const c_char, a1: c_int, a2: c_int) -> *mut c_char {
    // SAFETY: forwarded contract.
    unsafe { pbrk_of(s, &[a1, a2]) }
}

/// `__strpbrk_c3`.
///
/// # Safety
/// `s` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strpbrk_c3(s: *const c_char, a1: c_int, a2: c_int, a3: c_int) -> *mut c_char {
    // SAFETY: forwarded contract.
    unsafe { pbrk_of(s, &[a1, a2, a3]) }
}

// The "small copy" helpers took the source text split into packed structs of 2 to 8 bytes passed by value; with the
// System V calling convention each such struct travels in one integer register (or one stack slot), so they are
// declared here as 64-bit integers whose low bytes are the text.

/// Copy the `n` (1 to 8; others copy nothing) low bytes of `srcs[n - 1]` to `dest`.
///
/// # Safety
/// If `n` is 1 to 8, `dest` has room for `n` bytes.
unsafe fn put_small(dest: *mut u8, srcs: [u64; 8], n: usize) {
    if (1..=8).contains(&n) {
        // SAFETY: `dest` has room for `n` bytes (the contract).
        unsafe { ffi::bytes_mut(dest, n) }.copy_from_slice(&srcs[n - 1].to_ne_bytes()[..n]);
    }
}

/// `__mempcpy_small(dest, src1, src2 .. src8, srclen)`: copies `srclen` (1 to 8) bytes, returns the end.
///
/// # Safety
/// `dest` has room for `srclen` bytes.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __rl_old_mempcpy_small(dest: *mut u8, src1: c_int, src2: u64, src3: u64, src4: u64, src5: u64, src6: u64, src7: u64, src8: u64, srclen: usize) -> *mut u8 {
    // the one-byte case takes a `char`
    let srcs = [u64::from(src1 as u8), src2, src3, src4, src5, src6, src7, src8];
    // SAFETY: `dest` has room for `srclen` bytes (the contract).
    unsafe { put_small(dest, srcs, srclen as u32 as usize) };
    dest.wrapping_add(srclen)
}

/// `__strcpy_small(dest, src2 .. src8, srclen)`: copies a string of `srclen` (1 to 8, the NUL included) bytes.
///
/// # Safety
/// `dest` has room for `srclen` bytes.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __rl_old_strcpy_small(dest: *mut u8, src2: u64, src3: u64, src4: u64, src5: u64, src6: u64, src7: u64, src8: u64, srclen: usize) -> *mut u8 {
    // SAFETY: `dest` has room for `srclen` bytes (the contract).
    unsafe { copy_small(dest, [0, src2, src3, src4, src5, src6, src7, src8], srclen) };
    dest
}

/// `__stpcpy_small`: as `__strcpy_small`, returns the address of the NUL.
///
/// # Safety
/// `dest` has room for `srclen` bytes.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __rl_old_stpcpy_small(dest: *mut u8, src2: u64, src3: u64, src4: u64, src5: u64, src6: u64, src7: u64, src8: u64, srclen: usize) -> *mut u8 {
    // SAFETY: `dest` has room for `srclen` bytes (the contract).
    unsafe { copy_small(dest, [0, src2, src3, src4, src5, src6, src7, src8], srclen) };
    dest.wrapping_add(srclen.wrapping_sub(1))
}

/// The copy of `__strcpy_small` and `__stpcpy_small`: a lone NUL for `srclen` 1, else [`put_small`].
///
/// # Safety
/// `dest` has room for `srclen` bytes.
unsafe fn copy_small(dest: *mut u8, srcs: [u64; 8], srclen: usize) {
    let n = srclen as u32 as usize;
    if n == 1 {
        // SAFETY: `dest` has room for one byte.
        unsafe { *dest = 0 };
    } else {
        // SAFETY: forwarded contract.
        unsafe { put_small(dest, srcs, n) };
    }
}

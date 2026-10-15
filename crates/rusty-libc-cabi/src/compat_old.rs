use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{errno, ffi, syscall};

const ENOSYS: i32 = 38;
const EINVAL: i32 = 22;

fn fail<T>(e: i32, v: T) -> T {
    errno::set(e);
    v
}

unsafe fn sys(nr: usize, a: usize, b: usize, c: usize, d: usize, e: usize) -> isize {
    let r = unsafe { syscall::syscall5(nr, a, b, c, d, e) };
    match syscall::check(r) {
        Ok(v) => v as isize,
        Err(e) => fail(e.0, -1),
    }
}

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_sigvec(sig: c_int, vec: *const SigVec, ovec: *mut SigVec) -> c_int {
    let new = unsafe { vec.as_ref() }.map(sigvec_action);
    let old = match rusty_libc_signal::action::sigaction_rs(sig, new.as_ref()) {
        Ok(old) => old,
        Err(e) => return fail(e.0, -1),
    };
    if let Some(o) = unsafe { ffi::out(ovec) } {
        *o = action_sigvec(&old);
    }
    0
}

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_vtimes(current: *mut Vtimes, child: *mut Vtimes) -> c_int {
    if vtimes_one(unsafe { ffi::out(current) }, 0) < 0 {
        return -1;
    }
    if vtimes_one(unsafe { ffi::out(child) }, -1) < 0 {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_sstk(_increment: c_int) -> *mut c_void {
    fail(ENOSYS, usize::MAX as *mut c_void)
}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_sysctl(_name: *mut c_int, _nlen: c_int, _oldval: *mut c_void, _oldlenp: *mut usize, _newval: *mut c_void, _newlen: usize) -> c_int {
    fail(ENOSYS, -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_ustat(dev: c_ulong, ubuf: *mut c_void) -> c_int {
    let k = dev & 0xffff_ffff;
    if k != dev {
        return fail(EINVAL, -1);
    }
    unsafe { sys(136, k as usize, ubuf as usize, 0, 0, 0) as c_int }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_uselib(library: *const c_char) -> c_int {
    unsafe { sys(134, library as usize, 0, 0, 0, 0) as c_int }
}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_bdflush(_func: c_int, _data: c_long) -> c_int {
    fail(ENOSYS, -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_create_module(name: *const c_char, size: usize) -> *mut c_void {
    unsafe { sys(174, name as usize, size, 0, 0, 0) as *mut c_void }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_get_kernel_syms(table: *mut c_void) -> c_int {
    unsafe { sys(177, table as usize, 0, 0, 0, 0) as c_int }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_query_module(name: *const c_char, which: c_int, buf: *mut c_void, bufsize: usize, ret: *mut usize) -> c_int {
    unsafe { sys(178, name as usize, which as usize, buf as usize, bufsize, ret as usize) as c_int }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_nfsservctl(cmd: c_int, argp: *mut c_void, resp: *mut c_void) -> c_long {
    unsafe { sys(180, cmd as usize, argp as usize, resp as usize, 0, 0) as c_long }
}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_streams_enosys() -> c_int {
    fail(ENOSYS, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_matherr(_exc: *mut core::ffi::c_void) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_isastream(fd: c_int) -> c_int {
    match rusty_libc_core::unistd::fcntl_int(fd, 1, 0) {
        Ok(_) => 0,
        Err(e) => fail(e.0, -1),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_step(string: *const c_char, expbuf: *const c_char) -> c_int {
    unsafe { rusty_libc_regex::cabi::step(string, expbuf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_advance(string: *const c_char, expbuf: *const c_char) -> c_int {
    unsafe { rusty_libc_regex::cabi::advance(string, expbuf) }
}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_tr_break() {}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_dl_mcount_wrapper(_selfpc: *mut c_void) {}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_pthread_kill_other_threads_np() {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_default_morecore(increment: isize) -> *mut c_void {
    let r = rusty_libc_sys::unistd::sbrk(increment);
    if r as usize == usize::MAX { null_mut() } else { r }
}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_nss_lookup(_ni: *mut c_void, _fct_name: *const c_char, _fctp: *mut *mut c_void) -> c_int {
    fail(ENOSYS, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_old_nss_next(_ni: *mut c_void, _fct_name: *const c_char, _fctp: *mut *mut c_void, _status: c_int, _all_values: c_int) -> c_int {
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_nss_database_lookup(_database: *const c_char, _alternate: *const c_char, _defconfig: *const c_char, ni: *mut *mut c_void) -> c_int {
    unsafe { *ni = null_mut() };
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_io_vfscanf(fp: *mut rusty_libc_stdio::file::File, format: *const c_char, ap: core::ffi::VaList, errp: *mut c_int) -> c_int {
    let rv = unsafe { rusty_libc_stdio::vfscanf(fp, format, ap) };
    if let Some(e) = unsafe { ffi::out(errp) } {
        *e = c_int::from(rv == -1);
    }
    rv
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_ivaliduser(hostf: *mut rusty_libc_stdio::file::File, raddr: u32, luser: *const c_char, ruser: *const c_char) -> c_int {
    let mut ra = [0u8; 16];
    ra[..2].copy_from_slice(&2u16.to_ne_bytes());
    ra[4..8].copy_from_slice(&raddr.to_ne_bytes());
    let f = unsafe { rusty_libc_stdio::file::stream(hostf) };
    let mut data: *mut u8 = null_mut();
    let (mut len, mut cap) = (0usize, 0usize);
    loop {
        if len == cap {
            let ncap = if cap == 0 { 4096 } else { cap * 2 };
            let np = unsafe { rusty_libc_malloc::realloc(data.cast(), ncap) } as *mut u8;
            if np.is_null() {
                unsafe { rusty_libc_malloc::free(data.cast()) };
                return -1;
            }
            data = np;
            cap = ncap;
        }
        let n = rusty_libc_stdio::file::read_bytes(f, unsafe { ffi::bytes_mut(data.wrapping_add(len), cap - len) });
        if n == 0 {
            break;
        }
        len += n;
    }
    let text = unsafe { ffi::bytes(data, len) };
    let luser = unsafe { ffi::cstr_bytes(luser) };
    let ruser = unsafe { ffi::cstr_bytes(ruser) };
    let r = rusty_libc_net::rcmd::validuser_text(text, &ra, luser, ruser, b"-");
    unsafe { rusty_libc_malloc::free(data.cast()) };
    if r.is_ok() { 0 } else { -1 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_sigismember(set: *const [c_ulong; 16], sig: c_int) -> c_int {
    let set = unsafe { &*set };
    let s = (sig as i64) - 1;
    c_int::from(set[(s / 64) as usize] & (1u64 << (s % 64)) != 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_sigaddset(set: *mut [c_ulong; 16], sig: c_int) -> c_int {
    let set = unsafe { &mut *set };
    let s = (sig as i64) - 1;
    set[(s / 64) as usize] |= 1u64 << (s % 64);
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_sigdelset(set: *mut [c_ulong; 16], sig: c_int) -> c_int {
    let set = unsafe { &mut *set };
    let s = (sig as i64) - 1;
    set[(s / 64) as usize] &= !(1u64 << (s % 64));
    0
}

macro_rules! cset {
    ($c:expr, $set:expr) => {
        $set.iter().any(|&x| x == $c)
    };
}

unsafe fn strlen_until(s: *const c_char, stop: impl Fn(u8) -> bool) -> usize {
    let b = unsafe { ffi::cstr_bytes(s) };
    b.iter().position(|&c| stop(c)).unwrap_or(b.len())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strtok_r_1c(mut s: *mut c_char, sep: c_char, nextp: *mut *mut c_char) -> *mut c_char {
    if s.is_null() {
        s = unsafe { *nextp };
    }
    while unsafe { *s } == sep {
        s = s.wrapping_add(1);
    }
    let mut result = null_mut();
    if unsafe { *s } != 0 {
        result = s;
        s = s.wrapping_add(1);
        loop {
            let c = unsafe { *s };
            if c == 0 {
                break;
            }
            s = s.wrapping_add(1);
            if c == sep {
                unsafe { *s.wrapping_sub(1) = 0 };
                break;
            }
        }
    }
    unsafe { *nextp = s };
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strsep_1c(sp: *mut *mut c_char, reject: c_char) -> *mut c_char {
    let retval = unsafe { *sp };
    if !retval.is_null() {
        let mut p = retval;
        let c = loop {
            let c = unsafe { *p };
            if c == 0 || c == reject {
                break c;
            }
            p = p.wrapping_add(1);
        };
        if c == reject {
            unsafe { *p = 0 };
            unsafe { *sp = p.wrapping_add(1) };
        } else {
            unsafe { *sp = null_mut() };
        }
    }
    retval
}

unsafe fn strsep_n(sp: *mut *mut c_char, rej: &[c_char]) -> *mut c_char {
    let retval = unsafe { *sp };
    if !retval.is_null() {
        let mut cp = retval;
        loop {
            let c = unsafe { *cp };
            if c == 0 {
                cp = null_mut();
                break;
            }
            if cset!(c, rej) {
                unsafe { *cp = 0 };
                cp = cp.wrapping_add(1);
                break;
            }
            cp = cp.wrapping_add(1);
        }
        unsafe { *sp = cp };
    }
    retval
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strsep_2c(sp: *mut *mut c_char, r1: c_char, r2: c_char) -> *mut c_char {
    unsafe { strsep_n(sp, &[r1, r2]) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strsep_3c(sp: *mut *mut c_char, r1: c_char, r2: c_char, r3: c_char) -> *mut c_char {
    unsafe { strsep_n(sp, &[r1, r2, r3]) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strcspn_c1(s: *const c_char, r1: c_int) -> usize {
    unsafe { strlen_until(s, |c| i32::from(c as c_char) == r1) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strcspn_c2(s: *const c_char, r1: c_int, r2: c_int) -> usize {
    unsafe { strlen_until(s, |c| i32::from(c as c_char) == r1 || i32::from(c as c_char) == r2) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strcspn_c3(s: *const c_char, r1: c_int, r2: c_int, r3: c_int) -> usize {
    unsafe { strlen_until(s, |c| [r1, r2, r3].contains(&i32::from(c as c_char))) }
}

unsafe fn span_of(s: *const c_char, acc: &[c_int]) -> usize {
    let mut n = 0;
    while acc.contains(&i32::from(unsafe { *s.wrapping_add(n) })) {
        n += 1;
    }
    n
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strspn_c1(s: *const c_char, a1: c_int) -> usize {
    unsafe { span_of(s, &[a1]) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strspn_c2(s: *const c_char, a1: c_int, a2: c_int) -> usize {
    unsafe { span_of(s, &[a1, a2]) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strspn_c3(s: *const c_char, a1: c_int, a2: c_int, a3: c_int) -> usize {
    unsafe { span_of(s, &[a1, a2, a3]) }
}

unsafe fn pbrk_of(s: *const c_char, acc: &[c_int]) -> *mut c_char {
    let b = unsafe { ffi::cstr_bytes(s) };
    match b.iter().position(|&c| acc.contains(&i32::from(c as c_char))) {
        Some(i) => s.wrapping_add(i).cast_mut(),
        None => null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strpbrk_c2(s: *const c_char, a1: c_int, a2: c_int) -> *mut c_char {
    unsafe { pbrk_of(s, &[a1, a2]) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strpbrk_c3(s: *const c_char, a1: c_int, a2: c_int, a3: c_int) -> *mut c_char {
    unsafe { pbrk_of(s, &[a1, a2, a3]) }
}

unsafe fn put_small(dest: *mut u8, srcs: [u64; 8], n: usize) {
    if (1..=8).contains(&n) {
        unsafe { ffi::bytes_mut(dest, n) }.copy_from_slice(&srcs[n - 1].to_ne_bytes()[..n]);
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __rl_old_mempcpy_small(dest: *mut u8, src1: c_int, src2: u64, src3: u64, src4: u64, src5: u64, src6: u64, src7: u64, src8: u64, srclen: usize) -> *mut u8 {
    let srcs = [u64::from(src1 as u8), src2, src3, src4, src5, src6, src7, src8];
    unsafe { put_small(dest, srcs, srclen as u32 as usize) };
    dest.wrapping_add(srclen)
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __rl_old_strcpy_small(dest: *mut u8, src2: u64, src3: u64, src4: u64, src5: u64, src6: u64, src7: u64, src8: u64, srclen: usize) -> *mut u8 {
    unsafe { copy_small(dest, [0, src2, src3, src4, src5, src6, src7, src8], srclen) };
    dest
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __rl_old_stpcpy_small(dest: *mut u8, src2: u64, src3: u64, src4: u64, src5: u64, src6: u64, src7: u64, src8: u64, srclen: usize) -> *mut u8 {
    unsafe { copy_small(dest, [0, src2, src3, src4, src5, src6, src7, src8], srclen) };
    dest.wrapping_add(srclen.wrapping_sub(1))
}

unsafe fn copy_small(dest: *mut u8, srcs: [u64; 8], srclen: usize) {
    let n = srclen as u32 as usize;
    if n == 1 {
        unsafe { *dest = 0 };
    } else {
        unsafe { put_small(dest, srcs, n) };
    }
}

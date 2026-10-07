use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{errno, syscall};

const ENOSYS: i32 = 38;
const EINVAL: i32 = 22;

fn fail<T>(e: i32, v: T) -> T {
    errno::set(e);
    v
}

unsafe fn sys(nr: usize, a: usize, b: usize, c: usize, d: usize, e: usize) -> isize {
    unsafe {
        let r = syscall::syscall5(nr, a, b, c, d, e);
        if r > usize::MAX - 4095 {
            errno::set((r as isize).wrapping_neg() as i32);
            -1
        } else {
            r as isize
        }
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
    unsafe {
        let mut old = rusty_libc_signal::types::Sigaction::ZERO;
        let mut new = rusty_libc_signal::types::Sigaction::ZERO;
        let n: *const rusty_libc_signal::types::Sigaction = if vec.is_null() {
            core::ptr::null()
        } else {
            let v = &*vec;
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
            &new
        };
        if rusty_libc_signal::action::sigaction(sig, n, &mut old) < 0 {
            return -1;
        }
        if !ovec.is_null() {
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
            (*ovec).sv_handler = old.sa_handler;
            (*ovec).sv_mask = old.sa_mask.val[0] as u32 as c_int;
            (*ovec).sv_flags = sv_flags;
        }
        0
    }
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

unsafe fn vtimes_one(vt: *mut Vtimes, who: c_int) -> c_int {
    unsafe {
        if vt.is_null() {
            return 0;
        }
        let mut u = rusty_libc_sys::resource::Rusage::default();
        if rusty_libc_sys::resource::getrusage(who, (&mut u as *mut rusty_libc_sys::resource::Rusage).cast()) < 0 {
            return -1;
        }
        let t = |tv: &rusty_libc_sys::resource::Timeval| (tv.tv_sec * VTIMES_UNITS_PER_SECOND + tv.tv_usec * VTIMES_UNITS_PER_SECOND / 1_000_000) as c_int;
        (*vt).vm_utime = t(&u.ru_utime);
        (*vt).vm_stime = t(&u.ru_stime);
        (*vt).vm_idsrss = (u.ru_idrss + u.ru_isrss) as u32;
        (*vt).vm_majflt = u.ru_majflt as c_int;
        (*vt).vm_minflt = u.ru_minflt as c_int;
        (*vt).vm_nswap = u.ru_nswap as c_int;
        (*vt).vm_inblk = u.ru_inblock as c_int;
        (*vt).vm_oublk = u.ru_oublock as c_int;
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_vtimes(current: *mut Vtimes, child: *mut Vtimes) -> c_int {
    unsafe {
        if vtimes_one(current, 0) < 0 || vtimes_one(child, -1) < 0 {
            return -1;
        }
        0
    }
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
    unsafe {
        let k = dev & 0xffff_ffff;
        if k != dev {
            return fail(EINVAL, -1);
        }
        sys(136, k as usize, ubuf as usize, 0, 0, 0) as c_int
    }
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
    unsafe {
        if sys(72, fd as usize, 1, 0, 0, 0) < 0 {
            return -1;
        }
    }
    0
}

unsafe extern "C" {
    static mut loc1: *mut c_char;
    static mut loc2: *mut c_char;
}

unsafe fn compiled(expbuf: *const c_char) -> *const rusty_libc_regex::cabi::RegexT {
    let p = expbuf as usize + core::mem::align_of::<*const c_void>();
    (p - p % core::mem::align_of::<*const c_void>()) as *const rusty_libc_regex::cabi::RegexT
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_step(string: *const c_char, expbuf: *const c_char) -> c_int {
    unsafe {
        let mut m: rusty_libc_regex::cabi::RegMatch = core::mem::zeroed();
        if rusty_libc_regex::cabi::regexec(compiled(expbuf), string, 1, &mut m, 2 ) == 1  {
            return 0;
        }
        loc1 = string.offset(m.so as isize) as *mut c_char;
        loc2 = string.offset(m.eo as isize) as *mut c_char;
        1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_advance(string: *const c_char, expbuf: *const c_char) -> c_int {
    unsafe {
        let mut m: rusty_libc_regex::cabi::RegMatch = core::mem::zeroed();
        if rusty_libc_regex::cabi::regexec(compiled(expbuf), string, 1, &mut m, 2) == 1 || m.so != 0 {
            return 0;
        }
        loc2 = string.offset(m.eo as isize) as *mut c_char;
        1
    }
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
    unsafe {
        *ni = null_mut();
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_io_vfscanf(fp: *mut rusty_libc_stdio::file::File, format: *const c_char, ap: core::ffi::VaList, errp: *mut c_int) -> c_int {
    unsafe {
        let rv = rusty_libc_stdio::vfscanf(fp, format, ap);
        if !errp.is_null() {
            *errp = c_int::from(rv == -1);
        }
        rv
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_ivaliduser(hostf: *mut rusty_libc_stdio::file::File, raddr: u32, luser: *const c_char, ruser: *const c_char) -> c_int {
    unsafe {
        let mut ra = [0u8; 16];
        ra[..2].copy_from_slice(&2u16.to_ne_bytes());
        ra[4..8].copy_from_slice(&raddr.to_ne_bytes());
        let mut data: *mut u8 = null_mut();
        let (mut len, mut cap) = (0usize, 0usize);
        loop {
            if len == cap {
                let ncap = if cap == 0 { 4096 } else { cap * 2 };
                let np = rusty_libc_malloc::realloc(data.cast(), ncap) as *mut u8;
                if np.is_null() {
                    rusty_libc_malloc::free(data.cast());
                    return -1;
                }
                data = np;
                cap = ncap;
            }
            let n = rusty_libc_stdio::file::read_bytes(hostf, data.add(len), cap - len);
            if n == 0 {
                break;
            }
            len += n;
        }
        let r = rusty_libc_net::rcmd::validuser(core::slice::from_raw_parts(data, len), ra.as_ptr().cast(), 16, luser, ruser, c"-".as_ptr());
        rusty_libc_malloc::free(data.cast());
        if r.is_ok() { 0 } else { -1 }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_sigismember(set: *const [c_ulong; 16], sig: c_int) -> c_int {
    unsafe {
        let s = (sig as i64) - 1;
        c_int::from((*set)[(s / 64) as usize] & (1u64 << (s % 64)) != 0)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_sigaddset(set: *mut [c_ulong; 16], sig: c_int) -> c_int {
    unsafe {
        let s = (sig as i64) - 1;
        (*set)[(s / 64) as usize] |= 1u64 << (s % 64);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_sigdelset(set: *mut [c_ulong; 16], sig: c_int) -> c_int {
    unsafe {
        let s = (sig as i64) - 1;
        (*set)[(s / 64) as usize] &= !(1u64 << (s % 64));
        0
    }
}

macro_rules! cset {
    ($c:expr, $set:expr) => {
        $set.iter().any(|&x| x == $c)
    };
}

unsafe fn strlen_until(s: *const c_char, stop: impl Fn(u8) -> bool) -> usize {
    unsafe {
        let mut n = 0;
        while *s.add(n) != 0 && !stop(*s.add(n) as u8) {
            n += 1;
        }
        n
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strtok_r_1c(mut s: *mut c_char, sep: c_char, nextp: *mut *mut c_char) -> *mut c_char {
    unsafe {
        if s.is_null() {
            s = *nextp;
        }
        while *s == sep {
            s = s.add(1);
        }
        let mut result = null_mut();
        if *s != 0 {
            result = s;
            s = s.add(1);
            while *s != 0 {
                let c = *s;
                s = s.add(1);
                if c == sep {
                    *s.sub(1) = 0;
                    break;
                }
            }
        }
        *nextp = s;
        result
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_old_strsep_1c(sp: *mut *mut c_char, reject: c_char) -> *mut c_char {
    unsafe {
        let retval = *sp;
        if !retval.is_null() {
            let mut p = retval;
            while *p != 0 && *p != reject {
                p = p.add(1);
            }
            if *p == reject {
                *p = 0;
                *sp = p.add(1);
            } else {
                *sp = null_mut();
            }
        }
        retval
    }
}

unsafe fn strsep_n(sp: *mut *mut c_char, rej: &[c_char]) -> *mut c_char {
    unsafe {
        let retval = *sp;
        if !retval.is_null() {
            let mut cp = retval;
            loop {
                if *cp == 0 {
                    cp = null_mut();
                    break;
                }
                if cset!(*cp, rej) {
                    *cp = 0;
                    cp = cp.add(1);
                    break;
                }
                cp = cp.add(1);
            }
            *sp = cp;
        }
        retval
    }
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
    unsafe {
        let mut n = 0;
        while acc.contains(&i32::from(*s.add(n))) {
            n += 1;
        }
        n
    }
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

unsafe fn pbrk_of(mut s: *const c_char, acc: &[c_int]) -> *mut c_char {
    unsafe {
        while *s != 0 && !acc.contains(&i32::from(*s)) {
            s = s.add(1);
        }
        if *s == 0 { null_mut() } else { s as *mut c_char }
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
    unsafe {
        if (1..=8).contains(&n) {
            core::ptr::copy_nonoverlapping(srcs[n - 1..].as_ptr().cast::<u8>(), dest, n);
        }
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __rl_old_mempcpy_small(dest: *mut u8, src1: c_int, src2: u64, src3: u64, src4: u64, src5: u64, src6: u64, src7: u64, src8: u64, srclen: usize) -> *mut u8 {
    unsafe {
        let srcs = [u64::from(src1 as u8), src2, src3, src4, src5, src6, src7, src8];
        put_small(dest, srcs, srclen as u32 as usize);
        dest.add(srclen)
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __rl_old_strcpy_small(dest: *mut u8, src2: u64, src3: u64, src4: u64, src5: u64, src6: u64, src7: u64, src8: u64, srclen: usize) -> *mut u8 {
    unsafe {
        let n = srclen as u32 as usize;
        if n == 1 {
            *dest = 0;
        } else {
            put_small(dest, [0, src2, src3, src4, src5, src6, src7, src8], n);
        }
        dest
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __rl_old_stpcpy_small(dest: *mut u8, src2: u64, src3: u64, src4: u64, src5: u64, src6: u64, src7: u64, src8: u64, srclen: usize) -> *mut u8 {
    unsafe {
        let n = srclen as u32 as usize;
        if n == 1 {
            *dest = 0;
        } else {
            put_small(dest, [0, src2, src3, src4, src5, src6, src7, src8], n);
        }
        dest.add(srclen.wrapping_sub(1))
    }
}

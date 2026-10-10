#![allow(clippy::deref_addrof)]
use core::ffi::{c_char, c_int, c_long, c_uint, c_ushort, c_void};
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::{errno, syscall};

const EINVAL: i32 = 22;

static LOCK: AtomicBool = AtomicBool::new(false);

struct Guard(bool);
impl Guard {
    #[inline(always)]
    fn new() -> Guard {
        if !rusty_libc_core::lock::multithreaded() {
            return Guard(false);
        }
        while LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        Guard(true)
    }
}
impl Drop for Guard {
    #[inline(always)]
    fn drop(&mut self) {
        if self.0 {
            LOCK.store(false, Ordering::Release);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rand_r(seed: *mut c_uint) -> c_int {
    let mut next = unsafe { *seed };
    next = next.wrapping_mul(1103515245).wrapping_add(12345);
    let mut result = ((next / 65536) % 2048) as c_int;
    next = next.wrapping_mul(1103515245).wrapping_add(12345);
    result <<= 10;
    result ^= ((next / 65536) % 1024) as c_int;
    next = next.wrapping_mul(1103515245).wrapping_add(12345);
    result <<= 10;
    result ^= ((next / 65536) % 1024) as c_int;
    unsafe { *seed = next };
    result
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RandomData {
    pub fptr: *mut i32,
    pub rptr: *mut i32,
    pub state: *mut i32,
    pub rand_type: c_int,
    pub rand_deg: c_int,
    pub rand_sep: c_int,
    pub end_ptr: *mut i32,
}

const TYPE_0: c_int = 0;
const TYPE_4: c_int = 4;
const MAX_TYPES: c_int = 5;
const BREAK: [usize; 5] = [8, 32, 64, 128, 256];
const DEGREES: [c_int; 5] = [0, 7, 15, 31, 63];
const SEPS: [c_int; 5] = [0, 3, 1, 3, 1];

#[inline]
unsafe fn rd(b: *mut i32, idx: isize) -> i32 {
    unsafe { b.byte_offset(idx * 4).read_unaligned() }
}
#[inline]
unsafe fn wr(b: *mut i32, idx: isize, v: i32) {
    unsafe { b.byte_offset(idx * 4).write_unaligned(v) }
}
#[inline]
fn word_diff(a: *mut i32, b: *mut i32) -> i32 {
    ((a as isize).wrapping_sub(b as isize) / 4) as i32
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn random_r(buf: *mut RandomData, result: *mut i32) -> c_int {
    if buf.is_null() || result.is_null() {
        errno::set(EINVAL);
        return -1;
    }
    let b = unsafe { &mut *buf };
    let state = b.state;
    unsafe {
        if b.rand_type == TYPE_0 {
            let val = ((rd(state, 0) as u32).wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff) as i32;
            wr(state, 0, val);
            *result = val;
        } else {
            let mut fptr = b.fptr;
            let mut rptr = b.rptr;
            let end = b.end_ptr;
            let val = (rd(fptr, 0) as u32).wrapping_add(rd(rptr, 0) as u32);
            wr(fptr, 0, val as i32);
            *result = (val >> 1) as i32;
            fptr = fptr.byte_add(4);
            if fptr >= end {
                fptr = state;
                rptr = rptr.byte_add(4);
            } else {
                rptr = rptr.byte_add(4);
                if rptr >= end {
                    rptr = state;
                }
            }
            b.fptr = fptr;
            b.rptr = rptr;
        }
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srandom_r(seed: c_uint, buf: *mut RandomData) -> c_int {
    if buf.is_null() {
        return -1;
    }
    let b = unsafe { &mut *buf };
    let ty = b.rand_type;
    if ty as c_uint >= MAX_TYPES as c_uint {
        return -1;
    }
    let state = b.state;
    let seed = if seed == 0 { 1 } else { seed };
    unsafe {
        wr(state, 0, seed as i32);
        if ty == TYPE_0 {
            return 0;
        }
        let mut word = seed as i32;
        let kc = b.rand_deg;
        for i in 1..kc as isize {
            let w = word as i64;
            let hi = w / 127773;
            let lo = w % 127773;
            let mut nw = 16807 * lo - 2836 * hi;
            if nw < 0 {
                nw += 2147483647;
            }
            word = nw as i32;
            wr(state, i, word);
        }
        b.fptr = state.byte_offset(b.rand_sep as isize * 4);
        b.rptr = state;
        let mut discard = 0i32;
        for _ in 0..kc * 10 {
            random_r(buf, &mut discard);
        }
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn initstate_r(seed: c_uint, arg_state: *mut c_char, n: usize, buf: *mut RandomData) -> c_int {
    if buf.is_null() {
        errno::set(EINVAL);
        return -1;
    }
    let b = unsafe { &mut *buf };
    let old_state = b.state;
    if !old_state.is_null() {
        let old_type = b.rand_type;
        unsafe {
            if old_type == TYPE_0 {
                wr(old_state, -1, TYPE_0);
            } else {
                wr(old_state, -1, MAX_TYPES * word_diff(b.rptr, old_state) + old_type);
            }
        }
    }
    let ty: c_int = if n >= BREAK[3] {
        if n < BREAK[4] { 3 } else { 4 }
    } else if n < BREAK[1] {
        if n < BREAK[0] {
            errno::set(EINVAL);
            return -1;
        }
        0
    } else if n < BREAK[2] {
        1
    } else {
        2
    };
    let degree = DEGREES[ty as usize];
    let sep = SEPS[ty as usize];
    b.rand_type = ty;
    b.rand_sep = sep;
    b.rand_deg = degree;
    let state = unsafe { arg_state.byte_add(4) }.cast::<i32>();
    b.end_ptr = unsafe { state.byte_add(4 * degree as usize) };
    b.state = state;
    unsafe {
        srandom_r(seed, buf);
        wr(state, -1, TYPE_0);
        if ty != TYPE_0 {
            wr(state, -1, word_diff((*buf).rptr, state) * MAX_TYPES + ty);
        }
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setstate_r(arg_state: *mut c_char, buf: *mut RandomData) -> c_int {
    if arg_state.is_null() || buf.is_null() {
        errno::set(EINVAL);
        return -1;
    }
    let b = unsafe { &mut *buf };
    let new_state = unsafe { arg_state.byte_add(4) }.cast::<i32>();
    let old_type = b.rand_type;
    let old_state = b.state;
    unsafe {
        if !old_state.is_null() {
            if old_type == TYPE_0 {
                wr(old_state, -1, TYPE_0);
            } else {
                wr(old_state, -1, MAX_TYPES * word_diff(b.rptr, old_state) + old_type);
            }
        }
        let word = rd(new_state, -1);
        let ty = word % MAX_TYPES;
        if !(TYPE_0..=TYPE_4).contains(&ty) {
            errno::set(EINVAL);
            return -1;
        }
        let degree = DEGREES[ty as usize];
        let sep = SEPS[ty as usize];
        b.rand_deg = degree;
        b.rand_sep = sep;
        b.rand_type = ty;
        if ty != TYPE_0 {
            let rear = (word / MAX_TYPES) as isize;
            b.rptr = new_state.byte_offset(rear * 4);
            b.fptr = new_state.byte_offset(((rear + sep as isize) % degree as isize) * 4);
        }
        b.state = new_state;
        b.end_ptr = new_state.byte_add(4 * degree as usize);
    }
    0
}

static mut RANDTBL: [i32; 32] = [
    3, -1726662223, 379960547, 1735697613, 1040273694, 1313901226, 1627687941, -179304937, -2073333483,
    1780058412, -1989503057, -615974602, 344556628, 939512070, -1249116260, 1507946756, -812545463,
    154635395, 1388815473, -1926676823, 525320961, -1009028674, 968117788, -123449607, 1284210865,
    435012392, -2017506339, -911064859, -370259173, 1132637927, 1398500161, -205601318,
];

static mut UNSAFE_STATE: RandomData = RandomData {
    fptr: (&raw mut RANDTBL).cast::<i32>().wrapping_add(4),
    rptr: (&raw mut RANDTBL).cast::<i32>().wrapping_add(1),
    state: (&raw mut RANDTBL).cast::<i32>().wrapping_add(1),
    rand_type: 3,
    rand_deg: 31,
    rand_sep: 3,
    end_ptr: (&raw mut RANDTBL).cast::<i32>().wrapping_add(32),
};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srandom(seed: c_uint) {
    let _g = Guard::new();
    unsafe { srandom_r(seed, &raw mut UNSAFE_STATE) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srand(seed: c_uint) {
    unsafe { srandom(seed) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn random() -> c_long {
    let _g = Guard::new();
    let mut r = 0i32;
    unsafe { random_r(&raw mut UNSAFE_STATE, &mut r) };
    r as c_long
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rand() -> c_int {
    unsafe { random() as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn initstate(seed: c_uint, arg_state: *mut c_char, n: usize) -> *mut c_char {
    let _g = Guard::new();
    unsafe {
        let ostate = (*(&raw const UNSAFE_STATE)).state.byte_sub(4);
        let ret = initstate_r(seed, arg_state, n, &raw mut UNSAFE_STATE);
        if ret == -1 { core::ptr::null_mut() } else { ostate.cast() }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setstate(arg_state: *mut c_char) -> *mut c_char {
    let _g = Guard::new();
    unsafe {
        let ostate = (*(&raw const UNSAFE_STATE)).state.byte_sub(4);
        if setstate_r(arg_state, &raw mut UNSAFE_STATE) < 0 { core::ptr::null_mut() } else { ostate.cast() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Drand48Data {
    pub x: [c_ushort; 3],
    pub old_x: [c_ushort; 3],
    pub c: c_ushort,
    pub init: c_ushort,
    pub a: u64,
}

const A48: u64 = 0x5deece66d;
const C48: u16 = 0xb;

unsafe fn iterate(xsubi: *mut c_ushort, buf: *mut Drand48Data) {
    unsafe {
        if (*buf).init == 0 {
            (*buf).a = A48;
            (*buf).c = C48;
            (*buf).init = 1;
        }
        let x = (xsubi.add(2).read_volatile() as u64) << 32 | (xsubi.add(1).read_volatile() as u64) << 16 | xsubi.read_volatile() as u64;
        let r = x.wrapping_mul((*buf).a).wrapping_add((*buf).c as u64);
        *xsubi = r as u16;
        *xsubi.add(1) = (r >> 16) as u16;
        *xsubi.add(2) = (r >> 32) as u16;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn erand48_r(xsubi: *mut c_ushort, buf: *mut Drand48Data, result: *mut f64) -> c_int {
    unsafe {
        iterate(xsubi, buf);
        let (x0, x1, x2) = (*xsubi as u64, *xsubi.add(1) as u64, *xsubi.add(2) as u64);
        let mant0 = (x2 << 4) | (x1 >> 12);
        let mant1 = ((x1 & 0xfff) << 20) | (x0 << 4);
        let bits = (0x3ffu64 << 52) | (mant0 << 32) | mant1;
        *result = f64::from_bits(bits) - 1.0;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn drand48_r(buf: *mut Drand48Data, result: *mut f64) -> c_int {
    unsafe { erand48_r((*buf).x.as_mut_ptr(), buf, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nrand48_r(xsubi: *mut c_ushort, buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    unsafe {
        iterate(xsubi, buf);
        *result = ((*xsubi.add(2) as c_long) << 15) | ((*xsubi.add(1) as c_long) >> 1);
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lrand48_r(buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    if buf.is_null() {
        return -1;
    }
    unsafe { nrand48_r((*buf).x.as_mut_ptr(), buf, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn jrand48_r(xsubi: *mut c_ushort, buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    unsafe {
        iterate(xsubi, buf);
        *result = ((((*xsubi.add(2) as u32) << 16) | *xsubi.add(1) as u32) as i32) as c_long;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mrand48_r(buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    if buf.is_null() {
        return -1;
    }
    unsafe { jrand48_r((*buf).x.as_mut_ptr(), buf, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srand48_r(seedval: c_long, buf: *mut Drand48Data) -> c_int {
    let s = (seedval as u64) & 0xffff_ffff;
    unsafe {
        (*buf).x[2] = (s >> 16) as u16;
        (*buf).x[1] = (s & 0xffff) as u16;
        (*buf).x[0] = 0x330e;
        (*buf).a = A48;
        (*buf).c = C48;
        (*buf).init = 1;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn seed48_r(seed16v: *mut c_ushort, buf: *mut Drand48Data) -> c_int {
    unsafe {
        (*buf).old_x = (*buf).x;
        (*buf).x[2] = *seed16v.add(2);
        (*buf).x[1] = *seed16v.add(1);
        (*buf).x[0] = *seed16v;
        (*buf).a = A48;
        (*buf).c = C48;
        (*buf).init = 1;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lcong48_r(param: *mut c_ushort, buf: *mut Drand48Data) -> c_int {
    unsafe {
        for i in 0..3 {
            (*buf).x[i] = *param.add(i);
        }
        (*buf).a = (*param.add(5) as u64) << 32 | (*param.add(4) as u64) << 16 | *param.add(3) as u64;
        (*buf).c = *param.add(6);
        (*buf).init = 1;
    }
    0
}

static mut DRAND48: Drand48Data = Drand48Data { x: [0; 3], old_x: [0; 3], c: 0, init: 0, a: 0 };

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn drand48() -> f64 {
    let _g = Guard::new();
    let mut r = 0.0;
    unsafe { drand48_r(&raw mut DRAND48, &mut r) };
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn erand48(xsubi: *mut c_ushort) -> f64 {
    let _g = Guard::new();
    let mut r = 0.0;
    unsafe { erand48_r(xsubi, &raw mut DRAND48, &mut r) };
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lrand48() -> c_long {
    let _g = Guard::new();
    let mut r = 0;
    unsafe { lrand48_r(&raw mut DRAND48, &mut r) };
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nrand48(xsubi: *mut c_ushort) -> c_long {
    let _g = Guard::new();
    let mut r = 0;
    unsafe { nrand48_r(xsubi, &raw mut DRAND48, &mut r) };
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mrand48() -> c_long {
    let _g = Guard::new();
    let mut r = 0;
    unsafe { mrand48_r(&raw mut DRAND48, &mut r) };
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn jrand48(xsubi: *mut c_ushort) -> c_long {
    let _g = Guard::new();
    let mut r = 0;
    unsafe { jrand48_r(xsubi, &raw mut DRAND48, &mut r) };
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srand48(seedval: c_long) {
    let _g = Guard::new();
    unsafe { srand48_r(seedval, &raw mut DRAND48) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn seed48(seed16v: *mut c_ushort) -> *mut c_ushort {
    let _g = Guard::new();
    unsafe {
        seed48_r(seed16v, &raw mut DRAND48);
        (*(&raw mut DRAND48)).old_x.as_mut_ptr()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lcong48(param: *mut c_ushort) {
    let _g = Guard::new();
    unsafe { lcong48_r(param, &raw mut DRAND48) };
}

#[cold]
fn getrandom_failure() -> ! {
    let _ = rusty_libc_core::unistd::write(2, b"Fatal glibc error: cannot get entropy for arc4random\n");
    rusty_libc_core::process::abort()
}

unsafe fn raw_read_urandom(mut p: *mut u8, mut n: usize) {
    const O_RDONLY_CLOEXEC_NOCTTY: usize = 0o2000000 | 0o400;
    const AT_FDCWD: usize = -100isize as usize;
    let fd = loop {
        let r = unsafe {
            syscall::syscall4(syscall::SYS_OPENAT, AT_FDCWD, c"/dev/urandom".as_ptr() as usize, O_RDONLY_CLOEXEC_NOCTTY, 0)
        };
        match syscall::check(r) {
            Ok(fd) => break fd,
            Err(e) if e.0 == errno::EINTR => continue,
            Err(_) => getrandom_failure(),
        }
    };
    while n > 0 {
        let r = unsafe { syscall::syscall3(syscall::SYS_READ, fd, p as usize, n) };
        match syscall::check(r) {
            Ok(0) => getrandom_failure(),
            Ok(l) => {
                p = unsafe { p.add(l) };
                n -= l;
            }
            Err(e) if e.0 == errno::EINTR => {}
            Err(_) => getrandom_failure(),
        }
    }
    unsafe { syscall::syscall1(syscall::SYS_CLOSE, fd) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random_buf(mut p: *mut c_void, mut n: usize) {
    const ENOSYS: i32 = 38;
    while n > 0 {
        let r = unsafe { syscall::syscall3(syscall::SYS_GETRANDOM, p as usize, n, 0) };
        match syscall::check(r) {
            Ok(l) if l > 0 => {
                p = unsafe { p.byte_add(l) };
                n -= l;
            }
            Err(e) if e.0 == errno::EINTR => {}
            Err(e) if e.0 == ENOSYS => {
                unsafe { raw_read_urandom(p.cast(), n) };
                return;
            }
            _ => getrandom_failure(),
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random() -> u32 {
    let mut r = 0u32;
    unsafe { arc4random_buf((&raw mut r).cast(), 4) };
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random_uniform(n: u32) -> u32 {
    uniform_with(n, || unsafe { arc4random() })
}

fn uniform_with(n: u32, mut next: impl FnMut() -> u32) -> u32 {
    if n <= 1 {
        return 0;
    }
    if n.is_power_of_two() {
        return next() & (n - 1);
    }
    let z = n.leading_zeros();
    let mask = u32::MAX >> z;
    let bits = 32 - z;
    loop {
        let mut value = next();
        let r = value & mask;
        if r < n {
            return r;
        }
        let mut left = z as i32;
        while left >= bits as i32 {
            value >>= bits;
            let r = value & mask;
            if r < n {
                return r;
            }
            left -= bits as i32;
        }
    }
}


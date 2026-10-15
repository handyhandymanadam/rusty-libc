use core::ffi::{c_char, c_int, c_long, c_uint, c_ushort, c_void};
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::{SyncCell, errno};

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

#[inline]
pub fn rand_r_step(seed: &mut c_uint) -> c_int {
    let mut next = *seed;
    next = next.wrapping_mul(1103515245).wrapping_add(12345);
    let mut result = ((next / 65536) % 2048) as c_int;
    next = next.wrapping_mul(1103515245).wrapping_add(12345);
    result <<= 10;
    result ^= ((next / 65536) % 1024) as c_int;
    next = next.wrapping_mul(1103515245).wrapping_add(12345);
    result <<= 10;
    result ^= ((next / 65536) % 1024) as c_int;
    *seed = next;
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rand_r(seed: *mut c_uint) -> c_int {
    rand_r_step(unsafe { &mut *seed })
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
fn word_diff(a: *mut i32, b: *mut i32) -> i32 {
    ((a as isize).wrapping_sub(b as isize) / 4) as i32
}

struct Gen<'a>(&'a mut RandomData);

impl<'a> Gen<'a> {
    #[inline(always)]
    unsafe fn new(b: &'a mut RandomData) -> Gen<'a> {
        Gen(b)
    }

    #[inline(always)]
    fn rd(&self, p: *const i32) -> i32 {
        unsafe { p.read_unaligned() }
    }

    #[inline(always)]
    fn wr(&mut self, p: *mut i32, v: i32) {
        unsafe { p.write_unaligned(v) }
    }

    #[inline(always)]
    fn step(&mut self) -> i32 {
        let state = self.0.state;
        if self.0.rand_type == TYPE_0 {
            let val = ((self.rd(state) as u32).wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff) as i32;
            self.wr(state, val);
            val
        } else {
            let mut fptr = self.0.fptr;
            let mut rptr = self.0.rptr;
            let end = self.0.end_ptr;
            let val = (self.rd(fptr) as u32).wrapping_add(self.rd(rptr) as u32);
            self.wr(fptr, val as i32);
            fptr = fptr.wrapping_byte_add(4);
            if fptr >= end {
                fptr = state;
                rptr = rptr.wrapping_byte_add(4);
            } else {
                rptr = rptr.wrapping_byte_add(4);
                if rptr >= end {
                    rptr = state;
                }
            }
            self.0.fptr = fptr;
            self.0.rptr = rptr;
            (val >> 1) as i32
        }
    }

    fn seed(&mut self, seed: c_uint) {
        let state = self.0.state;
        let seed = if seed == 0 { 1 } else { seed };
        self.wr(state, seed as i32);
        if self.0.rand_type == TYPE_0 {
            return;
        }
        let mut word = seed as i32;
        let kc = self.0.rand_deg;
        for i in 1..kc as usize {
            let w = word as i64;
            let hi = w / 127773;
            let lo = w % 127773;
            let mut nw = 16807 * lo - 2836 * hi;
            if nw < 0 {
                nw += 2147483647;
            }
            word = nw as i32;
            self.wr(state.wrapping_add(i), word);
        }
        self.0.fptr = state.wrapping_byte_add(self.0.rand_sep as usize * 4);
        self.0.rptr = state;
        for _ in 0..kc * 10 {
            self.step();
        }
    }

    fn save_type_word(&mut self) {
        let state = self.0.state;
        let w = if self.0.rand_type == TYPE_0 { TYPE_0 } else { MAX_TYPES * word_diff(self.0.rptr, state) + self.0.rand_type };
        self.wr(state.wrapping_sub(1), w);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn random_r(buf: *mut RandomData, result: *mut i32) -> c_int {
    let Some(b) = (unsafe { buf.as_mut() }) else {
        errno::set(EINVAL);
        return -1;
    };
    if result.is_null() {
        errno::set(EINVAL);
        return -1;
    }
    let v = unsafe { Gen::new(b) }.step();
    unsafe { result.write(v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srandom_r(seed: c_uint, buf: *mut RandomData) -> c_int {
    let Some(b) = (unsafe { buf.as_mut() }) else { return -1 };
    if b.rand_type as c_uint >= MAX_TYPES as c_uint {
        return -1;
    }
    unsafe { Gen::new(b) }.seed(seed);
    0
}

fn type_for_size(n: usize) -> Option<c_int> {
    Some(if n >= BREAK[3] {
        if n < BREAK[4] { 3 } else { 4 }
    } else if n < BREAK[1] {
        if n < BREAK[0] {
            return None;
        }
        0
    } else if n < BREAK[2] {
        1
    } else {
        2
    })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn initstate_r(seed: c_uint, arg_state: *mut c_char, n: usize, buf: *mut RandomData) -> c_int {
    let Some(b) = (unsafe { buf.as_mut() }) else {
        errno::set(EINVAL);
        return -1;
    };
    if !b.state.is_null() {
        unsafe { Gen::new(b) }.save_type_word();
    }
    let Some(ty) = type_for_size(n) else {
        errno::set(EINVAL);
        return -1;
    };
    let degree = DEGREES[ty as usize];
    b.rand_type = ty;
    b.rand_sep = SEPS[ty as usize];
    b.rand_deg = degree;
    let state = arg_state.wrapping_byte_add(4).cast::<i32>();
    b.end_ptr = state.wrapping_byte_add(4 * degree as usize);
    b.state = state;
    let mut g = unsafe { Gen::new(b) };
    g.seed(seed);
    g.wr(state.wrapping_sub(1), TYPE_0);
    if ty != TYPE_0 {
        let w = word_diff(g.0.rptr, state) * MAX_TYPES + ty;
        g.wr(state.wrapping_sub(1), w);
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
    let new_state = arg_state.wrapping_byte_add(4).cast::<i32>();
    if !b.state.is_null() {
        unsafe { Gen::new(b) }.save_type_word();
    }
    let word = unsafe { arg_state.cast::<i32>().read_unaligned() };
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
        b.rptr = new_state.wrapping_byte_offset(rear * 4);
        b.fptr = new_state.wrapping_byte_offset(((rear + sep as isize) % degree as isize) * 4);
    }
    b.state = new_state;
    b.end_ptr = new_state.wrapping_byte_add(4 * degree as usize);
    0
}

const RANDTBL_INIT: [i32; 32] = [
    3, -1726662223, 379960547, 1735697613, 1040273694, 1313901226, 1627687941, -179304937, -2073333483,
    1780058412, -1989503057, -615974602, 344556628, 939512070, -1249116260, 1507946756, -812545463,
    154635395, 1388815473, -1926676823, 525320961, -1009028674, 968117788, -123449607, 1284210865,
    435012392, -2017506339, -911064859, -370259173, 1132637927, 1398500161, -205601318,
];

static RANDTBL: SyncCell<[i32; 32]> = SyncCell::new(RANDTBL_INIT);

static RANDOM: SyncCell<RandomData> = SyncCell::new(RandomData {
    fptr: RANDTBL.as_ptr().cast::<i32>().wrapping_add(4),
    rptr: RANDTBL.as_ptr().cast::<i32>().wrapping_add(1),
    state: RANDTBL.as_ptr().cast::<i32>().wrapping_add(1),
    rand_type: 3,
    rand_deg: 31,
    rand_sep: 3,
    end_ptr: RANDTBL.as_ptr().cast::<i32>().wrapping_add(32),
});

#[inline(always)]
fn with_random<R>(f: impl FnOnce(&mut RandomData) -> R) -> R {
    let _g = Guard::new();
    unsafe { RANDOM.with_unsync(f) }
}

#[inline(always)]
unsafe fn global_gen(b: &mut RandomData) -> Gen<'_> {
    unsafe { Gen::new(b) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srandom(seed: c_uint) {
    with_random(|b| unsafe { global_gen(b) }.seed(seed));
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srand(seed: c_uint) {
    unsafe { srandom(seed) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn random() -> c_long {
    with_random(|b| unsafe { global_gen(b) }.step()) as c_long
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rand() -> c_int {
    unsafe { random() as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn initstate(seed: c_uint, arg_state: *mut c_char, n: usize) -> *mut c_char {
    with_random(|b| {
        let ostate = b.state.wrapping_byte_sub(4);
        let ret = unsafe { initstate_r(seed, arg_state, n, b) };
        if ret == -1 { core::ptr::null_mut() } else { ostate.cast() }
    })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setstate(arg_state: *mut c_char) -> *mut c_char {
    with_random(|b| {
        let ostate = b.state.wrapping_byte_sub(4);
        if unsafe { setstate_r(arg_state, b) } < 0 { core::ptr::null_mut() } else { ostate.cast() }
    })
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

struct Lcg<'a> {
    a: &'a mut u64,
    c: &'a mut c_ushort,
    init: &'a mut c_ushort,
}

#[inline(always)]
fn split(buf: &mut Drand48Data) -> (&mut [c_ushort; 3], Lcg<'_>) {
    let Drand48Data { x, a, c, init, .. } = buf;
    (x, Lcg { a, c, init })
}

#[inline(always)]
fn iterate(x: &mut [c_ushort; 3], l: Lcg<'_>) {
    if *l.init == 0 {
        *l.a = A48;
        *l.c = C48;
        *l.init = 1;
    }
    let x2 = unsafe { core::ptr::read_volatile(&x[2]) };
    let x1 = unsafe { core::ptr::read_volatile(&x[1]) };
    let x0 = unsafe { core::ptr::read_volatile(&x[0]) };
    let v = (u64::from(x2) << 32) | (u64::from(x1) << 16) | u64::from(x0);
    let r = v.wrapping_mul(*l.a).wrapping_add(u64::from(*l.c));
    x[0] = r as u16;
    x[1] = (r >> 16) as u16;
    x[2] = (r >> 32) as u16;
}

#[inline(always)]
fn erand48_step(x: &mut [c_ushort; 3], l: Lcg<'_>) -> f64 {
    iterate(x, l);
    let (x0, x1, x2) = (u64::from(x[0]), u64::from(x[1]), u64::from(x[2]));
    let mant0 = (x2 << 4) | (x1 >> 12);
    let mant1 = ((x1 & 0xfff) << 20) | (x0 << 4);
    let bits = (0x3ffu64 << 52) | (mant0 << 32) | mant1;
    f64::from_bits(bits) - 1.0
}

#[inline(always)]
fn nrand48_step(x: &mut [c_ushort; 3], l: Lcg<'_>) -> c_long {
    iterate(x, l);
    (c_long::from(x[2]) << 15) | (c_long::from(x[1]) >> 1)
}

#[inline(always)]
fn jrand48_step(x: &mut [c_ushort; 3], l: Lcg<'_>) -> c_long {
    iterate(x, l);
    (((u32::from(x[2]) << 16) | u32::from(x[1])) as i32) as c_long
}

#[inline]
pub fn erand48_core(x: &mut [c_ushort; 3], buf: &mut Drand48Data) -> f64 {
    erand48_step(x, split(buf).1)
}

#[inline]
pub fn nrand48_core(x: &mut [c_ushort; 3], buf: &mut Drand48Data) -> c_long {
    nrand48_step(x, split(buf).1)
}

#[inline]
pub fn jrand48_core(x: &mut [c_ushort; 3], buf: &mut Drand48Data) -> c_long {
    jrand48_step(x, split(buf).1)
}

#[inline(always)]
fn on_own_x<R>(buf: &mut Drand48Data, step: fn(&mut [c_ushort; 3], Lcg<'_>) -> R) -> R {
    let (x, l) = split(buf);
    step(x, l)
}

pub fn srand48_core(seedval: c_long, buf: &mut Drand48Data) {
    let s = (seedval as u64) & 0xffff_ffff;
    buf.x[2] = (s >> 16) as u16;
    buf.x[1] = (s & 0xffff) as u16;
    buf.x[0] = 0x330e;
    buf.a = A48;
    buf.c = C48;
    buf.init = 1;
}

pub fn seed48_core(seed16v: &[c_ushort; 3], buf: &mut Drand48Data) {
    buf.old_x = buf.x;
    buf.x[2] = seed16v[2];
    buf.x[1] = seed16v[1];
    buf.x[0] = seed16v[0];
    buf.a = A48;
    buf.c = C48;
    buf.init = 1;
}

pub fn lcong48_core(param: &[c_ushort; 7], buf: &mut Drand48Data) {
    buf.x.copy_from_slice(&param[..3]);
    buf.a = (u64::from(param[5]) << 32) | (u64::from(param[4]) << 16) | u64::from(param[3]);
    buf.c = param[6];
    buf.init = 1;
}

#[inline(always)]
unsafe fn get3(p: *const c_ushort) -> [c_ushort; 3] {
    unsafe { p.cast::<[c_ushort; 3]>().read() }
}

#[inline(always)]
unsafe fn put3(p: *mut c_ushort, v: [c_ushort; 3]) {
    unsafe { p.cast::<[c_ushort; 3]>().write(v) }
}

#[inline(always)]
unsafe fn put<T>(p: *mut T, v: T) {
    unsafe { p.write(v) }
}

#[inline(always)]
unsafe fn data<'a>(buf: *mut Drand48Data) -> &'a mut Drand48Data {
    unsafe { &mut *buf }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn erand48_r(xsubi: *mut c_ushort, buf: *mut Drand48Data, result: *mut f64) -> c_int {
    let mut x = unsafe { get3(xsubi) };
    let v = erand48_core(&mut x, unsafe { data(buf) });
    unsafe { put3(xsubi, x) };
    unsafe { put(result, v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn drand48_r(buf: *mut Drand48Data, result: *mut f64) -> c_int {
    let v = on_own_x(unsafe { data(buf) }, erand48_step);
    unsafe { put(result, v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nrand48_r(xsubi: *mut c_ushort, buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    let mut x = unsafe { get3(xsubi) };
    let v = nrand48_core(&mut x, unsafe { data(buf) });
    unsafe { put3(xsubi, x) };
    unsafe { put(result, v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lrand48_r(buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    let Some(b) = (unsafe { buf.as_mut() }) else { return -1 };
    let v = on_own_x(b, nrand48_step);
    unsafe { put(result, v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn jrand48_r(xsubi: *mut c_ushort, buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    let mut x = unsafe { get3(xsubi) };
    let v = jrand48_core(&mut x, unsafe { data(buf) });
    unsafe { put3(xsubi, x) };
    unsafe { put(result, v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mrand48_r(buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    let Some(b) = (unsafe { buf.as_mut() }) else { return -1 };
    let v = on_own_x(b, jrand48_step);
    unsafe { put(result, v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srand48_r(seedval: c_long, buf: *mut Drand48Data) -> c_int {
    srand48_core(seedval, unsafe { data(buf) });
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn seed48_r(seed16v: *mut c_ushort, buf: *mut Drand48Data) -> c_int {
    let s = unsafe { get3(seed16v) };
    seed48_core(&s, unsafe { data(buf) });
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lcong48_r(param: *mut c_ushort, buf: *mut Drand48Data) -> c_int {
    let p = unsafe { param.cast::<[c_ushort; 7]>().read() };
    lcong48_core(&p, unsafe { data(buf) });
    0
}

static DRAND48: SyncCell<Drand48Data> = SyncCell::new(Drand48Data { x: [0; 3], old_x: [0; 3], c: 0, init: 0, a: 0 });

#[inline(always)]
fn with_drand<R>(f: impl FnOnce(&mut Drand48Data) -> R) -> R {
    let _g = Guard::new();
    unsafe { DRAND48.with_unsync(f) }
}

#[inline(always)]
unsafe fn with_xsubi<R>(xsubi: *mut c_ushort, core: fn(&mut [c_ushort; 3], &mut Drand48Data) -> R) -> R {
    let mut x = unsafe { get3(xsubi) };
    let r = with_drand(|d| core(&mut x, d));
    unsafe { put3(xsubi, x) };
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn drand48() -> f64 {
    with_drand(|d| on_own_x(d, erand48_step))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn erand48(xsubi: *mut c_ushort) -> f64 {
    unsafe { with_xsubi(xsubi, erand48_core) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lrand48() -> c_long {
    with_drand(|d| on_own_x(d, nrand48_step))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nrand48(xsubi: *mut c_ushort) -> c_long {
    unsafe { with_xsubi(xsubi, nrand48_core) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mrand48() -> c_long {
    with_drand(|d| on_own_x(d, jrand48_step))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn jrand48(xsubi: *mut c_ushort) -> c_long {
    unsafe { with_xsubi(xsubi, jrand48_core) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srand48(seedval: c_long) {
    with_drand(|d| srand48_core(seedval, d));
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn seed48(seed16v: *mut c_ushort) -> *mut c_ushort {
    let s = unsafe { get3(seed16v) };
    with_drand(|d| seed48_core(&s, d));
    DRAND48.as_ptr().cast::<c_ushort>().wrapping_add(3)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lcong48(param: *mut c_ushort) {
    let p = unsafe { param.cast::<[c_ushort; 7]>().read() };
    with_drand(|d| lcong48_core(&p, d));
}

#[cold]
fn getrandom_failure() -> ! {
    let _ = rusty_libc_core::unistd::write(2, b"Fatal glibc error: cannot get entropy for arc4random\n");
    rusty_libc_core::process::abort()
}

fn read_urandom(mut buf: &mut [u8]) {
    const O_RDONLY_CLOEXEC_NOCTTY: i32 = 0o2000000 | 0o400;
    let fd = loop {
        match crate::sys::open(c"/dev/urandom", O_RDONLY_CLOEXEC_NOCTTY, 0) {
            Ok(fd) => break fd,
            Err(e) if e.0 == errno::EINTR => continue,
            Err(_) => getrandom_failure(),
        }
    };
    while !buf.is_empty() {
        match rusty_libc_core::unistd::read_nocancel(fd, buf) {
            Ok(0) => getrandom_failure(),
            Ok(l) => buf = &mut buf[l..],
            Err(e) if e.0 == errno::EINTR => {}
            Err(_) => getrandom_failure(),
        }
    }
    let _ = rusty_libc_core::unistd::close(fd);
}

pub fn fill_random(mut buf: &mut [u8]) {
    const ENOSYS: i32 = 38;
    while !buf.is_empty() {
        match rusty_libc_core::syscall::check(crate::sys::getrandom(buf, 0)) {
            Ok(l) if l > 0 => buf = &mut buf[l..],
            Err(e) if e.0 == errno::EINTR => {}
            Err(e) if e.0 == ENOSYS => return read_urandom(buf),
            _ => getrandom_failure(),
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random_buf(p: *mut c_void, n: usize) {
    fill_random(unsafe { rusty_libc_core::ffi::bytes_mut(p.cast(), n) });
}

#[inline]
pub fn arc4random_u32() -> u32 {
    let mut b = [0u8; 4];
    fill_random(&mut b);
    u32::from_ne_bytes(b)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random() -> u32 {
    arc4random_u32()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random_uniform(n: u32) -> u32 {
    uniform_with(n, arc4random_u32)
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


//! rand.h family: `rand`/`srand`, the BSD `random` family (with `random_data` as in glibc), the
//! 48-bit `drand48` family (with `drand48_data` as in glibc) and `arc4random`.
//!
//! Written from the documented and observed behaviour of glibc 2.43 so the same seed gives the same
//! sequence: the additive feedback generator (trinomials of degree 7, 15, 31, 63; seeding by the
//! Park-Miller "minimal standard" recurrence 16807 * x mod 2^31-1, then 10 * degree discarded values),
//! the linear congruential type 0, and the 48-bit linear congruential generator
//! x = (0x5deece66d * x + 0xb) mod 2^48.
//! The default `random` table (`RANDTBL_INIT`) is data taken from glibc's stdlib/random.c: it is what
//! `initstate(1, tbl, 128)` produces, and a unit test checks that against this code's own `initstate_r`.
//! `arc4random*` read the kernel's getrandom, with a /dev/urandom fallback when the call is missing.
//!
//! Shape (BRIEF-UNSAFE U2): the global generators are `SyncCell`s used only under the generator lock ([`Guard`]); the
//! drand48 family is safe code on `&mut [u16; 3]` and `&mut Drand48Data`, the C functions copying their pointer arguments
//! in and out once. What stays unsafe: the C pointer arguments, and the `random_data` state array, which is the caller's
//! memory described by raw pointers inside the struct (glibc's layout): [`Gen`] holds the rule for it, and each read or
//! write of a state word is one audited operation.
use core::ffi::{c_char, c_int, c_long, c_uint, c_ushort, c_void};
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::{SyncCell, errno};

const EINVAL: i32 = 22;

// ---- one lock for the global generator states ----

static LOCK: AtomicBool = AtomicBool::new(false);

/// The generator lock; while the process has one thread nothing is taken (the token remembers that, so a thread created
/// in between never releases a lock it did not take).
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

// ---- rand_r ----

/// `rand_r` on the caller's seed: the per-caller 31-bit generator of POSIX (three 1103515245 steps per result).
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

/// `rand_r`: the per-caller 31-bit generator of POSIX.
///
/// # Safety
/// `seed` must point to a valid `unsigned int`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rand_r(seed: *mut c_uint) -> c_int {
    // SAFETY: `seed` points to an unsigned int (the caller's contract); NULL faults on the read, as in glibc.
    rand_r_step(unsafe { &mut *seed })
}

// ---- random family ----

/// glibc's `struct random_data` (same field order and sizes).
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

/// A `random_data` whose state array may be read and written (glibc's arrays may be misaligned: unaligned accesses).
///
/// Rule: the word before `state` (the type word) and the words `state[0 .. max(rand_deg, 1)]` are readable and writable
/// memory of the caller for the life of the borrow, and `fptr` and `rptr` point into `state[0 .. rand_deg]` (or anywhere
/// in that array for type 0, which uses neither). `initstate_r` and `setstate_r` establish it; the C functions take it
/// from their callers, as glibc does.
struct Gen<'a>(&'a mut RandomData);

impl<'a> Gen<'a> {
    /// # Safety
    /// `b` follows the rule above.
    #[inline(always)]
    unsafe fn new(b: &'a mut RandomData) -> Gen<'a> {
        Gen(b)
    }

    /// The word at `p`, a word of the state array (or its type word).
    #[inline(always)]
    fn rd(&self, p: *const i32) -> i32 {
        // SAFETY: Gen's rule: `p` is a word of the caller's state array (every caller passes one).
        unsafe { p.read_unaligned() }
    }

    #[inline(always)]
    fn wr(&mut self, p: *mut i32, v: i32) {
        // SAFETY: as in `rd`.
        unsafe { p.write_unaligned(v) }
    }

    /// One `random_r` step.
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

    /// `srandom_r` on a valid type (checked by the caller).
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
            // state[i] = 16807 * state[i - 1] % 2147483647 without overflowing 31 bits.
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

    /// Store the type and rear position in the type word (what initstate_r and setstate_r do for the old state).
    fn save_type_word(&mut self) {
        let state = self.0.state;
        let w = if self.0.rand_type == TYPE_0 { TYPE_0 } else { MAX_TYPES * word_diff(self.0.rptr, state) + self.0.rand_type };
        self.wr(state.wrapping_sub(1), w);
    }
}

/// # Safety
/// `buf` and `result` must be valid (or null, which fails with EINVAL); the state array of `buf` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn random_r(buf: *mut RandomData, result: *mut i32) -> c_int {
    // SAFETY: NULL or a valid random_data (the caller's contract).
    let Some(b) = (unsafe { buf.as_mut() }) else {
        errno::set(EINVAL);
        return -1;
    };
    if result.is_null() {
        errno::set(EINVAL);
        return -1;
    }
    // SAFETY: the state array of a valid random_data follows Gen's rule (the caller's contract).
    let v = unsafe { Gen::new(b) }.step();
    // SAFETY: `result` is a valid, non-NULL int pointer (the caller's contract).
    unsafe { result.write(v) };
    0
}

/// # Safety
/// `buf` must be valid (or null: returns -1) and its `state` pointer must be set up (see `initstate_r`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srandom_r(seed: c_uint, buf: *mut RandomData) -> c_int {
    // SAFETY: NULL or a valid random_data (the caller's contract).
    let Some(b) = (unsafe { buf.as_mut() }) else { return -1 };
    if b.rand_type as c_uint >= MAX_TYPES as c_uint {
        return -1;
    }
    // SAFETY: as in random_r.
    unsafe { Gen::new(b) }.seed(seed);
    0
}

/// The type for a state array of `n` bytes, or None (EINVAL) below 8 bytes.
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

/// # Safety
/// `arg_state` must point to `n` writable bytes; `buf` must be valid (or null: EINVAL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn initstate_r(seed: c_uint, arg_state: *mut c_char, n: usize, buf: *mut RandomData) -> c_int {
    // SAFETY: NULL or a valid random_data (the caller's contract).
    let Some(b) = (unsafe { buf.as_mut() }) else {
        errno::set(EINVAL);
        return -1;
    };
    if !b.state.is_null() {
        // SAFETY: a set-up random_data follows Gen's rule (the caller's contract).
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
    // SAFETY: the state array is the caller's `n` bytes (at least 4 * (degree + 1), and at least 8 for type 0, as the
    // table above makes sure), so Gen's rule holds for the new state; fptr and rptr are set by `seed` before use.
    let mut g = unsafe { Gen::new(b) };
    g.seed(seed);
    g.wr(state.wrapping_sub(1), TYPE_0);
    if ty != TYPE_0 {
        let w = word_diff(g.0.rptr, state) * MAX_TYPES + ty;
        g.wr(state.wrapping_sub(1), w);
    }
    0
}

/// # Safety
/// `arg_state` must be a state array made by `initstate_r` (or null: EINVAL); `buf` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setstate_r(arg_state: *mut c_char, buf: *mut RandomData) -> c_int {
    if arg_state.is_null() || buf.is_null() {
        errno::set(EINVAL);
        return -1;
    }
    // SAFETY: a valid random_data (the caller's contract), not NULL (checked).
    let b = unsafe { &mut *buf };
    let new_state = arg_state.wrapping_byte_add(4).cast::<i32>();
    if !b.state.is_null() {
        // SAFETY: a set-up random_data follows Gen's rule (the caller's contract).
        unsafe { Gen::new(b) }.save_type_word();
    }
    // SAFETY: `arg_state` is a state array made by initstate_r: its first word is the type word (the caller's contract).
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

/// glibc's default table (from stdlib/random.c): `initstate(1, RANDTBL, 128)` leaves exactly this (a
/// test checks it). Element 0 holds the type (3) multiplexed with the rear pointer position (0).
const RANDTBL_INIT: [i32; 32] = [
    3, -1726662223, 379960547, 1735697613, 1040273694, 1313901226, 1627687941, -179304937, -2073333483,
    1780058412, -1989503057, -615974602, 344556628, 939512070, -1249116260, 1507946756, -812545463,
    154635395, 1388815473, -1926676823, 525320961, -1009028674, 968117788, -123449607, 1284210865,
    435012392, -2017506339, -911064859, -370259173, 1132637927, 1398500161, -205601318,
];

/// The default state array; only reached through `RANDOM`'s pointers (under the generator lock).
static RANDTBL: SyncCell<[i32; 32]> = SyncCell::new(RANDTBL_INIT);

/// The generator of `random`, `srandom`, `initstate` and `setstate`: used only under the generator lock ([`with_random`]).
static RANDOM: SyncCell<RandomData> = SyncCell::new(RandomData {
    fptr: RANDTBL.as_ptr().cast::<i32>().wrapping_add(4),
    rptr: RANDTBL.as_ptr().cast::<i32>().wrapping_add(1),
    state: RANDTBL.as_ptr().cast::<i32>().wrapping_add(1),
    rand_type: 3,
    rand_deg: 31,
    rand_sep: 3,
    end_ptr: RANDTBL.as_ptr().cast::<i32>().wrapping_add(32),
});

/// Run `f` on the global `random` generator under the generator lock.
#[inline(always)]
fn with_random<R>(f: impl FnOnce(&mut RandomData) -> R) -> R {
    let _g = Guard::new();
    // SAFETY: RANDOM is only reached here, under the lock (or with one thread); `f` does not come back here.
    unsafe { RANDOM.with_unsync(f) }
}

/// The global generator as a [`Gen`].
///
/// # Safety
/// None beyond the C contract: the global state always follows Gen's rule (RANDTBL at first, then the arrays the callers of
/// initstate and setstate vouched for). Marked unsafe to keep that dependency on the callers visible.
#[inline(always)]
unsafe fn global_gen(b: &mut RandomData) -> Gen<'_> {
    // SAFETY: forwarded (see above).
    unsafe { Gen::new(b) }
}

/// # Safety
/// Always safe to call (unsafe only as a C function).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srandom(seed: c_uint) {
    // SAFETY: the global state follows Gen's rule (see global_gen); its type is always valid (set by initstate/setstate).
    with_random(|b| unsafe { global_gen(b) }.seed(seed));
}

/// # Safety
/// Always safe to call (unsafe only as a C function).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srand(seed: c_uint) {
    // SAFETY: no precondition.
    unsafe { srandom(seed) }
}

/// # Safety
/// Always safe to call (unsafe only as a C function).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn random() -> c_long {
    // SAFETY: the global state follows Gen's rule (see global_gen).
    with_random(|b| unsafe { global_gen(b) }.step()) as c_long
}

/// # Safety
/// Always safe to call (unsafe only as a C function).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rand() -> c_int {
    // SAFETY: no precondition.
    unsafe { random() as c_int }
}

/// # Safety
/// `arg_state` must point to `n` bytes that stay valid while the generator uses them.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn initstate(seed: c_uint, arg_state: *mut c_char, n: usize) -> *mut c_char {
    with_random(|b| {
        let ostate = b.state.wrapping_byte_sub(4);
        // SAFETY: `b` is a valid random_data; the caller vouches for `arg_state`.
        let ret = unsafe { initstate_r(seed, arg_state, n, b) };
        if ret == -1 { core::ptr::null_mut() } else { ostate.cast() }
    })
}

/// # Safety
/// `arg_state` must be a state array made by `initstate`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setstate(arg_state: *mut c_char) -> *mut c_char {
    with_random(|b| {
        let ostate = b.state.wrapping_byte_sub(4);
        // SAFETY: `b` is a valid random_data; the caller vouches for `arg_state`.
        if unsafe { setstate_r(arg_state, b) } < 0 { core::ptr::null_mut() } else { ostate.cast() }
    })
}

// ---- drand48 family ----

/// glibc's `struct drand48_data` (24 bytes).
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

/// The multiplier, addend and "initialised" flag of a `drand48_data`, borrowed apart from its `x` so that a step can work on
/// the struct's own `x` in place (copying it out and back would put a wide load right after three narrow stores: a
/// store-forwarding stall, 1.6x the time of lrand48_r).
struct Lcg<'a> {
    a: &'a mut u64,
    c: &'a mut c_ushort,
    init: &'a mut c_ushort,
}

/// `buf` split into its own `x` and the rest.
#[inline(always)]
fn split(buf: &mut Drand48Data) -> (&mut [c_ushort; 3], Lcg<'_>) {
    let Drand48Data { x, a, c, init, .. } = buf;
    (x, Lcg { a, c, init })
}

/// One step of x = a * x + c (mod 2^48) on `x`, setting up the default constants first if the data was never
/// initialised.
#[inline(always)]
fn iterate(x: &mut [c_ushort; 3], l: Lcg<'_>) {
    if *l.init == 0 {
        *l.a = A48;
        *l.c = C48;
        *l.init = 1;
    }
    // three separate 16-bit loads (volatile: the compiler would merge them into a wider load that cannot be forwarded from
    // the three 16-bit stores of the previous call, a stall of about ten cycles; core::hint::black_box keeps them apart too
    // but costs more than it saves: 1.6x the time of erand48)
    // SAFETY: a read through a valid reference.
    let x2 = unsafe { core::ptr::read_volatile(&x[2]) };
    // SAFETY: as above.
    let x1 = unsafe { core::ptr::read_volatile(&x[1]) };
    // SAFETY: as above.
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
    // 48 random bits in the top of the 52-bit fraction of a number in [1, 2), minus 1.
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
    // (int32_t) ((xsubi[2] << 16) | xsubi[1]), sign-extended to long.
    (((u32::from(x[2]) << 16) | u32::from(x[1])) as i32) as c_long
}

/// `erand48_r` on references: a double in [0, 1).
#[inline]
pub fn erand48_core(x: &mut [c_ushort; 3], buf: &mut Drand48Data) -> f64 {
    erand48_step(x, split(buf).1)
}

/// `nrand48_r` on references: a non-negative long below 2^31.
#[inline]
pub fn nrand48_core(x: &mut [c_ushort; 3], buf: &mut Drand48Data) -> c_long {
    nrand48_step(x, split(buf).1)
}

/// `jrand48_r` on references: a long in [-2^31, 2^31).
#[inline]
pub fn jrand48_core(x: &mut [c_ushort; 3], buf: &mut Drand48Data) -> c_long {
    jrand48_step(x, split(buf).1)
}

/// Run one of the steps on `buf`'s own `x`, in place.
#[inline(always)]
fn on_own_x<R>(buf: &mut Drand48Data, step: fn(&mut [c_ushort; 3], Lcg<'_>) -> R) -> R {
    let (x, l) = split(buf);
    step(x, l)
}

/// `srand48_r` on a reference.
pub fn srand48_core(seedval: c_long, buf: &mut Drand48Data) {
    let s = (seedval as u64) & 0xffff_ffff;
    buf.x[2] = (s >> 16) as u16;
    buf.x[1] = (s & 0xffff) as u16;
    buf.x[0] = 0x330e;
    buf.a = A48;
    buf.c = C48;
    buf.init = 1;
}

/// `seed48_r` on references.
pub fn seed48_core(seed16v: &[c_ushort; 3], buf: &mut Drand48Data) {
    buf.old_x = buf.x;
    buf.x[2] = seed16v[2];
    buf.x[1] = seed16v[1];
    buf.x[0] = seed16v[0];
    buf.a = A48;
    buf.c = C48;
    buf.init = 1;
}

/// `lcong48_r` on references.
pub fn lcong48_core(param: &[c_ushort; 7], buf: &mut Drand48Data) {
    buf.x.copy_from_slice(&param[..3]);
    buf.a = (u64::from(param[5]) << 32) | (u64::from(param[4]) << 16) | u64::from(param[3]);
    buf.c = param[6];
    buf.init = 1;
}

/// The three shorts at a C `xsubi`/`seed16v` pointer, copied in (they may lie inside a `drand48_data` the call also uses).
///
/// # Safety
/// `p` points to 3 readable shorts.
#[inline(always)]
unsafe fn get3(p: *const c_ushort) -> [c_ushort; 3] {
    // SAFETY: forwarded contract (an unsigned short[3] is 2-aligned).
    unsafe { p.cast::<[c_ushort; 3]>().read() }
}

/// Copy the three shorts back out.
///
/// # Safety
/// `p` points to 3 writable shorts.
#[inline(always)]
unsafe fn put3(p: *mut c_ushort, v: [c_ushort; 3]) {
    // SAFETY: forwarded contract.
    unsafe { p.cast::<[c_ushort; 3]>().write(v) }
}

/// Write a result through a C out-pointer (no NULL check, as glibc).
///
/// # Safety
/// `p` is valid for a write.
#[inline(always)]
unsafe fn put<T>(p: *mut T, v: T) {
    // SAFETY: forwarded contract.
    unsafe { p.write(v) }
}

/// The caller's `drand48_data` (no NULL check, as glibc: NULL faults).
///
/// # Safety
/// `buf` points to a valid `drand48_data` not otherwise used during the call.
#[inline(always)]
unsafe fn data<'a>(buf: *mut Drand48Data) -> &'a mut Drand48Data {
    // SAFETY: forwarded contract.
    unsafe { &mut *buf }
}

/// # Safety
/// `xsubi` and `buf` must be valid; `result` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn erand48_r(xsubi: *mut c_ushort, buf: *mut Drand48Data, result: *mut f64) -> c_int {
    // SAFETY: `xsubi` points to 3 shorts (the caller's contract).
    let mut x = unsafe { get3(xsubi) };
    // SAFETY: a valid drand48_data (the caller's contract); `x` is a copy, so `xsubi` may lie inside it.
    let v = erand48_core(&mut x, unsafe { data(buf) });
    // SAFETY: as above; the borrow of `buf` has ended.
    unsafe { put3(xsubi, x) };
    // SAFETY: `result` is writable (the caller's contract).
    unsafe { put(result, v) };
    0
}

/// # Safety
/// `buf` and `result` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn drand48_r(buf: *mut Drand48Data, result: *mut f64) -> c_int {
    // SAFETY: a valid drand48_data (the caller's contract).
    let v = on_own_x(unsafe { data(buf) }, erand48_step);
    // SAFETY: `result` is writable (the caller's contract).
    unsafe { put(result, v) };
    0
}

/// # Safety
/// `xsubi`, `buf` and `result` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nrand48_r(xsubi: *mut c_ushort, buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    // SAFETY: `xsubi` points to 3 shorts (the caller's contract).
    let mut x = unsafe { get3(xsubi) };
    // SAFETY: a valid drand48_data (the caller's contract); `x` is a copy.
    let v = nrand48_core(&mut x, unsafe { data(buf) });
    // SAFETY: as above; the borrow of `buf` has ended.
    unsafe { put3(xsubi, x) };
    // SAFETY: `result` is writable (the caller's contract).
    unsafe { put(result, v) };
    0
}

/// # Safety
/// `buf` (or null: returns -1) and `result` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lrand48_r(buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    // SAFETY: NULL or a valid drand48_data (the caller's contract).
    let Some(b) = (unsafe { buf.as_mut() }) else { return -1 };
    let v = on_own_x(b, nrand48_step);
    // SAFETY: `result` is writable (the caller's contract).
    unsafe { put(result, v) };
    0
}

/// # Safety
/// `xsubi`, `buf` and `result` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn jrand48_r(xsubi: *mut c_ushort, buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    // SAFETY: `xsubi` points to 3 shorts (the caller's contract).
    let mut x = unsafe { get3(xsubi) };
    // SAFETY: a valid drand48_data (the caller's contract); `x` is a copy.
    let v = jrand48_core(&mut x, unsafe { data(buf) });
    // SAFETY: as above; the borrow of `buf` has ended.
    unsafe { put3(xsubi, x) };
    // SAFETY: `result` is writable (the caller's contract).
    unsafe { put(result, v) };
    0
}

/// # Safety
/// `buf` (or null: returns -1) and `result` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mrand48_r(buf: *mut Drand48Data, result: *mut c_long) -> c_int {
    // SAFETY: NULL or a valid drand48_data (the caller's contract).
    let Some(b) = (unsafe { buf.as_mut() }) else { return -1 };
    let v = on_own_x(b, jrand48_step);
    // SAFETY: `result` is writable (the caller's contract).
    unsafe { put(result, v) };
    0
}

/// # Safety
/// `buf` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srand48_r(seedval: c_long, buf: *mut Drand48Data) -> c_int {
    // SAFETY: a valid drand48_data (the caller's contract).
    srand48_core(seedval, unsafe { data(buf) });
    0
}

/// # Safety
/// `seed16v` must point to 3 shorts; `buf` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn seed48_r(seed16v: *mut c_ushort, buf: *mut Drand48Data) -> c_int {
    // SAFETY: `seed16v` points to 3 shorts (the caller's contract); copied, so it may lie inside `buf`.
    let s = unsafe { get3(seed16v) };
    // SAFETY: a valid drand48_data (the caller's contract).
    seed48_core(&s, unsafe { data(buf) });
    0
}

/// # Safety
/// `param` must point to 7 shorts; `buf` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lcong48_r(param: *mut c_ushort, buf: *mut Drand48Data) -> c_int {
    // SAFETY: `param` points to 7 shorts (the caller's contract); copied, so it may overlap `buf`.
    let p = unsafe { param.cast::<[c_ushort; 7]>().read() };
    // SAFETY: a valid drand48_data (the caller's contract).
    lcong48_core(&p, unsafe { data(buf) });
    0
}

/// The global state of the non-`_r` functions. Starts all zero (not initialised), like glibc's, so the
/// first `drand48()` without `srand48()` starts from x = 0. Used only under the generator lock ([`with_drand`]).
static DRAND48: SyncCell<Drand48Data> = SyncCell::new(Drand48Data { x: [0; 3], old_x: [0; 3], c: 0, init: 0, a: 0 });

/// Run `f` on the global 48-bit state under the generator lock.
#[inline(always)]
fn with_drand<R>(f: impl FnOnce(&mut Drand48Data) -> R) -> R {
    let _g = Guard::new();
    // SAFETY: DRAND48 is only reached here, under the lock (or with one thread); `f` does not come back here. The pointer
    // seed48 returns into it is the C caller's to use as glibc allows (it is copied in and out, never borrowed, below).
    unsafe { DRAND48.with_unsync(f) }
}

/// Run a core on a C `xsubi` with the global state.
///
/// # Safety
/// `xsubi` points to 3 readable and writable shorts.
#[inline(always)]
unsafe fn with_xsubi<R>(xsubi: *mut c_ushort, core: fn(&mut [c_ushort; 3], &mut Drand48Data) -> R) -> R {
    // SAFETY: forwarded contract; copied, so it may be the pointer seed48 returned into the global state.
    let mut x = unsafe { get3(xsubi) };
    let r = with_drand(|d| core(&mut x, d));
    // SAFETY: forwarded contract.
    unsafe { put3(xsubi, x) };
    r
}

/// # Safety
/// Always safe to call (unsafe only as a C function).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn drand48() -> f64 {
    with_drand(|d| on_own_x(d, erand48_step))
}

/// # Safety
/// `xsubi` must point to 3 shorts.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn erand48(xsubi: *mut c_ushort) -> f64 {
    // SAFETY: the caller's contract.
    unsafe { with_xsubi(xsubi, erand48_core) }
}

/// # Safety
/// Always safe to call (unsafe only as a C function).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lrand48() -> c_long {
    with_drand(|d| on_own_x(d, nrand48_step))
}

/// # Safety
/// `xsubi` must point to 3 shorts.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nrand48(xsubi: *mut c_ushort) -> c_long {
    // SAFETY: the caller's contract.
    unsafe { with_xsubi(xsubi, nrand48_core) }
}

/// # Safety
/// Always safe to call (unsafe only as a C function).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mrand48() -> c_long {
    with_drand(|d| on_own_x(d, jrand48_step))
}

/// # Safety
/// `xsubi` must point to 3 shorts.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn jrand48(xsubi: *mut c_ushort) -> c_long {
    // SAFETY: the caller's contract.
    unsafe { with_xsubi(xsubi, jrand48_core) }
}

/// # Safety
/// Always safe to call (unsafe only as a C function).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn srand48(seedval: c_long) {
    with_drand(|d| srand48_core(seedval, d));
}

/// Returns a pointer to the previous state (valid until the next `seed48` call).
///
/// # Safety
/// `seed16v` must point to 3 shorts.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn seed48(seed16v: *mut c_ushort) -> *mut c_ushort {
    // SAFETY: `seed16v` points to 3 shorts (the caller's contract); copied in first.
    let s = unsafe { get3(seed16v) };
    with_drand(|d| seed48_core(&s, d));
    // old_x is the second field (offset 6) of the global state; only its address is made here
    DRAND48.as_ptr().cast::<c_ushort>().wrapping_add(3)
}

/// # Safety
/// `param` must point to 7 shorts.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lcong48(param: *mut c_ushort) {
    // SAFETY: `param` points to 7 shorts (the caller's contract); copied in first.
    let p = unsafe { param.cast::<[c_ushort; 7]>().read() };
    with_drand(|d| lcong48_core(&p, d));
}

// ---- arc4random ----

#[cold]
fn getrandom_failure() -> ! {
    let _ = rusty_libc_core::unistd::write(2, b"Fatal glibc error: cannot get entropy for arc4random\n");
    rusty_libc_core::process::abort()
}

/// Fill `buf` from /dev/urandom (the fallback when getrandom is missing); aborts when that fails.
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

/// Fill `buf` with random bytes (getrandom, or /dev/urandom when the kernel lacks it). Aborts if the system cannot supply
/// entropy. (Difference from glibc: the fallback reads /dev/urandom without first waiting on /dev/random.)
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

/// Fill `n` bytes at `p` with random bytes. Aborts if the system cannot supply entropy.
///
/// # Safety
/// `p` must be valid for `n` bytes of writes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random_buf(p: *mut c_void, n: usize) {
    // SAFETY: `p` holds `n` writable bytes (the caller's contract); with n == 0 any pointer will do.
    fill_random(unsafe { rusty_libc_core::ffi::bytes_mut(p.cast(), n) });
}

/// A random 32-bit number.
#[inline]
pub fn arc4random_u32() -> u32 {
    let mut b = [0u8; 4];
    fill_random(&mut b);
    u32::from_ne_bytes(b)
}

/// # Safety
/// Always safe to call (unsafe only as a C function).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random() -> u32 {
    arc4random_u32()
}

/// A uniform number below `n` (0 for n <= 1), using glibc's mask-and-reject method that also reuses
/// the unused high bits of a rejected value.
///
/// # Safety
/// Always safe to call (unsafe only as a C function).
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

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, clippy::deref_addrof)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The global generators exist once in this process and once in the host glibc.
    static LOCK: Mutex<()> = Mutex::new(());

    mod host {
        use super::super::{Drand48Data, RandomData};
        use core::ffi::{c_char, c_int, c_long, c_uint, c_ushort};
        unsafe extern "C" {
            pub fn rand() -> c_int;
            pub fn srand(s: c_uint);
            pub fn rand_r(s: *mut c_uint) -> c_int;
            pub fn random() -> c_long;
            pub fn srandom(s: c_uint);
            pub fn initstate(s: c_uint, st: *mut c_char, n: usize) -> *mut c_char;
            pub fn setstate(st: *mut c_char) -> *mut c_char;
            pub fn random_r(b: *mut RandomData, r: *mut i32) -> c_int;
            pub fn srandom_r(s: c_uint, b: *mut RandomData) -> c_int;
            pub fn initstate_r(s: c_uint, st: *mut c_char, n: usize, b: *mut RandomData) -> c_int;
            pub fn setstate_r(st: *mut c_char, b: *mut RandomData) -> c_int;
            pub fn drand48() -> f64;
            pub fn erand48(x: *mut c_ushort) -> f64;
            pub fn lrand48() -> c_long;
            pub fn nrand48(x: *mut c_ushort) -> c_long;
            pub fn mrand48() -> c_long;
            pub fn jrand48(x: *mut c_ushort) -> c_long;
            pub fn srand48(s: c_long);
            pub fn seed48(x: *mut c_ushort) -> *mut c_ushort;
            pub fn lcong48(p: *mut c_ushort);
            pub fn drand48_r(b: *mut Drand48Data, r: *mut f64) -> c_int;
            pub fn erand48_r(x: *mut c_ushort, b: *mut Drand48Data, r: *mut f64) -> c_int;
            pub fn lrand48_r(b: *mut Drand48Data, r: *mut c_long) -> c_int;
            pub fn nrand48_r(x: *mut c_ushort, b: *mut Drand48Data, r: *mut c_long) -> c_int;
            pub fn mrand48_r(b: *mut Drand48Data, r: *mut c_long) -> c_int;
            pub fn jrand48_r(x: *mut c_ushort, b: *mut Drand48Data, r: *mut c_long) -> c_int;
            pub fn srand48_r(s: c_long, b: *mut Drand48Data) -> c_int;
            pub fn seed48_r(x: *mut c_ushort, b: *mut Drand48Data) -> c_int;
            pub fn lcong48_r(p: *mut c_ushort, b: *mut Drand48Data) -> c_int;
        }
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    const SEEDS: [c_uint; 8] = [0, 1, 2, 42, 12345, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff];

    fn zero_data() -> RandomData {
        RandomData {
            fptr: core::ptr::null_mut(),
            rptr: core::ptr::null_mut(),
            state: core::ptr::null_mut(),
            rand_type: 0,
            rand_deg: 0,
            rand_sep: 0,
            end_ptr: core::ptr::null_mut(),
        }
    }

    #[test]
    fn rand_srand_default_sequence() {
        let _g = LOCK.lock().unwrap();
        // Before any srand: the default table.
        for _ in 0..1000 {
            assert_eq!(unsafe { rand() }, unsafe { host::rand() });
        }
        let mut rng = Rng(7);
        let mut seeds = SEEDS.to_vec();
        seeds.extend((0..50).map(|_| rng.next() as c_uint));
        for s in seeds {
            unsafe {
                srand(s);
                host::srand(s);
                for _ in 0..500 {
                    assert_eq!(rand(), host::rand(), "seed {s}");
                }
                srandom(s);
                host::srandom(s);
                for _ in 0..500 {
                    assert_eq!(random(), host::random());
                }
            }
        }
        unsafe {
            srand(1);
            host::srand(1);
            assert_eq!(rand(), host::rand());
        }
    }

    #[test]
    fn default_table_is_what_initstate_one_gives() {
        let _g = LOCK.lock().unwrap();
        let mut tbl = [0i32; 32];
        let mut b = zero_data();
        unsafe {
            assert_eq!(initstate_r(1, tbl.as_mut_ptr().cast(), 128, &mut b), 0);
            assert_eq!(tbl, RANDTBL_INIT);
        }
    }

    #[test]
    fn initstate_all_sizes_global_and_reentrant() {
        let _g = LOCK.lock().unwrap();
        let mut rng = Rng(11);
        for &n in &[0usize, 7, 8, 9, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000] {
            for seed in [0u32, 1, 5, 99999, 0xdeadbeef] {
                // global functions, with misaligned state arrays too
                for off in [0usize, 1, 4] {
                    let mut a = vec![0xa5u8; 2048];
                    let mut b = vec![0xa5u8; 2048];
                    unsafe {
                        let ra = initstate(seed, a.as_mut_ptr().add(off + 8).cast(), n);
                        let rb = host::initstate(seed, b.as_mut_ptr().add(off + 8).cast(), n);
                        assert_eq!(ra.is_null(), rb.is_null(), "n {n}");
                        if ra.is_null() {
                            continue;
                        }
                        for _ in 0..300 {
                            assert_eq!(random(), host::random(), "n {n} seed {seed} off {off}");
                        }
                        assert_eq!(a, b, "state bytes n {n} off {off}");
                        // switch back to the old state and compare again
                        let sa = setstate(ra);
                        let sb = host::setstate(rb);
                        assert_eq!(sa.is_null(), sb.is_null());
                        for _ in 0..50 {
                            assert_eq!(random(), host::random());
                        }
                        // and back to ours
                        let sa = setstate(sa);
                        let sb = host::setstate(sb);
                        assert_eq!(sa.is_null(), sb.is_null());
                        assert_eq!(a, b);
                        for _ in 0..50 {
                            assert_eq!(random(), host::random());
                        }
                        // restore the default generators for the next round
                        setstate(ra);
                        host::setstate(rb);
                    }
                }
                // reentrant, via random_data structs
                let mut a = vec![0x5au8; 1024];
                let mut b = vec![0x5au8; 1024];
                let (mut da, mut db) = (zero_data(), zero_data());
                unsafe {
                    let ra = initstate_r(seed, a.as_mut_ptr().cast(), n, &mut da);
                    let rb = host::initstate_r(seed, b.as_mut_ptr().cast(), n, &mut db);
                    assert_eq!(ra, rb);
                    if ra != 0 {
                        continue;
                    }
                    assert_eq!(da.rand_type, db.rand_type);
                    for _ in 0..(rng.next() % 400) {
                        let (mut x, mut y) = (0i32, 0i32);
                        assert_eq!(random_r(&mut da, &mut x), host::random_r(&mut db, &mut y));
                        assert_eq!(x, y);
                    }
                    assert_eq!(a, b);
                    assert_eq!(srandom_r(seed ^ 7, &mut da), host::srandom_r(seed ^ 7, &mut db));
                    for _ in 0..100 {
                        let (mut x, mut y) = (0i32, 0i32);
                        random_r(&mut da, &mut x);
                        host::random_r(&mut db, &mut y);
                        assert_eq!(x, y);
                    }
                    assert_eq!(a, b);
                }
            }
        }
    }

    #[test]
    fn setstate_errors_match() {
        let _g = LOCK.lock().unwrap();
        for word in [5i32, 9, 100, -1, -7, 3 + 5 * 10, 1 + 5 * 3, 4 + 5 * 62] {
            let mut a = [0i32; 80];
            let mut b = [0i32; 80];
            a[1] = word;
            b[1] = word;
            let mut ta = vec![0u8; 512];
            let mut tb = vec![0u8; 512];
            let (mut da, mut db) = (zero_data(), zero_data());
            unsafe {
                initstate_r(3, ta.as_mut_ptr().cast(), 128, &mut da);
                host::initstate_r(3, tb.as_mut_ptr().cast(), 128, &mut db);
                // the word sits just before the state pointer (arg_state + 4 bytes) - 4 = arg_state
                let ra = setstate_r(a.as_mut_ptr().add(1).cast::<c_char>(), &mut da);
                let rb = host::setstate_r(b.as_mut_ptr().add(1).cast::<c_char>(), &mut db);
                assert_eq!(ra, rb, "word {word}");
                if ra == 0 {
                    assert_eq!((da.rand_type, da.rand_deg, da.rand_sep), (db.rand_type, db.rand_deg, db.rand_sep));
                    let (mut x, mut y) = (0, 0);
                    random_r(&mut da, &mut x);
                    host::random_r(&mut db, &mut y);
                    assert_eq!(x, y);
                }
            }
        }
    }

    #[test]
    fn rand_r_matches() {
        let mut rng = Rng(3);
        for _ in 0..200 {
            let s = rng.next() as c_uint;
            let (mut a, mut b) = (s, s);
            for _ in 0..200 {
                unsafe { assert_eq!(rand_r(&mut a), host::rand_r(&mut b)) };
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn layouts() {
        assert_eq!(core::mem::size_of::<Drand48Data>(), 24);
        assert_eq!(core::mem::offset_of!(Drand48Data, a), 16);
        assert_eq!(core::mem::size_of::<RandomData>(), 48);
        assert_eq!(core::mem::offset_of!(RandomData, rand_type), 24);
        assert_eq!(core::mem::offset_of!(RandomData, end_ptr), 40);
    }

    #[test]
    fn drand48_family_global() {
        let _g = LOCK.lock().unwrap();
        // Unseeded start (x = 0, constants not yet set). Only this test touches the global 48-bit state,
        // so it is still pristine here.
        unsafe {
            for _ in 0..10 {
                assert_eq!(drand48().to_bits(), host::drand48().to_bits());
            }
        }
        let mut rng = Rng(21);
        for round in 0..60 {
            let seed = if round < 4 { [0, 1, -1, 0x7fff_ffff][round as usize] } else { rng.next() as c_long };
            unsafe {
                srand48(seed);
                host::srand48(seed);
                for _ in 0..100 {
                    assert_eq!(drand48().to_bits(), host::drand48().to_bits());
                    assert_eq!(lrand48(), host::lrand48());
                    assert_eq!(mrand48(), host::mrand48());
                }
                let mut xa = [rng.next() as u16, rng.next() as u16, rng.next() as u16];
                let mut xb = xa;
                for _ in 0..100 {
                    assert_eq!(erand48(xa.as_mut_ptr()).to_bits(), host::erand48(xb.as_mut_ptr()).to_bits());
                    assert_eq!(nrand48(xa.as_mut_ptr()), host::nrand48(xb.as_mut_ptr()));
                    assert_eq!(jrand48(xa.as_mut_ptr()), host::jrand48(xb.as_mut_ptr()));
                    assert_eq!(xa, xb);
                }
                // seed48 returns the old state
                let mut s = [rng.next() as u16, rng.next() as u16, rng.next() as u16];
                let oa = seed48(s.as_mut_ptr());
                let ob = host::seed48(s.as_mut_ptr());
                assert_eq!(core::slice::from_raw_parts(oa, 3), core::slice::from_raw_parts(ob, 3));
                for _ in 0..20 {
                    assert_eq!(lrand48(), host::lrand48());
                }
                // lcong48 with random multiplier and addend
                let mut p: [u16; 7] = core::array::from_fn(|_| rng.next() as u16);
                lcong48(p.as_mut_ptr());
                host::lcong48(p.as_mut_ptr());
                for _ in 0..50 {
                    assert_eq!(drand48().to_bits(), host::drand48().to_bits());
                    assert_eq!(mrand48(), host::mrand48());
                }
            }
        }
    }

    #[test]
    fn drand48_family_reentrant() {
        let mut rng = Rng(77);
        let z = Drand48Data { x: [0; 3], old_x: [0; 3], c: 0, init: 0, a: 0 };
        for _ in 0..40 {
            let (mut a, mut b) = (z, z);
            unsafe {
                // uninitialised buffer first (default constants), then each seeding function
                let mut x = [0.0f64; 2];
                assert_eq!(drand48_r(&mut a, &mut x[0]), host::drand48_r(&mut b, &mut x[1]));
                assert_eq!(x[0].to_bits(), x[1].to_bits());
                let seed = rng.next() as c_long;
                assert_eq!(srand48_r(seed, &mut a), host::srand48_r(seed, &mut b));
                for i in 0..50 {
                    let mut x = [0.0f64; 2];
                    let (mut l, mut m) = (0 as c_long, 0 as c_long);
                    match i % 4 {
                        0 => {
                            assert_eq!(drand48_r(&mut a, &mut x[0]), host::drand48_r(&mut b, &mut x[1]));
                            assert_eq!(x[0].to_bits(), x[1].to_bits());
                        }
                        1 => {
                            assert_eq!(lrand48_r(&mut a, &mut l), host::lrand48_r(&mut b, &mut m));
                            assert_eq!(l, m);
                        }
                        2 => {
                            assert_eq!(mrand48_r(&mut a, &mut l), host::mrand48_r(&mut b, &mut m));
                            assert_eq!(l, m);
                        }
                        _ => {
                            let mut xs = [rng.next() as u16, rng.next() as u16, rng.next() as u16];
                            let mut ys = xs;
                            assert_eq!(nrand48_r(xs.as_mut_ptr(), &mut a, &mut l), host::nrand48_r(ys.as_mut_ptr(), &mut b, &mut m));
                            assert_eq!(l, m);
                            assert_eq!(jrand48_r(xs.as_mut_ptr(), &mut a, &mut l), host::jrand48_r(ys.as_mut_ptr(), &mut b, &mut m));
                            assert_eq!(l, m);
                            assert_eq!(erand48_r(xs.as_mut_ptr(), &mut a, &mut x[0]), host::erand48_r(ys.as_mut_ptr(), &mut b, &mut x[1]));
                            assert_eq!(x[0].to_bits(), x[1].to_bits());
                            assert_eq!(xs, ys);
                        }
                    }
                }
                let mut s = [rng.next() as u16, rng.next() as u16, rng.next() as u16];
                assert_eq!(seed48_r(s.as_mut_ptr(), &mut a), host::seed48_r(s.as_mut_ptr(), &mut b));
                assert_eq!((a.x, a.old_x, a.c, a.init, a.a), (b.x, b.old_x, b.c, b.init, b.a));
                let mut p: [u16; 7] = core::array::from_fn(|_| rng.next() as u16);
                assert_eq!(lcong48_r(p.as_mut_ptr(), &mut a), host::lcong48_r(p.as_mut_ptr(), &mut b));
                assert_eq!((a.x, a.old_x, a.c, a.init, a.a), (b.x, b.old_x, b.c, b.init, b.a));
                let mut x = [0.0f64; 2];
                drand48_r(&mut a, &mut x[0]);
                host::drand48_r(&mut b, &mut x[1]);
                assert_eq!(x[0].to_bits(), x[1].to_bits());
            }
        }
        unsafe {
            let mut l = 0;
            assert_eq!(lrand48_r(core::ptr::null_mut(), &mut l), -1);
            assert_eq!(mrand48_r(core::ptr::null_mut(), &mut l), -1);
        }
    }

    #[test]
    fn arc4random_basics() {
        unsafe {
            let mut buf = vec![0u8; 100_000];
            arc4random_buf(buf.as_mut_ptr().cast(), buf.len());
            let mut seen = [false; 256];
            for &b in &buf {
                seen[b as usize] = true;
            }
            assert!(seen.iter().all(|&s| s));
            arc4random_buf(buf.as_mut_ptr().cast(), 0);
            let (a, b, c) = (arc4random(), arc4random(), arc4random());
            assert!(!(a == b && b == c));
            assert_eq!(arc4random_uniform(0), 0);
            assert_eq!(arc4random_uniform(1), 0);
            for n in [2u32, 3, 7, 10, 100, 1 << 16, 1_000_000_007, 0x8000_0001, u32::MAX] {
                let mut counts = [0u32; 10];
                for _ in 0..2000 {
                    let v = arc4random_uniform(n);
                    assert!(v < n);
                    counts[(v as u64 * 10 / n as u64) as usize] += 1;
                }
                if n >= 100 {
                    assert!(counts.iter().all(|&c| c > 100), "n {n}: {counts:?}");
                }
            }
        }
    }

    #[test]
    fn uniform_algorithm_is_glibcs() {
        // n = 10: z = 28, mask = 15, bits = 4.
        assert_eq!(uniform_with(10, || 0), 0);
        assert_eq!(uniform_with(10, || 0xffff_fff3), 3);
        // all nibbles 15: every nibble rejected, then a new value is drawn
        let mut calls = 0;
        let r = uniform_with(10, || {
            calls += 1;
            if calls == 1 { 0xffff_ffff } else { 0x4 }
        });
        assert_eq!((r, calls), (4, 2));
        // low nibble 0xa rejected, the next nibble (5) is used without a new draw
        let mut calls = 0;
        let r = uniform_with(10, || {
            calls += 1;
            0x5a
        });
        assert_eq!((r, calls), (5, 1));
        assert_eq!(uniform_with(16, || 0x12345), 5);
    }
}

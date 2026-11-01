//! fenv.h for x86-64: exception flags, rounding mode, trap masks and the whole floating-point
//! environment. Every change is made in both units, the x87 FPU (control and status word) and the
//! SSE unit (MXCSR), exactly the way glibc keeps them in step, because C code may compute with
//! either: `double` arithmetic uses SSE, `long double` uses x87, and `fetestexcept` reports the OR
//! of both.
//!
//! The C names (`feclearexcept`, ...) are plain `extern "C"` functions. The Rust-side API is the
//! `*_exceptions` / `round_mode` group at the bottom of the file.
//!
//! Constants for the header (glibc x86-64 values): FE_INVALID 0x01, FE_DIVBYZERO 0x04,
//! FE_OVERFLOW 0x08, FE_UNDERFLOW 0x10, FE_INEXACT 0x20, FE_ALL_EXCEPT 0x3d, FE_TONEAREST 0,
//! FE_DOWNWARD 0x400, FE_UPWARD 0x800, FE_TOWARDZERO 0xc00, `FE_DFL_ENV` = (const fenv_t *) -1,
//! `FE_NOMASK_ENV` = (const fenv_t *) -2, `FE_DFL_MODE` = (const femode_t *) -1, `fexcept_t` =
//! unsigned short. Rust holds these in the constants below.
//!
//! Exception state, rounding mode and trap masks live in CPU registers that belong to one thread,
//! so these functions never interfere across threads.
use core::arch::asm;
use core::ffi::c_int;

pub const FE_INVALID: c_int = 0x01;
/// x86-specific "denormal operand" flag (glibc keeps it out of FE_ALL_EXCEPT).
pub const FE_DENORM: c_int = 0x02;
pub const FE_DIVBYZERO: c_int = 0x04;
pub const FE_OVERFLOW: c_int = 0x08;
pub const FE_UNDERFLOW: c_int = 0x10;
pub const FE_INEXACT: c_int = 0x20;
pub const FE_ALL_EXCEPT: c_int = 0x3d;
const FE_ALL_EXCEPT_X86: u32 = 0x3f;

pub const FE_TONEAREST: c_int = 0;
pub const FE_DOWNWARD: c_int = 0x400;
pub const FE_UPWARD: c_int = 0x800;
pub const FE_TOWARDZERO: c_int = 0xc00;

/// x87 precision-control bits of the control word (extended precision = 0x300).
const FPU_EXTENDED: u16 = 0x300;

/// `fexcept_t`.
pub type FexceptT = u16;

/// `fenv_t`: the 28-byte block `fnstenv` writes, then MXCSR (32 bytes, glibc's layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FenvT {
    pub control_word: u16,
    pub reserved1: u16,
    pub status_word: u16,
    pub reserved2: u16,
    pub tags: u16,
    pub reserved3: u16,
    pub eip: u32,
    pub cs_selector: u16,
    /// `__opcode:11` and 5 reserved bits.
    pub opcode: u16,
    pub data_offset: u32,
    pub data_selector: u16,
    pub reserved5: u16,
    pub mxcsr: u32,
}

/// `femode_t`: x87 control word and MXCSR.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FemodeT {
    pub control_word: u16,
    pub reserved: u16,
    pub mxcsr: u32,
}

/// `FE_DFL_ENV`: the default environment (all exceptions masked, round to nearest).
pub const FE_DFL_ENV: *const FenvT = usize::MAX as *const FenvT;
/// `FE_NOMASK_ENV`: environment with every exception enabled (trapping).
pub const FE_NOMASK_ENV: *const FenvT = (usize::MAX - 1) as *const FenvT;
/// `FE_DFL_MODE`: the default control modes.
pub const FE_DFL_MODE: *const FemodeT = usize::MAX as *const FemodeT;

// ---------------------------------------------------------------------------------------------
// registers

#[inline]
pub(crate) fn mxcsr_get() -> u32 {
    let mut v: u32 = 0;
    // SAFETY: stmxcsr writes the 4-byte MXCSR to `v`, a live local u32; nothing else is touched.
    unsafe { asm!("stmxcsr [{0}]", in(reg) &mut v, options(nostack, preserves_flags)) };
    v
}

#[inline]
pub(crate) fn mxcsr_set(v: u32) {
    // SAFETY: ldmxcsr reads the 4 bytes of `v`, a live local. Every caller builds `v` from the current MXCSR or from a
    // saved one and changes only mode, mask and flag bits, so no reserved bit is set (that would fault).
    unsafe { asm!("ldmxcsr [{0}]", in(reg) &v, options(nostack, preserves_flags)) };
}

#[inline]
pub(crate) fn cw_get() -> u16 {
    let mut v: u16 = 0;
    // SAFETY: fnstcw writes the 2-byte x87 control word to `v`, a live local u16.
    unsafe { asm!("fnstcw [{0}]", in(reg) &mut v, options(nostack, preserves_flags)) };
    v
}

#[inline]
pub(crate) fn cw_set(v: u16) {
    // SAFETY: fldcw reads the 2 bytes of `v`, a live local; it changes only the x87 control modes.
    unsafe { asm!("fldcw [{0}]", in(reg) &v, options(nostack, preserves_flags)) };
}

#[inline]
fn sw_get() -> u16 {
    let v: u16;
    // SAFETY: fnstsw copies the x87 status word to ax (declared as the output); no memory is touched.
    unsafe { asm!("fnstsw ax", out("ax") v, options(nomem, nostack, preserves_flags)) };
    v
}

/// `fnstenv` (which also masks every x87 exception as a side effect).
#[inline]
fn env_store(env: &mut FenvT) {
    // SAFETY: fnstenv writes the 28-byte x87 environment to the start of `*env`, a `&mut FenvT` (32 bytes, glibc's layout
    // with those 28 bytes first).
    unsafe { asm!("fnstenv [{0}]", in(reg) env as *mut FenvT, options(nostack)) };
}

#[inline]
fn env_load(env: &FenvT) {
    // SAFETY: fldenv reads the first 28 bytes of `*env`, a `&FenvT` (the layout fnstenv writes).
    unsafe { asm!("fldenv [{0}]", in(reg) env as *const FenvT, options(nostack)) };
}

/// The x87 half of the environment without disturbing the exception mask.
#[inline]
fn env_get_x87(env: &mut FenvT) {
    env_store(env);
    env_load(env);
}

// ---------------------------------------------------------------------------------------------
// C functions

/// Clear the exception flags in `excepts` in both units.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn feclearexcept(excepts: c_int) -> c_int {
    let excepts = (excepts & FE_ALL_EXCEPT) as u32;
    let mut env = FenvT::default();
    env_store(&mut env);
    // glibc keeps only FE_ALL_EXCEPT bits that are not being cleared (`status &= excepts ^ 0x3d`),
    // so the x87 "denormal operand" flag (0x02, not an FE_* flag) goes with every call too
    env.status_word &= !((excepts | FE_DENORM as u32) as u16);
    env_load(&env);
    mxcsr_set(mxcsr_get() & !excepts);
    0
}

/// Raise the exceptions in `excepts`, one at a time, invalid and divide-by-zero by really
/// dividing, the others by setting the x87 status bit and executing `fwait` (so an enabled
/// exception traps exactly as in glibc).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn feraiseexcept(excepts: c_int) -> c_int {
    if excepts & FE_INVALID != 0 {
        div_ss(0.0, 0.0);
    }
    if excepts & FE_DIVBYZERO != 0 {
        div_ss(1.0, 0.0);
    }
    for bit in [FE_OVERFLOW, FE_UNDERFLOW, FE_INEXACT] {
        if excepts & bit != 0 {
            let mut env = FenvT::default();
            env_store(&mut env);
            env.status_word |= bit as u16;
            env_load(&env);
            // SAFETY: fwait only makes the x87 unit deliver the pending exception just set (a trap if it is enabled, as
            // glibc's feraiseexcept does); no memory or register is touched.
            unsafe { asm!("fwait", options(nomem, nostack)) };
        }
    }
    0
}

#[inline(never)]
fn div_ss(a: f32, b: f32) {
    let mut r = a;
    // SAFETY: divss on two xmm registers (declared operands); it only computes and sets MXCSR flags, the point here.
    unsafe { asm!("divss {0}, {1}", inout(xmm_reg) r, in(xmm_reg) b, options(nomem, nostack, preserves_flags)) };
    core::hint::black_box(r);
}

/// Which of `excepts` are raised in either unit.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fetestexcept(excepts: c_int) -> c_int {
    ((u32::from(sw_get()) | mxcsr_get()) & excepts as u32 & FE_ALL_EXCEPT as u32) as c_int
}

/// Store the flags selected by `excepts` in `*flagp`.
///
/// # Safety
/// `flagp` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fegetexceptflag(flagp: *mut FexceptT, excepts: c_int) -> c_int {
    let flag = fetestexcept(excepts) as FexceptT;
    // SAFETY: the C contract: `flagp` points to a writable fexcept_t (glibc does not check it either).
    unsafe { flagp.write(flag) };
    0
}

/// Set the flags selected by `excepts` from `*flagp` (cleared in both units, set in SSE only, so
/// that setting never traps).
///
/// # Safety
/// `flagp` must be valid for a read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fesetexceptflag(flagp: *const FexceptT, excepts: c_int) -> c_int {
    // SAFETY: the C contract: `flagp` points to a readable fexcept_t.
    let flag = unsafe { flagp.read() };
    set_exception_flags(flag, excepts)
}

/// Safe form of `fesetexceptflag`: set the flags selected by `excepts` from `flag`.
pub fn set_exception_flags(flag: FexceptT, excepts: c_int) -> c_int {
    let excepts = (excepts & FE_ALL_EXCEPT) as u32;
    let flag = u32::from(flag);
    let mut env = FenvT::default();
    env_store(&mut env);
    env.status_word &= !((excepts & !flag) as u16);
    env_load(&env);
    let mut m = mxcsr_get();
    m ^= (m ^ flag) & excepts;
    mxcsr_set(m);
    0
}

/// C23 `fetestexceptflag`: the flags of `excepts` that are set in `*flagp`.
///
/// # Safety
/// `flagp` must be valid for a read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fetestexceptflag(flagp: *const FexceptT, excepts: c_int) -> c_int {
    // SAFETY: the C contract: `flagp` points to a readable fexcept_t.
    let flag = unsafe { flagp.read() };
    (u32::from(flag) & excepts as u32 & FE_ALL_EXCEPT as u32) as c_int
}

/// C23 `fesetexcept`: set the flags without raising a trap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fesetexcept(excepts: c_int) -> c_int {
    mxcsr_set(mxcsr_get() | (excepts & FE_ALL_EXCEPT) as u32);
    0
}

/// Current rounding mode (the x87 control word's bits 10-11).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fegetround() -> c_int {
    (cw_get() & 0xc00) as c_int
}

/// Set the rounding mode in both units; nonzero for a value that is not one of the four.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fesetround(round: c_int) -> c_int {
    if round & !0xc00 != 0 {
        return 1;
    }
    cw_set((cw_get() & !0xc00) | round as u16);
    mxcsr_set((mxcsr_get() & !0x6000) | ((round as u32) << 3));
    0
}

/// Store the current environment (x87 state and MXCSR) in `*envp`.
///
/// # Safety
/// `envp` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fegetenv(envp: *mut FenvT) -> c_int {
    let mut env = FenvT::default();
    get_env(&mut env);
    // SAFETY: the C contract: `envp` points to a writable fenv_t (the caller's block may be uninitialised, so it is
    // written whole rather than borrowed).
    unsafe { envp.write(env) };
    0
}

/// Safe form of `fegetenv`: the current environment (x87 state and MXCSR) into `env`.
pub fn get_env(env: &mut FenvT) {
    env_get_x87(env);
    env.mxcsr = mxcsr_get();
}

/// Which environment `fesetenv` and `feupdateenv` install.
#[derive(Clone, Copy, Debug)]
pub enum EnvSrc<'a> {
    /// `FE_DFL_ENV`.
    Default,
    /// `FE_NOMASK_ENV`.
    NoMask,
    /// A block saved by `fegetenv` / `feholdexcept`.
    Saved(&'a FenvT),
}

impl<'a> EnvSrc<'a> {
    /// The C argument: the two special pointer values, else a pointer to a saved block.
    ///
    /// # Safety
    /// `envp` is `FE_DFL_ENV`, `FE_NOMASK_ENV` or points to a readable `fenv_t` that lives for `'a`.
    #[inline]
    pub unsafe fn from_c(envp: *const FenvT) -> EnvSrc<'a> {
        if envp == FE_DFL_ENV {
            EnvSrc::Default
        } else if envp == FE_NOMASK_ENV {
            EnvSrc::NoMask
        } else {
            // SAFETY: neither special value, so by the contract above a readable fenv_t that lives for 'a.
            EnvSrc::Saved(unsafe { &*envp })
        }
    }
}

/// Install `*envp`, or the default (`FE_DFL_ENV`) or all-trapping (`FE_NOMASK_ENV`) environment.
/// Fields glibc does not take from the saved block (reserved bits, tag word) stay as they are.
///
/// # Safety
/// `envp` must be `FE_DFL_ENV`, `FE_NOMASK_ENV` or point to a readable `fenv_t`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fesetenv(envp: *const FenvT) -> c_int {
    // SAFETY: the C contract (above) is `EnvSrc::from_c`'s.
    set_env(unsafe { EnvSrc::from_c(envp) });
    0
}

/// Safe form of `fesetenv`.
pub fn set_env(src: EnvSrc<'_>) {
    let mut t = FenvT::default();
    env_store(&mut t);
    t.mxcsr = mxcsr_get();
    let x87_all = FE_ALL_EXCEPT_X86 as u16;
    if let EnvSrc::Default = src {
        t.control_word |= x87_all;
        t.control_word &= !(FE_TOWARDZERO as u16);
        t.control_word |= FPU_EXTENDED;
        t.status_word &= !x87_all;
        t.eip = 0;
        t.cs_selector = 0;
        t.opcode = 0;
        t.data_offset = 0;
        t.data_selector = 0;
        t.mxcsr &= !FE_ALL_EXCEPT_X86;
        t.mxcsr |= FE_ALL_EXCEPT_X86 << 7;
        t.mxcsr &= !0x6000;
        t.mxcsr &= !0x8040;
    } else if let EnvSrc::NoMask = src {
        t.control_word &= !((FE_ALL_EXCEPT | FE_TOWARDZERO) as u16);
        t.control_word |= FE_DENORM as u16;
        t.control_word |= FPU_EXTENDED;
        t.status_word &= !x87_all;
        t.eip = 0;
        t.cs_selector = 0;
        t.opcode = 0;
        t.data_offset = 0;
        t.data_selector = 0;
        t.mxcsr &= !FE_ALL_EXCEPT_X86;
        t.mxcsr &= !0x6000;
        t.mxcsr &= !((FE_ALL_EXCEPT as u32) << 7);
        t.mxcsr |= (FE_DENORM as u32) << 7;
        t.mxcsr &= !0x8040;
    } else if let EnvSrc::Saved(e) = src {
        let keep = x87_all | FE_TOWARDZERO as u16 | FPU_EXTENDED;
        t.control_word = (t.control_word & !keep) | (e.control_word & keep);
        t.status_word = (t.status_word & !x87_all) | (e.status_word & x87_all);
        t.eip = e.eip;
        t.cs_selector = e.cs_selector;
        t.opcode = e.opcode;
        t.data_offset = e.data_offset;
        t.data_selector = e.data_selector;
        t.mxcsr = e.mxcsr;
    }
    env_load(&t);
    mxcsr_set(t.mxcsr);
}

/// Save the environment in `*envp`, clear all flags and mask every exception (non-stop mode).
///
/// # Safety
/// `envp` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn feholdexcept(envp: *mut FenvT) -> c_int {
    let mut env = FenvT::default();
    hold_into(&mut env);
    // SAFETY: the C contract: `envp` points to a writable fenv_t (written whole: the block may be uninitialised).
    unsafe { envp.write(env) };
    0
}

/// Safe form of `feholdexcept`: save the environment in `env`, clear all flags, mask every exception.
pub fn hold_into(env: &mut FenvT) {
    env_store(env); // fnstenv masks all x87 exceptions
    env.mxcsr = mxcsr_get();
    // SAFETY: fnclex clears the x87 exception flags; no memory or general register is touched.
    unsafe { asm!("fnclex", options(nomem, nostack)) };
    mxcsr_set((env.mxcsr | 0x1f80) & !0x3f);
}

/// Install `*envp`, then raise the exceptions that were pending before.
///
/// # Safety
/// As [`fesetenv`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn feupdateenv(envp: *const FenvT) -> c_int {
    // SAFETY: the C contract (as fesetenv's) is `EnvSrc::from_c`'s.
    update_env_src(unsafe { EnvSrc::from_c(envp) });
    0
}

/// Safe form of `feupdateenv`.
pub fn update_env_src(src: EnvSrc<'_>) {
    let pending = fetestexcept(FE_ALL_EXCEPT);
    set_env(src);
    feraiseexcept(pending);
}

/// Enable traps for `excepts`; returns the previously enabled set (read from the x87 mask).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn feenableexcept(excepts: c_int) -> c_int {
    let excepts = (excepts & FE_ALL_EXCEPT) as u32;
    let cw = cw_get();
    let old = !u32::from(cw) & FE_ALL_EXCEPT as u32;
    cw_set(cw & !(excepts as u16));
    mxcsr_set(mxcsr_get() & !(excepts << 7));
    old as c_int
}

/// Disable traps for `excepts`; returns the previously enabled set.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fedisableexcept(excepts: c_int) -> c_int {
    let excepts = (excepts & FE_ALL_EXCEPT) as u32;
    let cw = cw_get();
    let old = !u32::from(cw) & FE_ALL_EXCEPT as u32;
    cw_set(cw | excepts as u16);
    mxcsr_set(mxcsr_get() | (excepts << 7));
    old as c_int
}

/// The set of exceptions that currently trap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fegetexcept() -> c_int {
    (!u32::from(cw_get()) & FE_ALL_EXCEPT as u32) as c_int
}

/// C23 `fegetmode`: store the control modes (x87 control word, MXCSR).
///
/// # Safety
/// `modep` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fegetmode(modep: *mut FemodeT) -> c_int {
    let m = get_mode();
    // The two mode fields only: the reserved bytes keep what the caller had there, as in glibc.
    // SAFETY: the C contract: `modep` points to a writable femode_t; `control_word` is its first field.
    unsafe { modep.cast::<u16>().write(m.control_word) };
    let mxcsr = modep.wrapping_byte_add(core::mem::offset_of!(FemodeT, mxcsr)).cast::<u32>();
    // SAFETY: as above; `mxcsr` points to the aligned u32 field at offset 4 of the same femode_t.
    unsafe { mxcsr.write(m.mxcsr) };
    0
}

/// Safe form of `fegetmode`: the control modes (x87 control word, MXCSR; `reserved` 0).
pub fn get_mode() -> FemodeT {
    FemodeT { control_word: cw_get(), reserved: 0, mxcsr: mxcsr_get() }
}

/// C23 `fesetmode`: install control modes, keeping the SSE exception flags.
///
/// # Safety
/// `modep` must be `FE_DFL_MODE` or point to a readable `femode_t`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fesetmode(modep: *const FemodeT) -> c_int {
    let m = if modep == FE_DFL_MODE {
        None
    } else {
        // SAFETY: not FE_DFL_MODE, so by the C contract a readable femode_t.
        Some(unsafe { &*modep })
    };
    set_mode(m);
    0
}

/// Safe form of `fesetmode`: install `m` (`None` = `FE_DFL_MODE`), keeping the SSE exception flags.
pub fn set_mode(m: Option<&FemodeT>) {
    let mut mxcsr = mxcsr_get() & FE_ALL_EXCEPT_X86;
    let cw;
    if let Some(m) = m {
        cw = m.control_word;
        mxcsr |= m.mxcsr & !FE_ALL_EXCEPT_X86;
    } else {
        cw = 0x37f;
        mxcsr |= FE_ALL_EXCEPT_X86 << 7;
    }
    cw_set(cw);
    mxcsr_set(mxcsr);
}

// ---------------------------------------------------------------------------------------------
// Rust API

/// The four IEEE rounding directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum RoundMode {
    Nearest = FE_TONEAREST,
    Downward = FE_DOWNWARD,
    Upward = FE_UPWARD,
    TowardZero = FE_TOWARDZERO,
}

impl RoundMode {
    /// From the C constant (`FE_TONEAREST`, ...); `None` for any other value.
    pub fn from_c(v: c_int) -> Option<RoundMode> {
        match v {
            FE_TONEAREST => Some(RoundMode::Nearest),
            FE_DOWNWARD => Some(RoundMode::Downward),
            FE_UPWARD => Some(RoundMode::Upward),
            FE_TOWARDZERO => Some(RoundMode::TowardZero),
            _ => None,
        }
    }
    pub fn to_c(self) -> c_int {
        self as c_int
    }
}

/// Current rounding mode.
pub fn round_mode() -> RoundMode {
    // the x87 control word only ever holds the four values in bits 10-11
    RoundMode::from_c(fegetround()).unwrap_or(RoundMode::Nearest)
}

/// Set the rounding mode (both units).
pub fn set_round_mode(mode: RoundMode) {
    fesetround(mode.to_c());
}

/// Rounding mode as the SSE unit sees it (what `double` arithmetic uses).
pub(crate) fn sse_round_mode() -> RoundMode {
    match (mxcsr_get() >> 13) & 3 {
        0 => RoundMode::Nearest,
        1 => RoundMode::Downward,
        2 => RoundMode::Upward,
        _ => RoundMode::TowardZero,
    }
}

/// Which of the exception bits in `mask` (FE_* values) are raised.
pub fn test_exceptions(mask: u32) -> u32 {
    fetestexcept(mask as c_int) as u32
}

/// Clear the exception flags in `mask`.
pub fn clear_exceptions(mask: u32) {
    feclearexcept(mask as c_int);
}

/// Raise the exceptions in `mask` (traps if enabled).
pub fn raise_exceptions(mask: u32) {
    feraiseexcept(mask as c_int);
}

/// Set the flags in `mask` without trapping.
pub fn set_exceptions(mask: u32) {
    fesetexcept(mask as c_int);
}

/// The set of trapping exceptions.
pub fn enabled_exceptions() -> u32 {
    fegetexcept() as u32
}

/// Make exactly `mask` trap; returns the previous set.
pub fn set_enabled_exceptions(mask: u32) -> u32 {
    let old = fegetexcept();
    fedisableexcept(FE_ALL_EXCEPT);
    feenableexcept(mask as c_int);
    old as u32
}

/// The whole environment, saved and restorable.
#[derive(Clone, Copy, Debug)]
pub struct Env(pub FenvT);

/// Current environment.
pub fn save_env() -> Env {
    let mut e = FenvT::default();
    get_env(&mut e);
    Env(e)
}

/// Install an environment saved earlier.
pub fn restore_env(env: &Env) {
    set_env(EnvSrc::Saved(&env.0));
}

/// Save the environment, clear the flags and mask all exceptions (`feholdexcept`).
pub fn hold_exceptions() -> Env {
    let mut e = FenvT::default();
    hold_into(&mut e);
    Env(e)
}

/// Install a saved environment and re-raise the exceptions raised since (`feupdateenv`).
pub fn update_env(env: &Env) {
    update_env_src(EnvSrc::Saved(&env.0));
}

/// Run `f` with the rounding mode set to `mode`, then put the previous mode back.
pub fn with_round_mode<R>(mode: RoundMode, f: impl FnOnce() -> R) -> R {
    let old = round_mode();
    set_round_mode(mode);
    let r = f();
    set_round_mode(old);
    r
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test and the host-library bindings
    use super::*;
    use core::ffi::c_int;
    use core::hint::black_box;

    unsafe extern "C" {
        #[link_name = "feclearexcept"]
        fn h_feclearexcept(e: c_int) -> c_int;
        #[link_name = "feraiseexcept"]
        fn h_feraiseexcept(e: c_int) -> c_int;
        #[link_name = "fetestexcept"]
        fn h_fetestexcept(e: c_int) -> c_int;
        #[link_name = "fegetexceptflag"]
        fn h_fegetexceptflag(f: *mut u16, e: c_int) -> c_int;
        #[link_name = "fesetexceptflag"]
        fn h_fesetexceptflag(f: *const u16, e: c_int) -> c_int;
        #[link_name = "fegetround"]
        fn h_fegetround() -> c_int;
        #[link_name = "fesetround"]
        fn h_fesetround(r: c_int) -> c_int;
        #[link_name = "fegetenv"]
        fn h_fegetenv(e: *mut FenvT) -> c_int;
        #[link_name = "fesetenv"]
        fn h_fesetenv(e: *const FenvT) -> c_int;
        #[link_name = "feholdexcept"]
        fn h_feholdexcept(e: *mut FenvT) -> c_int;
        #[link_name = "feupdateenv"]
        fn h_feupdateenv(e: *const FenvT) -> c_int;
        #[link_name = "feenableexcept"]
        fn h_feenableexcept(e: c_int) -> c_int;
        #[link_name = "fedisableexcept"]
        fn h_fedisableexcept(e: c_int) -> c_int;
        #[link_name = "fegetexcept"]
        fn h_fegetexcept() -> c_int;
        #[link_name = "fegetmode"]
        fn h_fegetmode(m: *mut FemodeT) -> c_int;
        #[link_name = "fesetmode"]
        fn h_fesetmode(m: *const FemodeT) -> c_int;
        #[link_name = "fesetexcept"]
        fn h_fesetexcept(e: c_int) -> c_int;
    }

    /// Restores the default environment when a test ends, even by panic. The registers belong
    /// to the thread, so tests running in parallel threads do not disturb each other.
    struct Restore(FenvT);
    impl Restore {
        fn new() -> Restore {
            let mut e = FenvT::default();
            unsafe { h_fegetenv(&mut e) };
            Restore(e)
        }
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { h_fesetenv(&self.0) };
        }
    }

    const ALL: [c_int; 5] = [FE_INVALID, FE_DIVBYZERO, FE_OVERFLOW, FE_UNDERFLOW, FE_INEXACT];

    fn state() -> (FenvT, FemodeT) {
        let (mut e, mut m) = (FenvT::default(), FemodeT::default());
        unsafe {
            h_fegetenv(&mut e);
            h_fegetmode(&mut m);
        }
        // the tag word and x87 pointers are not part of what is compared
        (e, m)
    }

    fn same_env(a: &FenvT, b: &FenvT) -> bool {
        a.control_word == b.control_word
            && a.status_word == b.status_word
            && a.mxcsr == b.mxcsr
            && a.tags == b.tags
    }

    #[test]
    fn layout() {
        assert_eq!(core::mem::size_of::<FenvT>(), 32);
        assert_eq!(core::mem::offset_of!(FenvT, mxcsr), 28);
        assert_eq!(core::mem::offset_of!(FenvT, data_offset), 20);
        assert_eq!(core::mem::size_of::<FemodeT>(), 8);
        assert_eq!(FE_DFL_ENV as isize, -1);
        assert_eq!(FE_NOMASK_ENV as isize, -2);
        assert_eq!(FE_DFL_MODE as isize, -1);
    }

    #[test]
    fn flags_match_host() {
        let _r = Restore::new();
        for subset in 0..32u32 {
            let mask: c_int = ALL.iter().enumerate().filter(|(i, _)| subset >> i & 1 != 0).fold(0, |a, (_, b)| a | b);
            for clear_mask in [0, FE_ALL_EXCEPT, FE_INEXACT | FE_OVERFLOW] {
                unsafe {
                    h_feclearexcept(FE_ALL_EXCEPT);
                    h_feraiseexcept(mask);
                }
                let host = unsafe { h_fetestexcept(FE_ALL_EXCEPT) };
                let mut hf = 0u16;
                unsafe { h_fegetexceptflag(&mut hf, FE_ALL_EXCEPT) };
                let (he, hm) = state();
                unsafe { h_feclearexcept(clear_mask) };
                let host_after = unsafe { h_fetestexcept(FE_ALL_EXCEPT) };
                let (he2, hm2) = state();

                feclearexcept(FE_ALL_EXCEPT);
                feraiseexcept(mask);
                assert_eq!(fetestexcept(FE_ALL_EXCEPT), host, "raise {mask:#x}");
                let mut f = 0u16;
                unsafe { fegetexceptflag(&mut f, FE_ALL_EXCEPT) };
                assert_eq!(f, hf);
                let (e, m) = state();
                assert!(same_env(&e, &he), "env after raise {mask:#x}: {e:x?} vs {he:x?}");
                assert_eq!(m, hm);
                feclearexcept(clear_mask);
                assert_eq!(fetestexcept(FE_ALL_EXCEPT), host_after);
                let (e2, m2) = state();
                assert!(same_env(&e2, &he2));
                assert_eq!(m2, hm2);
                // selective test
                assert_eq!(fetestexcept(FE_INEXACT | FE_INVALID), host_after & (FE_INEXACT | FE_INVALID));
            }
        }
    }

    #[test]
    fn exceptions_raised_by_arithmetic_are_seen() {
        let _r = Restore::new();
        feclearexcept(FE_ALL_EXCEPT);
        let x = black_box(1.0f64) / black_box(0.0f64);
        assert!(x.is_infinite());
        assert_eq!(fetestexcept(FE_ALL_EXCEPT), FE_DIVBYZERO);
        feclearexcept(FE_ALL_EXCEPT);
        let y = black_box(f64::MAX) * black_box(2.0);
        assert!(y.is_infinite());
        assert_eq!(fetestexcept(FE_ALL_EXCEPT), FE_OVERFLOW | FE_INEXACT);
        feclearexcept(FE_ALL_EXCEPT);
        assert_eq!(fetestexcept(FE_ALL_EXCEPT), 0);
        assert_eq!(test_exceptions(0x3d), 0);
        raise_exceptions(FE_UNDERFLOW as u32);
        assert_eq!(test_exceptions(0x3d), FE_UNDERFLOW as u32);
        clear_exceptions(0x3d);
    }

    #[test]
    fn exceptionflag_set_and_get() {
        let _r = Restore::new();
        for saved in [0u16, 1, 4, 8, 0x10, 0x20, 0x3d, 0x15] {
            for excepts in [FE_ALL_EXCEPT, FE_INVALID | FE_INEXACT, FE_OVERFLOW, 0] {
                for start in [0, FE_ALL_EXCEPT, FE_DIVBYZERO | FE_UNDERFLOW] {
                    unsafe {
                        h_feclearexcept(FE_ALL_EXCEPT);
                        h_feraiseexcept(start);
                        h_fesetexceptflag(&saved, excepts);
                    }
                    let (he, hm) = state();
                    feclearexcept(FE_ALL_EXCEPT);
                    feraiseexcept(start);
                    unsafe { fesetexceptflag(&saved, excepts) };
                    let (e, m) = state();
                    assert!(same_env(&e, &he), "saved {saved:#x} excepts {excepts:#x} start {start:#x}");
                    assert_eq!(m, hm);
                    assert_eq!(unsafe { fetestexceptflag(&saved, excepts) }, i32::from(saved) & excepts & FE_ALL_EXCEPT);
                }
            }
        }
        // fesetexcept sets without clearing
        unsafe { h_feclearexcept(FE_ALL_EXCEPT) };
        unsafe { h_fesetexcept(FE_OVERFLOW | FE_INEXACT) };
        let (he, _) = state();
        feclearexcept(FE_ALL_EXCEPT);
        fesetexcept(FE_OVERFLOW | FE_INEXACT);
        assert!(same_env(&state().0, &he));
    }

    #[test]
    fn rounding_modes_match_host_and_change_arithmetic() {
        let _r = Restore::new();
        assert_eq!(fegetround(), FE_TONEAREST);
        for mode in [FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO, FE_TONEAREST] {
            unsafe { h_fesetround(mode) };
            let (he, hm) = state();
            let hr = unsafe { h_fegetround() };
            unsafe { h_fesetround(FE_TONEAREST) };
            assert_eq!(fesetround(mode), 0);
            assert_eq!(fegetround(), hr);
            let (e, m) = state();
            assert!(same_env(&e, &he));
            assert_eq!(m, hm);
            assert_eq!(round_mode().to_c(), mode);
            // double arithmetic (SSE) and the control word agree
            let up = black_box(1.0f64) + black_box(1e-30);
            let dn = black_box(1.0f64) - black_box(1e-30);
            match mode {
                FE_UPWARD => assert!(up > 1.0 && dn == 1.0),
                FE_DOWNWARD => assert!(up == 1.0 && dn < 1.0),
                FE_TOWARDZERO => assert!(up == 1.0 && dn < 1.0),
                _ => assert!(up == 1.0 && dn == 1.0),
            }
            assert_eq!(sse_round_mode().to_c(), mode);
        }
        assert_eq!(fesetround(0x123), 1);
        assert_eq!(fesetround(0x400 | 0x1), 1);
        assert_eq!(fegetround(), FE_TONEAREST);
        set_round_mode(RoundMode::Upward);
        assert_eq!(round_mode(), RoundMode::Upward);
        assert_eq!(with_round_mode(RoundMode::Downward, round_mode), RoundMode::Downward);
        assert_eq!(round_mode(), RoundMode::Upward);
        assert_eq!(RoundMode::from_c(7), None);
    }

    #[test]
    fn trap_masks_match_host() {
        let _r = Restore::new();
        for en in [FE_INVALID, FE_DIVBYZERO | FE_OVERFLOW, FE_ALL_EXCEPT, 0, FE_INEXACT] {
            unsafe {
                h_fedisableexcept(FE_ALL_EXCEPT);
                let ho = h_feenableexcept(en);
                let hg = h_fegetexcept();
                let (he, hm) = state();
                let hd = h_fedisableexcept(FE_OVERFLOW);
                let hg2 = h_fegetexcept();
                let (he2, _) = state();
                h_fedisableexcept(FE_ALL_EXCEPT);
                let _ = (ho, hg, hd, hg2);
                let (o, g) = (feenableexcept(en), fegetexcept());
                assert_eq!((o, g), (ho, hg));
                // fedisableexcept at the very start left everything masked
                fedisableexcept(FE_ALL_EXCEPT);
                feenableexcept(en);
                let (e, m) = state();
                assert!(same_env(&e, &he), "{e:x?} {he:x?}");
                assert_eq!(m, hm);
                let d = fedisableexcept(FE_OVERFLOW);
                assert_eq!((d, fegetexcept()), (hd, hg2));
                assert!(same_env(&state().0, &he2));
                fedisableexcept(FE_ALL_EXCEPT);
            }
        }
        assert_eq!(enabled_exceptions(), 0);
        let old = set_enabled_exceptions(FE_INVALID as u32);
        assert_eq!(old, 0);
        assert_eq!(enabled_exceptions(), FE_INVALID as u32);
        fedisableexcept(FE_ALL_EXCEPT);
    }

    #[test]
    fn env_functions_match_host() {
        let _r = Restore::new();
        // fegetenv of the default state
        let mut a = FenvT::default();
        let mut b = FenvT::default();
        unsafe {
            h_fegetenv(&mut a);
            fegetenv(&mut b);
        }
        assert_eq!(a, b);
        // fesetenv of the three special values, from a perturbed state
        for special in [FE_DFL_ENV, FE_NOMASK_ENV] {
            for perturb in 0..4 {
                let prep = || {
                    unsafe { h_fesetenv(FE_DFL_ENV) };
                    match perturb {
                        1 => {
                            h_fesetround_checked(FE_UPWARD);
                            unsafe { h_feraiseexcept(FE_INEXACT | FE_OVERFLOW) };
                        }
                        2 => unsafe {
                            h_feenableexcept(FE_DIVBYZERO);
                        },
                        3 => {
                            h_fesetround_checked(FE_TOWARDZERO);
                            unsafe { h_feraiseexcept(FE_INVALID) };
                        }
                        _ => {}
                    }
                };
                prep();
                unsafe { h_fesetenv(special) };
                let (he, hm) = state();
                let mut hfull = FenvT::default();
                unsafe { h_fegetenv(&mut hfull) };
                unsafe { h_fesetenv(FE_DFL_ENV) };
                prep();
                unsafe { fesetenv(special) };
                let (e, m) = state();
                let mut full = FenvT::default();
                unsafe { fegetenv(&mut full) };
                assert!(same_env(&e, &he), "special {:p} perturb {perturb}: {e:x?} vs {he:x?}", special);
                assert_eq!(m, hm);
                assert_eq!(full, hfull);
                unsafe { h_fesetenv(FE_DFL_ENV) };
            }
        }
        // feholdexcept and feupdateenv
        for flags in [0, FE_INEXACT, FE_DIVBYZERO | FE_UNDERFLOW, FE_ALL_EXCEPT] {
            for rm in [FE_TONEAREST, FE_UPWARD] {
                let run = |own: bool| -> (FenvT, FenvT, c_int, FenvT, c_int, (FenvT, FemodeT)) {
                    unsafe {
                        h_fesetenv(FE_DFL_ENV);
                        h_fesetround(rm);
                        h_feraiseexcept(flags);
                        let mut saved = FenvT::default();
                        if own {
                            feholdexcept(&mut saved);
                        } else {
                            h_feholdexcept(&mut saved);
                        }
                        let mut during = FenvT::default();
                        h_fegetenv(&mut during);
                        let t1 = h_fetestexcept(FE_ALL_EXCEPT);
                        h_feraiseexcept(FE_OVERFLOW); // happens while held (masked)
                        if own {
                            feupdateenv(&saved);
                        } else {
                            h_feupdateenv(&saved);
                        }
                        let mut after = FenvT::default();
                        h_fegetenv(&mut after);
                        let t2 = h_fetestexcept(FE_ALL_EXCEPT);
                        (saved, during, t1, after, t2, state())
                    }
                };
                let h = run(false);
                let o = run(true);
                assert!(same_env(&h.0, &o.0), "saved flags {flags:#x}");
                assert_eq!(h.0, o.0);
                assert!(same_env(&h.1, &o.1));
                assert_eq!(h.2, o.2);
                assert_eq!(h.2, 0);
                assert!(same_env(&h.3, &o.3));
                assert_eq!(h.4, o.4);
                assert_eq!(h.4, flags | FE_OVERFLOW);
            }
        }
        // fesetenv with an environment taken from the host and with a hand-built one
        unsafe {
            h_fesetenv(FE_DFL_ENV);
            h_fesetround(FE_DOWNWARD);
            h_feraiseexcept(FE_UNDERFLOW);
            h_feenableexcept(FE_INVALID);
        }
        let mut saved = FenvT::default();
        unsafe { h_fegetenv(&mut saved) };
        let mut weird = saved;
        weird.eip = 0x1234;
        weird.opcode = 0x55;
        weird.data_selector = 7;
        for env in [saved, weird] {
            unsafe { h_fesetenv(FE_DFL_ENV) };
            unsafe { h_fesetenv(&env) };
            let (he, hm) = state();
            let mut hfull = FenvT::default();
            unsafe { h_fegetenv(&mut hfull) };
            unsafe { h_fesetenv(FE_DFL_ENV) };
            unsafe { fesetenv(&env) };
            let (e, m) = state();
            let mut full = FenvT::default();
            unsafe { fegetenv(&mut full) };
            assert!(same_env(&e, &he));
            assert_eq!(m, hm);
            assert_eq!(full, hfull);
        }
        // Rust-side save/restore
        unsafe { h_fesetenv(FE_DFL_ENV) };
        let before = save_env();
        set_round_mode(RoundMode::Upward);
        raise_exceptions(FE_INEXACT as u32);
        restore_env(&before);
        assert_eq!(round_mode(), RoundMode::Nearest);
        let held = hold_exceptions();
        raise_exceptions(FE_UNDERFLOW as u32);
        update_env(&held);
        assert_eq!(test_exceptions(0x3d), FE_UNDERFLOW as u32);
        clear_exceptions(0x3d);
    }

    fn h_fesetround_checked(m: c_int) {
        assert_eq!(unsafe { h_fesetround(m) }, 0);
    }

    #[test]
    fn mode_functions_match_host() {
        let _r = Restore::new();
        for rm in [FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO] {
            for flags in [0, FE_INEXACT | FE_INVALID] {
                unsafe {
                    h_fesetenv(FE_DFL_ENV);
                    h_fesetround(rm);
                    h_feenableexcept(0);
                    h_feraiseexcept(flags);
                }
                let (mut hm, mut m) = (FemodeT::default(), FemodeT::default());
                unsafe {
                    h_fegetmode(&mut hm);
                    fegetmode(&mut m);
                }
                assert_eq!(hm, m);
                // set the mode on a state with different flags and rounding
                for target in [FE_DFL_MODE, &hm as *const FemodeT] {
                    unsafe {
                        h_fesetenv(FE_DFL_ENV);
                        h_fesetround(FE_UPWARD);
                        h_feraiseexcept(FE_DIVBYZERO);
                        h_fesetmode(target);
                    }
                    let (he, hmm) = state();
                    unsafe {
                        h_fesetenv(FE_DFL_ENV);
                        h_fesetround(FE_UPWARD);
                        h_feraiseexcept(FE_DIVBYZERO);
                        fesetmode(target);
                    }
                    let (e, mm) = state();
                    assert!(same_env(&e, &he), "rm {rm:#x} target {target:p}: {e:x?} {he:x?}");
                    assert_eq!(mm, hmm);
                }
            }
        }
    }
}

use core::arch::asm;
use core::ffi::c_int;

pub const FE_INVALID: c_int = 0x01;
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

const FPU_EXTENDED: u16 = 0x300;

pub type FexceptT = u16;

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
    pub opcode: u16,
    pub data_offset: u32,
    pub data_selector: u16,
    pub reserved5: u16,
    pub mxcsr: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FemodeT {
    pub control_word: u16,
    pub reserved: u16,
    pub mxcsr: u32,
}

pub const FE_DFL_ENV: *const FenvT = usize::MAX as *const FenvT;
pub const FE_NOMASK_ENV: *const FenvT = (usize::MAX - 1) as *const FenvT;
pub const FE_DFL_MODE: *const FemodeT = usize::MAX as *const FemodeT;

#[inline]
pub(crate) fn mxcsr_get() -> u32 {
    let mut v: u32 = 0;
    unsafe { asm!("stmxcsr [{0}]", in(reg) &mut v, options(nostack, preserves_flags)) };
    v
}

#[inline]
pub(crate) fn mxcsr_set(v: u32) {
    unsafe { asm!("ldmxcsr [{0}]", in(reg) &v, options(nostack, preserves_flags)) };
}

#[inline]
fn cw_get() -> u16 {
    let mut v: u16 = 0;
    unsafe { asm!("fnstcw [{0}]", in(reg) &mut v, options(nostack, preserves_flags)) };
    v
}

#[inline]
fn cw_set(v: u16) {
    unsafe { asm!("fldcw [{0}]", in(reg) &v, options(nostack, preserves_flags)) };
}

#[inline]
fn sw_get() -> u16 {
    let v: u16;
    unsafe { asm!("fnstsw ax", out("ax") v, options(nomem, nostack, preserves_flags)) };
    v
}

#[inline]
fn env_store(env: &mut FenvT) {
    unsafe { asm!("fnstenv [{0}]", in(reg) env as *mut FenvT, options(nostack)) };
}

#[inline]
fn env_load(env: &FenvT) {
    unsafe { asm!("fldenv [{0}]", in(reg) env as *const FenvT, options(nostack)) };
}

#[inline]
fn env_get_x87(env: &mut FenvT) {
    env_store(env);
    env_load(env);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn feclearexcept(excepts: c_int) -> c_int {
    let excepts = (excepts & FE_ALL_EXCEPT) as u32;
    let mut env = FenvT::default();
    env_store(&mut env);
    env.status_word &= !((excepts | FE_DENORM as u32) as u16);
    env_load(&env);
    mxcsr_set(mxcsr_get() & !excepts);
    0
}

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
            unsafe { asm!("fwait", options(nomem, nostack)) };
        }
    }
    0
}

#[inline(never)]
fn div_ss(a: f32, b: f32) {
    let mut r = a;
    unsafe { asm!("divss {0}, {1}", inout(xmm_reg) r, in(xmm_reg) b, options(nomem, nostack, preserves_flags)) };
    core::hint::black_box(r);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fetestexcept(excepts: c_int) -> c_int {
    ((u32::from(sw_get()) | mxcsr_get()) & excepts as u32 & FE_ALL_EXCEPT as u32) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fegetexceptflag(flagp: *mut FexceptT, excepts: c_int) -> c_int {
    unsafe { *flagp = fetestexcept(excepts) as FexceptT };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fesetexceptflag(flagp: *const FexceptT, excepts: c_int) -> c_int {
    let excepts = (excepts & FE_ALL_EXCEPT) as u32;
    let flag = u32::from(unsafe { *flagp });
    let mut env = FenvT::default();
    env_store(&mut env);
    env.status_word &= !((excepts & !flag) as u16);
    env_load(&env);
    let mut m = mxcsr_get();
    m ^= (m ^ flag) & excepts;
    mxcsr_set(m);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fetestexceptflag(flagp: *const FexceptT, excepts: c_int) -> c_int {
    (u32::from(unsafe { *flagp }) & excepts as u32 & FE_ALL_EXCEPT as u32) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fesetexcept(excepts: c_int) -> c_int {
    mxcsr_set(mxcsr_get() | (excepts & FE_ALL_EXCEPT) as u32);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fegetround() -> c_int {
    (cw_get() & 0xc00) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fesetround(round: c_int) -> c_int {
    if round & !0xc00 != 0 {
        return 1;
    }
    cw_set((cw_get() & !0xc00) | round as u16);
    mxcsr_set((mxcsr_get() & !0x6000) | ((round as u32) << 3));
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fegetenv(envp: *mut FenvT) -> c_int {
    let env = unsafe { &mut *envp };
    env_get_x87(env);
    env.mxcsr = mxcsr_get();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fesetenv(envp: *const FenvT) -> c_int {
    let mut t = FenvT::default();
    env_store(&mut t);
    t.mxcsr = mxcsr_get();
    let x87_all = FE_ALL_EXCEPT_X86 as u16;
    if envp == FE_DFL_ENV {
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
    } else if envp == FE_NOMASK_ENV {
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
    } else {
        let e = unsafe { &*envp };
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
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn feholdexcept(envp: *mut FenvT) -> c_int {
    let env = unsafe { &mut *envp };
    env_store(env);
    env.mxcsr = mxcsr_get();
    unsafe { asm!("fnclex", options(nomem, nostack)) };
    mxcsr_set((env.mxcsr | 0x1f80) & !0x3f);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn feupdateenv(envp: *const FenvT) -> c_int {
    let pending = fetestexcept(FE_ALL_EXCEPT);
    unsafe { fesetenv(envp) };
    feraiseexcept(pending);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn feenableexcept(excepts: c_int) -> c_int {
    let excepts = (excepts & FE_ALL_EXCEPT) as u32;
    let cw = cw_get();
    let old = !u32::from(cw) & FE_ALL_EXCEPT as u32;
    cw_set(cw & !(excepts as u16));
    mxcsr_set(mxcsr_get() & !(excepts << 7));
    old as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fedisableexcept(excepts: c_int) -> c_int {
    let excepts = (excepts & FE_ALL_EXCEPT) as u32;
    let cw = cw_get();
    let old = !u32::from(cw) & FE_ALL_EXCEPT as u32;
    cw_set(cw | excepts as u16);
    mxcsr_set(mxcsr_get() | (excepts << 7));
    old as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fegetexcept() -> c_int {
    (!u32::from(cw_get()) & FE_ALL_EXCEPT as u32) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fegetmode(modep: *mut FemodeT) -> c_int {
    let m = unsafe { &mut *modep };
    m.control_word = cw_get();
    m.mxcsr = mxcsr_get();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fesetmode(modep: *const FemodeT) -> c_int {
    let mut mxcsr = mxcsr_get() & FE_ALL_EXCEPT_X86;
    let cw;
    if modep == FE_DFL_MODE {
        cw = 0x37f;
        mxcsr |= FE_ALL_EXCEPT_X86 << 7;
    } else {
        let m = unsafe { &*modep };
        cw = m.control_word;
        mxcsr |= m.mxcsr & !FE_ALL_EXCEPT_X86;
    }
    cw_set(cw);
    mxcsr_set(mxcsr);
    0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum RoundMode {
    Nearest = FE_TONEAREST,
    Downward = FE_DOWNWARD,
    Upward = FE_UPWARD,
    TowardZero = FE_TOWARDZERO,
}

impl RoundMode {
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

pub fn round_mode() -> RoundMode {
    RoundMode::from_c(fegetround()).unwrap_or(RoundMode::Nearest)
}

pub fn set_round_mode(mode: RoundMode) {
    fesetround(mode.to_c());
}

pub(crate) fn sse_round_mode() -> RoundMode {
    match (mxcsr_get() >> 13) & 3 {
        0 => RoundMode::Nearest,
        1 => RoundMode::Downward,
        2 => RoundMode::Upward,
        _ => RoundMode::TowardZero,
    }
}

pub fn test_exceptions(mask: u32) -> u32 {
    fetestexcept(mask as c_int) as u32
}

pub fn clear_exceptions(mask: u32) {
    feclearexcept(mask as c_int);
}

pub fn raise_exceptions(mask: u32) {
    feraiseexcept(mask as c_int);
}

pub fn set_exceptions(mask: u32) {
    fesetexcept(mask as c_int);
}

pub fn enabled_exceptions() -> u32 {
    fegetexcept() as u32
}

pub fn set_enabled_exceptions(mask: u32) -> u32 {
    let old = fegetexcept();
    fedisableexcept(FE_ALL_EXCEPT);
    feenableexcept(mask as c_int);
    old as u32
}

#[derive(Clone, Copy, Debug)]
pub struct Env(pub FenvT);

pub fn save_env() -> Env {
    let mut e = FenvT::default();
    unsafe { fegetenv(&mut e) };
    Env(e)
}

pub fn restore_env(env: &Env) {
    unsafe { fesetenv(&env.0) };
}

pub fn hold_exceptions() -> Env {
    let mut e = FenvT::default();
    unsafe { feholdexcept(&mut e) };
    Env(e)
}

pub fn update_env(env: &Env) {
    unsafe { feupdateenv(&env.0) };
}

pub fn with_round_mode<R>(mode: RoundMode, f: impl FnOnce() -> R) -> R {
    let old = round_mode();
    set_round_mode(mode);
    let r = f();
    set_round_mode(old);
    r
}


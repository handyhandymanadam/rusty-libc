use crate::consts::{
    EINVAL, ENOSYS, NSIG, SA_INTERRUPT, SA_NODEFER, SA_RESETHAND, SA_RESTART, SIG_BLOCK, SIG_ERR, SIG_HOLD, SIG_IGN, SIG_SETMASK,
    SIG_UNBLOCK,
};
use crate::sigset::{is_internal_signal, sigaddset, sigdelset};
use crate::types::{Sigaction, Sighandler, Sigset};
use crate::wait::{sigprocmask, sigsuspend};
use crate::fail;
use core::ffi::c_int;
use core::sync::atomic::{AtomicU64, Ordering};
use rusty_libc_core::signal::{KSigaction, SA_RESTORER};
use rusty_libc_core::{Errno, errno};

core::arch::global_asm!(
    ".pushsection .text,\"ax\",@progbits",
    "nop",
    ".balign 16",
    ".globl __restore_rt",
    ".type __restore_rt,@function",
    "__restore_rt:",
    "mov rax, 15",
    "syscall",
    ".size __restore_rt, . - __restore_rt",
    ".popsection",
);

pub fn restorer_address() -> usize {
    let a: usize;
    unsafe { core::arch::asm!("lea {0}, [rip + __restore_rt]", out(reg) a, options(nomem, nostack, preserves_flags)) };
    a
}

#[repr(C)]
pub struct Sigvec {
    pub sv_handler: Sighandler,
    pub sv_mask: c_int,
    pub sv_flags: c_int,
}

const SV_ONSTACK: c_int = 1;
const SV_INTERRUPT: c_int = 2;
const SV_RESETHAND: c_int = 4;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigvec(sig: c_int, vec: *const Sigvec, ovec: *mut Sigvec) -> c_int {
    unsafe {
        let new = vec.as_ref().map(|v| {
            let mut a = Sigaction { sa_handler: v.sv_handler, sa_mask: Sigset::EMPTY, sa_flags: 0, sa_restorer: 0 };
            a.sa_mask.val[0] = v.sv_mask as u32 as u64;
            if v.sv_flags & SV_ONSTACK != 0 {
                a.sa_flags |= crate::consts::SA_ONSTACK;
            }
            if v.sv_flags & SV_RESETHAND != 0 {
                a.sa_flags |= SA_RESETHAND;
            }
            if v.sv_flags & SV_INTERRUPT == 0 {
                a.sa_flags |= SA_RESTART;
            }
            a
        });
        match sigaction_rs(sig, new.as_ref()) {
            Ok(old) => {
                if let Some(o) = ovec.as_mut() {
                    o.sv_handler = old.sa_handler;
                    o.sv_mask = old.sa_mask.val[0] as c_int;
                    o.sv_flags = 0;
                    if old.sa_flags & crate::consts::SA_ONSTACK != 0 {
                        o.sv_flags |= SV_ONSTACK;
                    }
                    if old.sa_flags & SA_RESETHAND != 0 {
                        o.sv_flags |= SV_RESETHAND;
                    }
                    if old.sa_flags & SA_RESTART == 0 {
                        o.sv_flags |= SV_INTERRUPT;
                    }
                }
                0
            }
            Err(e) => fail(e.0),
        }
    }
}

static SIGINTR: AtomicU64 = AtomicU64::new(0);

fn intr_bit(sig: i32) -> u64 {
    1u64 << (sig - 1)
}

fn valid_signal(sig: i32) -> bool {
    sig > 0 && sig < NSIG && !is_internal_signal(sig)
}

pub fn sigaction_rs(sig: i32, act: Option<&Sigaction>) -> Result<Sigaction, Errno> {
    if !valid_signal(sig) {
        return Err(Errno(EINVAL));
    }
    let kact = act.map(|a| KSigaction {
        handler: a.sa_handler,
        flags: u64::from(a.sa_flags as u32) | SA_RESTORER,
        restorer: restorer_address(),
        mask: a.sa_mask.val[0],
    });
    let old = rusty_libc_core::signal::sigaction(sig, kact.as_ref())?;
    Ok(Sigaction { sa_handler: old.handler, sa_mask: Sigset::from_mask(old.mask), sa_flags: old.flags as i32, sa_restorer: old.restorer })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigaction(sig: c_int, act: *const Sigaction, oact: *mut Sigaction) -> c_int {
    unsafe {
        match sigaction_rs(sig, act.as_ref()) {
            Ok(old) => {
                if !oact.is_null() {
                    *oact = old;
                }
                0
            }
            Err(e) => fail(e.0),
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigaction(sig: c_int, act: *const Sigaction, oact: *mut Sigaction) -> c_int {
    unsafe { sigaction(sig, act, oact) }
}

fn set_handler(sig: i32, handler: Sighandler, flags: i32, mask: Sigset) -> Sighandler {
    let act = Sigaction { sa_handler: handler, sa_mask: mask, sa_flags: flags, sa_restorer: 0 };
    match sigaction_rs(sig, Some(&act)) {
        Ok(old) => old.sa_handler,
        Err(e) => {
            errno::set(e.0);
            SIG_ERR
        }
    }
}

fn bsd_signal_impl(sig: c_int, handler: Sighandler) -> Sighandler {
    if handler == SIG_ERR || !valid_signal(sig) {
        errno::set(EINVAL);
        return SIG_ERR;
    }
    let mut mask = Sigset::EMPTY;
    mask.insert(sig);
    let flags = if SIGINTR.load(Ordering::Relaxed) & intr_bit(sig) != 0 { 0 } else { SA_RESTART };
    set_handler(sig, handler, flags, mask)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn signal(sig: c_int, handler: Sighandler) -> Sighandler {
    bsd_signal_impl(sig, handler)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn bsd_signal(sig: c_int, handler: Sighandler) -> Sighandler {
    bsd_signal_impl(sig, handler)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ssignal(sig: c_int, handler: Sighandler) -> Sighandler {
    bsd_signal_impl(sig, handler)
}

fn sysv_signal_impl(sig: c_int, handler: Sighandler) -> Sighandler {
    if handler == SIG_ERR || !(1..NSIG).contains(&sig) {
        errno::set(EINVAL);
        return SIG_ERR;
    }
    let flags = (SA_RESETHAND | SA_NODEFER | SA_INTERRUPT) & !SA_RESTART;
    set_handler(sig, handler, flags, Sigset::EMPTY)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sysv_signal(sig: c_int, handler: Sighandler) -> Sighandler {
    sysv_signal_impl(sig, handler)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __sysv_signal(sig: c_int, handler: Sighandler) -> Sighandler {
    sysv_signal_impl(sig, handler)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn siginterrupt(sig: c_int, interrupt: c_int) -> c_int {
    let mut act = match sigaction_rs(sig, None) {
        Ok(a) => a,
        Err(e) => return fail(e.0),
    };
    if interrupt != 0 {
        SIGINTR.fetch_or(intr_bit(sig), Ordering::Relaxed);
        act.sa_flags &= !SA_RESTART;
    } else {
        SIGINTR.fetch_and(!intr_bit(sig), Ordering::Relaxed);
        act.sa_flags |= SA_RESTART;
    }
    match sigaction_rs(sig, Some(&act)) {
        Ok(_) => 0,
        Err(e) => fail(e.0),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigset(sig: c_int, disp: Sighandler) -> Sighandler {
    unsafe {
        let mut set = Sigset::EMPTY;
        let mut oset = Sigset::EMPTY;
        if sigaddset(&mut set, sig) < 0 {
            return SIG_ERR;
        }
        if disp == SIG_HOLD {
            if sigprocmask(SIG_BLOCK, &set, &mut oset) < 0 {
                return SIG_ERR;
            }
            if oset.has(sig) {
                return SIG_HOLD;
            }
            return match sigaction_rs(sig, None) {
                Ok(old) => old.sa_handler,
                Err(e) => {
                    errno::set(e.0);
                    SIG_ERR
                }
            };
        }
        let act = Sigaction { sa_handler: disp, sa_mask: Sigset::EMPTY, sa_flags: 0, sa_restorer: 0 };
        let old = match sigaction_rs(sig, Some(&act)) {
            Ok(o) => o,
            Err(e) => {
                errno::set(e.0);
                return SIG_ERR;
            }
        };
        if sigprocmask(SIG_UNBLOCK, &set, &mut oset) < 0 {
            return SIG_ERR;
        }
        if oset.has(sig) { SIG_HOLD } else { old.sa_handler }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sighold(sig: c_int) -> c_int {
    unsafe {
        let mut set = Sigset::EMPTY;
        if sigaddset(&mut set, sig) < 0 {
            return -1;
        }
        sigprocmask(SIG_BLOCK, &set, core::ptr::null_mut())
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigrelse(sig: c_int) -> c_int {
    unsafe {
        let mut set = Sigset::EMPTY;
        if sigaddset(&mut set, sig) < 0 {
            return -1;
        }
        sigprocmask(SIG_UNBLOCK, &set, core::ptr::null_mut())
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigignore(sig: c_int) -> c_int {
    let act = Sigaction { sa_handler: SIG_IGN, sa_mask: Sigset::EMPTY, sa_flags: 0, sa_restorer: 0 };
    match sigaction_rs(sig, Some(&act)) {
        Ok(_) => 0,
        Err(e) => fail(e.0),
    }
}

fn old_mask_to_set(mask: c_int) -> Sigset {
    Sigset::from_mask(u64::from(mask as u32))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigblock(mask: c_int) -> c_int {
    unsafe {
        let set = old_mask_to_set(mask);
        let mut oset = Sigset::EMPTY;
        if sigprocmask(SIG_BLOCK, &set, &mut oset) < 0 {
            return -1;
        }
        oset.val[0] as u32 as c_int
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigsetmask(mask: c_int) -> c_int {
    unsafe {
        let set = old_mask_to_set(mask);
        let mut oset = Sigset::EMPTY;
        if sigprocmask(SIG_SETMASK, &set, &mut oset) < 0 {
            return -1;
        }
        oset.val[0] as u32 as c_int
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn siggetmask() -> c_int {
    sigblock(0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __sigpause(sig_or_mask: c_int, is_sig: c_int) -> c_int {
    unsafe {
        let mut set;
        if is_sig != 0 {
            set = Sigset::EMPTY;
            if sigprocmask(0, core::ptr::null(), &mut set) < 0 || sigdelset(&mut set, sig_or_mask) < 0 {
                return -1;
            }
        } else {
            set = old_mask_to_set(sig_or_mask);
        }
        sigsuspend(&set)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigpause(mask: c_int) -> c_int {
    __sigpause(mask, 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __xpg_sigpause(sig: c_int) -> c_int {
    __sigpause(sig, 1)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigreturn(_scp: *mut crate::types::Sigcontext) -> c_int {
    fail(ENOSYS)
}

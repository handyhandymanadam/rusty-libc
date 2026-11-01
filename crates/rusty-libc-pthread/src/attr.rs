//! pthread_attr_t and the attribute functions. The object is 56 bytes like glibc's: scheduling
//! parameter, policy, flags, guard size, stack address (the TOP of the stack, as in glibc), stack
//! size, and a pointer to an extension (CPU affinity set and signal mask) that is allocated with
//! calloc on first use.
//!
//! Safe core: the methods of `PthreadAttr` work on references; the exported functions convert their pointer arguments once
//! (`with_attr!`, `out!`) and call them. Unsafe left here: the extension block (`AttrExt::cpuset`, `ext`, the calloc/free
//! calls), and the boundary conversions.
use crate::sys::*;
use core::ffi::{c_int, c_void};
use rusty_libc_core::syscall::syscall3;

pub const ATTR_FLAG_DETACHSTATE: c_int = 0x01;
pub const ATTR_FLAG_NOTINHERITSCHED: c_int = 0x02;
pub const ATTR_FLAG_SCOPEPROCESS: c_int = 0x04;
pub const ATTR_FLAG_STACKADDR: c_int = 0x08;
pub const ATTR_FLAG_SCHED_SET: c_int = 0x20;
pub const ATTR_FLAG_POLICY_SET: c_int = 0x40;

pub const PTHREAD_CREATE_JOINABLE: c_int = 0;
pub const PTHREAD_CREATE_DETACHED: c_int = 1;
pub const PTHREAD_INHERIT_SCHED: c_int = 0;
pub const PTHREAD_EXPLICIT_SCHED: c_int = 1;
pub const PTHREAD_SCOPE_SYSTEM: c_int = 0;
pub const PTHREAD_SCOPE_PROCESS: c_int = 1;
pub const PTHREAD_STACK_MIN: usize = 16384;

pub const SCHED_OTHER: c_int = 0;
pub const SCHED_FIFO: c_int = 1;
pub const SCHED_RR: c_int = 2;

const SYS_SCHED_GET_PRIORITY_MAX: usize = 146;
const SYS_SCHED_GET_PRIORITY_MIN: usize = 147;

/// Extension data of an attribute (in its own calloc block): a header, then `map_size - EXT_HDR` bytes for the CPU set.
#[repr(C)]
pub struct AttrExt {
    /// Size of the whole block.
    pub map_size: usize,
    pub cpusetsize: usize,
    pub sigmask: u64,
    pub sigmask_set: u32,
    pub _pad: u32,
    // the CPU set bytes follow
}

const EXT_HDR: usize = core::mem::size_of::<AttrExt>();

impl AttrExt {
    /// The CPU set stored in the extension (`cpusetsize` bytes; empty when none is set).
    pub fn cpuset(&self) -> &[u8] {
        let n = self.cpusetsize.min(self.map_size.saturating_sub(EXT_HDR));
        let p = (self as *const AttrExt).wrapping_add(1).cast::<u8>();
        // SAFETY: an AttrExt only lives at the start of a block of `map_size` bytes (ext_get / ext_alloc), so the `n` bytes
        // after the header are inside that block and borrowed with `self`.
        unsafe { rusty_libc_core::ffi::bytes(p, n) }
    }

    /// The `n` bytes after the header, for writing a CPU set (`n` at most `map_size - EXT_HDR`, checked).
    pub(crate) fn room_mut(&mut self, n: usize) -> &mut [u8] {
        assert!(EXT_HDR + n <= self.map_size);
        let p = (self as *mut AttrExt).wrapping_add(1).cast::<u8>();
        // SAFETY: as in `cpuset`: the block holds `map_size` bytes, and `n` was checked to fit; the borrow is `self`'s.
        unsafe { rusty_libc_core::ffi::bytes_mut(p, n) }
    }
}

/// glibc's `struct pthread_attr` (this is what `pthread_attr_t` holds).
///
/// `extension` is NULL or a block from `calloc` that holds an `AttrExt` header and its CPU set and belongs to this
/// attribute (made by `ext_get` / `ext_alloc`, freed by `destroy`). A program that copies a `pthread_attr_t` byte by byte
/// shares the block between the copies, as it does with glibc (destroying both frees it twice there too).
#[repr(C)]
pub struct PthreadAttr {
    pub schedparam: SchedParam,
    pub schedpolicy: c_int,
    pub flags: c_int,
    pub guardsize: usize,
    pub stackaddr: *mut c_void,
    pub stacksize: usize,
    pub extension: *mut AttrExt,
    pub unused: *mut c_void,
}

const _: () = assert!(core::mem::size_of::<PthreadAttr>() == 56);
const _: () = assert!(core::mem::offset_of!(PthreadAttr, guardsize) == 16);

fn sched_prio_range(policy: c_int) -> Option<(c_int, c_int)> {
    // minimum first, as glibc's check_sched_priority_attr asks
    // SAFETY: plain-value system call.
    let min = unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GET_PRIORITY_MIN, policy as usize) };
    // SAFETY: plain-value system call.
    let max = unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GET_PRIORITY_MAX, policy as usize) };
    if errno_of(max) != 0 || errno_of(min) != 0 { None } else { Some((min as c_int, max as c_int)) }
}

fn check_prio(prio: c_int, policy: c_int) -> c_int {
    match sched_prio_range(policy) {
        Some((lo, hi)) if prio >= lo && prio <= hi => 0,
        _ => EINVAL,
    }
}

/// Size (in bytes) of the kernel's CPU mask, found by probing sched_getaffinity.
pub fn kernel_cpumask_size() -> usize {
    static SIZE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let s = SIZE.load(core::sync::atomic::Ordering::Relaxed);
    if s != 0 {
        return s;
    }
    let mut buf = [0u8; 1024];
    let mut size = 128usize; // bytes, doubled until the kernel accepts
    loop {
        // (the probe buffer is 1024 bytes: a larger size is offered as 1024, which a kernel with a larger mask refuses with
        // EINVAL, so the doubling ends at the 128-byte fallback instead of letting the kernel write past the buffer)
        let r = sched_getaffinity(0, &mut buf[..size.min(1024)]);
        if r >= 0 {
            SIZE.store(r as usize, core::sync::atomic::Ordering::Relaxed);
            return r as usize;
        }
        if r != -(EINVAL as isize) || size >= 8192 {
            return 128;
        }
        size *= 2;
    }
}

impl PthreadAttr {
    /// What `pthread_attr_init` makes: everything zero but the guard size, one page (the standard's default).
    pub const fn new() -> PthreadAttr {
        PthreadAttr { schedparam: SchedParam { sched_priority: 0 }, schedpolicy: 0, flags: 0, guardsize: PAGE, stackaddr: core::ptr::null_mut(), stacksize: 0, extension: core::ptr::null_mut(), unused: core::ptr::null_mut() }
    }

    /// The extension, if there is one.
    pub fn ext(&self) -> Option<&AttrExt> {
        // SAFETY: `extension` is NULL or this attribute's own live block (the type's invariant), borrowed with `self`.
        unsafe { self.extension.as_ref() }
    }

    fn ext_mut(&mut self) -> Option<&mut AttrExt> {
        // SAFETY: as in `ext`, exclusively borrowed with `self`.
        unsafe { self.extension.as_mut() }
    }

    /// The extension with room for a CPU set of `size_needed` bytes: the current one if it is big enough, else a new
    /// zeroed one that keeps the signal mask (the old one is freed).
    fn ext_get(&mut self, size_needed: usize) -> Result<&mut AttrExt, c_int> {
        if self.ext().is_some_and(|e| e.map_size >= EXT_HDR + size_needed) {
            return self.ext_mut().ok_or(ENOMEM);
        }
        let len = EXT_HDR + size_needed;
        // SAFETY: plain allocation call.
        let p = unsafe { rusty_libc_malloc::calloc(1, len) }.cast::<AttrExt>();
        // SAFETY: a fresh zeroed block of `len >= EXT_HDR` bytes (calloc aligns for any type): all zero is a valid AttrExt,
        // and nothing else knows the block yet.
        let Some(new) = (unsafe { p.as_mut() }) else { return Err(ENOMEM) };
        if let Some(cur) = self.ext() {
            new.sigmask = cur.sigmask;
            new.sigmask_set = cur.sigmask_set;
            // SAFETY: the old block is ours (invariant) and is replaced below, so nothing uses it after this.
            unsafe { rusty_libc_malloc::free(self.extension.cast()) };
        }
        new.map_size = len;
        self.extension = p;
        Ok(new)
    }

    /// A fresh extension of `size` CPU-set bytes for an attribute that has none (pthread_getattr_np's result).
    pub(crate) fn ext_alloc(&mut self, size: usize) -> Result<&mut AttrExt, c_int> {
        let len = EXT_HDR + size;
        // SAFETY: plain allocation call.
        let p = unsafe { rusty_libc_malloc::calloc(1, len) }.cast::<AttrExt>();
        // SAFETY: a fresh zeroed block (see ext_get).
        let Some(e) = (unsafe { p.as_mut() }) else { return Err(ENOMEM) };
        e.map_size = len;
        self.extension = p;
        Ok(e)
    }

    /// `pthread_attr_destroy`: free the extension.
    pub fn destroy(&mut self) {
        if !self.extension.is_null() {
            // SAFETY: the block is ours (invariant); the pointer is cleared right after.
            unsafe { rusty_libc_malloc::free(self.extension.cast()) };
            self.extension = core::ptr::null_mut();
        }
    }

    /// A copy whose extension is a new block (pthread_getattr_default_np, pthread_create's default, mq_notify): Err(ENOMEM)
    /// gives the copy without an extension too, as the old in-place copy left it.
    pub fn duplicate(&self) -> Result<PthreadAttr, (PthreadAttr, c_int)> {
        let mut d = PthreadAttr { extension: core::ptr::null_mut(), ..*self };
        if let Some(se) = self.ext() {
            let Ok(de) = d.ext_get(se.cpusetsize) else { return Err((d, ENOMEM)) };
            de.cpusetsize = se.cpusetsize;
            de.sigmask = se.sigmask;
            de.sigmask_set = se.sigmask_set;
            let src = se.cpuset();
            de.room_mut(src.len()).copy_from_slice(src);
        }
        Ok(d)
    }

    pub fn detachstate(&self) -> c_int {
        if self.flags & ATTR_FLAG_DETACHSTATE != 0 { PTHREAD_CREATE_DETACHED } else { PTHREAD_CREATE_JOINABLE }
    }

    pub fn set_detachstate(&mut self, detachstate: c_int) -> c_int {
        match detachstate {
            PTHREAD_CREATE_DETACHED => self.flags |= ATTR_FLAG_DETACHSTATE,
            PTHREAD_CREATE_JOINABLE => self.flags &= !ATTR_FLAG_DETACHSTATE,
            _ => return EINVAL,
        }
        0
    }

    pub fn set_schedparam(&mut self, param: &SchedParam) -> c_int {
        let r = check_prio(param.sched_priority, self.schedpolicy);
        if r != 0 {
            return r;
        }
        self.schedparam = *param;
        self.flags |= ATTR_FLAG_SCHED_SET;
        0
    }

    pub fn set_schedpolicy(&mut self, policy: c_int) -> c_int {
        if !(SCHED_OTHER..=SCHED_RR).contains(&policy) {
            return EINVAL;
        }
        self.schedpolicy = policy;
        self.flags |= ATTR_FLAG_POLICY_SET;
        0
    }

    pub fn inheritsched(&self) -> c_int {
        if self.flags & ATTR_FLAG_NOTINHERITSCHED != 0 { PTHREAD_EXPLICIT_SCHED } else { PTHREAD_INHERIT_SCHED }
    }

    pub fn set_inheritsched(&mut self, inherit: c_int) -> c_int {
        match inherit {
            PTHREAD_EXPLICIT_SCHED => self.flags |= ATTR_FLAG_NOTINHERITSCHED,
            PTHREAD_INHERIT_SCHED => self.flags &= !ATTR_FLAG_NOTINHERITSCHED,
            _ => return EINVAL,
        }
        0
    }

    pub fn scope(&self) -> c_int {
        if self.flags & ATTR_FLAG_SCOPEPROCESS != 0 { PTHREAD_SCOPE_PROCESS } else { PTHREAD_SCOPE_SYSTEM }
    }

    pub fn set_scope(&mut self, scope: c_int) -> c_int {
        match scope {
            PTHREAD_SCOPE_SYSTEM => self.flags &= !ATTR_FLAG_SCOPEPROCESS,
            PTHREAD_SCOPE_PROCESS => return ENOTSUP,
            _ => return EINVAL,
        }
        0
    }

    pub fn set_stackaddr(&mut self, stackaddr: *mut c_void) {
        self.stackaddr = stackaddr;
        self.flags |= ATTR_FLAG_STACKADDR;
    }

    /// The stack size; one the program did not set reads as the size the system will use.
    pub fn get_stacksize(&self) -> usize {
        if self.stacksize == 0 { crate::thread::default_stacksize() } else { self.stacksize }
    }

    pub fn set_stacksize(&mut self, stacksize: usize) -> c_int {
        if stacksize < PTHREAD_STACK_MIN {
            return EINVAL;
        }
        self.stacksize = stacksize;
        0
    }

    /// (lowest address, size): the stored address is the top of the stack.
    pub fn stack(&self) -> (*mut c_void, usize) {
        (self.stackaddr.cast::<u8>().wrapping_sub(self.stacksize).cast(), self.stacksize)
    }

    pub fn set_stack(&mut self, stackaddr: *mut c_void, stacksize: usize) -> c_int {
        if stacksize < PTHREAD_STACK_MIN {
            return EINVAL;
        }
        self.stacksize = stacksize;
        self.stackaddr = stackaddr.cast::<u8>().wrapping_add(stacksize).cast();
        self.flags |= ATTR_FLAG_STACKADDR;
        0
    }

    /// `pthread_attr_setaffinity_np`; None clears the set.
    pub fn set_affinity(&mut self, cpuset: Option<&[u8]>) -> c_int {
        let Some(cpuset) = cpuset.filter(|c| !c.is_empty()) else {
            if let Some(e) = self.ext_mut() {
                e.cpusetsize = 0;
            }
            return 0;
        };
        // bits beyond what the kernel supports must be zero
        let ks = kernel_cpumask_size();
        if cpuset.len() > ks && cpuset[ks..].iter().any(|&b| b != 0) {
            return EINVAL;
        }
        let Ok(e) = self.ext_get(cpuset.len()) else { return ENOMEM };
        e.cpusetsize = cpuset.len();
        e.room_mut(cpuset.len()).copy_from_slice(cpuset);
        0
    }

    /// `pthread_attr_getaffinity_np` into `out`.
    pub fn get_affinity(&self, out: &mut [u8]) -> c_int {
        match self.ext().map(AttrExt::cpuset).filter(|s| !s.is_empty()) {
            Some(src) => {
                // bits that do not fit in the caller's buffer must be zero
                if src.len() > out.len() && src[out.len()..].iter().any(|&b| b != 0) {
                    return EINVAL;
                }
                let n = src.len().min(out.len());
                out[..n].copy_from_slice(&src[..n]);
                out[n..].fill(0);
            }
            // no set stored: every CPU
            None => out.fill(0xff),
        }
        0
    }

    /// `pthread_attr_setsigmask_np`; None clears it. glibc keeps SIGCANCEL and SIGSETXID out of any mask a program sets.
    pub fn set_sigmask(&mut self, sigmask: Option<&SigsetT>) -> c_int {
        let Some(m) = sigmask else {
            if let Some(e) = self.ext_mut() {
                e.sigmask_set = 0;
            }
            return 0;
        };
        let Ok(e) = self.ext_get(0) else { return ENOMEM };
        e.sigmask = m.val[0] & !crate::cancel::INTERNAL_SIGNALS;
        e.sigmask_set = 1;
        0
    }

    /// The stored signal mask (`pthread_attr_getsigmask_np`), None when none was set.
    pub fn sigmask(&self) -> Option<u64> {
        self.ext().filter(|e| e.sigmask_set != 0).map(|e| e.sigmask)
    }
}

impl Default for PthreadAttr {
    fn default() -> Self {
        Self::new()
    }
}

/// The bytes between `flags` and `guardsize` (struct padding): every writer of a whole attribute zeroes them, as glibc's
/// memset-based pthread_attr_init does (programs that compare attribute bytes see zeros there).
const PAD_AT: usize = core::mem::offset_of!(PthreadAttr, flags) + core::mem::size_of::<c_int>();
const PAD_LEN: usize = core::mem::offset_of!(PthreadAttr, guardsize) - PAD_AT;

/// Write `a` to `dst` with the padding zeroed.
///
/// # Safety
/// `dst` is writable memory for one attribute; its old contents are not read or freed.
pub(crate) unsafe fn write_attr(dst: *mut PthreadAttr, a: PthreadAttr) {
    // SAFETY: forwarded contract; write does not read or drop the old bytes.
    unsafe { core::ptr::write(dst, a) };
    // SAFETY: the padding bytes lie inside `*dst` (forwarded contract).
    unsafe { core::ptr::write_bytes(dst.cast::<u8>().wrapping_add(PAD_AT), 0, PAD_LEN) };
}

/// Copy of an attribute (used by mq_notify): the extension is not shared. On ENOMEM `dst` holds the copy without an
/// extension.
///
/// # Safety
/// `src` is an initialised attribute; `dst` is writable memory for one (its old contents are not read or freed), not
/// overlapping `src`.
pub unsafe fn attr_copy(dst: *mut PthreadAttr, src: *const PthreadAttr) -> c_int {
    // SAFETY: `src` is an initialised attribute (caller's contract).
    let (d, r) = match unsafe { arg(src) }.duplicate() {
        Ok(d) => (d, 0),
        Err((d, e)) => (d, e),
    };
    // a byte copy of the source first (padding included, as before), then the copy's own extension
    // SAFETY: both point to one attribute and do not overlap (caller's contract).
    unsafe { core::ptr::copy_nonoverlapping(src, dst, 1) };
    // SAFETY: `dst` now holds an attribute (caller's contract: writable).
    unsafe { (*dst).extension = d.extension };
    r
}

/// The exported attribute functions take the C object as a raw pointer, convert it once (glibc dereferences it without a
/// NULL check: a NULL faults, as there) and call the safe method above.
macro_rules! with_attr {
    ($p:expr) => {{
        // SAFETY: the C caller passes an initialised pthread_attr_t that no other thread uses during the call.
        unsafe { arg_mut($p) }
    }};
}
macro_rules! with_attr_ref {
    ($p:expr) => {{
        // SAFETY: the C caller passes an initialised pthread_attr_t that nothing writes during the call.
        unsafe { arg($p) }
    }};
}
macro_rules! out {
    ($p:expr) => {{
        // SAFETY: the C caller passes a writable out-parameter (glibc writes it without a NULL check).
        unsafe { arg_mut($p) }
    }};
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_init(attr: *mut PthreadAttr) -> c_int {
    // SAFETY: `attr` is writable memory for one attribute (C contract); its old contents are not read.
    unsafe { write_attr(attr, PthreadAttr::new()) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_destroy(attr: *mut PthreadAttr) -> c_int {
    with_attr!(attr).destroy();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getdetachstate(attr: *const PthreadAttr, detachstate: *mut c_int) -> c_int {
    *out!(detachstate) = with_attr_ref!(attr).detachstate();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setdetachstate(attr: *mut PthreadAttr, detachstate: c_int) -> c_int {
    with_attr!(attr).set_detachstate(detachstate)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getguardsize(attr: *const PthreadAttr, guardsize: *mut usize) -> c_int {
    *out!(guardsize) = with_attr_ref!(attr).guardsize;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setguardsize(attr: *mut PthreadAttr, guardsize: usize) -> c_int {
    with_attr!(attr).guardsize = guardsize;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getschedparam(attr: *const PthreadAttr, param: *mut SchedParam) -> c_int {
    *out!(param) = with_attr_ref!(attr).schedparam;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setschedparam(attr: *mut PthreadAttr, param: *const SchedParam) -> c_int {
    // SAFETY: `param` is a valid struct sched_param (C contract; read without a NULL check, as glibc).
    let param = unsafe { arg(param) };
    with_attr!(attr).set_schedparam(param)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getschedpolicy(attr: *const PthreadAttr, policy: *mut c_int) -> c_int {
    *out!(policy) = with_attr_ref!(attr).schedpolicy;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setschedpolicy(attr: *mut PthreadAttr, policy: c_int) -> c_int {
    with_attr!(attr).set_schedpolicy(policy)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getinheritsched(attr: *const PthreadAttr, inherit: *mut c_int) -> c_int {
    *out!(inherit) = with_attr_ref!(attr).inheritsched();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setinheritsched(attr: *mut PthreadAttr, inherit: c_int) -> c_int {
    with_attr!(attr).set_inheritsched(inherit)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getscope(attr: *const PthreadAttr, scope: *mut c_int) -> c_int {
    *out!(scope) = with_attr_ref!(attr).scope();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setscope(attr: *mut PthreadAttr, scope: c_int) -> c_int {
    with_attr!(attr).set_scope(scope)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstackaddr(attr: *const PthreadAttr, stackaddr: *mut *mut c_void) -> c_int {
    *out!(stackaddr) = with_attr_ref!(attr).stackaddr;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstackaddr(attr: *mut PthreadAttr, stackaddr: *mut c_void) -> c_int {
    with_attr!(attr).set_stackaddr(stackaddr);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstacksize(attr: *const PthreadAttr, stacksize: *mut usize) -> c_int {
    let a = with_attr_ref!(attr);
    let out = out!(stacksize);
    // (stored first, then replaced when unset: the order glibc's code has)
    *out = a.stacksize;
    if *out == 0 {
        *out = a.get_stacksize();
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstacksize(attr: *mut PthreadAttr, stacksize: usize) -> c_int {
    with_attr!(attr).set_stacksize(stacksize)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstack(attr: *const PthreadAttr, stackaddr: *mut *mut c_void, stacksize: *mut usize) -> c_int {
    let (lo, size) = with_attr_ref!(attr).stack();
    *out!(stackaddr) = lo;
    *out!(stacksize) = size;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstack(attr: *mut PthreadAttr, stackaddr: *mut c_void, stacksize: usize) -> c_int {
    with_attr!(attr).set_stack(stackaddr, stacksize)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setaffinity_np(attr: *mut PthreadAttr, cpusetsize: usize, cpuset: *const CpuSet) -> c_int {
    let set = if cpuset.is_null() || cpusetsize == 0 {
        None
    } else {
        // SAFETY: a non-NULL `cpuset` holds `cpusetsize` readable bytes (C contract).
        Some(unsafe { rusty_libc_core::ffi::bytes(cpuset.cast::<u8>(), cpusetsize) })
    };
    with_attr!(attr).set_affinity(set)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getaffinity_np(attr: *const PthreadAttr, cpusetsize: usize, cpuset: *mut CpuSet) -> c_int {
    let a = with_attr_ref!(attr);
    // SAFETY: `cpuset` holds `cpusetsize` writable bytes (C contract).
    let out = unsafe { rusty_libc_core::ffi::bytes_mut(cpuset.cast::<u8>(), cpusetsize) };
    a.get_affinity(out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setsigmask_np(attr: *mut PthreadAttr, sigmask: *const SigsetT) -> c_int {
    // SAFETY: `sigmask` is NULL or a valid sigset_t (C contract).
    let m = unsafe { sigmask.as_ref() };
    with_attr!(attr).set_sigmask(m)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getsigmask_np(attr: *const PthreadAttr, sigmask: *mut SigsetT) -> c_int {
    let m = with_attr_ref!(attr).sigmask();
    let out = out!(sigmask);
    *out = SigsetT { val: [0; 16] };
    match m {
        None => PTHREAD_ATTR_NO_SIGMASK,
        Some(v) => {
            out.val[0] = v;
            0
        }
    }
}

/// `pthread_attr_getsigmask_np` returns PTHREAD_ATTR_NOSIGMASK_NP (-1) when no mask was set.
pub const PTHREAD_ATTR_NO_SIGMASK: c_int = -1;

/// Raw sched_setscheduler(tid, ...).
pub fn sched_setscheduler(tid: i32, policy: c_int, param: &SchedParam) -> c_int {
    // SAFETY: `param` is a valid struct sched_param borrowed for the call.
    errno_of(unsafe { syscall3(SYS_SCHED_SETSCHEDULER, tid as usize, policy as usize, param as *const SchedParam as usize) })
}

/// sched_setaffinity(tid, mask): 0 or the error number.
pub fn sched_setaffinity(tid: i32, mask: &[u8]) -> c_int {
    // SAFETY: the kernel reads `mask.len()` bytes of the borrowed mask.
    errno_of(unsafe { syscall3(SYS_SCHED_SETAFFINITY, tid as usize, mask.len(), mask.as_ptr() as usize) })
}

/// sched_getaffinity(tid, mask): the number of bytes the kernel wrote, or -errno.
pub fn sched_getaffinity(tid: i32, mask: &mut [u8]) -> isize {
    // SAFETY: the kernel writes at most `mask.len()` bytes into the borrowed mask.
    let r = unsafe { syscall3(SYS_SCHED_GETAFFINITY, tid as usize, mask.len(), mask.as_mut_ptr() as usize) };
    let e = errno_of(r);
    if e != 0 { -(e as isize) } else { r as isize }
}

pub fn sched_setparam(tid: i32, param: &SchedParam) -> c_int {
    // SAFETY: `param` is a valid struct sched_param borrowed for the call.
    errno_of(unsafe { rusty_libc_core::syscall::syscall2(SYS_SCHED_SETPARAM, tid as usize, param as *const SchedParam as usize) })
}

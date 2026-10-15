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

#[repr(C)]
pub struct AttrExt {
    pub map_size: usize,
    pub cpusetsize: usize,
    pub sigmask: u64,
    pub sigmask_set: u32,
    pub _pad: u32,
}

const EXT_HDR: usize = core::mem::size_of::<AttrExt>();

impl AttrExt {
    pub fn cpuset(&self) -> &[u8] {
        let n = self.cpusetsize.min(self.map_size.saturating_sub(EXT_HDR));
        let p = (self as *const AttrExt).wrapping_add(1).cast::<u8>();
        unsafe { rusty_libc_core::ffi::bytes(p, n) }
    }

    pub(crate) fn room_mut(&mut self, n: usize) -> &mut [u8] {
        assert!(EXT_HDR + n <= self.map_size);
        let p = (self as *mut AttrExt).wrapping_add(1).cast::<u8>();
        unsafe { rusty_libc_core::ffi::bytes_mut(p, n) }
    }
}

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
    let min = unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GET_PRIORITY_MIN, policy as usize) };
    let max = unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GET_PRIORITY_MAX, policy as usize) };
    if errno_of(max) != 0 || errno_of(min) != 0 { None } else { Some((min as c_int, max as c_int)) }
}

fn check_prio(prio: c_int, policy: c_int) -> c_int {
    match sched_prio_range(policy) {
        Some((lo, hi)) if prio >= lo && prio <= hi => 0,
        _ => EINVAL,
    }
}

pub fn kernel_cpumask_size() -> usize {
    static SIZE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let s = SIZE.load(core::sync::atomic::Ordering::Relaxed);
    if s != 0 {
        return s;
    }
    let mut buf = [0u8; 1024];
    let mut size = 128usize;
    loop {
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
    pub const fn new() -> PthreadAttr {
        PthreadAttr { schedparam: SchedParam { sched_priority: 0 }, schedpolicy: 0, flags: 0, guardsize: PAGE, stackaddr: core::ptr::null_mut(), stacksize: 0, extension: core::ptr::null_mut(), unused: core::ptr::null_mut() }
    }

    pub fn ext(&self) -> Option<&AttrExt> {
        unsafe { self.extension.as_ref() }
    }

    fn ext_mut(&mut self) -> Option<&mut AttrExt> {
        unsafe { self.extension.as_mut() }
    }

    fn ext_get(&mut self, size_needed: usize) -> Result<&mut AttrExt, c_int> {
        if self.ext().is_some_and(|e| e.map_size >= EXT_HDR + size_needed) {
            return self.ext_mut().ok_or(ENOMEM);
        }
        let len = EXT_HDR + size_needed;
        let p = unsafe { rusty_libc_malloc::calloc(1, len) }.cast::<AttrExt>();
        let Some(new) = (unsafe { p.as_mut() }) else { return Err(ENOMEM) };
        if let Some(cur) = self.ext() {
            new.sigmask = cur.sigmask;
            new.sigmask_set = cur.sigmask_set;
            unsafe { rusty_libc_malloc::free(self.extension.cast()) };
        }
        new.map_size = len;
        self.extension = p;
        Ok(new)
    }

    pub(crate) fn ext_alloc(&mut self, size: usize) -> Result<&mut AttrExt, c_int> {
        let len = EXT_HDR + size;
        let p = unsafe { rusty_libc_malloc::calloc(1, len) }.cast::<AttrExt>();
        let Some(e) = (unsafe { p.as_mut() }) else { return Err(ENOMEM) };
        e.map_size = len;
        self.extension = p;
        Ok(e)
    }

    pub fn destroy(&mut self) {
        if !self.extension.is_null() {
            unsafe { rusty_libc_malloc::free(self.extension.cast()) };
            self.extension = core::ptr::null_mut();
        }
    }

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

    pub fn set_affinity(&mut self, cpuset: Option<&[u8]>) -> c_int {
        let Some(cpuset) = cpuset.filter(|c| !c.is_empty()) else {
            if let Some(e) = self.ext_mut() {
                e.cpusetsize = 0;
            }
            return 0;
        };
        let ks = kernel_cpumask_size();
        if cpuset.len() > ks && cpuset[ks..].iter().any(|&b| b != 0) {
            return EINVAL;
        }
        let Ok(e) = self.ext_get(cpuset.len()) else { return ENOMEM };
        e.cpusetsize = cpuset.len();
        e.room_mut(cpuset.len()).copy_from_slice(cpuset);
        0
    }

    pub fn get_affinity(&self, out: &mut [u8]) -> c_int {
        match self.ext().map(AttrExt::cpuset).filter(|s| !s.is_empty()) {
            Some(src) => {
                if src.len() > out.len() && src[out.len()..].iter().any(|&b| b != 0) {
                    return EINVAL;
                }
                let n = src.len().min(out.len());
                out[..n].copy_from_slice(&src[..n]);
                out[n..].fill(0);
            }
            None => out.fill(0xff),
        }
        0
    }

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

    pub fn sigmask(&self) -> Option<u64> {
        self.ext().filter(|e| e.sigmask_set != 0).map(|e| e.sigmask)
    }
}

impl Default for PthreadAttr {
    fn default() -> Self {
        Self::new()
    }
}

const PAD_AT: usize = core::mem::offset_of!(PthreadAttr, flags) + core::mem::size_of::<c_int>();
const PAD_LEN: usize = core::mem::offset_of!(PthreadAttr, guardsize) - PAD_AT;

pub(crate) unsafe fn write_attr(dst: *mut PthreadAttr, a: PthreadAttr) {
    unsafe { core::ptr::write(dst, a) };
    unsafe { core::ptr::write_bytes(dst.cast::<u8>().wrapping_add(PAD_AT), 0, PAD_LEN) };
}

pub unsafe fn attr_copy(dst: *mut PthreadAttr, src: *const PthreadAttr) -> c_int {
    let (d, r) = match unsafe { arg(src) }.duplicate() {
        Ok(d) => (d, 0),
        Err((d, e)) => (d, e),
    };
    unsafe { core::ptr::copy_nonoverlapping(src, dst, 1) };
    unsafe { (*dst).extension = d.extension };
    r
}

macro_rules! with_attr {
    ($p:expr) => {{
        unsafe { arg_mut($p) }
    }};
}
macro_rules! with_attr_ref {
    ($p:expr) => {{
        unsafe { arg($p) }
    }};
}
macro_rules! out {
    ($p:expr) => {{
        unsafe { arg_mut($p) }
    }};
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_init(attr: *mut PthreadAttr) -> c_int {
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
        Some(unsafe { rusty_libc_core::ffi::bytes(cpuset.cast::<u8>(), cpusetsize) })
    };
    with_attr!(attr).set_affinity(set)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getaffinity_np(attr: *const PthreadAttr, cpusetsize: usize, cpuset: *mut CpuSet) -> c_int {
    let a = with_attr_ref!(attr);
    let out = unsafe { rusty_libc_core::ffi::bytes_mut(cpuset.cast::<u8>(), cpusetsize) };
    a.get_affinity(out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setsigmask_np(attr: *mut PthreadAttr, sigmask: *const SigsetT) -> c_int {
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

pub const PTHREAD_ATTR_NO_SIGMASK: c_int = -1;

pub fn sched_setscheduler(tid: i32, policy: c_int, param: &SchedParam) -> c_int {
    errno_of(unsafe { syscall3(SYS_SCHED_SETSCHEDULER, tid as usize, policy as usize, param as *const SchedParam as usize) })
}

pub fn sched_setaffinity(tid: i32, mask: &[u8]) -> c_int {
    errno_of(unsafe { syscall3(SYS_SCHED_SETAFFINITY, tid as usize, mask.len(), mask.as_ptr() as usize) })
}

pub fn sched_getaffinity(tid: i32, mask: &mut [u8]) -> isize {
    let r = unsafe { syscall3(SYS_SCHED_GETAFFINITY, tid as usize, mask.len(), mask.as_mut_ptr() as usize) };
    let e = errno_of(r);
    if e != 0 { -(e as isize) } else { r as isize }
}

pub fn sched_setparam(tid: i32, param: &SchedParam) -> c_int {
    errno_of(unsafe { rusty_libc_core::syscall::syscall2(SYS_SCHED_SETPARAM, tid as usize, param as *const SchedParam as usize) })
}

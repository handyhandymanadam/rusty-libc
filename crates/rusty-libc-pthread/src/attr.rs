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
    pub fn cpuset(&self) -> *mut u8 {
        if self.cpusetsize == 0 { core::ptr::null_mut() } else { unsafe { (self as *const AttrExt as *mut u8).add(EXT_HDR) } }
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
    let max = unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GET_PRIORITY_MAX, policy as usize) };
    let min = unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GET_PRIORITY_MIN, policy as usize) };
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
    let mut buf = [0u64; 128];
    let mut size = 128usize;
    loop {
        let r = unsafe { syscall3(SYS_SCHED_GETAFFINITY, 0, size, buf.as_mut_ptr() as usize) };
        if errno_of(r) == 0 {
            SIZE.store(r, core::sync::atomic::Ordering::Relaxed);
            return r;
        }
        if errno_of(r) != EINVAL || size >= 8192 {
            return 128;
        }
        size *= 2;
    }
}

unsafe fn ext_get(a: *mut PthreadAttr, size_needed: usize) -> Result<*mut AttrExt, c_int> {
    unsafe {
        let cur = (*a).extension;
        if !cur.is_null() && (*cur).map_size >= EXT_HDR + size_needed {
            return Ok(cur);
        }
        let len = align_up(EXT_HDR + size_needed, PAGE);
        let p = mmap(len, 3).map_err(|_| ENOMEM)? as *mut AttrExt;
        if !cur.is_null() {
            (*p).sigmask = (*cur).sigmask;
            (*p).sigmask_set = (*cur).sigmask_set;
            munmap(cur as *mut u8, (*cur).map_size);
        }
        (*p).map_size = len;
        (*a).extension = p;
        Ok(p)
    }
}

pub unsafe fn attr_copy(dst: *mut PthreadAttr, src: *const PthreadAttr) -> c_int {
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, 1);
        (*dst).extension = core::ptr::null_mut();
        let se = (*src).extension;
        if !se.is_null() {
            let r = ext_get(dst, (*se).cpusetsize);
            let Ok(de) = r else { return ENOMEM };
            (*de).cpusetsize = (*se).cpusetsize;
            (*de).sigmask = (*se).sigmask;
            (*de).sigmask_set = (*se).sigmask_set;
            core::ptr::copy_nonoverlapping(se.add(1) as *const u8, de.add(1) as *mut u8, (*se).cpusetsize);
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_init(attr: *mut PthreadAttr) -> c_int {
    unsafe {
        core::ptr::write_bytes(attr, 0, 1);
        (*attr).guardsize = PAGE;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_destroy(attr: *mut PthreadAttr) -> c_int {
    unsafe {
        let e = (*attr).extension;
        if !e.is_null() {
            munmap(e as *mut u8, (*e).map_size);
            (*attr).extension = core::ptr::null_mut();
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getdetachstate(attr: *const PthreadAttr, detachstate: *mut c_int) -> c_int {
    unsafe {
        *detachstate = if (*attr).flags & ATTR_FLAG_DETACHSTATE != 0 { PTHREAD_CREATE_DETACHED } else { PTHREAD_CREATE_JOINABLE };
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setdetachstate(attr: *mut PthreadAttr, detachstate: c_int) -> c_int {
    unsafe {
        match detachstate {
            PTHREAD_CREATE_DETACHED => (*attr).flags |= ATTR_FLAG_DETACHSTATE,
            PTHREAD_CREATE_JOINABLE => (*attr).flags &= !ATTR_FLAG_DETACHSTATE,
            _ => return EINVAL,
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getguardsize(attr: *const PthreadAttr, guardsize: *mut usize) -> c_int {
    unsafe {
        *guardsize = (*attr).guardsize;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setguardsize(attr: *mut PthreadAttr, guardsize: usize) -> c_int {
    unsafe {
        (*attr).guardsize = guardsize;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getschedparam(attr: *const PthreadAttr, param: *mut SchedParam) -> c_int {
    unsafe {
        *param = (*attr).schedparam;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setschedparam(attr: *mut PthreadAttr, param: *const SchedParam) -> c_int {
    unsafe {
        let r = check_prio((*param).sched_priority, (*attr).schedpolicy);
        if r != 0 {
            return r;
        }
        (*attr).schedparam = *param;
        (*attr).flags |= ATTR_FLAG_SCHED_SET;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getschedpolicy(attr: *const PthreadAttr, policy: *mut c_int) -> c_int {
    unsafe {
        *policy = (*attr).schedpolicy;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setschedpolicy(attr: *mut PthreadAttr, policy: c_int) -> c_int {
    unsafe {
        if !(SCHED_OTHER..=SCHED_RR).contains(&policy) {
            return EINVAL;
        }
        (*attr).schedpolicy = policy;
        (*attr).flags |= ATTR_FLAG_POLICY_SET;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getinheritsched(attr: *const PthreadAttr, inherit: *mut c_int) -> c_int {
    unsafe {
        *inherit = if (*attr).flags & ATTR_FLAG_NOTINHERITSCHED != 0 { PTHREAD_EXPLICIT_SCHED } else { PTHREAD_INHERIT_SCHED };
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setinheritsched(attr: *mut PthreadAttr, inherit: c_int) -> c_int {
    unsafe {
        match inherit {
            PTHREAD_EXPLICIT_SCHED => (*attr).flags |= ATTR_FLAG_NOTINHERITSCHED,
            PTHREAD_INHERIT_SCHED => (*attr).flags &= !ATTR_FLAG_NOTINHERITSCHED,
            _ => return EINVAL,
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getscope(attr: *const PthreadAttr, scope: *mut c_int) -> c_int {
    unsafe {
        *scope = if (*attr).flags & ATTR_FLAG_SCOPEPROCESS != 0 { PTHREAD_SCOPE_PROCESS } else { PTHREAD_SCOPE_SYSTEM };
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setscope(attr: *mut PthreadAttr, scope: c_int) -> c_int {
    unsafe {
        match scope {
            PTHREAD_SCOPE_SYSTEM => (*attr).flags &= !ATTR_FLAG_SCOPEPROCESS,
            PTHREAD_SCOPE_PROCESS => return ENOTSUP,
            _ => return EINVAL,
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstackaddr(attr: *const PthreadAttr, stackaddr: *mut *mut c_void) -> c_int {
    unsafe {
        *stackaddr = (*attr).stackaddr;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstackaddr(attr: *mut PthreadAttr, stackaddr: *mut c_void) -> c_int {
    unsafe {
        (*attr).stackaddr = stackaddr;
        (*attr).flags |= ATTR_FLAG_STACKADDR;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstacksize(attr: *const PthreadAttr, stacksize: *mut usize) -> c_int {
    unsafe {
        *stacksize = (*attr).stacksize;
        if *stacksize == 0 {
            *stacksize = crate::thread::default_stacksize();
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstacksize(attr: *mut PthreadAttr, stacksize: usize) -> c_int {
    unsafe {
        if stacksize < PTHREAD_STACK_MIN {
            return EINVAL;
        }
        (*attr).stacksize = stacksize;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstack(attr: *const PthreadAttr, stackaddr: *mut *mut c_void, stacksize: *mut usize) -> c_int {
    unsafe {
        *stackaddr = ((*attr).stackaddr as *mut u8).wrapping_sub((*attr).stacksize) as *mut c_void;
        *stacksize = (*attr).stacksize;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstack(attr: *mut PthreadAttr, stackaddr: *mut c_void, stacksize: usize) -> c_int {
    unsafe {
        if stacksize < PTHREAD_STACK_MIN {
            return EINVAL;
        }
        (*attr).stacksize = stacksize;
        (*attr).stackaddr = (stackaddr as *mut u8).wrapping_add(stacksize) as *mut c_void;
        (*attr).flags |= ATTR_FLAG_STACKADDR;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setaffinity_np(attr: *mut PthreadAttr, cpusetsize: usize, cpuset: *const CpuSet) -> c_int {
    unsafe {
        let cpuset = cpuset as *const u8;
        if cpuset.is_null() || cpusetsize == 0 {
            let e = (*attr).extension;
            if !e.is_null() {
                (*e).cpusetsize = 0;
            }
            return 0;
        }
        let ks = kernel_cpumask_size();
        if cpusetsize > ks {
            for i in ks..cpusetsize {
                if *cpuset.add(i) != 0 {
                    return EINVAL;
                }
            }
        }
        let Ok(e) = ext_get(attr, cpusetsize) else { return ENOMEM };
        (*e).cpusetsize = cpusetsize;
        core::ptr::copy_nonoverlapping(cpuset, e.add(1) as *mut u8, cpusetsize);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getaffinity_np(attr: *const PthreadAttr, cpusetsize: usize, cpuset: *mut CpuSet) -> c_int {
    unsafe {
        let cpuset = cpuset as *mut u8;
        let e = (*attr).extension;
        if !e.is_null() && (*e).cpusetsize != 0 {
            let have = (*e).cpusetsize;
            let src = e.add(1) as *const u8;
            if have > cpusetsize {
                for i in cpusetsize..have {
                    if *src.add(i) != 0 {
                        return EINVAL;
                    }
                }
            }
            let n = have.min(cpusetsize);
            core::ptr::copy_nonoverlapping(src, cpuset, n);
            core::ptr::write_bytes(cpuset.add(n), 0, cpusetsize - n);
        } else {
            core::ptr::write_bytes(cpuset, 0xff, cpusetsize);
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setsigmask_np(attr: *mut PthreadAttr, sigmask: *const SigsetT) -> c_int {
    unsafe {
        if sigmask.is_null() {
            let e = (*attr).extension;
            if !e.is_null() {
                (*e).sigmask_set = 0;
            }
            return 0;
        }
        let Ok(e) = ext_get(attr, 0) else { return ENOMEM };
        (*e).sigmask = (*sigmask).val[0] & !crate::cancel::INTERNAL_SIGNALS;
        (*e).sigmask_set = 1;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getsigmask_np(attr: *const PthreadAttr, sigmask: *mut SigsetT) -> c_int {
    unsafe {
        let e = (*attr).extension;
        if e.is_null() || (*e).sigmask_set == 0 {
            *sigmask = SigsetT { val: [0; 16] };
            return PTHREAD_ATTR_NO_SIGMASK;
        }
        *sigmask = SigsetT { val: [0; 16] };
        (*sigmask).val[0] = (*e).sigmask;
        0
    }
}

pub const PTHREAD_ATTR_NO_SIGMASK: c_int = -1;

pub fn sched_setscheduler(tid: i32, policy: c_int, param: &SchedParam) -> c_int {
    errno_of(unsafe { syscall3(SYS_SCHED_SETSCHEDULER, tid as usize, policy as usize, param as *const SchedParam as usize) })
}

pub fn sched_setaffinity(tid: i32, size: usize, mask: *const u8) -> c_int {
    errno_of(unsafe { syscall3(SYS_SCHED_SETAFFINITY, tid as usize, size, mask as usize) })
}

pub fn sched_getaffinity(tid: i32, size: usize, mask: *mut u8) -> isize {
    let r = unsafe { syscall3(SYS_SCHED_GETAFFINITY, tid as usize, size, mask as usize) };
    let e = errno_of(r);
    if e != 0 { -(e as isize) } else { r as isize }
}

pub fn sched_setparam(tid: i32, param: &SchedParam) -> c_int {
    errno_of(unsafe { rusty_libc_core::syscall::syscall2(SYS_SCHED_SETPARAM, tid as usize, param as *const SchedParam as usize) })
}

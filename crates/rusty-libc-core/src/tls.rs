use crate::syscall::{self, syscall2, syscall6};
use core::ptr::null_mut;

const SYS_ARCH_PRCTL: usize = 158;
const ARCH_SET_FS: usize = 0x1002;
const SYS_MMAP: usize = 9;
const SYS_MUNMAP: usize = 11;

pub const AT_PHDR: usize = 3;
pub const AT_PHENT: usize = 4;
pub const AT_PHNUM: usize = 5;
pub const AT_RANDOM: usize = 25;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;

pub const TCB_SIZE: usize = 4096;

#[repr(C)]
pub struct Tcb {
    pub tcb: *mut Tcb,
    pub dtv: *mut u8,
    pub self_ptr: *mut Tcb,
    pub multiple_threads: i32,
    pub gscope_flag: i32,
    pub sysinfo: usize,
    pub stack_guard: usize,
    pub pointer_guard: usize,
    pub tid: i32,
    pub _pad: i32,
    pub cancelhandling: u32,
    pub _pad2: u32,
    pub dl_error: usize,
    pub db_list: crate::thread_db::ListT,
    pub db_start: usize,
    pub db: crate::thread_db::DbZero,
    pub db_dtv: [usize; 6],
}

#[inline(always)]
pub fn current() -> *mut Tcb {
    let p: *mut Tcb;
    unsafe { core::arch::asm!("mov {}, fs:0", out(reg) p, options(nostack, readonly, preserves_flags)) };
    p
}

#[inline(always)]
pub fn current_tid() -> i32 {
    let v: i32;
    unsafe {
        core::arch::asm!("mov {0:e}, fs:[{off}]", out(reg) v, off = const core::mem::offset_of!(Tcb, tid), options(nostack, readonly, preserves_flags))
    };
    v
}

#[repr(C)]
struct Phdr {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

#[derive(Clone, Copy)]
pub struct Template {
    pub image: usize,
    pub filesz: usize,
    pub memsz: usize,
    pub align: usize,
}

static mut TEMPLATE: Template = Template { image: 0, filesz: 0, memsz: 0, align: 1 };

#[cfg(feature = "shared")]
pub static DL_TLS_INIT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "shared")]
pub static DL_TLS_FREE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg(feature = "shared")]
pub static DL_TLS_SYNC: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "shared")]
pub static DL_FORK_CHILD: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub unsafe fn loader_fork_child() {
    #[cfg(feature = "shared")]
    {
        let h = DL_FORK_CHILD.load(core::sync::atomic::Ordering::Relaxed);
        if h != 0 {
            unsafe { core::mem::transmute::<usize, unsafe extern "C" fn()>(h)() };
        }
    }
}

#[cfg(feature = "shared")]
pub static MAIN_TP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg(feature = "shared")]
pub const DL_DEBUG_TLS_BIT: u32 = 1 << 11;
#[cfg(feature = "shared")]
pub static DL_DEBUG_WRITE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub enum DebugArg<'a> {
    S(&'a [u8]),
    X(usize),
    D(i64),
}

#[inline]
pub fn debug_tls_on() -> bool {
    #[cfg(feature = "shared")]
    {
        DL_DEBUG_WRITE.load(core::sync::atomic::Ordering::Relaxed) != 0
    }
    #[cfg(not(feature = "shared"))]
    {
        false
    }
}

pub fn debug_tls(parts: &[DebugArg<'_>]) {
    #[cfg(feature = "shared")]
    {
        let h = DL_DEBUG_WRITE.load(core::sync::atomic::Ordering::Relaxed);
        if h == 0 {
            return;
        }
        let mut buf = [0u8; 256];
        let mut n = 0;
        let mut put = |b: &[u8]| {
            let k = b.len().min(buf.len() - n);
            buf[n..n + k].copy_from_slice(&b[..k]);
            n += k;
        };
        for p in parts {
            let mut t = [0u8; 24];
            let mut i = t.len();
            match *p {
                DebugArg::S(s) => put(s),
                DebugArg::X(mut v) => {
                    loop {
                        i -= 1;
                        t[i] = b"0123456789abcdef"[v & 15];
                        v >>= 4;
                        if v == 0 {
                            break;
                        }
                    }
                    put(b"0x");
                    put(&t[i..]);
                }
                DebugArg::D(v) => {
                    let mut u = v.unsigned_abs();
                    loop {
                        i -= 1;
                        t[i] = b'0' + (u % 10) as u8;
                        u /= 10;
                        if u == 0 {
                            break;
                        }
                    }
                    if v < 0 {
                        i -= 1;
                        t[i] = b'-';
                    }
                    put(&t[i..]);
                }
            }
        }
        put(b"\n");
        unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*const u8, usize)>(h)(buf.as_ptr(), n) };
    }
    #[cfg(not(feature = "shared"))]
    let _ = parts;
}

pub unsafe fn sync_new_thread(tp: *mut Tcb) {
    #[cfg(feature = "shared")]
    {
        let h = DL_TLS_SYNC.load(core::sync::atomic::Ordering::Relaxed);
        if h != 0 {
            unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Tcb)>(h)(tp) };
        }
    }
    #[cfg(not(feature = "shared"))]
    let _ = tp;
}

pub fn main_thread_pointer() -> usize {
    #[cfg(feature = "shared")]
    {
        MAIN_TP.load(core::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(feature = "shared"))]
    {
        0
    }
}

#[cfg(feature = "shared")]
pub unsafe fn set_dynamic_template(memsz: usize, align: usize) {
    unsafe { *core::ptr::addr_of_mut!(TEMPLATE) = Template { image: 0, filesz: 0, memsz, align: align.max(1) } };
}

pub unsafe fn dtv_allocation(tp: *mut Tcb) -> usize {
    #[cfg(feature = "shared")]
    {
        if DL_TLS_INIT.load(core::sync::atomic::Ordering::Relaxed) == 0 {
            return 0;
        }
        unsafe {
            let d = *((tp as usize + 8) as *const usize);
            if d == 0 { 0 } else { *((d + 8) as *const usize) }
        }
    }
    #[cfg(not(feature = "shared"))]
    {
        let _ = tp;
        0
    }
}

pub unsafe fn release_block(tp: *mut Tcb) {
    #[cfg(feature = "shared")]
    {
        let h = DL_TLS_FREE.load(core::sync::atomic::Ordering::Relaxed);
        if h != 0 {
            unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Tcb)>(h)(tp) };
        }
    }
    #[cfg(not(feature = "shared"))]
    let _ = tp;
}

pub fn template() -> Template {
    unsafe { *core::ptr::addr_of!(TEMPLATE) }
}

fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

unsafe fn find_template(aux: *const usize) -> Template {
    unsafe {
        let (mut phdr, mut phent, mut phnum) = (0usize, 0usize, 0usize);
        let mut a = aux;
        while *a != 0 {
            match *a {
                AT_PHDR => phdr = *a.add(1),
                AT_PHENT => phent = *a.add(1),
                AT_PHNUM => phnum = *a.add(1),
                _ => {}
            }
            a = a.add(2);
        }
        let mut t = Template { image: 0, filesz: 0, memsz: 0, align: 1 };
        if phdr == 0 || phent < core::mem::size_of::<Phdr>() {
            return t;
        }
        let mut bias = 0usize;
        for i in 0..phnum {
            let h = &*((phdr + i * phent) as *const Phdr);
            if h.kind == PT_PHDR {
                bias = phdr.wrapping_sub(h.vaddr as usize);
            }
        }
        for i in 0..phnum {
            let h = &*((phdr + i * phent) as *const Phdr);
            if h.kind == PT_TLS {
                t = Template { image: (h.vaddr as usize).wrapping_add(bias), filesz: h.filesz as usize, memsz: h.memsz as usize, align: (h.align as usize).max(1) };
            }
        }
        t
    }
}

pub fn block_layout(t: &Template) -> (usize, usize) {
    let align = t.align.max(64);
    let tls = align_up(t.memsz, align);
    (tls + TCB_SIZE, tls)
}

pub unsafe fn setup_block(base: *mut u8, t: &Template, canary: usize, pointer_guard: usize) -> *mut Tcb {
    unsafe {
        let (_, tp_off) = block_layout(t);
        let tp = base.add(tp_off) as *mut Tcb;
        if t.filesz > 0 {
            core::ptr::copy_nonoverlapping(t.image as *const u8, (tp as *mut u8).sub(align_up(t.memsz, t.align.max(1))), t.filesz);
        }
        (*tp).tcb = tp;
        (*tp).self_ptr = tp;
        (*tp).stack_guard = canary;
        (*tp).pointer_guard = pointer_guard;
        #[cfg(not(feature = "shared"))]
        crate::thread_db::set_static_dtv(tp, (tp as usize).wrapping_sub(align_up(t.memsz, t.align.max(1))));
        #[cfg(feature = "shared")]
        {
            let h = DL_TLS_INIT.load(core::sync::atomic::Ordering::Relaxed);
            if h != 0 {
                core::mem::transmute::<usize, unsafe extern "C" fn(*mut Tcb)>(h)(tp);
            }
        }
        tp
    }
}

pub unsafe fn set_thread_pointer(tp: *mut Tcb) {
    unsafe { syscall2(SYS_ARCH_PRCTL, ARCH_SET_FS, tp as usize) };
}

pub unsafe fn init_main(aux: *const usize) {
    unsafe {
        let t = find_template(aux);
        *core::ptr::addr_of_mut!(TEMPLATE) = t;
        let (size, _) = block_layout(&t);
        let base = syscall6(SYS_MMAP, 0, size, 3, 0x22, usize::MAX, 0);
        if base > usize::MAX - 4095 {
            syscall2(231, 127, 0);
            loop {
                core::hint::spin_loop();
            }
        }
        let (mut canary, mut guard) = (0usize, 0usize);
        let mut a = aux;
        while *a != 0 {
            if *a == AT_RANDOM {
                let r = *a.add(1) as *const usize;
                if !r.is_null() {
                    canary = *r & !0xff;
                    guard = *r.add(1);
                }
            }
            a = a.add(2);
        }
        let tp = setup_block(base as *mut u8, &t, canary, guard);
        set_thread_pointer(tp);
        (*tp).tid = syscall::syscall0(syscall::SYS_GETTID) as i32;
        syscall::syscall1(218 , core::ptr::addr_of_mut!((*tp).tid) as usize);
        crate::thread_db::init(tp, 0);
    }
}

pub fn refresh_tid_after_fork() {
    let tp = current();
    if !tp.is_null() {
        unsafe {
            (*tp).tid = syscall::syscall0(syscall::SYS_GETTID) as i32;
            syscall::syscall1(218 , core::ptr::addr_of_mut!((*tp).tid) as usize);
        }
    }
}

pub const NO_TCB: *mut Tcb = null_mut();

pub static CANCEL_SYSCALL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[inline]
pub unsafe fn syscall_cp(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    unsafe {
        let h = CANCEL_SYSCALL.load(core::sync::atomic::Ordering::Relaxed);
        if h == 0 {
            syscall6(nr, a1, a2, a3, a4, a5, a6)
        } else {
            let f: extern "C" fn(usize, usize, usize, usize, usize, usize, usize) -> usize = core::mem::transmute(h);
            f(nr, a1, a2, a3, a4, a5, a6)
        }
    }
}

const _: () = assert!(core::mem::offset_of!(Tcb, multiple_threads) == 0x18);
const _: () = assert!(core::mem::offset_of!(Tcb, stack_guard) == 0x28);
const _: () = assert!(core::mem::offset_of!(Tcb, pointer_guard) == 0x30);
const _: () = assert!(core::mem::offset_of!(Tcb, tid) == 0x38);
const _: () = assert!(core::mem::offset_of!(Tcb, cancelhandling) == 0x40);
const _: () = assert!(core::mem::offset_of!(Tcb, dl_error) == 0x48);

const INLINE_DTORS: usize = 2;
const MORE_PAGE: usize = 4096;

#[derive(Clone, Copy)]
struct ThreadDtor {
    f: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    obj: *mut core::ffi::c_void,
}

const MORE_DTORS: usize = MORE_PAGE / core::mem::size_of::<ThreadDtor>();

#[thread_local]
static mut THREAD_DTORS: [ThreadDtor; INLINE_DTORS] = [ThreadDtor { f: None, obj: core::ptr::null_mut() }; INLINE_DTORS];
#[thread_local]
static mut THREAD_DTORS_MORE: *mut ThreadDtor = null_mut();
#[thread_local]
static mut THREAD_DTOR_N: usize = 0;

pub fn register_thread_dtor(f: unsafe extern "C" fn(*mut core::ffi::c_void), obj: *mut core::ffi::c_void) -> bool {
    unsafe {
        let n = THREAD_DTOR_N;
        let d = ThreadDtor { f: Some(f), obj };
        if n < INLINE_DTORS {
            (*core::ptr::addr_of_mut!(THREAD_DTORS))[n] = d;
        } else {
            if n - INLINE_DTORS >= MORE_DTORS {
                return false;
            }
            if THREAD_DTORS_MORE.is_null() {
                let p = syscall6(SYS_MMAP, 0, MORE_PAGE, 3, 0x22, usize::MAX, 0);
                if p > usize::MAX - 4095 {
                    return false;
                }
                THREAD_DTORS_MORE = p as *mut ThreadDtor;
            }
            *THREAD_DTORS_MORE.add(n - INLINE_DTORS) = d;
        }
        THREAD_DTOR_N = n + 1;
        true
    }
}

pub fn run_thread_dtors() {
    unsafe {
        while THREAD_DTOR_N > 0 {
            THREAD_DTOR_N -= 1;
            let n = THREAD_DTOR_N;
            let d = if n < INLINE_DTORS { (*core::ptr::addr_of_mut!(THREAD_DTORS))[n] } else { *THREAD_DTORS_MORE.add(n - INLINE_DTORS) };
            if let Some(f) = d.f {
                f(d.obj);
            }
        }
        if !THREAD_DTORS_MORE.is_null() {
            syscall2(SYS_MUNMAP, THREAD_DTORS_MORE as usize, MORE_PAGE);
            THREAD_DTORS_MORE = null_mut();
        }
    }
}

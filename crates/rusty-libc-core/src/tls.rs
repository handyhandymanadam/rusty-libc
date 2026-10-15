#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::SyncCell;
use crate::syscall::{self, syscall2, syscall6};
use core::cell::Cell;
use core::ptr::null_mut;

const SYS_ARCH_PRCTL: usize = 158;
const ARCH_SET_FS: usize = 0x1002;
const SYS_MMAP: usize = 9;
const SYS_BRK: usize = 12;

pub const AT_PHDR: usize = 3;
pub const AT_PHENT: usize = 4;
pub const AT_PHNUM: usize = 5;
pub const AT_RANDOM: usize = 25;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;

pub const TCB_SIZE: usize = 2368;

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
    pub _unused38: [i32; 2],
    pub cancelhandling: u32,
    pub _pad2: u32,
    pub feature_1: u32,
    pub _unused4c: i32,
    pub private_tm: [usize; 4],
    pub private_ss: usize,
    pub ssp_base: usize,
    pub dl_error: usize,
    pub db_list: crate::thread_db::ListT,
    pub db_start: usize,
    pub db: crate::thread_db::DbZero,
    pub db_dtv: [usize; 6],
    pub _gap: [u8; 0x2d0 - 0x100],
    pub tid: i32,
    pub _pad: i32,
    pub robust_prev: *mut u8,
    pub robust: RobustHead,
}

#[repr(C)]
pub struct RobustHead {
    pub list: *mut u8,
    pub futex_offset: isize,
    pub list_op_pending: *mut u8,
}

const _: () = assert!(TCB_SIZE == 2368 && TCB_SIZE.is_multiple_of(64));
const _: () = assert!(core::mem::size_of::<Tcb>() <= TCB_SIZE);
const _: () = assert!(core::mem::offset_of!(Tcb, tid) == 0x2d0);
const _: () = assert!(core::mem::offset_of!(Tcb, robust_prev) == 0x2d8);
const _: () = assert!(core::mem::offset_of!(Tcb, robust) == 0x2e0);

pub const ROBUST_FUTEX_OFFSET: isize = -32;
const SYS_SET_ROBUST_LIST: usize = 273;

pub unsafe fn robust_register(tp: *mut Tcb) {
    let head = unsafe { &raw mut (*tp).robust };
    unsafe { (*tp).robust_prev = head as *mut u8 };
    unsafe { head.write(RobustHead { list: head as *mut u8, futex_offset: ROBUST_FUTEX_OFFSET, list_op_pending: null_mut() }) };
    unsafe { syscall2(SYS_SET_ROBUST_LIST, head as usize, core::mem::size_of::<RobustHead>()) };
}

static STACK_END: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn set_stack_end(v: usize) {
    STACK_END.store(v, core::sync::atomic::Ordering::Relaxed);
}

pub fn stack_end() -> usize {
    #[cfg(feature = "shared")]
    {
        let a: usize;
        unsafe { core::arch::asm!(".weak __libc_stack_end", "mov {0}, [rip + __libc_stack_end@GOTPCREL]", out(reg) a, options(nomem, nostack, preserves_flags)) };
        if a != 0 {
            return unsafe { *(a as *const usize) };
        }
    }
    STACK_END.load(core::sync::atomic::Ordering::Relaxed)
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

static TEMPLATE: SyncCell<Template> = SyncCell::new(Template { image: 0, filesz: 0, memsz: 0, align: 1 });

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
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn()>(h) };
            unsafe { f() };
        }
    }
}

pub static INITIAL_TP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn is_initial_thread() -> bool {
    match INITIAL_TP.load(core::sync::atomic::Ordering::Relaxed) {
        0 => crate::unistd::gettid() == crate::unistd::getpid(),
        tp => current() as usize == tp,
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
        let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*const u8, usize)>(h) };
        unsafe { f(buf.as_ptr(), n) };
    }
    #[cfg(not(feature = "shared"))]
    let _ = parts;
}

pub unsafe fn sync_new_thread(tp: *mut Tcb) {
    #[cfg(feature = "shared")]
    {
        let h = DL_TLS_SYNC.load(core::sync::atomic::Ordering::Relaxed);
        if h != 0 {
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Tcb)>(h) };
            unsafe { f(tp) };
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
    unsafe { TEMPLATE.write(Template { image: 0, filesz: 0, memsz, align: align.max(1) }) };
}

pub unsafe fn dtv_allocation(tp: *mut Tcb) -> usize {
    #[cfg(feature = "shared")]
    {
        if DL_TLS_INIT.load(core::sync::atomic::Ordering::Relaxed) == 0 {
            return 0;
        }
        let d = unsafe { *((tp as usize + 8) as *const usize) };
        if d == 0 { 0 } else { unsafe { *((d + 8) as *const usize) } }
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
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Tcb)>(h) };
            unsafe { f(tp) };
        }
    }
    #[cfg(not(feature = "shared"))]
    let _ = tp;
}

pub fn template() -> Template {
    unsafe { TEMPLATE.read() }
}

fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

unsafe fn find_template(aux: *const usize) -> Template {
    let (mut phdr, mut phent, mut phnum) = (0usize, 0usize, 0usize);
    let mut a = aux;
    loop {
        let [tag, val] = unsafe { *(a as *const [usize; 2]) };
        if tag == 0 {
            break;
        }
        match tag {
            AT_PHDR => phdr = val,
            AT_PHENT => phent = val,
            AT_PHNUM => phnum = val,
            _ => {}
        }
        a = a.wrapping_add(2);
    }
    let mut t = Template { image: 0, filesz: 0, memsz: 0, align: 1 };
    if phdr == 0 || phent < core::mem::size_of::<Phdr>() {
        return t;
    }
    let ph = |i: usize| {
        unsafe { &*((phdr + i * phent) as *const Phdr) }
    };
    let mut bias = 0usize;
    for i in 0..phnum {
        let h = ph(i);
        if h.kind == PT_PHDR {
            bias = phdr.wrapping_sub(h.vaddr as usize);
        }
    }
    for i in 0..phnum {
        let h = ph(i);
        if h.kind == PT_TLS {
            t = Template { image: (h.vaddr as usize).wrapping_add(bias), filesz: h.filesz as usize, memsz: h.memsz as usize, align: (h.align as usize).max(1) };
        }
    }
    t
}

pub fn block_layout(t: &Template) -> (usize, usize) {
    let align = t.align.max(64);
    let tls = align_up(t.memsz, align);
    (tls + TCB_SIZE, tls)
}

pub unsafe fn setup_block(base: *mut u8, t: &Template, canary: usize, pointer_guard: usize) -> *mut Tcb {
    let (_, tp_off) = block_layout(t);
    let tp = base.wrapping_add(tp_off) as *mut Tcb;
    if t.filesz > 0 {
        let dst = (tp as *mut u8).wrapping_sub(align_up(t.memsz, t.align.max(1)));
        unsafe { core::ptr::copy_nonoverlapping(t.image as *const u8, dst, t.filesz) };
    }
    unsafe { (*tp).tcb = tp };
    unsafe { (*tp).self_ptr = tp };
    unsafe { (*tp).stack_guard = canary };
    unsafe { (*tp).pointer_guard = pointer_guard };
    #[cfg(not(feature = "shared"))]
    {
        let block = (tp as usize).wrapping_sub(align_up(t.memsz, t.align.max(1)));
        unsafe { crate::thread_db::set_static_dtv(tp, block) };
    }
    #[cfg(feature = "shared")]
    {
        let h = DL_TLS_INIT.load(core::sync::atomic::Ordering::Relaxed);
        if h != 0 {
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Tcb)>(h) };
            unsafe { f(tp) };
        }
    }
    tp
}

pub unsafe fn set_thread_pointer(tp: *mut Tcb) {
    unsafe { syscall2(SYS_ARCH_PRCTL, ARCH_SET_FS, tp as usize) };
}

pub unsafe fn init_main(aux: *const usize) {
    {
        let t = unsafe { find_template(aux) };
        unsafe { TEMPLATE.write(t) };
        let (size, _) = block_layout(&t);
        let align = t.align.max(64);
        let prev = unsafe { syscall::syscall1(SYS_BRK, 0) };
        let got = unsafe { syscall::syscall1(SYS_BRK, prev.wrapping_add(size + align)) };
        let base = if prev != 0 && got == prev.wrapping_add(size + align) {
            align_up(prev, align)
        } else {
            unsafe { syscall6(SYS_MMAP, 0, size, 3, 0x22, usize::MAX, 0) }
        };
        if base > usize::MAX - 4095 {
            unsafe { syscall2(231, 127, 0) };
            loop {
                core::hint::spin_loop();
            }
        }
        let (mut canary, mut guard) = (0usize, 0usize);
        let mut a = aux;
        loop {
            let [tag, val] = unsafe { *(a as *const [usize; 2]) };
            if tag == 0 {
                break;
            }
            if tag == AT_RANDOM {
                let r = val as *const [usize; 2];
                if !r.is_null() {
                    let [r0, r1] = unsafe { r.read_unaligned() };
                    canary = r0 & !0xff;
                    guard = r1;
                }
            }
            a = a.wrapping_add(2);
        }
        let tp = unsafe { setup_block(base as *mut u8, &t, canary, guard) };
        unsafe { set_thread_pointer(tp) };
        INITIAL_TP.store(tp as usize, core::sync::atomic::Ordering::Relaxed);
        let tidp = unsafe { core::ptr::addr_of_mut!((*tp).tid) };
        let tid = unsafe { syscall::syscall1(218 , tidp as usize) } as i32;
        unsafe { tidp.write(tid) };
        unsafe { robust_register(tp) };
        unsafe { crate::thread_db::init(tp, 0) };
    }
}

pub const NO_TCB: *mut Tcb = null_mut();

pub static CANCEL_SYSCALL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[inline]
pub unsafe fn syscall_cp(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    let h = CANCEL_SYSCALL.load(core::sync::atomic::Ordering::Relaxed);
    if h == 0 {
        unsafe { syscall6(nr, a1, a2, a3, a4, a5, a6) }
    } else {
        let f: extern "C" fn(usize, usize, usize, usize, usize, usize, usize) -> usize = unsafe { core::mem::transmute(h) };
        f(nr, a1, a2, a3, a4, a5, a6)
    }
}

const _: () = assert!(core::mem::offset_of!(Tcb, multiple_threads) == 0x18);
const _: () = assert!(core::mem::offset_of!(Tcb, stack_guard) == 0x28);
const _: () = assert!(core::mem::offset_of!(Tcb, pointer_guard) == 0x30);
const _: () = assert!(core::mem::offset_of!(Tcb, db_dtv) + 48 == 0x100);
const _: () = assert!(core::mem::offset_of!(Tcb, tid) == 0x2d0);
const _: () = assert!(core::mem::offset_of!(Tcb, cancelhandling) == 0x40);
const _: () = assert!(core::mem::offset_of!(Tcb, dl_error) == 0x80);
const _: () = assert!(core::mem::offset_of!(Tcb, feature_1) == 0x48);
const _: () = assert!(core::mem::offset_of!(Tcb, private_tm) == 0x50);
const _: () = assert!(core::mem::offset_of!(Tcb, private_ss) == 0x70);
const _: () = assert!(core::mem::offset_of!(Tcb, ssp_base) == 0x78);

const INLINE_DTORS: usize = 2;

#[derive(Clone, Copy)]
struct ThreadDtor {
    f: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    obj: *mut core::ffi::c_void,
    dso: usize,
}

const NO_DTOR: ThreadDtor = ThreadDtor { f: None, obj: core::ptr::null_mut(), dso: 0 };

#[thread_local]
static THREAD_DTORS: [Cell<ThreadDtor>; INLINE_DTORS] = [const { Cell::new(NO_DTOR) }; INLINE_DTORS];
#[thread_local]
static THREAD_DTORS_MORE: Cell<crate::pages::PageVec<ThreadDtor>> = Cell::new(crate::pages::PageVec::new());
#[thread_local]
static THREAD_DTOR_N: Cell<usize> = Cell::new(0);

pub static DL_TLS_DTOR_REF: crate::lock::Locked<Option<extern "C" fn(usize, isize)>> = crate::lock::Locked::new(None);

fn tls_dtor_ref(dso: usize, delta: isize) {
    if dso != 0
        && let Some(f) = DL_TLS_DTOR_REF.with(|h| *h)
    {
        f(dso, delta);
    }
}

pub fn register_thread_dtor(f: unsafe extern "C" fn(*mut core::ffi::c_void), obj: *mut core::ffi::c_void, dso: usize) -> bool {
    let n = THREAD_DTOR_N.get();
    let d = ThreadDtor { f: Some(f), obj, dso };
    if n < INLINE_DTORS {
        THREAD_DTORS[n].set(d);
    } else {
        let mut more = THREAD_DTORS_MORE.take();
        let ok = more.grow(n - INLINE_DTORS + 1, NO_DTOR);
        if ok {
            more.as_mut_slice()[n - INLINE_DTORS] = d;
        }
        THREAD_DTORS_MORE.set(more);
        if !ok {
            return false;
        }
    }
    THREAD_DTOR_N.set(n + 1);
    tls_dtor_ref(dso, 1);
    true
}

pub fn run_thread_dtors() {
    while THREAD_DTOR_N.get() > 0 {
        let n = THREAD_DTOR_N.get() - 1;
        THREAD_DTOR_N.set(n);
        let d = if n < INLINE_DTORS {
            THREAD_DTORS[n].get()
        } else {
            let mut more = THREAD_DTORS_MORE.take();
            let d = more.as_mut_slice()[n - INLINE_DTORS];
            THREAD_DTORS_MORE.set(more);
            d
        };
        if let Some(f) = d.f {
            unsafe { f(d.obj) };
        }
        tls_dtor_ref(d.dso, -1);
    }
    drop(THREAD_DTORS_MORE.take());
}

//! Thread-local storage for the main thread and the thread control block (TCB).
//!
//! x86-64 uses TLS variant II: the thread pointer (`%fs` base) points at the TCB; the thread's
//! TLS block sits just below it, so a `#[thread_local]` static is reached as `%fs:-offset` (the
//! linker fixes the offset for a static executable). `%fs:0` holds the TCB's own address and
//! `%fs:0x28` the stack-protector canary, which is what gcc's generated code expects.
//!
//! `init_main` runs first thing in `_start`, before any code that sets `errno`.
//!
//! What stays unsafe here, and why: the TCB is reached through the thread pointer (`%fs`), a raw address no Rust value owns;
//! its fields are read and written by other threads (the thread list, libthread_db through the debugger), by the kernel
//! (the tid at thread exit) and by compiler-generated code (`%fs:0x28`), so the code keeps raw field accesses, one per
//! block, instead of long-lived references. The loader's hooks are function addresses stored as words (`transmute` back to
//! the type they were stored from). The auxiliary vector and program headers are read where the kernel put them.
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

/// Size reserved for the TCB behind the thread pointer. Fixed offsets 0..0x40 follow glibc's
/// header (self pointer, stack canary, pointer guard); everything after is ours. glibc 2.43's `sizeof (struct pthread)` on
/// x86_64 (its `_thread_db_sizeof_pthread`), a multiple of 64: rusty-libc-pthread's `Thread` fits (asserted there). It was
/// 4096, which put every thread's stack 1.7 KB lower than glibc's on a stack the program gives (FIXLIST #79); the loader's
/// copy of this constant (rusty-libc-ldso tls.rs) must be the same.
pub const TCB_SIZE: usize = 2368;

/// The start of the thread control block. `repr(C)`: the offsets are used from assembly and by
/// compiler-generated code (`%fs:0x28`).
#[repr(C)]
pub struct Tcb {
    /// `%fs:0`: address of this TCB (the thread pointer itself).
    pub tcb: *mut Tcb,
    /// `%fs:8`: dynamic thread vector (unused in static programs).
    pub dtv: *mut u8,
    /// `%fs:16`: glibc keeps a second self pointer here.
    pub self_ptr: *mut Tcb,
    pub multiple_threads: i32,
    pub gscope_flag: i32,
    /// `%fs:0x20`: glibc's `sysinfo` slot (unused). Without it every field below sat 8 bytes too low and gcc's
    /// `%fs:0x28` canary read the pointer guard.
    pub sysinfo: usize,
    /// `%fs:0x28`: stack-protector canary.
    pub stack_guard: usize,
    /// `%fs:0x30`: pointer-mangling guard.
    pub pointer_guard: usize,
    /// `%fs:0x38`: unused (glibc's `unused_vgetcpu_cache`, which glibc no longer uses either; the thread id moved to glibc's
    /// offset, see `tid`).
    pub _unused38: [i32; 2],
    /// `%fs:0x40`: cancellation state word (bits are defined by rusty-libc-pthread: disabled, asynchronous,
    /// requested, exiting). Read by the cancellable system call stub, so it lives in the header. (Still inside glibc's unused
    /// `unused_vgetcpu_cache`: nothing outside glibc reads that slot.)
    pub cancelhandling: u32,
    pub _pad2: u32,
    /// `%fs:0x48` to `%fs:0x80`: glibc's slots that code outside the C library reads or writes, kept at their meaning:
    /// `feature_1` (CET state: 0, neither IBT nor shadow stack enabled), `__private_tm` (four words owned by libitm, GCC's
    /// transactional memory runtime, which keeps its per-thread data there), `__private_ss` (`%fs:0x70`: the split-stack
    /// limit that every function built with gcc `-fsplit-stack`, gccgo's runtime among them, compares the stack pointer with,
    /// and libgcc's `__morestack` writes) and `ssp_base` (shadow stack marker, 0). This library never writes them after the
    /// TCB is zeroed.
    pub feature_1: u32,
    pub _unused4c: i32,
    pub private_tm: [usize; 4],
    pub private_ss: usize,
    pub ssp_base: usize,
    /// `%fs:0x80` onwards is glibc's `__glibc_unused2` and `__padding` (kept only for the size of the header): this library's
    /// own fields live there.
    /// `%fs:0x80`: this thread's `dlerror` message buffer (allocated by the loader on the first error, freed with the
    /// thread's loader data). Read and written only by the dynamic loader (crates/rusty-libc-ldso, which uses the offset).
    pub dl_error: usize,
    /// The debugger's view (crate::thread_db): this thread's node in libthread_db's thread list, its start routine (0 for
    /// the main thread) and fields libthread_db reads that stay zero.
    pub db_list: crate::thread_db::ListT,
    pub db_start: usize,
    pub db: crate::thread_db::DbZero,
    /// A static program's dtv for debuggers (crate::thread_db::set_static_dtv); unused under the dynamic loader.
    pub db_dtv: [usize; 6],
    pub _gap: [u8; 0x2d0 - 0x100],
    /// `%fs:0x2d0`: kernel thread id of this thread (set by the thread code; 0 until then). At glibc's offset in its
    /// `struct pthread` (glibc's `_thread_db_pthread_tid` says 720): Chromium's zygote, after a raw clone into a new pid
    /// namespace, reads the cached id through an error-checking mutex's owner and rewrites it at pthread_self() + 0x2d0,
    /// checking first that the offset holds the cached id (its renderers died with SIGTRAP while ours was at 0x38).
    pub tid: i32,
    pub _pad: i32,
    /// `%fs:0x2d8`, `%fs:0x2e0`: the robust futex list head (glibc's `robust_prev` and `robust_head`, same offsets). The list
    /// code writes the head's previous-entry pointer one word before `robust`. Registered with the kernel at startup, in each
    /// new thread and in each forked child, as glibc does ([`robust_register`]).
    pub robust_prev: *mut u8,
    pub robust: RobustHead,
}

/// The robust futex list head the kernel walks when a thread ends (`struct robust_list_head`).
#[repr(C)]
pub struct RobustHead {
    pub list: *mut u8,
    pub futex_offset: isize,
    pub list_op_pending: *mut u8,
}

// the TCB area (FIXLIST #79): glibc 2.43's sizeof (struct pthread) on x86_64, also exported as `_thread_db_sizeof_pthread`
// (thread_db.rs) and counted in `_dl_get_tls_static_info`; 64-aligned (the thread pointer of a block is), and the whole header
// with glibc's slots (self pointers, multiple_threads, stack and pointer guards, CET word, cancelhandling, tid, robust list, the
// thread_db fields and our private ones from 0x80) lies inside it. rusty-libc-pthread asserts the same for its `Thread`
// (this header and the thread's own fields), which is what a thread keeps above its thread pointer.
const _: () = assert!(TCB_SIZE == 2368 && TCB_SIZE.is_multiple_of(64));
const _: () = assert!(core::mem::size_of::<Tcb>() <= TCB_SIZE);
const _: () = assert!(core::mem::offset_of!(Tcb, tid) == 0x2d0);
const _: () = assert!(core::mem::offset_of!(Tcb, robust_prev) == 0x2d8);
const _: () = assert!(core::mem::offset_of!(Tcb, robust) == 0x2e0);

/// glibc's `futex_offset`: from a mutex's list entry (`__list.__next`, byte 32 of `pthread_mutex_t`) back to its lock word.
pub const ROBUST_FUTEX_OFFSET: isize = -32;
const SYS_SET_ROBUST_LIST: usize = 273;

/// Start the thread's robust mutex list empty and register it with the kernel (glibc does this at startup, in every new
/// thread and in the child of every fork: the kernel forgets the registration in a forked child, and the child owns none of
/// the parent's mutexes). A failure is ignored, as in glibc.
///
/// # Safety
/// `tp` must be the calling thread's TCB.
pub unsafe fn robust_register(tp: *mut Tcb) {
    // SAFETY: `tp` is the calling thread's TCB (caller's contract): only the field's address is taken.
    let head = unsafe { &raw mut (*tp).robust };
    // SAFETY: as above; the field belongs to the calling thread.
    unsafe { (*tp).robust_prev = head as *mut u8 };
    // SAFETY: `head` points to the TCB's list head (just derived); an empty list points to itself.
    unsafe { head.write(RobustHead { list: head as *mut u8, futex_offset: ROBUST_FUTEX_OFFSET, list_op_pending: null_mut() }) };
    // SAFETY: the kernel records the address of the head, which lives as long as the thread (its TCB).
    unsafe { syscall2(SYS_SET_ROBUST_LIST, head as usize, core::mem::size_of::<RobustHead>()) };
}

/// glibc's `__libc_stack_end` for a static program: the stack pointer the kernel started the program with (set by `_start`).
static STACK_END: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn set_stack_end(v: usize) {
    STACK_END.store(v, core::sync::atomic::Ordering::Relaxed);
}

/// `__libc_stack_end`: in the shared library the loader's variable, in a static program the value `_start` recorded; 0 when
/// neither exists (host unit tests).
pub fn stack_end() -> usize {
    #[cfg(feature = "shared")]
    {
        let a: usize;
        // SAFETY: loads the GOT slot of a weak symbol (the loader fills it at relocation; 0 when the loader does not define
        // `__libc_stack_end`); register output only.
        unsafe { core::arch::asm!(".weak __libc_stack_end", "mov {0}, [rip + __libc_stack_end@GOTPCREL]", out(reg) a, options(nomem, nostack, preserves_flags)) };
        if a != 0 {
            // SAFETY: the loader's `__libc_stack_end`, a word it set before running any library code.
            return unsafe { *(a as *const usize) };
        }
    }
    STACK_END.load(core::sync::atomic::Ordering::Relaxed)
}

/// The current thread's TCB.
#[inline(always)]
pub fn current() -> *mut Tcb {
    let p: *mut Tcb;
    // SAFETY: an 8-byte read at %fs:0, which after `init_main`, the loader or thread creation holds the TCB address (in a
    // host test binary the host libc's TCB, laid out the same at offset 0).
    unsafe { core::arch::asm!("mov {}, fs:0", out(reg) p, options(nostack, readonly, preserves_flags)) };
    p
}

/// The current thread's kernel thread id (`Tcb::tid`): one `%fs`-relative load, no pointer to chase first.
#[inline(always)]
pub fn current_tid() -> i32 {
    let v: i32;
    // SAFETY: a 4-byte read of the TCB's `tid` field; as `current`, the field offset comes from the struct.
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

/// Where the program's TLS template is: initial image address and size, total size, alignment.
#[derive(Clone, Copy)]
pub struct Template {
    pub image: usize,
    pub filesz: usize,
    pub memsz: usize,
    pub align: usize,
}

/// Written once at start-up (`init_main`, or `set_dynamic_template` from libc.so.6's constructor) before any other thread
/// exists; only read afterwards.
static TEMPLATE: SyncCell<Template> = SyncCell::new(Template { image: 0, filesz: 0, memsz: 0, align: 1 });

/// Under the dynamic loader (libc.so.6): `extern "C" fn(tp)` of the loader that copies the initial images of all
/// static TLS modules into the block below `tp` and creates the thread's dtv (0 in a static program).
#[cfg(feature = "shared")]
pub static DL_TLS_INIT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// Loader function `extern "C" fn(tp)` that frees what `DL_TLS_INIT` allocated (dtv, dynamically allocated blocks).
#[cfg(feature = "shared")]
pub static DL_TLS_FREE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Loader function `extern "C" fn(tp)` run by every new thread before user code: copies the initial images of the static
/// TLS modules that were added (dlopen with initial-exec TLS) between the creation of the thread's block and now.
#[cfg(feature = "shared")]
pub static DL_TLS_SYNC: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// Loader function `extern "C" fn()` that resets the loader's locks in a forked child (`loader_fork_child`).
#[cfg(feature = "shared")]
pub static DL_FORK_CHILD: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// In a forked child, first thing: the loader's locks held by threads of the parent are released (no-op in a static
/// program).
///
/// # Safety
/// Only in the child of a fork, before any other thread exists.
pub unsafe fn loader_fork_child() {
    #[cfg(feature = "shared")]
    {
        let h = DL_FORK_CHILD.load(core::sync::atomic::Ordering::Relaxed);
        if h != 0 {
            // SAFETY: the word was stored from the address of the loader's `__libc_ldso_fork_child` (an `extern "C" fn()`).
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn()>(h) };
            // SAFETY: in the child of a fork, before other threads (caller's contract), which is when the loader expects it.
            unsafe { f() };
        }
    }
}

/// The thread pointer of the thread the program started on (set by the startup code, static and shared; 0 before it ran,
/// as in a Rust test binary).
pub static INITIAL_TP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Is the calling thread the one the program started on? glibc tells by its thread descriptor (`__resp` starts as `&_res` in
/// the initial thread only); this compares thread pointers and makes no system call (a seccomp allowlist made from glibc's
/// calls may not have gettid). Before the startup code ran (Rust test binaries): the thread id equals the process id.
pub fn is_initial_thread() -> bool {
    match INITIAL_TP.load(core::sync::atomic::Ordering::Relaxed) {
        0 => crate::unistd::gettid() == crate::unistd::getpid(),
        tp => current() as usize == tp,
    }
}

/// The main thread's thread pointer (0 in a static program); the loader's walk over all threads includes it.
#[cfg(feature = "shared")]
pub static MAIN_TP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// glibc's DL_DEBUG_TLS bit of the loader's `LD_DEBUG` mask.
#[cfg(feature = "shared")]
pub const DL_DEBUG_TLS_BIT: u32 = 1 << 11;
/// Under `LD_DEBUG=tls`: the loader's `extern "C" fn(buf, len)` that prints a debugging line (0 otherwise, and in a static
/// program).
#[cfg(feature = "shared")]
pub static DL_DEBUG_WRITE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// A piece of an `LD_DEBUG=tls` line.
pub enum DebugArg<'a> {
    S(&'a [u8]),
    /// `0x%lx`
    X(usize),
    /// `%ld`
    D(i64),
}

/// Whether `LD_DEBUG=tls` asked for the thread code's TCB lines.
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

/// Print one `LD_DEBUG=tls` line made of `parts` (glibc's wording; the loader adds the process-id tag).
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
        // SAFETY: the word was stored from the loader's `__libc_ldso_debug_write` (`extern "C" fn(*const u8, usize)`).
        let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*const u8, usize)>(h) };
        // SAFETY: `buf` holds `n` initialised bytes.
        unsafe { f(buf.as_ptr(), n) };
    }
    #[cfg(not(feature = "shared"))]
    let _ = parts;
}

/// Called by a new thread first thing (no-op in a static program).
///
/// # Safety
/// `tp` is the calling thread's thread pointer.
pub unsafe fn sync_new_thread(tp: *mut Tcb) {
    #[cfg(feature = "shared")]
    {
        let h = DL_TLS_SYNC.load(core::sync::atomic::Ordering::Relaxed);
        if h != 0 {
            // SAFETY: the word was stored from the loader's `__libc_ldso_tls_sync` (`extern "C" fn(tp)`).
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Tcb)>(h) };
            // SAFETY: `tp` is the calling thread's thread pointer (caller's contract).
            unsafe { f(tp) };
        }
    }
    #[cfg(not(feature = "shared"))]
    let _ = tp;
}

/// The main thread's thread pointer (0 in a static program).
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

/// Set the template from the loader's answer: the static TLS area is `memsz` bytes with alignment `align`; the
/// images are copied by the loader (`DL_TLS_INIT`), so `filesz` stays 0.
///
/// # Safety
/// Call once, before any thread is created.
#[cfg(feature = "shared")]
pub unsafe fn set_dynamic_template(memsz: usize, align: usize) {
    // SAFETY: start-up, before any other thread exists (caller's contract): nothing else reads or writes the cell.
    unsafe { TEMPLATE.write(Template { image: 0, filesz: 0, memsz, align: align.max(1) }) };
}

/// The start of the heap block holding the dtv the loader made for the thread at `tp` (0 in a static program). The TCB holds
/// `&dtv[1]` (`tp + 8`), 16 bytes into the block, so a leak checker sees only an interior pointer to it; the loader's
/// `init_block` keeps the block's start in `dtv[1].to_free` (`dtv[1]` is {generation, start}).
///
/// # Safety
/// `tp` is the thread pointer of a thread whose block `setup_block` made.
pub unsafe fn dtv_allocation(tp: *mut Tcb) -> usize {
    #[cfg(feature = "shared")]
    {
        if DL_TLS_INIT.load(core::sync::atomic::Ordering::Relaxed) == 0 {
            return 0;
        }
        // SAFETY: `tp + 8` is the TCB's dtv field (caller's contract: a thread whose block `setup_block` made).
        let d = unsafe { *((tp as usize + 8) as *const usize) };
        // SAFETY: a non-zero dtv is `&dtv[1]` of the loader's block; `dtv[1]` is {generation, start}, so `d + 8` is readable.
        if d == 0 { 0 } else { unsafe { *((d + 8) as *const usize) } }
    }
    #[cfg(not(feature = "shared"))]
    {
        let _ = tp;
        0
    }
}

/// Give back what the loader allocated for the thread whose thread pointer is `tp` (no-op in a static program).
///
/// # Safety
/// `tp` must be the thread pointer of a thread that is no longer running.
pub unsafe fn release_block(tp: *mut Tcb) {
    #[cfg(feature = "shared")]
    {
        let h = DL_TLS_FREE.load(core::sync::atomic::Ordering::Relaxed);
        if h != 0 {
            // SAFETY: the word was stored from the loader's `__libc_ldso_tls_free_block` (`extern "C" fn(tp)`).
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Tcb)>(h) };
            // SAFETY: the thread at `tp` no longer runs (caller's contract).
            unsafe { f(tp) };
        }
    }
    #[cfg(not(feature = "shared"))]
    let _ = tp;
}

/// The program's TLS template (all zero sizes when the program has no TLS).
pub fn template() -> Template {
    // SAFETY: written only at start-up, before any other thread exists (see `TEMPLATE`); no write can race this read.
    unsafe { TEMPLATE.read() }
}

fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

/// Find the PT_TLS segment from the auxiliary vector's program-header entries.
///
/// # Safety
/// `aux` must point at the kernel's auxiliary vector.
unsafe fn find_template(aux: *const usize) -> Template {
    let (mut phdr, mut phent, mut phnum) = (0usize, 0usize, 0usize);
    let mut a = aux;
    loop {
        // SAFETY: `a` is at a (tag, value) pair of the kernel's vector (caller's contract); the walk stops at AT_NULL.
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
        // SAFETY: the kernel's AT_PHDR/AT_PHENT/AT_PHNUM describe the program's mapped header table: `i < phnum` entries
        // of `phent >= size_of::<Phdr>()` bytes, aligned (ELF64 tables are 8-byte aligned).
        unsafe { &*((phdr + i * phent) as *const Phdr) }
    };
    // load bias: zero for a normal static executable, nonzero for static-pie
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

/// Size of the per-thread allocation for TLS block + TCB, and the offset of the thread pointer in it.
pub fn block_layout(t: &Template) -> (usize, usize) {
    let align = t.align.max(64);
    let tls = align_up(t.memsz, align);
    (tls + TCB_SIZE, tls)
}

/// Lay out a thread's TLS block and TCB inside `base` (zeroed memory of at least
/// `block_layout(..).0` bytes, aligned to 64 or more): copy the initial image, set the TCB's
/// self pointers and canary. Returns the thread pointer.
///
/// # Safety
/// `base` must be valid, zeroed, writable memory of the required size and alignment.
pub unsafe fn setup_block(base: *mut u8, t: &Template, canary: usize, pointer_guard: usize) -> *mut Tcb {
    let (_, tp_off) = block_layout(t);
    // the TCB sits `tp_off` bytes into the block, the TLS image just below it (inside the block: `block_layout`)
    let tp = base.wrapping_add(tp_off) as *mut Tcb;
    if t.filesz > 0 {
        let dst = (tp as *mut u8).wrapping_sub(align_up(t.memsz, t.align.max(1)));
        // SAFETY: the template's image is `filesz` readable bytes of the program (PT_TLS, or set by the caller); `dst` is the
        // start of the TLS area inside the block (`base` holds the whole layout, caller's contract); they do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(t.image as *const u8, dst, t.filesz) };
    }
    // SAFETY: `tp` is inside the block, which is writable and aligned (caller's contract); no one else sees it yet.
    unsafe { (*tp).tcb = tp };
    // SAFETY: as above.
    unsafe { (*tp).self_ptr = tp };
    // SAFETY: as above.
    unsafe { (*tp).stack_guard = canary };
    // SAFETY: as above.
    unsafe { (*tp).pointer_guard = pointer_guard };
    // a static program has no dtv; debuggers are given one (crate::thread_db)
    #[cfg(not(feature = "shared"))]
    {
        let block = (tp as usize).wrapping_sub(align_up(t.memsz, t.align.max(1)));
        // SAFETY: `tp` is the TCB being set up.
        unsafe { crate::thread_db::set_static_dtv(tp, block) };
    }
    #[cfg(feature = "shared")]
    {
        let h = DL_TLS_INIT.load(core::sync::atomic::Ordering::Relaxed);
        if h != 0 {
            // SAFETY: the word was stored from the loader's `__libc_ldso_tls_init_block` (`extern "C" fn(tp)`).
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Tcb)>(h) };
            // SAFETY: `tp` is a fresh thread pointer whose block below it the loader fills (its contract).
            unsafe { f(tp) };
        }
    }
    tp
}

/// Set the thread pointer register (`%fs` base) of the calling thread.
///
/// # Safety
/// `tp` must point at a valid TCB.
pub unsafe fn set_thread_pointer(tp: *mut Tcb) {
    // SAFETY: arch_prctl(ARCH_SET_FS) only sets the register; `tp` points at a valid TCB (caller's contract), which is
    // what every later %fs access relies on.
    unsafe { syscall2(SYS_ARCH_PRCTL, ARCH_SET_FS, tp as usize) };
}

/// Set up TLS for the main thread: allocate the block, copy `.tdata`, set `%fs`.
/// The canary and pointer guard come from the kernel's `AT_RANDOM` bytes.
///
/// # Safety
/// Call once, first thing in `_start`; `aux` is the kernel's auxiliary vector.
pub unsafe fn init_main(aux: *const usize) {
    {
        // SAFETY: `aux` is the kernel's auxiliary vector (caller's contract).
        let t = unsafe { find_template(aux) };
        // SAFETY: first thing at start-up, one thread (caller's contract).
        unsafe { TEMPLATE.write(t) };
        let (size, _) = block_layout(&t);
        // from the program break as glibc's `_dl_early_allocate` takes it (brk(0), then brk(old + size)), with mmap only when
        // the break cannot grow: a seccomp allowlist made from glibc's calls has brk but, for a small static program, no mmap.
        // Fresh memory from either is zero: covers .tbss and the rest of the TCB. The extra `align` bytes let the block start
        // on its alignment wherever the break was.
        let align = t.align.max(64);
        // SAFETY: brk with plain values: the query, then the new break (the kernel maps or refuses).
        let prev = unsafe { syscall::syscall1(SYS_BRK, 0) };
        // SAFETY: as above.
        let got = unsafe { syscall::syscall1(SYS_BRK, prev.wrapping_add(size + align)) };
        let base = if prev != 0 && got == prev.wrapping_add(size + align) {
            align_up(prev, align)
        } else {
            // SAFETY: an anonymous private mapping at an address the kernel picks: no existing memory is touched.
            unsafe { syscall6(SYS_MMAP, 0, size, 3, 0x22, usize::MAX, 0) }
        };
        if base > usize::MAX - 4095 {
            // no memory at startup: nothing sensible can run
            // SAFETY: exit_group with plain values.
            unsafe { syscall2(231, 127, 0) };
            loop {
                core::hint::spin_loop();
            }
        }
        let (mut canary, mut guard) = (0usize, 0usize);
        let mut a = aux;
        loop {
            // SAFETY: `a` is at a (tag, value) pair of the kernel's vector; the walk stops at AT_NULL.
            let [tag, val] = unsafe { *(a as *const [usize; 2]) };
            if tag == 0 {
                break;
            }
            if tag == AT_RANDOM {
                let r = val as *const [usize; 2];
                if !r.is_null() {
                    // SAFETY: AT_RANDOM points at 16 random bytes the kernel put on the initial stack. They follow the
                    // platform string, so they need not be 8-byte aligned: read unaligned.
                    let [r0, r1] = unsafe { r.read_unaligned() };
                    // glibc clears the low byte of the canary so a string copy cannot read past it
                    canary = r0 & !0xff;
                    guard = r1;
                }
            }
            a = a.wrapping_add(2);
        }
        // SAFETY: `base` is fresh zeroed memory of `size` bytes aligned to `align` (from brk past an aligned start, or mmap).
        let tp = unsafe { setup_block(base as *mut u8, &t, canary, guard) };
        // SAFETY: `tp` is the TCB just set up.
        unsafe { set_thread_pointer(tp) };
        INITIAL_TP.store(tp as usize, core::sync::atomic::Ordering::Relaxed);
        // the main thread's kernel thread id (the thread code and the locks compare against it), from set_tid_address as
        // glibc's __tls_init_tp takes it: the kernel clears the id and wakes waiters when the thread exits (pthread_join of the
        // main thread, after it called pthread_exit, depends on that)
        // SAFETY: the address of the TCB's tid field (the TCB lives as long as the process).
        let tidp = unsafe { core::ptr::addr_of_mut!((*tp).tid) };
        // SAFETY: set_tid_address stores the pointer for the thread's exit; `tidp` stays valid for the thread's life.
        let tid = unsafe { syscall::syscall1(218 /* set_tid_address */, tidp as usize) } as i32;
        // SAFETY: the field of our own TCB; one thread.
        unsafe { tidp.write(tid) };
        // the robust mutex list, registered at startup as glibc does
        // SAFETY: `tp` is the calling thread's TCB now.
        unsafe { robust_register(tp) };
        // libthread_db's thread list and TLS slot table (gdb)
        // SAFETY: once, at start-up, before any other thread.
        unsafe { crate::thread_db::init(tp, 0) };
    }
}

/// Null thread pointer, for tests that want to check `current()` is unset.
pub const NO_TCB: *mut Tcb = null_mut();

/// Hook for cancellable system calls: rusty-libc-pthread stores here the address of an
/// `extern "C" fn(nr, a1, a2, a3, a4, a5, a6) -> usize` that performs the system call as a
/// cancellation point (it acts on a pending `pthread_cancel` before the call starts, or when the
/// call is interrupted). 0 until the thread layer is first used.
pub static CANCEL_SYSCALL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// A system call that is a cancellation point (read, write, nanosleep, ...): other crates call this
/// instead of `syscallN` for the calls POSIX lists as cancellation points. Costs one load and a
/// branch when no thread was ever created or cancelled.
///
/// # Safety
/// The caller must pass arguments valid for system call `nr`.
#[inline]
pub unsafe fn syscall_cp(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    let h = CANCEL_SYSCALL.load(core::sync::atomic::Ordering::Relaxed);
    if h == 0 {
        // SAFETY: the arguments are valid for `nr` (caller's contract).
        unsafe { syscall6(nr, a1, a2, a3, a4, a5, a6) }
    } else {
        // SAFETY: rusty-libc-pthread stores only the address of its cancellable-call stub, this exact signature. (Its
        // arguments are those of `syscall6`; the caller's contract covers them.)
        let f: extern "C" fn(usize, usize, usize, usize, usize, usize, usize) -> usize = unsafe { core::mem::transmute(h) };
        f(nr, a1, a2, a3, a4, a5, a6)
    }
}

// the lock fast path reads `multiple_threads` at %fs:0x18; gcc's stack protector reads the canary at %fs:0x28; the dynamic
// loader (crates/rusty-libc-ldso) writes the canary, the pointer guard and expects the dtv at the offsets of glibc's TCB header
const _: () = assert!(core::mem::offset_of!(Tcb, multiple_threads) == 0x18);
const _: () = assert!(core::mem::offset_of!(Tcb, stack_guard) == 0x28);
const _: () = assert!(core::mem::offset_of!(Tcb, pointer_guard) == 0x30);
const _: () = assert!(core::mem::offset_of!(Tcb, db_dtv) + 48 == 0x100);
const _: () = assert!(core::mem::offset_of!(Tcb, tid) == 0x2d0);
const _: () = assert!(core::mem::offset_of!(Tcb, cancelhandling) == 0x40);
const _: () = assert!(core::mem::offset_of!(Tcb, dl_error) == 0x80);
// glibc's tcbhead_t slots read from outside the C library (see the fields): feature_1, __private_tm, __private_ss, ssp_base
const _: () = assert!(core::mem::offset_of!(Tcb, feature_1) == 0x48);
const _: () = assert!(core::mem::offset_of!(Tcb, private_tm) == 0x50);
const _: () = assert!(core::mem::offset_of!(Tcb, private_ss) == 0x70);
const _: () = assert!(core::mem::offset_of!(Tcb, ssp_base) == 0x78);

// ---- thread_local destructors (__cxa_thread_atexit_impl) ----

/// Destructors kept in the thread's static TLS (two: a Rust thread registers one list, C++ a few); more go into a mapping
/// (`PageVec`, one page first, doubling: glibc's list has no limit) made when the third is registered and unmapped when the
/// thread has run them all. Static TLS is paid by every thread (and by every dlmopen namespace's libc copy), so it holds
/// only these two entries, the count and the mapping's pointer and size.
const INLINE_DTORS: usize = 2;

#[derive(Clone, Copy)]
struct ThreadDtor {
    f: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    obj: *mut core::ffi::c_void,
    /// The `dso` argument (the registering object's `&__dso_handle`), handed back to the loader once `f` ran
    dso: usize,
}

const NO_DTOR: ThreadDtor = ThreadDtor { f: None, obj: core::ptr::null_mut(), dso: 0 };

// Per thread (`Cell`s: only the owning thread touches them, and no reference into them is held across a destructor call,
// which may register further destructors).
#[thread_local]
static THREAD_DTORS: [Cell<ThreadDtor>; INLINE_DTORS] = [const { Cell::new(NO_DTOR) }; INLINE_DTORS];
/// The mapping for the entries past the inline ones (empty until the third is registered); taken out of the cell while it
/// is worked on.
#[thread_local]
static THREAD_DTORS_MORE: Cell<crate::pages::PageVec<ThreadDtor>> = Cell::new(crate::pages::PageVec::new());
#[thread_local]
static THREAD_DTOR_N: Cell<usize> = Cell::new(0);

/// The loader's `__libc_ldso_tls_dtor_ref(dso, delta)` (None in a static program): keeps the object `dso` points into
/// loaded while it has destructors pending (glibc's `l_tls_dtor_count`, which `dlclose` checks). Stored at start-up.
pub static DL_TLS_DTOR_REF: crate::lock::Locked<Option<extern "C" fn(usize, isize)>> = crate::lock::Locked::new(None);

fn tls_dtor_ref(dso: usize, delta: isize) {
    if dso != 0
        && let Some(f) = DL_TLS_DTOR_REF.with(|h| *h)
    {
        f(dso, delta);
    }
}

/// Register `f(obj)` to run when the calling thread exits (or, for the main thread, in `exit`), in reverse order of
/// registration; `dso` (the registering object's `&__dso_handle`) stays loaded until then. False only if no memory is left
/// for the table (glibc then ends the process with a fatal error).
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

/// Run and clear the calling thread's destructors (they may register more: loop until none are left).
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
            // SAFETY: the destructor and object registered together through `__cxa_thread_atexit_impl`, whose contract is
            // that `f(obj)` may run when the thread ends.
            unsafe { f(d.obj) };
        }
        tls_dtor_ref(d.dso, -1);
    }
    drop(THREAD_DTORS_MORE.take()); // unmaps the extra entries
}

//! What a debugger's `libthread_db.so.1` needs to see the threads and the thread-local variables of a program (gdb's
//! `info threads`, `thread N`, `print some_tls_variable`), the way glibc 2.43 provides it.
//!
//! glibc's libthread_db (the one installed with the system, which gdb loads) does not know the thread library's layout: it
//! reads it from the program. It looks up, by name in any loaded object, `__nptl_version` (must be "2.43"), descriptors
//! `_thread_db_<struct>_<field>` (three 32-bit words: size in bits, element count, byte offset) and `_thread_db_sizeof_<struct>`,
//! and a few variables. With them it walks two circular lists of thread descriptors (glibc's `_dl_stack_user`, which holds the
//! main thread, and `_dl_stack_used`), reads each thread's id, start routine and cancellation word, takes the thread
//! descriptor of an LWP from its `%fs` base (`_thread_db_const_thread_area` 25: gdb's FS register index), and finds a TLS block
//! through the thread's dtv and the loader's slot table (`_dl_tls_dtv_slotinfo_list`: generation and link_map per module id).
//!
//! Here the descriptors describe this library's own layout:
//! * the "thread descriptor" is the TCB ([`Tcb`]), which every thread has at its thread pointer; the debugger's list node
//!   (`db_list`), start routine and the always-zero event fields live in it;
//! * `__nptl_rtld_global` points at [`DbGlobal`], which holds the two list heads and the slot table's address (glibc points it
//!   at the loader's `_rtld_global`; libthread_db only reads the fields the descriptors name);
//! * under the dynamic loader the slot table is the loader's (crates/rusty-libc-ldso `Tls::db`: `{len, next, [{gen, map}]}` chunks,
//!   the dtv in glibc's shape); a static program, which has no loader, gets a one-module dtv in each TCB (`db_dtv`, see
//!   [`set_static_dtv`]), a slot table with module 1 and a link_map-shaped record (`STATIC_MAP`) with the program's TLS offset.
//!
//! All the symbols come from one `global_asm!` block, so one object of libc.a holds them; the startup code refers to it, so a
//! static program always carries them (libc.a is built with one codegen unit per function). Written from glibc's nptl_db
//! sources (read as reference: structs.def, td_ta_thr_iter.c, td_thr_tlsbase.c, td_thr_get_info.c), no code copied.
//!
//! What stays unsafe: the lists are intrusive (their nodes are fields of the threads' TCBs) and are read by a debugger from
//! outside the process, so they stay raw pointers in glibc's layout. Invariant (The Rust Reference p.628: a structure
//! invariant discharges the blocks): every node on a list is a live TCB's `db_list`, and the lists are changed only while
//! one thread can do so (start-up, a forked child) or under the thread list lock (`add`, `remove`).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::tls::Tcb;
use core::mem::{offset_of, size_of};

/// glibc's `list_t`: a node of a circular doubly linked list.
#[repr(C)]
pub struct ListT {
    pub next: *mut ListT,
    pub prev: *mut ListT,
}

/// Fields libthread_db reads from every thread descriptor that this library does not use: event reporting (gdb no longer
/// uses it) and the scheduling policy and priority (SCHED_OTHER, 0: the thread's priority is then reported as 0). Always zero.
#[repr(C)]
pub struct DbZero {
    pub report_events: u8,
    pub _pad: [u8; 3],
    pub schedpolicy: i32,
    pub sched_priority: i32,
    pub _pad2: i32,
    /// `td_eventbuf_t`: event mask (two words), event number, event data.
    pub eventmask: [u32; 2],
    pub eventnum: i32,
    pub _pad3: i32,
    pub eventdata: usize,
    pub nextevent: usize,
}

/// What `__nptl_rtld_global` points at: the list of threads on stacks the program gave (the main thread; glibc's
/// `_dl_stack_user`), the list of threads on stacks this library made (`_dl_stack_used`), and the TLS slot table.
#[repr(C)]
pub struct DbGlobal {
    pub stack_user: ListT,
    pub stack_used: ListT,
    pub slotinfo: usize,
}

/// glibc's `struct dtv_slotinfo` (one module id: the dtv generation from which it is valid and its link_map) and the head of
/// `struct dtv_slotinfo_list` (`len` entries follow `next`). The loader keeps the same shape.
#[repr(C)]
pub struct DbSlot {
    pub generation: usize,
    pub map: usize,
}

#[repr(C)]
pub struct DbSlotList<const N: usize> {
    pub len: usize,
    pub next: usize,
    pub slots: [DbSlot; N],
}

/// Byte offsets of `tls_modid` and `tls_offset` in the loader's `struct link_map` (crates/rusty-libc-ldso/src/map.rs asserts
/// them); `STATIC_MAP` uses the same offsets.
pub const LINK_MAP_TLS_MODID: usize = 504;
pub const LINK_MAP_TLS_OFFSET: usize = 544;

// The globals below are written while the process is single-threaded (start-up, thread creation under the stack-list
// lock) and read by debuggers from outside: `SyncCell` (U1) with raw pointers handed out by `as_ptr`.
use crate::SyncCell;

#[cfg_attr(not(feature = "start"), allow(dead_code))]
static DB_GLOBAL: SyncCell<DbGlobal> = SyncCell::new(DbGlobal {
    stack_user: ListT { next: core::ptr::null_mut(), prev: core::ptr::null_mut() },
    stack_used: ListT { next: core::ptr::null_mut(), prev: core::ptr::null_mut() },
    slotinfo: 0,
});

fn global() -> *mut DbGlobal {
    DB_GLOBAL.as_ptr()
}

/// `_dl_stack_used`'s head (an address only).
fn head_used() -> *mut ListT {
    // SAFETY: `global()` is our static's address; only the field's address is taken.
    unsafe { &raw mut (*global()).stack_used }
}

/// `_dl_stack_user`'s head (an address only).
fn head_user() -> *mut ListT {
    // SAFETY: as in `head_used`.
    unsafe { &raw mut (*global()).stack_user }
}

/// Static program: the slot table (module 1 = the program, valid from dtv generation 1) and the link_map-shaped record with
/// the program's static TLS offset. Each thread's dtv lives in its TCB ([`set_static_dtv`]).
#[cfg(not(feature = "shared"))]
static STATIC_SLOTS: SyncCell<DbSlotList<2>> = SyncCell::new(DbSlotList { len: 2, next: 0, slots: [DbSlot { generation: 0, map: 0 }, DbSlot { generation: 1, map: 0 }] });
#[cfg(not(feature = "shared"))]
static STATIC_MAP: SyncCell<[usize; LINK_MAP_TLS_OFFSET / 8 + 1]> = SyncCell::new([0; LINK_MAP_TLS_OFFSET / 8 + 1]);

/// A static program has no dynamic loader and no dtv of its own; debuggers (libthread_db, and gdb's built-in TLS lookup, which
/// reads `dtv[module].pointer` from the thread pointer's dtv slot) are given one in glibc's shape inside the TCB: `dtv[-1]` = 1
/// slot, `dtv[0]` = generation 1, `dtv[1]` = the thread's block of the program's TLS (`block`).
///
/// # Safety
/// `tp` is a thread's TCB being set up.
#[cfg(not(feature = "shared"))]
pub unsafe fn set_static_dtv(tp: *mut Tcb, block: usize) {
    // SAFETY: `tp` is a TCB being set up (caller's contract): only the field's address is taken.
    let d = unsafe { &raw mut (*tp).db_dtv };
    // dtv[-1] = 1 slot, dtv[0] = generation 1, dtv[1] = {the block, unused}: words 0, 2 and 4 of `db_dtv` (6 words)
    // SAFETY: `d` points to the TCB's 6-word `db_dtv`, which no one else uses yet.
    unsafe { (*d)[0] = 1 };
    // SAFETY: as above.
    unsafe { (*d)[2] = 1 };
    // SAFETY: as above.
    unsafe { (*d)[4] = block };
    // SAFETY: as above: the TCB's dtv field.
    unsafe { (*tp).dtv = (d as *mut usize).wrapping_add(2) as *mut u8 };
}

/// An empty list: the head points to itself.
///
/// # Safety
/// `h` is a list head that no one else changes now (module invariant).
unsafe fn list_init(h: *mut ListT) {
    // SAFETY: caller's contract.
    unsafe { h.write(ListT { next: h, prev: h }) };
}

/// Append node `n` to the list headed by `h`.
///
/// # Safety
/// `h` is an initialised head and `n` a node not on any list; no one else changes the list now (module invariant).
unsafe fn list_add(h: *mut ListT, n: *mut ListT) {
    // SAFETY: `h` is an initialised head (caller's contract).
    let last = unsafe { (*h).prev };
    // SAFETY: `n` is a live node (caller's contract).
    unsafe { n.write(ListT { next: h, prev: last }) };
    // SAFETY: `last` is on the list (the head itself when empty), so live (module invariant).
    unsafe { (*last).next = n };
    // SAFETY: as for `h` above.
    unsafe { (*h).prev = n };
}

/// Take node `n` off its list (nothing if it is on none).
///
/// # Safety
/// `n` is a live node; no one else changes its list now (module invariant).
unsafe fn list_del(n: *mut ListT) {
    // SAFETY: caller's contract.
    let ListT { next, prev } = unsafe { n.read() };
    if next.is_null() {
        return;
    }
    // SAFETY: `prev` and `next` are on the same list as `n`, so live (module invariant).
    unsafe { (*prev).next = next };
    // SAFETY: as above.
    unsafe { (*next).prev = prev };
    // SAFETY: caller's contract.
    unsafe { n.write(ListT { next: core::ptr::null_mut(), prev: core::ptr::null_mut() }) };
}

/// Start the lists with the main thread (whose TCB is `main`) and record where the slot table is: the loader's (`slots`,
/// shared library) or this file's (0, static program). Until this runs libthread_db shows only the main thread.
///
/// # Safety
/// Once, at startup, before any other thread exists.
pub unsafe fn init(main: *mut Tcb, slots: usize) {
    let g = global();
    #[cfg(not(feature = "shared"))]
    let slots = {
        let _ = slots;
        // the program's TLS block sits `align_up(memsz, align)` below the thread pointer (tls::setup_block)
        let t = crate::tls::template();
        let a = t.align.max(1);
        // SAFETY: start-up, one thread (caller's contract); a debugger only reads these.
        unsafe {
            STATIC_MAP.with_unsync(|m| {
                m[LINK_MAP_TLS_MODID / 8] = 1;
                m[LINK_MAP_TLS_OFFSET / 8] = (t.memsz + a - 1) & !(a - 1);
            })
        };
        // SAFETY: as above.
        unsafe { STATIC_SLOTS.with_unsync(|l| l.slots[1].map = STATIC_MAP.as_ptr() as usize) };
        STATIC_SLOTS.as_ptr() as usize
    };
    // SAFETY: `g` is our static DbGlobal; start-up, one thread (caller's contract).
    unsafe { (*g).slotinfo = slots };
    // SAFETY: as above: the heads are ours, nothing else changes them now.
    unsafe { list_init(head_used()) };
    // SAFETY: as above.
    unsafe { list_init(head_user()) };
    // SAFETY: `main` is the main thread's TCB (caller's contract): only the field's address is taken.
    let node = unsafe { &raw mut (*main).db_list };
    // SAFETY: the head was just initialised; the main thread's node is on no list.
    unsafe { list_add(head_user(), node) };
    // the descriptors' object must be part of a static program: this reference pulls it in
    #[cfg(feature = "start")]
    core::hint::black_box(&raw const __nptl_version);
}

/// A thread made by pthread_create (on a stack of ours or of the program; both kinds go on `_dl_stack_used`, libthread_db
/// walks both lists the same way). Called with the thread list lock held.
///
/// # Safety
/// `t` is a thread's TCB; the lists were started with [`init`].
pub unsafe fn add(t: *mut Tcb) {
    let g = global();
    // SAFETY: our static DbGlobal; the caller holds the thread list lock.
    if unsafe { (*g).stack_used.next }.is_null() {
        return;
    }
    // SAFETY: `t` is a thread's TCB (caller's contract): only the field's address is taken.
    let node = unsafe { &raw mut (*t).db_list };
    // SAFETY: the head is initialised (checked); a new thread's node is on no list; the lock is held.
    unsafe { list_add(head_used(), node) };
}

/// Take a thread off the lists (it has ended). Called with the thread list lock held.
///
/// # Safety
/// `t` is a thread's TCB.
pub unsafe fn remove(t: *mut Tcb) {
    // SAFETY: `t` is a thread's TCB (caller's contract): only the field's address is taken.
    let node = unsafe { &raw mut (*t).db_list };
    // SAFETY: a live node; the caller holds the thread list lock.
    unsafe { list_del(node) }
}

/// In the child of a fork: only `me` exists.
///
/// # Safety
/// The calling thread's TCB, in the child, before any other thread is made.
pub unsafe fn after_fork(me: *mut Tcb) {
    let g = global();
    // SAFETY: our static DbGlobal; the forked child has one thread (caller's contract).
    if unsafe { (*g).stack_used.next }.is_null() {
        return;
    }
    // SAFETY: as above: nothing else changes the heads.
    unsafe { list_init(head_used()) };
    // SAFETY: as above.
    unsafe { list_init(head_user()) };
    // SAFETY: `me` is the calling thread's TCB (caller's contract): only the field's address is taken.
    let node = unsafe { &raw mut (*me).db_list };
    // SAFETY: the node is ours; the parent's list it was on no longer exists in the child.
    unsafe { node.write(ListT { next: core::ptr::null_mut(), prev: core::ptr::null_mut() }) };
    // SAFETY: the head was just initialised and the node is on no list.
    unsafe { list_add(head_user(), node) };
}

#[cfg(feature = "start")]
unsafe extern "C" {
    static __nptl_version: u8;
}

// The names, values and meaning are glibc's (nptl_db/structs.def, db_info.c); the offsets are ours. A descriptor is
// {size in bits, number of elements, byte offset}.
#[cfg(feature = "start")]
core::arch::global_asm!(
    ".pushsection .rodata.rl_thread_db,\"a\",@progbits",
    ".balign 8",
    ".globl __nptl_version", ".type __nptl_version, @object", ".size __nptl_version, 5",
    "__nptl_version: .asciz \"2.43\"",
    ".balign 4",
    ".globl _thread_db_const_thread_area", "_thread_db_const_thread_area: .long 25",
    ".globl _thread_db_sizeof_pthread", "_thread_db_sizeof_pthread: .long {sz_pthread}",
    ".globl _thread_db_sizeof_list_t", "_thread_db_sizeof_list_t: .long 16",
    ".globl _thread_db_sizeof_td_thr_events_t", "_thread_db_sizeof_td_thr_events_t: .long 8",
    ".globl _thread_db_sizeof_td_eventbuf_t", "_thread_db_sizeof_td_eventbuf_t: .long 24",
    ".globl _thread_db_sizeof_dtv_slotinfo_list", "_thread_db_sizeof_dtv_slotinfo_list: .long 16",
    ".globl _thread_db_sizeof_dtv_slotinfo", "_thread_db_sizeof_dtv_slotinfo: .long 16",
    ".globl _thread_db_pthread_list", "_thread_db_pthread_list: .long 128, 1, {o_list}",
    ".globl _thread_db_pthread_report_events", "_thread_db_pthread_report_events: .long 8, 1, {o_report}",
    ".globl _thread_db_pthread_tid", "_thread_db_pthread_tid: .long 32, 1, {o_tid}",
    ".globl _thread_db_pthread_start_routine", "_thread_db_pthread_start_routine: .long 64, 1, {o_start}",
    ".globl _thread_db_pthread_cancelhandling", "_thread_db_pthread_cancelhandling: .long 32, 1, {o_cancel}",
    ".globl _thread_db_pthread_schedpolicy", "_thread_db_pthread_schedpolicy: .long 32, 1, {o_policy}",
    ".globl _thread_db_pthread_schedparam_sched_priority", "_thread_db_pthread_schedparam_sched_priority: .long 32, 1, {o_prio}",
    // thread-specific data is not laid out like glibc's (td_thr_tsd cannot read it): the field only gives td_thr_get_info's
    // ti_tls an address inside the descriptor
    ".globl _thread_db_pthread_specific", "_thread_db_pthread_specific: .long 64, 1, {o_eventdata}",
    ".globl _thread_db_pthread_eventbuf", "_thread_db_pthread_eventbuf: .long 192, 1, {o_eventbuf}",
    ".globl _thread_db_pthread_eventbuf_eventmask", "_thread_db_pthread_eventbuf_eventmask: .long 64, 1, {o_eventbuf}",
    ".globl _thread_db_pthread_eventbuf_eventmask_event_bits", "_thread_db_pthread_eventbuf_eventmask_event_bits: .long 32, 2, {o_eventbuf}",
    ".globl _thread_db_pthread_nextevent", "_thread_db_pthread_nextevent: .long 64, 1, {o_next}",
    ".globl _thread_db_pthread_dtvp", "_thread_db_pthread_dtvp: .long 64, 1, {o_dtv}",
    ".globl _thread_db_list_t_next", "_thread_db_list_t_next: .long 64, 1, 0",
    ".globl _thread_db_list_t_prev", "_thread_db_list_t_prev: .long 64, 1, 8",
    ".globl _thread_db_td_thr_events_t_event_bits", "_thread_db_td_thr_events_t_event_bits: .long 32, 2, 0",
    ".globl _thread_db_td_eventbuf_t_eventnum", "_thread_db_td_eventbuf_t_eventnum: .long 32, 1, 8",
    ".globl _thread_db_td_eventbuf_t_eventdata", "_thread_db_td_eventbuf_t_eventdata: .long 64, 1, 16",
    ".globl _thread_db___nptl_nthreads", "_thread_db___nptl_nthreads: .long 64, 1, 0",
    ".globl _thread_db___nptl_last_event", "_thread_db___nptl_last_event: .long 64, 1, 0",
    ".globl _thread_db___nptl_rtld_global", "_thread_db___nptl_rtld_global: .long 64, 1, 0",
    ".globl _thread_db_rtld_global__dl_stack_user", "_thread_db_rtld_global__dl_stack_user: .long 128, 1, {o_user}",
    ".globl _thread_db_rtld_global__dl_stack_used", "_thread_db_rtld_global__dl_stack_used: .long 128, 1, {o_used}",
    ".globl _thread_db_rtld_global__dl_tls_dtv_slotinfo_list", "_thread_db_rtld_global__dl_tls_dtv_slotinfo_list: .long 64, 1, {o_slots}",
    ".globl _thread_db_link_map_l_tls_modid", "_thread_db_link_map_l_tls_modid: .long 64, 1, {o_modid}",
    ".globl _thread_db_link_map_l_tls_offset", "_thread_db_link_map_l_tls_offset: .long 64, 1, {o_tlsoff}",
    // the dtv has no fixed bound (glibc's descriptor uses UINT32_MAX / 2 / 16 elements)
    ".globl _thread_db_dtv_dtv", "_thread_db_dtv_dtv: .long 128, 134217727, 0",
    ".globl _thread_db_dtv_t_counter", "_thread_db_dtv_t_counter: .long 64, 1, 0",
    ".globl _thread_db_dtv_t_pointer_val", "_thread_db_dtv_t_pointer_val: .long 64, 1, 0",
    ".globl _thread_db_dtv_slotinfo_list_len", "_thread_db_dtv_slotinfo_list_len: .long 64, 1, 0",
    ".globl _thread_db_dtv_slotinfo_list_next", "_thread_db_dtv_slotinfo_list_next: .long 64, 1, 8",
    ".globl _thread_db_dtv_slotinfo_list_slotinfo", "_thread_db_dtv_slotinfo_list_slotinfo: .long 128, 0, 16",
    ".globl _thread_db_dtv_slotinfo_gen", "_thread_db_dtv_slotinfo_gen: .long 64, 1, 0",
    ".globl _thread_db_dtv_slotinfo_map", "_thread_db_dtv_slotinfo_map: .long 64, 1, 8",
    ".popsection",
    // the variables: the event words (never set: no event reporting) and the pointer to the list heads
    ".pushsection .data.rel.ro.rl_thread_db,\"aw\",@progbits",
    ".balign 8",
    ".globl __nptl_rtld_global", ".type __nptl_rtld_global, @object", ".size __nptl_rtld_global, 8",
    "__nptl_rtld_global: .quad {global}",
    ".popsection",
    ".pushsection .bss.rl_thread_db,\"aw\",@nobits",
    ".balign 8",
    ".globl __nptl_last_event", ".type __nptl_last_event, @object", ".size __nptl_last_event, 8",
    "__nptl_last_event: .zero 8",
    ".globl __nptl_threads_events", ".type __nptl_threads_events, @object", ".size __nptl_threads_events, 8",
    "__nptl_threads_events: .zero 8",
    ".popsection",
    // the breakpoint addresses of the creation and death events (glibc's empty functions)
    ".pushsection .text.rl_thread_db,\"ax\",@progbits",
    ".globl __nptl_create_event", ".type __nptl_create_event, @function",
    "__nptl_create_event: ret",
    ".size __nptl_create_event, . - __nptl_create_event",
    ".globl __nptl_death_event", ".type __nptl_death_event, @function",
    "__nptl_death_event: ret",
    ".size __nptl_death_event, . - __nptl_death_event",
    ".popsection",
    // the whole descriptor area every thread has from its thread pointer up (TCB header + rusty-libc-pthread's Thread, with the
    // thread-specific values): LLVM's sanitizers read this symbol as glibc's sizeof(struct pthread) and take
    // [tp - static TLS size, tp + this) as the thread's static TLS, which LeakSanitizer scans for pointers
    sz_pthread = const crate::tls::TCB_SIZE,
    o_list = const offset_of!(Tcb, db_list),
    o_report = const offset_of!(Tcb, db) + offset_of!(DbZero, report_events),
    o_tid = const offset_of!(Tcb, tid),
    o_start = const offset_of!(Tcb, db_start),
    o_cancel = const offset_of!(Tcb, cancelhandling),
    o_policy = const offset_of!(Tcb, db) + offset_of!(DbZero, schedpolicy),
    o_prio = const offset_of!(Tcb, db) + offset_of!(DbZero, sched_priority),
    o_eventbuf = const offset_of!(Tcb, db) + offset_of!(DbZero, eventmask),
    o_eventdata = const offset_of!(Tcb, db) + offset_of!(DbZero, eventdata),
    o_next = const offset_of!(Tcb, db) + offset_of!(DbZero, nextevent),
    o_dtv = const offset_of!(Tcb, dtv),
    o_user = const offset_of!(DbGlobal, stack_user),
    o_used = const offset_of!(DbGlobal, stack_used),
    o_slots = const offset_of!(DbGlobal, slotinfo),
    o_modid = const LINK_MAP_TLS_MODID,
    o_tlsoff = const LINK_MAP_TLS_OFFSET,
    global = sym DB_GLOBAL,
);

// libthread_db's td_eventbuf_t: mask (8 bytes), event number at 8, data at 16 (24 bytes)
const _: () = assert!(offset_of!(DbZero, eventnum) - offset_of!(DbZero, eventmask) == 8);
const _: () = assert!(offset_of!(DbZero, eventdata) - offset_of!(DbZero, eventmask) == 16);
const _: () = assert!(size_of::<ListT>() == 16 && size_of::<DbSlot>() == 16);

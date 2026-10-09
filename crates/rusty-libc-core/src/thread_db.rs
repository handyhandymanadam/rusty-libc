use crate::tls::Tcb;
use core::mem::{offset_of, size_of};

#[repr(C)]
pub struct ListT {
    pub next: *mut ListT,
    pub prev: *mut ListT,
}

#[repr(C)]
pub struct DbZero {
    pub report_events: u8,
    pub _pad: [u8; 3],
    pub schedpolicy: i32,
    pub sched_priority: i32,
    pub _pad2: i32,
    pub eventmask: [u32; 2],
    pub eventnum: i32,
    pub _pad3: i32,
    pub eventdata: usize,
    pub nextevent: usize,
}

#[repr(C)]
pub struct DbGlobal {
    pub stack_user: ListT,
    pub stack_used: ListT,
    pub slotinfo: usize,
}

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

pub const LINK_MAP_TLS_MODID: usize = 504;
pub const LINK_MAP_TLS_OFFSET: usize = 544;

#[cfg_attr(not(feature = "start"), allow(dead_code))]
struct Shared<T>(core::cell::UnsafeCell<T>);
unsafe impl<T> Sync for Shared<T> {}

#[cfg_attr(not(feature = "start"), allow(dead_code))]
static DB_GLOBAL: Shared<DbGlobal> = Shared(core::cell::UnsafeCell::new(DbGlobal {
    stack_user: ListT { next: core::ptr::null_mut(), prev: core::ptr::null_mut() },
    stack_used: ListT { next: core::ptr::null_mut(), prev: core::ptr::null_mut() },
    slotinfo: 0,
}));

fn global() -> *mut DbGlobal {
    DB_GLOBAL.0.get()
}

#[cfg(not(feature = "shared"))]
static STATIC_SLOTS: Shared<DbSlotList<2>> = Shared(core::cell::UnsafeCell::new(DbSlotList { len: 2, next: 0, slots: [DbSlot { generation: 0, map: 0 }, DbSlot { generation: 1, map: 0 }] }));
#[cfg(not(feature = "shared"))]
static STATIC_MAP: Shared<[usize; LINK_MAP_TLS_OFFSET / 8 + 1]> = Shared(core::cell::UnsafeCell::new([0; LINK_MAP_TLS_OFFSET / 8 + 1]));

#[cfg(not(feature = "shared"))]
pub unsafe fn set_static_dtv(tp: *mut Tcb, block: usize) {
    unsafe {
        let d = &raw mut (*tp).db_dtv as *mut usize;
        *d = 1;
        *d.add(2) = 1;
        *d.add(4) = block;
        (*tp).dtv = d.add(2) as *mut u8;
    }
}

unsafe fn list_init(h: *mut ListT) {
    unsafe {
        (*h).next = h;
        (*h).prev = h;
    }
}

unsafe fn list_add(h: *mut ListT, n: *mut ListT) {
    unsafe {
        let last = (*h).prev;
        (*n).next = h;
        (*n).prev = last;
        (*last).next = n;
        (*h).prev = n;
    }
}

unsafe fn list_del(n: *mut ListT) {
    unsafe {
        if (*n).next.is_null() {
            return;
        }
        (*(*n).prev).next = (*n).next;
        (*(*n).next).prev = (*n).prev;
        (*n).next = core::ptr::null_mut();
        (*n).prev = core::ptr::null_mut();
    }
}

pub unsafe fn init(main: *mut Tcb, slots: usize) {
    unsafe {
        let g = global();
        #[cfg(not(feature = "shared"))]
        let slots = {
            let _ = slots;
            let t = crate::tls::template();
            let a = t.align.max(1);
            (*STATIC_MAP.0.get())[LINK_MAP_TLS_MODID / 8] = 1;
            (*STATIC_MAP.0.get())[LINK_MAP_TLS_OFFSET / 8] = (t.memsz + a - 1) & !(a - 1);
            (*STATIC_SLOTS.0.get()).slots[1].map = STATIC_MAP.0.get() as usize;
            STATIC_SLOTS.0.get() as usize
        };
        (*g).slotinfo = slots;
        list_init(&raw mut (*g).stack_used);
        list_init(&raw mut (*g).stack_user);
        list_add(&raw mut (*g).stack_user, &raw mut (*main).db_list);
        #[cfg(feature = "start")]
        core::hint::black_box(&raw const __nptl_version);
    }
}

pub unsafe fn add(t: *mut Tcb) {
    unsafe {
        let g = global();
        if (*g).stack_used.next.is_null() {
            return;
        }
        list_add(&raw mut (*g).stack_used, &raw mut (*t).db_list);
    }
}

pub unsafe fn remove(t: *mut Tcb) {
    unsafe { list_del(&raw mut (*t).db_list) }
}

pub unsafe fn after_fork(me: *mut Tcb) {
    unsafe {
        let g = global();
        if (*g).stack_used.next.is_null() {
            return;
        }
        list_init(&raw mut (*g).stack_used);
        list_init(&raw mut (*g).stack_user);
        (*me).db_list = ListT { next: core::ptr::null_mut(), prev: core::ptr::null_mut() };
        list_add(&raw mut (*g).stack_user, &raw mut (*me).db_list);
    }
}

#[cfg(feature = "start")]
unsafe extern "C" {
    static __nptl_version: u8;
}

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
    ".globl _thread_db_dtv_dtv", "_thread_db_dtv_dtv: .long 128, 134217727, 0",
    ".globl _thread_db_dtv_t_counter", "_thread_db_dtv_t_counter: .long 64, 1, 0",
    ".globl _thread_db_dtv_t_pointer_val", "_thread_db_dtv_t_pointer_val: .long 64, 1, 0",
    ".globl _thread_db_dtv_slotinfo_list_len", "_thread_db_dtv_slotinfo_list_len: .long 64, 1, 0",
    ".globl _thread_db_dtv_slotinfo_list_next", "_thread_db_dtv_slotinfo_list_next: .long 64, 1, 8",
    ".globl _thread_db_dtv_slotinfo_list_slotinfo", "_thread_db_dtv_slotinfo_list_slotinfo: .long 128, 0, 16",
    ".globl _thread_db_dtv_slotinfo_gen", "_thread_db_dtv_slotinfo_gen: .long 64, 1, 0",
    ".globl _thread_db_dtv_slotinfo_map", "_thread_db_dtv_slotinfo_map: .long 64, 1, 8",
    ".popsection",
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
    ".pushsection .text.rl_thread_db,\"ax\",@progbits",
    ".globl __nptl_create_event", ".type __nptl_create_event, @function",
    "__nptl_create_event: ret",
    ".size __nptl_create_event, . - __nptl_create_event",
    ".globl __nptl_death_event", ".type __nptl_death_event, @function",
    "__nptl_death_event: ret",
    ".size __nptl_death_event, . - __nptl_death_event",
    ".popsection",
    sz_pthread = const size_of::<Tcb>(),
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

const _: () = assert!(offset_of!(DbZero, eventnum) - offset_of!(DbZero, eventmask) == 8);
const _: () = assert!(offset_of!(DbZero, eventdata) - offset_of!(DbZero, eventmask) == 16);
const _: () = assert!(size_of::<ListT>() == 16 && size_of::<DbSlot>() == 16);

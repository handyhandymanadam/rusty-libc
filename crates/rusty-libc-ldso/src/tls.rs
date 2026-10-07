use crate::map::*;
use crate::sys;
use crate::util::*;
use core::ptr::null_mut;

pub const MAX_TLS_MODS: usize = 2048;
const UNALLOCATED: usize = usize::MAX;
const STATIC_SURPLUS: usize = 1664;
pub const TCB_SIZE: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Dtv {
    pub val: usize,
    pub to_free: usize,
}

#[derive(Clone, Copy)]
pub struct Module {
    pub map: *mut LinkMap,
    pub image: usize,
    pub filesz: usize,
    pub memsz: usize,
    pub align: usize,
    pub offset: usize,
    pub is_static: bool,
    pub live: bool,
    pub late: bool,
    pub forced_dynamic: bool,
    pub first: usize,
    pub free: bool,
}

pub struct Tls {
    pub mods: [Module; MAX_TLS_MODS],
    pub nmods: usize,
    pub generation: usize,
    pub static_used: usize,
    pub static_total: usize,
    pub max_align: usize,
    pub ready: bool,
}

static mut TLS: Tls = Tls {
    mods: [Module { map: null_mut(), image: 0, filesz: 0, memsz: 0, align: 1, offset: 0, is_static: false, live: false, late: false, forced_dynamic: false, first: 0, free: false }; MAX_TLS_MODS],
    nmods: 0,
    generation: 1,
    static_used: 0,
    static_total: 0,
    max_align: 64,
    ready: false,
};

static TLS_LOCK: Lock = Lock::new();

#[inline(always)]
pub fn tls() -> &'static mut Tls {
    unsafe { &mut *(&raw mut TLS) }
}

pub fn ready() -> bool {
    tls().ready
}

fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

pub unsafe fn add_module(m: *mut LinkMap, static_now: bool) -> bool {
    unsafe {
        let t = tls();
        if (*m).tls_memsz == 0 && (*m).tls_filesz == 0 {
            return true;
        }
        let mut id = 0;
        if t.ready {
            TLS_LOCK.lock();
            for i in 1..=t.nmods {
                if t.mods[i].free {
                    id = i;
                    break;
                }
            }
            TLS_LOCK.unlock();
        }
        if id == 0 {
            if t.nmods + 1 >= MAX_TLS_MODS {
                return false;
            }
            id = t.nmods + 1;
        }
        let align = (*m).tls_align.max(1);
        let mut md = Module { map: m, image: (*m).tls_image, filesz: (*m).tls_filesz, memsz: (*m).tls_memsz, align, offset: 0, is_static: false, live: true, late: false, forced_dynamic: false, first: 0, free: false };
        if static_now {
            let off = align_up(t.static_used + md.memsz, align);
            if t.ready && off > t.static_total {
                return false;
            }
            md.first = t.static_used;
            t.static_used = off;
            md.offset = off;
            md.is_static = true;
            t.max_align = t.max_align.max(align);
            (*m).tls_offset = off;
            (*m).tls_static = true;
        }
        t.mods[id] = md;
        if id > t.nmods {
            t.nmods = id;
        }
        (*m).tls_modid = id;
        t.generation += 1;
        true
    }
}

pub unsafe fn setup_main_thread(random: *const usize) {
    unsafe {
        let t = tls();
        t.static_total = align_up(t.static_used + STATIC_SURPLUS, t.max_align);
        let size = t.static_total + TCB_SIZE;
        let base = sys::mmap(0, size, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0);
        if base < 0 && base > -4096 {
            crate::die(format_args!("cannot allocate TLS block"));
        }
        let tp = base as usize + t.static_total;
        let tcb = tp as *mut usize;
        *tcb = tp;
        *tcb.add(2) = tp;
        if !random.is_null() {
            *tcb.add(5) = *random & !0xff;
            *tcb.add(6) = *random.add(1);
        }
        *(tp as *mut u8).add(0x38).cast::<i32>() = sys::gettid();
        init_block(tp);
        if sys::set_fs(tp) < 0 {
            crate::die(format_args!("cannot set up the thread pointer"));
        }
        t.ready = true;
    }
}

pub unsafe extern "C" fn init_block(tp: usize) {
    unsafe {
        TLS_LOCK.lock();
        let t = tls();
        let cap = t.nmods + 64;
        let dtv = alloc_blk((cap + 2) * core::mem::size_of::<Dtv>(), 16) as *mut Dtv;
        (*dtv).val = cap;
        let d = dtv.add(1);
        (*d).val = t.generation;
        (*d).to_free = dtv as usize;
        for i in 1..=cap {
            (*d.add(i)).val = UNALLOCATED;
        }
        for id in 1..=t.nmods {
            let md = t.mods[id];
            if md.live && md.is_static {
                let p = tp - md.offset;
                core::ptr::copy_nonoverlapping(md.image as *const u8, p as *mut u8, md.filesz);
                (*d.add(id)).val = p;
            }
        }
        *((tp + 8) as *mut usize) = d as usize;
        TLS_LOCK.unlock();
    }
}

pub unsafe extern "C" fn free_block(tp: usize) {
    unsafe {
        let d = *((tp + 8) as *const usize) as *mut Dtv;
        if d.is_null() {
            return;
        }
        TLS_LOCK.lock();
        let cap = (*d.sub(1)).val;
        for i in 1..=cap {
            let e = *d.add(i);
            if e.to_free != 0 {
                let md = tls().mods[i];
                free_blk(e.to_free as *mut u8, md.memsz + md.align, md.align.max(16));
            }
        }
        free_blk(d.sub(1) as *mut u8, (cap + 2) * core::mem::size_of::<Dtv>(), 16);
        *((tp + 8) as *mut usize) = 0;
        let eb = (tp + 0x48) as *mut usize;
        if *eb != 0 {
            free_blk(*eb as *mut u8, crate::dl::ERRBUF_SIZE, 16);
            *eb = 0;
        }
        TLS_LOCK.unlock();
    }
}

#[repr(C)]
pub struct TlsIndex {
    pub module: usize,
    pub offset: usize,
}

#[inline(never)]
unsafe fn tls_get_addr_slow(ti: *const TlsIndex) -> usize {
    unsafe {
        TLS_LOCK.lock();
        let t = tls();
        let id = (*ti).module;
        let tp = sys::thread_pointer();
        let mut d = *((tp + 8) as *const usize) as *mut Dtv;
        let cap = (*d.sub(1)).val;
        if id > cap || id > t.nmods {
            if id > t.nmods || !t.mods[id].live {
                TLS_LOCK.unlock();
                crate::die(format_args!("TLS lookup for an unknown module"));
            }
            let ncap = (id + 32).max(cap * 2);
            let nd = alloc_blk((ncap + 2) * core::mem::size_of::<Dtv>(), 16) as *mut Dtv;
            (*nd).val = ncap;
            let nd = nd.add(1);
            for i in 0..=cap {
                *nd.add(i) = *d.add(i);
            }
            for i in cap + 1..=ncap {
                (*nd.add(i)).val = UNALLOCATED;
            }
            (*nd).to_free = nd.sub(1) as usize;
            free_blk(d.sub(1) as *mut u8, (cap + 2) * core::mem::size_of::<Dtv>(), 16);
            *((tp + 8) as *mut usize) = nd as usize;
            d = nd;
        }
        (*d).val = t.generation;
        let e = d.add(id);
        if (*e).val == UNALLOCATED {
            let md = t.mods[id];
            if !md.live {
                TLS_LOCK.unlock();
                crate::die(format_args!("TLS lookup for an unloaded module"));
            }
            if md.is_static {
                (*e).val = tp - md.offset;
                (*e).to_free = 0;
            } else {
                t.mods[id].forced_dynamic = true;
                let raw = alloc_blk(md.memsz + md.align, md.align.max(16));
                let p = align_up(raw as usize, md.align.max(1));
                core::ptr::copy_nonoverlapping(md.image as *const u8, p as *mut u8, md.filesz);
                (*e).val = p;
                (*e).to_free = raw as usize;
            }
        }
        let r = (*e).val + (*ti).offset;
        TLS_LOCK.unlock();
        r
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __tls_get_addr(ti: *const TlsIndex) -> usize {
    unsafe {
        let tp = sys::thread_pointer();
        let d = *((tp + 8) as *const usize) as *const Dtv;
        let id = (*ti).module;
        if !d.is_null() && id <= (*d.sub(1)).val {
            let e = *d.add(id);
            if e.val != UNALLOCATED && (*d).val == tls().generation {
                return e.val + (*ti).offset;
            }
        }
        tls_get_addr_slow(ti)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_tls_info(out: *mut usize) {
    unsafe {
        *out = tls().static_total;
        *out.add(1) = tls().max_align;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_tls_init_block(tp: usize) {
    unsafe { init_block(tp) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_tls_free_block(tp: usize) {
    unsafe { free_block(tp) }
}

unsafe fn init_static_for(tp: usize, id: usize) {
    unsafe {
        TLS_LOCK.lock();
        let md = tls().mods[id];
        if md.live && md.is_static {
            core::ptr::copy_nonoverlapping(md.image as *const u8, (tp - md.offset) as *mut u8, md.filesz);
            let d = *((tp + 8) as *const usize) as *mut Dtv;
            if !d.is_null() && id <= (*d.sub(1)).val {
                (*d.add(id)).val = tp - md.offset;
                (*d.add(id)).to_free = 0;
            }
        }
        TLS_LOCK.unlock();
    }
}

unsafe extern "C" fn walk_cb(tp: usize, arg: usize) {
    unsafe { init_static_for(tp, arg) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_tls_sync(tp: usize) {
    unsafe {
        let n = tls().nmods;
        for id in 1..=n {
            let md = tls().mods[id];
            if md.late && md.live && md.is_static {
                init_static_for(tp, id);
            }
        }
    }
}

pub unsafe fn add_static_late(m: *mut LinkMap) -> bool {
    unsafe {
        let t = tls();
        let id = (*m).tls_modid;
        if id == 0 {
            return true;
        }
        TLS_LOCK.lock();
        let md = &mut t.mods[id];
        if md.is_static {
            TLS_LOCK.unlock();
            return true;
        }
        let off = align_up(t.static_used + md.memsz, md.align);
        if md.forced_dynamic || off > t.static_total || md.align > t.max_align {
            TLS_LOCK.unlock();
            return false;
        }
        md.first = t.static_used;
        t.static_used = off;
        md.offset = off;
        md.is_static = true;
        md.late = true;
        (*m).tls_offset = off;
        (*m).tls_static = true;
        TLS_LOCK.unlock();
        copy_image_to_threads(id);
        true
    }
}

unsafe fn copy_image_to_threads(id: usize) {
    unsafe {
        init_static_for(sys::thread_pointer(), id);
        let g = core::slice::from_raw_parts((&raw const st().global) as *const *mut LinkMap, st().nglobal);
        let fl = crate::lookup::Flags { plt: false, skip: null_mut(), newest: false };
        if let Some(f) = crate::lookup::lookup(b"__libc_walk_threads", None, &[g], &fl) {
            let walker: unsafe extern "C" fn(unsafe extern "C" fn(usize, usize), usize) = core::mem::transmute(crate::lookup::sym_addr(&f));
            walker(walk_cb, id);
        }
    }
}

pub unsafe fn after_relocate(m: *mut LinkMap) {
    unsafe {
        let id = (*m).tls_modid;
        if id == 0 || (*m).tls_filesz == 0 {
            return;
        }
        let md = tls().mods[id];
        if !md.live || !md.is_static {
            return;
        }
        if md.late {
            copy_image_to_threads(id);
        } else {
            init_static_for(sys::thread_pointer(), id);
        }
    }
}

pub unsafe fn remove_module(m: *mut LinkMap) {
    unsafe {
        let id = (*m).tls_modid;
        if id != 0 {
            TLS_LOCK.lock();
            tls().mods[id].live = false;
            tls().generation += 1;
            let t = tls();
            if t.mods[id].is_static && !t.mods[id].forced_dynamic {
                loop {
                    let mut moved = false;
                    for i in 1..=t.nmods {
                        let md = &mut t.mods[i];
                        if !md.live && md.is_static && !md.free && md.offset == t.static_used {
                            t.static_used = md.first;
                            md.is_static = false;
                            moved = true;
                        }
                    }
                    if !moved {
                        break;
                    }
                }
            }
            TLS_LOCK.unlock();
            clear_in_threads(id);
            TLS_LOCK.lock();
            tls().mods[id].free = true;
            TLS_LOCK.unlock();
        }
    }
}

unsafe extern "C" fn clear_cb(tp: usize, id: usize) {
    unsafe {
        TLS_LOCK.lock();
        let d = *((tp + 8) as *const usize) as *mut Dtv;
        if !d.is_null() && id <= (*d.sub(1)).val {
            let e = d.add(id);
            if (*e).to_free != 0 {
                let md = tls().mods[id];
                free_blk((*e).to_free as *mut u8, md.memsz + md.align, md.align.max(16));
            }
            (*e).val = UNALLOCATED;
            (*e).to_free = 0;
        }
        TLS_LOCK.unlock();
    }
}

unsafe fn clear_in_threads(id: usize) {
    unsafe {
        let g = core::slice::from_raw_parts((&raw const st().global) as *const *mut LinkMap, st().nglobal);
        let fl = crate::lookup::Flags { plt: false, skip: null_mut(), newest: false };
        if let Some(f) = crate::lookup::lookup(b"__libc_walk_threads", None, &[g], &fl) {
            let walker: unsafe extern "C" fn(unsafe extern "C" fn(usize, usize), usize) = core::mem::transmute(crate::lookup::sym_addr(&f));
            walker(clear_cb, id);
        } else {
            clear_cb(sys::thread_pointer(), id);
        }
    }
}

core::arch::global_asm!(
    ".text",
    ".globl _dl_tlsdesc_return",
    ".hidden _dl_tlsdesc_return",
    ".type _dl_tlsdesc_return, @function",
    "_dl_tlsdesc_return:",
    "mov rax, [rax + 8]",
    "ret",
    ".size _dl_tlsdesc_return, .-_dl_tlsdesc_return",
    ".globl _dl_tlsdesc_dynamic",
    ".hidden _dl_tlsdesc_dynamic",
    ".type _dl_tlsdesc_dynamic, @function",
    "_dl_tlsdesc_dynamic:",
    "push rbp",
    "mov rbp, rsp",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "sub rsp, 256",
    "and rsp, -64",
    "sub rsp, 4096",
    "mov [rsp + 4096 - 8], rax",
    "xor ecx, ecx",
    "mov [rsp + 512], rcx",
    "mov [rsp + 520], rcx",
    "mov [rsp + 528], rcx",
    "mov [rsp + 536], rcx",
    "mov [rsp + 544], rcx",
    "mov [rsp + 552], rcx",
    "mov [rsp + 560], rcx",
    "mov [rsp + 568], rcx",
    "xor edx, edx",
    "mov eax, -1",
    "xsave [rsp]",
    "mov rdi, [rsp + 4096 - 8]",
    "mov rdi, [rdi + 8]",
    "call {tga}",
    "sub rax, fs:0",
    "mov [rsp + 4096 - 8], rax",
    "xor edx, edx",
    "mov eax, -1",
    "xrstor [rsp]",
    "mov rax, [rsp + 4096 - 8]",
    "lea rsp, [rbp - 64]",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rbp",
    "ret",
    ".size _dl_tlsdesc_dynamic, .-_dl_tlsdesc_dynamic",
    tga = sym __tls_get_addr,
);

unsafe extern "C" {
    pub fn _dl_tlsdesc_return();
    pub fn _dl_tlsdesc_dynamic();
}
